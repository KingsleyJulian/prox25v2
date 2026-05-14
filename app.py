from flask import Flask, render_template, jsonify, request, Response
import subprocess, json, os, re, sys, time, yaml, uuid, random, string, threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import ipaddress

app = Flask(__name__)

CONFIG_FILE   = '/etc/proxymanager/config.json'
NETPLAN_FILE  = '/etc/netplan/01-netcfg.yaml'
PROXY3_CFG    = '/etc/3proxy/3proxy.cfg'
RT_TABLES     = '/etc/iproute2/rt_tables'

SYS_NET       = '/sys/class/net'
TABLE_MIN     = 101
TABLE_MAX     = 249

VERSION_FILE  = '/opt/proxymanager/VERSION'
REPO_URL      = 'https://github.com/KingsleyJulian/prox25v2.git'
REPO_API      = 'https://api.github.com/repos/KingsleyJulian/prox25v2'
UPDATE_SCRIPT = '/opt/proxymanager/_self_update.sh'
UPDATE_LOG    = '/var/log/proxymanager-update.log'

# ISP lookup cache: iface -> {ip, public_ip, isp, country, city, ts}
ISP_CACHE = {}
ISP_TTL   = 900   # 15 minutes — ipinfo rate-limits the free tier

# ── helpers ──────────────────────────────────────────────────────────────────

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout.strip(), r.stderr.strip(), r.returncode

def list_nics():
    """Physical ethernet interfaces — anything in /sys/class/net with a backing device."""
    try:
        return sorted(
            i for i in os.listdir(SYS_NET)
            if os.path.exists(f'{SYS_NET}/{i}/device')
        )
    except FileNotFoundError:
        return []

def get_or_assign_tid(iface, cfg):
    table_ids = cfg.setdefault('table_ids', {})
    if iface in table_ids:
        return table_ids[iface]
    used = set(table_ids.values())
    for candidate in range(TABLE_MIN, TABLE_MAX + 1):
        if candidate not in used:
            table_ids[iface] = candidate
            return candidate
    raise RuntimeError('No free routing table IDs')

def detect_default_uplink():
    """Iface that physically holds the main-table default route right now."""
    out, _, _ = run(['ip', 'route', 'show', 'default'])
    m = re.search(r'default\s+via\s+\S+\s+dev\s+(\S+)', out)
    return m.group(1) if m else None

def get_uplink_iface():
    """Manual override from config wins; otherwise fall back to live default-route detection."""
    cfg = load_cfg()
    manual = cfg.get('uplink')
    if manual and manual in list_nics():
        return manual
    return detect_default_uplink()

def get_default_gateways():
    """iface -> default gateway IP (main table)."""
    out, _, _ = run(['ip', 'route', 'show', 'default'])
    gws = {}
    for line in out.splitlines():
        m = re.match(r'default\s+via\s+(\S+)\s+dev\s+(\S+)', line)
        if m:
            gws[m.group(2)] = m.group(1)
    return gws

def rand_pass(n=12):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=n))

def load_cfg():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {'interfaces': {}, 'proxies': [], 'next_port': 10001}

def save_cfg(cfg):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)

def get_iface_status():
    nics = list_nics()
    out, _, _ = run(['ip', 'addr', 'show'])
    result = {i: {'name': i, 'connected': False, 'ip': None, 'prefix': None} for i in nics}
    cur = None
    for line in out.splitlines():
        m = re.match(r'^\d+: (\S+?)[@:]', line)
        if m:
            cur = m.group(1)
            if cur in result:
                result[cur]['connected'] = 'LOWER_UP' in line
        elif cur in result:
            ip_m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if ip_m:
                result[cur]['ip']     = ip_m.group(1)
                result[cur]['prefix'] = ip_m.group(2)
    gws = get_default_gateways()
    for iface, data in result.items():
        data['gateway'] = gws.get(iface)
    return result

def _read_sys(path, cast=str):
    try:
        with open(path) as f:
            return cast(f.read().strip())
    except Exception:
        return None

def classify_iface(name):
    if name.startswith('enx'):
        return 'usb'
    if name.startswith(('enp', 'eno', 'eth')):
        return 'onboard'
    return 'other'

def get_iface_details():
    """Enriched per-NIC info for the scan page."""
    base = get_iface_status()
    cfg  = load_cfg()
    uplink = get_uplink_iface()
    counts = {}
    for p in cfg['proxies']:
        counts[p['interface']] = counts.get(p['interface'], 0) + 1
    result = {}
    for i, info in base.items():
        d = dict(info)
        d['type']        = classify_iface(i)
        d['mac']         = _read_sys(f'{SYS_NET}/{i}/address')
        d['link_speed']  = _read_sys(f'{SYS_NET}/{i}/speed', int)
        d['duplex']      = _read_sys(f'{SYS_NET}/{i}/duplex')
        d['mtu']         = _read_sys(f'{SYS_NET}/{i}/mtu', int)
        d['rx_bytes']    = _read_sys(f'{SYS_NET}/{i}/statistics/rx_bytes', int)
        d['tx_bytes']    = _read_sys(f'{SYS_NET}/{i}/statistics/tx_bytes', int)
        d['operstate']   = _read_sys(f'{SYS_NET}/{i}/operstate')
        try:
            d['driver'] = os.path.basename(os.readlink(f'{SYS_NET}/{i}/device/driver'))
        except Exception:
            d['driver'] = None
        d['configured']  = i in cfg['interfaces']
        d['cfg']         = cfg['interfaces'].get(i)
        d['proxy_count'] = counts.get(i, 0)
        d['is_uplink']   = (i == uplink)
        result[i] = d
    return result

def lookup_isp(iface, src_ip, force=False):
    """Query ipinfo.io from a specific source IP so the request exits via that NIC's
    policy-routed table. Cached per-iface for ISP_TTL seconds."""
    now = time.time()
    cached = ISP_CACHE.get(iface)
    if not force and cached and cached.get('ip') == src_ip and (now - cached.get('ts', 0)) < ISP_TTL:
        return cached
    cmd = ['curl', '--interface', src_ip, '-s', '-m', '8',
           '-H', 'Accept: application/json', 'https://ipinfo.io/json']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode != 0 or not r.stdout.strip():
            return {'ip': src_ip, 'error': (r.stderr or 'curl failed').strip()[:200], 'ts': now}
        data = json.loads(r.stdout)
        org = (data.get('org') or '').strip()
        # ipinfo "org" looks like "AS15169 Google LLC" — split AS number from name
        asn = ''
        isp = org
        m = re.match(r'^(AS\d+)\s+(.*)$', org)
        if m:
            asn, isp = m.group(1), m.group(2)
        info = {
            'ip':        src_ip,
            'public_ip': data.get('ip'),
            'isp':       isp or None,
            'asn':       asn or None,
            'country':   data.get('country'),
            'region':    data.get('region'),
            'city':      data.get('city'),
            'hostname':  data.get('hostname'),
            'ts':        now,
        }
        ISP_CACHE[iface] = info
        return info
    except Exception as e:
        return {'ip': src_ip, 'error': f'{type(e).__name__}: {e}', 'ts': now}

# ── netplan + routing ─────────────────────────────────────────────────────────

def update_netplan(iface, ip, prefix, gateway, t):
    with open(NETPLAN_FILE) as f:
        cfg = yaml.safe_load(f)
    net = str(ipaddress.IPv4Network(f'{ip}/{prefix}', strict=False))
    cfg['network']['ethernets'][iface] = {
        'addresses': [f'{ip}/{prefix}'],
        'routes': [
            {'to': 'default', 'via': gateway, 'metric': t, 'table': t},
            {'to': net, 'via': '0.0.0.0', 'scope': 'link', 'table': t},
        ],
        'routing-policy': [{'from': ip, 'table': t}],
        'nameservers': {'addresses': ['8.8.8.8', '8.8.4.4']},
    }
    with open(NETPLAN_FILE, 'w') as f:
        yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
    _, err, rc = run(['netplan', 'apply'])
    return rc == 0, err

def apply_policy_routing(iface, ip, gateway, t):
    tname = f'isp_{iface}'
    with open(RT_TABLES) as f:
        content = f.read()
    if tname not in content:
        with open(RT_TABLES, 'a') as f:
            f.write(f'{t}\t{tname}\n')
    run(['ip', 'route', 'replace', 'default', 'via', gateway, 'dev', iface, 'table', str(t)])
    run(['ip', 'rule', 'del', 'from', ip])
    run(['ip', 'rule', 'add', 'from', ip, 'table', str(t)])
    run(['ip', 'route', 'flush', 'cache'])

# ── 3proxy config ─────────────────────────────────────────────────────────────

def write_3proxy(proxies):
    lines = [
        'nserver 8.8.8.8',
        'nserver 8.8.4.4',
        'nscache 65536',
        'timeouts 1 5 30 60 180 1800 15 60',
        'log /var/log/3proxy/3proxy.log D',
        'maxconn 200',
        '',
        'auth strong',
    ]
    for p in proxies:
        lines.append(f"users {p['username']}:CL:{p['password']}")
    lines.append('')
    for p in proxies:
        lines += [
            f"# {p['interface']} | {p['username']}",
            'allow *',
            f"socks -p{p['port']} -i0.0.0.0 -e{p['exit_ip']} -a",
            '',
        ]
    os.makedirs(os.path.dirname(PROXY3_CFG), exist_ok=True)
    with open(PROXY3_CFG, 'w') as f:
        f.write('\n'.join(lines))

def reload_3proxy():
    run(['systemctl', 'restart', '3proxy'])

# ── routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan_page():
    return render_template('scan.html')

@app.route('/update')
def update_page():
    return render_template('update.html')

def read_local_sha():
    try:
        with open(VERSION_FILE) as f:
            return f.read().strip() or None
    except Exception:
        return None

@app.route('/api/version')
def api_version():
    local_sha = read_local_sha()
    try:
        r = subprocess.run(
            ['curl', '-s', '-m', '10', '-H', 'Accept: application/vnd.github+json',
             f'{REPO_API}/commits?per_page=20'],
            capture_output=True, text=True, timeout=12,
        )
        commits = json.loads(r.stdout) if r.stdout else []
    except Exception as e:
        return jsonify({
            'local': local_sha, 'local_short': (local_sha or '')[:7],
            'error': f'{type(e).__name__}: {e}',
        })
    if not isinstance(commits, list):
        msg = (commits or {}).get('message', 'GitHub API error')
        return jsonify({'local': local_sha, 'error': msg})
    remote_sha = commits[0]['sha'] if commits else None
    pending = []
    for c in commits:
        if c['sha'] == local_sha:
            break
        pending.append({
            'sha':     c['sha'][:7],
            'message': c['commit']['message'].split('\n')[0],
            'author':  c['commit']['author']['name'],
            'date':    c['commit']['author']['date'],
            'url':     c.get('html_url'),
        })
    return jsonify({
        'local':        local_sha,
        'local_short':  local_sha[:7] if local_sha else None,
        'remote':       remote_sha,
        'remote_short': remote_sha[:7] if remote_sha else None,
        'up_to_date':   (local_sha == remote_sha) if (local_sha and remote_sha) else False,
        'pending':      pending,
        'pending_count': len(pending),
    })

@app.route('/api/update', methods=['POST'])
def api_update():
    """Run the self-update via systemd-run so the updater survives our own
    service restart (systemd kills our cgroup when proxymanager bounces)."""
    script = f"""#!/bin/bash
set -e
exec >> {UPDATE_LOG} 2>&1
echo "=== $(date -Is) self-update started ==="
REPO=/var/lib/proxymanager/repo
mkdir -p /var/lib/proxymanager
if [ -d "$REPO/.git" ]; then
  git -C "$REPO" fetch --depth=1 origin main
  git -C "$REPO" reset --hard origin/main
else
  rm -rf "$REPO"
  git clone --depth=1 {REPO_URL} "$REPO"
fi
cd "$REPO"
# Strip CRLF in case the repo was ever touched from Windows
sed -i 's/\\r$//' install.sh
bash install.sh
echo "=== $(date -Is) self-update finished ==="
"""
    with open(UPDATE_SCRIPT, 'w') as f:
        f.write(script)
    os.chmod(UPDATE_SCRIPT, 0o755)
    open(UPDATE_LOG, 'a').close()
    unit = f'proxymanager-update-{int(time.time())}'
    r = subprocess.run(
        ['systemd-run', f'--unit={unit}', '--collect', '--no-block',
         'bash', UPDATE_SCRIPT],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return jsonify({'success': False, 'error': (r.stderr or 'systemd-run failed').strip()}), 500
    return jsonify({
        'success': True,
        'unit':    unit,
        'message': 'Update started. The service will restart in ~30s.',
    })

@app.route('/api/update/log')
def api_update_log():
    try:
        with open(UPDATE_LOG) as f:
            data = f.read()
    except FileNotFoundError:
        data = ''
    # Tail the last ~4KB so the response stays small
    return Response(data[-4096:], mimetype='text/plain')

@app.route('/api/scan')
def api_scan():
    details = get_iface_details()
    # Attach cached ISP info if present (don't block on fresh lookups here)
    for name, d in details.items():
        cached = ISP_CACHE.get(name)
        if cached and cached.get('ip') == d.get('ip'):
            d['isp_info'] = cached
    return jsonify(details)

@app.route('/api/isp')
def api_isp_all():
    """Refresh-on-demand ISP info for every configured iface, in parallel.
    Honours the cache so polling is cheap. ?force=1 bypasses cache, ?iface=<n>
    scopes to one NIC."""
    force = request.args.get('force') == '1'
    only  = request.args.get('iface')
    cfg = load_cfg()
    details = get_iface_status()
    targets = []
    for name in list_nics():
        if only and name != only:
            continue
        ip = (cfg['interfaces'].get(name) or {}).get('ip') or (details.get(name) or {}).get('ip')
        if not ip:
            continue
        targets.append((name, ip))
    out = {}
    if targets:
        with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
            futures = {pool.submit(lookup_isp, n, ip, force): n for n, ip in targets}
            for fut in futures:
                name = futures[fut]
                try:
                    out[name] = fut.result(timeout=15)
                except Exception as e:
                    out[name] = {'error': f'{type(e).__name__}: {e}'}
    # Include "no ip" rows too so the frontend can render them
    for name in list_nics():
        if only and name != only:
            continue
        if name not in out:
            out[name] = {'error': 'no ip'}
    return jsonify(out)

def warm_isp_cache():
    """Background pre-fetch of ISP info for every configured iface so the
    /scan page shows location instantly on first open."""
    try:
        cfg = load_cfg()
        details = get_iface_status()
        targets = []
        for name in list_nics():
            ip = (cfg['interfaces'].get(name) or {}).get('ip') or (details.get(name) or {}).get('ip')
            if ip:
                targets.append((name, ip))
        if not targets:
            return
        with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
            for name, ip in targets:
                pool.submit(lookup_isp, name, ip, False)
    except Exception:
        pass  # never let cache warming crash the app

@app.route('/api/speedtest/<iface>', methods=['POST'])
def api_speedtest(iface):
    """Measure ping / download / upload through a specific NIC by binding curl
    to that NIC's source IP. Hits Cloudflare's speed endpoints — much more
    reliable than speedtest-cli when forced through a non-default route."""
    try:
        if iface not in list_nics():
            return jsonify({'success': False, 'error': 'Unknown interface'}), 400
        cfg = load_cfg()
        src_ip = (cfg['interfaces'].get(iface) or {}).get('ip')
        if not src_ip:
            live = get_iface_status().get(iface) or {}
            src_ip = live.get('ip')
        if not src_ip:
            return jsonify({'success': False, 'error': 'No IP bound to interface'}), 400

        result = {'success': True, 'source_ip': src_ip, 'server': 'speed.cloudflare.com'}
        errors = []

        # 1) Ping — total time of a tiny request
        r = subprocess.run(
            ['curl', '-s', '-m', '8', '--interface', src_ip, '-o', '/dev/null',
             '-w', '%{time_total}',
             'https://www.cloudflare.com/cdn-cgi/trace'],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip():
            try:
                result['ping_ms'] = round(float(r.stdout.strip()) * 1000, 1)
            except ValueError:
                errors.append('ping parse error')
        else:
            errors.append(f'ping: {(r.stderr or "fail").strip()[:120]}')

        # 2) Download — pull 25MB, capture speed_download (bytes/sec)
        r = subprocess.run(
            ['curl', '-s', '-m', '30', '--interface', src_ip, '-o', '/dev/null',
             '-w', '%{speed_download}',
             'https://speed.cloudflare.com/__down?bytes=25000000'],
            capture_output=True, text=True, timeout=35,
        )
        if r.returncode == 0 and r.stdout.strip():
            try:
                result['download_mbps'] = round(float(r.stdout.strip()) * 8 / 1_000_000, 2)
            except ValueError:
                errors.append('download parse error')
        else:
            errors.append(f'download: {(r.stderr or "fail").strip()[:120]}')

        # 3) Upload — push 5MB of random bytes, capture speed_upload
        up_cmd = (
            f"head -c 5242880 /dev/urandom | "
            f"curl -s -m 25 --interface {src_ip} -X POST --data-binary @- "
            f"-o /dev/null -w '%{{speed_upload}}' https://speed.cloudflare.com/__up"
        )
        r = subprocess.run(['bash', '-c', up_cmd], capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            try:
                result['upload_mbps'] = round(float(r.stdout.strip()) * 8 / 1_000_000, 2)
            except ValueError:
                errors.append('upload parse error')
        else:
            errors.append(f'upload: {(r.stderr or "fail").strip()[:120]}')

        # If every probe failed, surface that instead of pretending success
        got_any = any(k in result for k in ('ping_ms', 'download_mbps', 'upload_mbps'))
        if not got_any:
            return jsonify({'success': False, 'error': '; '.join(errors) or 'all probes failed'}), 502
        if errors:
            result['warnings'] = errors
        return jsonify(result)
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'speedtest timed out'}), 504
    except Exception as e:
        return jsonify({'success': False, 'error': f'{type(e).__name__}: {e}'}), 500

@app.route('/api/uplink', methods=['GET'])
def api_uplink_get():
    cfg = load_cfg()
    return jsonify({
        'manual':  cfg.get('uplink'),
        'current': detect_default_uplink(),
        'effective': get_uplink_iface(),
    })

@app.route('/api/uplink', methods=['POST'])
def api_uplink_set():
    d = request.get_json(silent=True) or {}
    iface = d.get('interface')
    cfg = load_cfg()
    if iface in (None, '', 'auto'):
        # clear manual override
        cfg.pop('uplink', None)
        save_cfg(cfg)
        return jsonify({'success': True, 'manual': None, 'current': detect_default_uplink()})
    if iface not in list_nics():
        return jsonify({'success': False, 'error': 'Unknown interface'}), 400
    icfg = cfg['interfaces'].get(iface)
    if not icfg:
        return jsonify({'success': False, 'error': 'Configure interface first (need gateway)'}), 400
    gw = icfg['gateway']
    # Move the main-table default route to this iface. Tailscale will follow.
    _, err, rc = run(['ip', 'route', 'replace', 'default', 'via', gw, 'dev', iface])
    if rc != 0:
        return jsonify({'success': False, 'error': f'ip route replace failed: {err}'}), 500
    run(['ip', 'route', 'flush', 'cache'])
    cfg['uplink'] = iface
    save_cfg(cfg)
    return jsonify({
        'success': True,
        'manual':  iface,
        'current': detect_default_uplink(),
    })

def get_tailscale_ip():
    out, _, _ = run(['ip', 'addr', 'show', 'tailscale0'])
    m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', out)
    return m.group(1) if m else None

@app.route('/api/server-info')
def api_server_info():
    return jsonify({'tailscale_ip': get_tailscale_ip()})

@app.route('/api/status')
def api_status():
    live   = get_iface_status()
    cfg    = load_cfg()
    uplink = get_uplink_iface()
    counts = {}
    for p in cfg['proxies']:
        counts[p['interface']] = counts.get(p['interface'], 0) + 1
    for iface, data in live.items():
        data['configured'] = iface in cfg['interfaces']
        data['cfg']        = cfg['interfaces'].get(iface)
        data['proxy_count']= counts.get(iface, 0)
        data['is_uplink']  = (iface == uplink)
    return jsonify(live)

@app.route('/api/interface/setup', methods=['POST'])
def iface_setup():
    d      = request.json
    iface  = d['interface']
    ip     = d['ip']
    prefix = str(d['prefix'])
    gw     = d['gateway']
    if iface not in list_nics():
        return jsonify({'success': False, 'error': 'Unknown interface'}), 400
    cfg     = load_cfg()
    t       = get_or_assign_tid(iface, cfg)
    uplink  = (iface == get_uplink_iface())
    errors  = []
    # Skip netplan rewrite for the uplink — its config is owned by whatever
    # currently provides the default route (DHCP / existing static), and we
    # don't want to risk dropping Tailscale's path.
    if not uplink:
        ok, err = update_netplan(iface, ip, prefix, gw, t)
        if not ok:
            errors.append(f'netplan: {err}')
    apply_policy_routing(iface, ip, gw, t)
    cfg['interfaces'][iface] = {
        'ip': ip, 'prefix': int(prefix), 'gateway': gw,
        'table_id': t, 'is_uplink': uplink,
    }
    # update exit_ip on existing proxies for this interface
    for p in cfg['proxies']:
        if p['interface'] == iface:
            p['exit_ip'] = ip
    save_cfg(cfg)
    write_3proxy(cfg['proxies'])
    reload_3proxy()
    return jsonify({'success': len(errors) == 0, 'errors': errors})

@app.route('/api/interface/<iface>', methods=['DELETE'])
def iface_delete(iface):
    cfg = load_cfg()
    iface_cfg = cfg['interfaces'].pop(iface, None)
    if iface_cfg:
        run(['ip', 'rule', 'del', 'from', iface_cfg['ip']])
        save_cfg(cfg)
        write_3proxy(cfg['proxies'])
        reload_3proxy()
    return jsonify({'success': True})

@app.route('/api/proxies')
def list_proxies():
    cfg = load_cfg()
    iface_filter = request.args.get('interface')
    proxies = cfg['proxies']
    if iface_filter:
        proxies = [p for p in proxies if p['interface'] == iface_filter]
    return jsonify(proxies)

@app.route('/api/proxies', methods=['POST'])
def create_proxy():
    d     = request.json
    iface = d['interface']
    cfg   = load_cfg()
    if iface not in cfg['interfaces']:
        return jsonify({'success': False, 'error': 'Configure interface first'}), 400
    iface_cfg = cfg['interfaces'][iface]
    proxy = {
        'id':         str(uuid.uuid4())[:8],
        'interface':  iface,
        'exit_ip':    iface_cfg['ip'],
        'port':       cfg['next_port'],
        'username':   d.get('username') or f'px_{str(uuid.uuid4())[:6]}',
        'password':   d.get('password') or rand_pass(),
        'created_at': datetime.utcnow().isoformat(),
    }
    cfg['proxies'].append(proxy)
    cfg['next_port'] += 1
    save_cfg(cfg)
    write_3proxy(cfg['proxies'])
    reload_3proxy()
    return jsonify({'success': True, 'proxy': proxy})

@app.route('/api/proxies/bulk', methods=['POST'])
def bulk_create():
    d      = request.json
    iface  = d['interface']
    count  = int(d.get('count', 1))
    cfg    = load_cfg()
    if iface not in cfg['interfaces']:
        return jsonify({'success': False, 'error': 'Configure interface first'}), 400
    iface_cfg = cfg['interfaces'][iface]
    created = []
    for _ in range(min(count, 100)):
        proxy = {
            'id':         str(uuid.uuid4())[:8],
            'interface':  iface,
            'exit_ip':    iface_cfg['ip'],
            'port':       cfg['next_port'],
            'username':   f'px_{str(uuid.uuid4())[:6]}',
            'password':   rand_pass(),
            'created_at': datetime.utcnow().isoformat(),
        }
        cfg['proxies'].append(proxy)
        cfg['next_port'] += 1
        created.append(proxy)
    save_cfg(cfg)
    write_3proxy(cfg['proxies'])
    reload_3proxy()
    return jsonify({'success': True, 'created': len(created), 'proxies': created})

@app.route('/api/proxies/<pid>', methods=['DELETE'])
def delete_proxy(pid):
    cfg = load_cfg()
    cfg['proxies'] = [p for p in cfg['proxies'] if p['id'] != pid]
    save_cfg(cfg)
    write_3proxy(cfg['proxies'])
    reload_3proxy()
    return jsonify({'success': True})

def _test_one_proxy(p, dl_bytes=5_000_000):
    """Run exit-IP, latency, and download tests through a single SOCKS5 proxy.
    Returns a dict with all three results plus error info."""
    proxy_url = f"socks5h://{p['username']}:{p['password']}@127.0.0.1:{p['port']}"
    out = {
        'id':            p['id'],
        'port':          p['port'],
        'interface':     p['interface'],
        'configured_ip': p['exit_ip'],
        'success':       False,
    }
    t0 = time.time()
    try:
        # 1) Exit IP through the proxy
        r = subprocess.run(
            ['curl', '-s', '-m', '12', '-x', proxy_url, 'https://api.ipify.org'],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0 or not r.stdout.strip():
            out['error'] = (r.stderr or 'connect failed').strip()[:200]
            return out
        actual_ip = r.stdout.strip()
        out['actual_ip']    = actual_ip
        out['ip_match']     = (actual_ip == p['exit_ip'])

        # 2) Latency — small request, take total time
        r = subprocess.run(
            ['curl', '-s', '-m', '10', '-x', proxy_url, '-o', '/dev/null',
             '-w', '%{time_total}',
             'https://www.cloudflare.com/cdn-cgi/trace'],
            capture_output=True, text=True, timeout=12,
        )
        if r.returncode == 0 and r.stdout.strip():
            try:
                out['latency_ms'] = round(float(r.stdout.strip()) * 1000)
            except ValueError:
                pass

        # 3) Download speed — pulls dl_bytes from Cloudflare speedtest endpoint
        r = subprocess.run(
            ['curl', '-s', '-m', '30', '-x', proxy_url, '-o', '/dev/null',
             '-w', '%{speed_download}',
             f'https://speed.cloudflare.com/__down?bytes={dl_bytes}'],
            capture_output=True, text=True, timeout=35,
        )
        if r.returncode == 0 and r.stdout.strip():
            try:
                bps = float(r.stdout.strip())
                out['download_mbps'] = round(bps * 8 / 1_000_000, 2)
                out['download_bytes'] = dl_bytes
            except ValueError:
                pass

        out['success']    = True
        out['elapsed_ms'] = round((time.time() - t0) * 1000)
        return out
    except subprocess.TimeoutExpired:
        out['error'] = 'timeout'
        return out
    except Exception as e:
        out['error'] = f'{type(e).__name__}: {e}'
        return out

@app.route('/api/proxies/<pid>/test', methods=['POST'])
def api_test_proxy(pid):
    cfg = load_cfg()
    p = next((x for x in cfg['proxies'] if x['id'] == pid), None)
    if not p:
        return jsonify({'error': 'proxy not found'}), 404
    return jsonify(_test_one_proxy(p))

@app.route('/api/proxies/test-all', methods=['POST'])
def api_test_all():
    """Test every proxy (or only those on a given interface) in parallel."""
    cfg   = load_cfg()
    iface = (request.get_json(silent=True) or {}).get('interface') or request.args.get('interface')
    targets = [p for p in cfg['proxies'] if not iface or p['interface'] == iface]
    if not targets:
        return jsonify({'results': []})
    workers = min(10, len(targets))
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for r in pool.map(_test_one_proxy, targets):
            results.append(r)
    return jsonify({'results': results})

@app.route('/test')
def test_page():
    return render_template('test.html')

@app.route('/api/proxies/test-export.xlsx', methods=['POST'])
def api_test_export_xlsx():
    """Build an Excel workbook from a client-supplied list of test results.
    Body: { "results": [ {id, port, interface, configured_ip, actual_ip,
                          ip_match, latency_ms, download_mbps, success,
                          error, ...}, ... ] }
    """
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter
    from io import BytesIO

    body = request.get_json(silent=True) or {}
    results = body.get('results') or []
    # Pull live proxy creds so the exported file is immediately usable
    cfg = load_cfg()
    by_id = {p['id']: p for p in cfg['proxies']}

    wb = Workbook()
    ws = wb.active
    ws.title = 'Proxy Test Results'

    headers = [
        'Status', 'Interface', 'Host', 'Port', 'Username', 'Password',
        'Configured Exit IP', 'Actual Exit IP', 'IP Match',
        'Latency (ms)', 'Download (Mbps)', 'Connection String', 'Error',
    ]
    head_font = Font(bold=True, color='FFFFFF')
    head_fill = PatternFill(start_color='1F6FEB', end_color='1F6FEB', fill_type='solid')
    ok_fill   = PatternFill(start_color='DCFCE7', end_color='DCFCE7', fill_type='solid')
    fail_fill = PatternFill(start_color='FEE2E2', end_color='FEE2E2', fill_type='solid')
    warn_fill = PatternFill(start_color='FEF3C7', end_color='FEF3C7', fill_type='solid')

    for col, h in enumerate(headers, 1):
        c = ws.cell(row=1, column=col, value=h)
        c.font = head_font
        c.fill = head_fill
        c.alignment = Alignment(vertical='center')

    for i, r in enumerate(results, start=2):
        proxy = by_id.get(r.get('id')) or {}
        if not r.get('success'):
            status = 'DOWN'
            fill = fail_fill
        elif r.get('ip_match') is False:
            status = 'IP MISMATCH'
            fill = warn_fill
        else:
            status = 'OK'
            fill = ok_fill
        host = r.get('configured_ip') or proxy.get('exit_ip')
        port = r.get('port') or proxy.get('port')
        user = proxy.get('username', '')
        pw   = proxy.get('password', '')
        conn = f"{host}:{port}:{user}:{pw}" if host and port else ''
        row = [
            status,
            r.get('interface') or proxy.get('interface', ''),
            host or '',
            port or '',
            user,
            pw,
            r.get('configured_ip') or '',
            r.get('actual_ip') or '',
            'yes' if r.get('ip_match') else ('no' if r.get('ip_match') is False else ''),
            r.get('latency_ms') if r.get('latency_ms') is not None else '',
            r.get('download_mbps') if r.get('download_mbps') is not None else '',
            conn,
            r.get('error') or '',
        ]
        for col, val in enumerate(row, 1):
            c = ws.cell(row=i, column=col, value=val)
            c.fill = fill

    # Auto-ish width based on header length
    widths = [12, 12, 16, 8, 18, 18, 18, 18, 10, 14, 16, 50, 30]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = 'A2'

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)
    filename = f"proxy-tests-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.xlsx"
    return Response(
        buf.getvalue(),
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': f'attachment; filename={filename}'},
    )

@app.route('/api/proxies/export')
def export_proxies():
    cfg    = load_cfg()
    iface  = request.args.get('interface')
    fmt    = request.args.get('format', 'host:port:user:pass')
    proxies = [p for p in cfg['proxies'] if not iface or p['interface'] == iface]
    lines = []
    for p in proxies:
        if fmt == 'socks5':
            lines.append(f"socks5://{p['username']}:{p['password']}@{p['exit_ip']}:{p['port']}")
        else:
            lines.append(f"{p['exit_ip']}:{p['port']}:{p['username']}:{p['password']}")
    return Response('\n'.join(lines), mimetype='text/plain',
                    headers={'Content-Disposition': 'attachment; filename=proxies.txt'})

if __name__ == '__main__':
    # On startup: bring every physical NIC up (safety net for the udev rule),
    # then restore policy routing + regenerate 3proxy config
    for _iface in list_nics():
        run(['ip', 'link', 'set', _iface, 'up'])
    _cfg = load_cfg()
    for _iface, _icfg in _cfg.get('interfaces', {}).items():
        _t = _icfg.get('table_id') or get_or_assign_tid(_iface, _cfg)
        apply_policy_routing(_iface, _icfg['ip'], _icfg['gateway'], _t)
    save_cfg(_cfg)
    if _cfg.get('proxies'):
        write_3proxy(_cfg['proxies'])
        reload_3proxy()
    # Pre-warm ISP cache in a background thread so /scan shows location
    # without waiting on the first page open.
    threading.Thread(target=warm_isp_cache, daemon=True).start()
    app.run(host='0.0.0.0', port=8080, debug=False)
