from flask import Flask, render_template, jsonify, request, Response
import subprocess, json, os, re, yaml, uuid, random, string
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

def get_uplink_iface():
    """The iface currently holding the main-table default route (Tailscale relies on it)."""
    out, _, _ = run(['ip', 'route', 'show', 'default'])
    m = re.search(r'default\s+via\s+\S+\s+dev\s+(\S+)', out)
    return m.group(1) if m else None

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

@app.route('/api/scan')
def api_scan():
    return jsonify(get_iface_details())

@app.route('/api/speedtest/<iface>', methods=['POST'])
def api_speedtest(iface):
    if iface not in list_nics():
        return jsonify({'success': False, 'error': 'Unknown interface'}), 400
    cfg = load_cfg()
    src_ip = (cfg['interfaces'].get(iface) or {}).get('ip')
    if not src_ip:
        live = get_iface_status().get(iface) or {}
        src_ip = live.get('ip')
    if not src_ip:
        return jsonify({'success': False, 'error': 'No IP bound to interface'}), 400
    out, err, rc = run(['speedtest-cli', '--source', src_ip, '--json', '--secure'])
    if rc != 0 or not out:
        return jsonify({'success': False, 'error': (err or 'speedtest-cli failed')[:400]}), 500
    try:
        data = json.loads(out)
    except Exception as e:
        return jsonify({'success': False, 'error': f'parse error: {e}'}), 500
    return jsonify({
        'success':       True,
        'download_mbps': round(data.get('download', 0) / 1_000_000, 2),
        'upload_mbps':   round(data.get('upload', 0) / 1_000_000, 2),
        'ping_ms':       round(data.get('ping', 0), 1),
        'server':        (data.get('server') or {}).get('host'),
        'isp':           data.get('client', {}).get('isp'),
        'source_ip':     src_ip,
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
    app.run(host='0.0.0.0', port=8080, debug=False)
