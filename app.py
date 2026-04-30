from flask import Flask, render_template, jsonify, request, Response
import subprocess, json, os, re, yaml, uuid, random, string
from datetime import datetime
import ipaddress

app = Flask(__name__)

CONFIG_FILE   = '/etc/proxymanager/config.json'
NETPLAN_FILE  = '/etc/netplan/01-netcfg.yaml'
PROXY3_CFG    = '/etc/3proxy/3proxy.cfg'
RT_TABLES     = '/etc/iproute2/rt_tables'

MANAGED = ['enp5s0','enp6s0','enp7s0','enp8s0','enp9s0','enp10s0']
TABLE_BASE = 101  # enp5s0=101 ... enp10s0=106

# ── helpers ──────────────────────────────────────────────────────────────────

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout.strip(), r.stderr.strip(), r.returncode

def tid(iface):
    return TABLE_BASE + MANAGED.index(iface)

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
    out, _, _ = run(['ip', 'addr', 'show'])
    result = {i: {'name': i, 'connected': False, 'ip': None, 'prefix': None} for i in MANAGED}
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
    return result

# ── netplan + routing ─────────────────────────────────────────────────────────

def update_netplan(iface, ip, prefix, gateway):
    with open(NETPLAN_FILE) as f:
        cfg = yaml.safe_load(f)
    t = tid(iface)
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

def apply_policy_routing(iface, ip, gateway):
    t = tid(iface)
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
            'flush',
            f"allow {p['username']}",
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

@app.route('/api/status')
def api_status():
    live   = get_iface_status()
    cfg    = load_cfg()
    counts = {}
    for p in cfg['proxies']:
        counts[p['interface']] = counts.get(p['interface'], 0) + 1
    for iface, data in live.items():
        data['configured'] = iface in cfg['interfaces']
        data['cfg']        = cfg['interfaces'].get(iface)
        data['proxy_count']= counts.get(iface, 0)
    return jsonify(live)

@app.route('/api/interface/setup', methods=['POST'])
def iface_setup():
    d      = request.json
    iface  = d['interface']
    ip     = d['ip']
    prefix = str(d['prefix'])
    gw     = d['gateway']
    if iface not in MANAGED:
        return jsonify({'success': False, 'error': 'Invalid interface'}), 400
    errors = []
    ok, err = update_netplan(iface, ip, prefix, gw)
    if not ok:
        errors.append(f'netplan: {err}')
    apply_policy_routing(iface, ip, gw)
    cfg = load_cfg()
    cfg['interfaces'][iface] = {'ip': ip, 'prefix': int(prefix), 'gateway': gw, 'table_id': tid(iface)}
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
    # On startup, regenerate 3proxy config from saved state and reload
    _cfg = load_cfg()
    if _cfg.get('proxies'):
        write_3proxy(_cfg['proxies'])
        reload_3proxy()
    app.run(host='0.0.0.0', port=8080, debug=False)
