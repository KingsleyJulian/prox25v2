#!/bin/bash
set -e

echo "=== ProxyManager Installer ==="

# Fix any broken apt repos silently
apt-get update -qq 2>/dev/null || apt-get update --fix-missing -qq || true

# Python deps
apt-get install -y python3 python3-pip python3-venv build-essential git

# Create venv (Ubuntu 24.04 forbids system-wide pip per PEP 668)
mkdir -p /opt/proxymanager
if [ ! -x /opt/proxymanager/venv/bin/python3 ]; then
  python3 -m venv /opt/proxymanager/venv
fi
/opt/proxymanager/venv/bin/pip install --upgrade pip
/opt/proxymanager/venv/bin/pip install flask pyyaml speedtest-cli

# Build 3proxy from source (not in Ubuntu 24.04 repos)
if ! command -v 3proxy &>/dev/null; then
  echo "--- Building 3proxy from source ---"
  cd /tmp
  rm -rf 3proxy-src
  git clone --depth=1 https://github.com/3proxy/3proxy.git 3proxy-src
  cd 3proxy-src
  make -f Makefile.Linux
  make -f Makefile.Linux install
  cd -
  echo "--- 3proxy built and installed ---"
fi

# Directories
mkdir -p /opt/proxymanager/templates
mkdir -p /etc/proxymanager
mkdir -p /etc/3proxy
mkdir -p /var/log/3proxy

# Copy app files (support running from any directory)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/app.py" /opt/proxymanager/
cp "$SCRIPT_DIR/templates/index.html" /opt/proxymanager/templates/
cp "$SCRIPT_DIR/templates/scan.html" /opt/proxymanager/templates/
cp "$SCRIPT_DIR/templates/update.html" /opt/proxymanager/templates/

# Record the source commit so the self-update page can diff against GitHub
GIT_SHA="$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "$GIT_SHA" > /opt/proxymanager/VERSION

# Systemd service for ProxyManager web UI
cat > /etc/systemd/system/proxymanager.service << 'EOF'
[Unit]
Description=ProxyManager Web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/proxymanager
ExecStart=/opt/proxymanager/venv/bin/python3 /opt/proxymanager/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Systemd service for 3proxy
cat > /etc/systemd/system/3proxy.service << 'EOF'
[Unit]
Description=3proxy Proxy Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/3proxy /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Placeholder 3proxy config so it starts without error
cat > /etc/3proxy/3proxy.cfg << 'EOF'
nserver 8.8.8.8
nscache 65536
auth strong
EOF

# udev rule: auto-bring-up any physical ethernet NIC on add events
# Covers boot enumeration AND USB-ethernet hotplug. KERNEL=="en*" matches
# enp*/eno*/enx* but skips lo, tailscale0, docker0, bridges, veth, wg, tun.
cat > /etc/udev/rules.d/99-proxymanager-link-up.rules << 'EOF'
SUBSYSTEM=="net", ACTION=="add", KERNEL=="en*", RUN+="/usr/sbin/ip link set %k up"
EOF

udevadm control --reload-rules
# Trigger the rule for already-present devices (so existing DOWN NICs come up now)
udevadm trigger --subsystem-match=net --action=add

systemctl daemon-reload
systemctl enable proxymanager 3proxy
systemctl restart proxymanager 3proxy

SERVER_IP=$(hostname -I | awk '{print $1}')
TAILSCALE_IP=$(ip addr show tailscale0 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' || echo "")

echo ""
echo "=== Done! ==="
echo "ProxyManager: http://${SERVER_IP}:8080"
[ -n "$TAILSCALE_IP" ] && echo "Via Tailscale:  http://${TAILSCALE_IP}:8080"
