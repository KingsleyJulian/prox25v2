#!/bin/bash
set -e

echo "=== ProxyManager Installer ==="

# Dependencies
apt-get update -qq
apt-get install -y python3 python3-pip 3proxy

pip3 install flask pyyaml

# Directories
mkdir -p /opt/proxymanager/templates
mkdir -p /etc/proxymanager
mkdir -p /etc/3proxy
mkdir -p /var/log/3proxy

# Copy app files
cp app.py /opt/proxymanager/
cp templates/index.html /opt/proxymanager/templates/

# Systemd service for ProxyManager web UI
cat > /etc/systemd/system/proxymanager.service << 'EOF'
[Unit]
Description=ProxyManager Web UI
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/proxymanager
ExecStart=/usr/bin/python3 /opt/proxymanager/app.py
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
ExecStart=/usr/bin/3proxy /etc/3proxy/3proxy.cfg
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

systemctl daemon-reload
systemctl enable proxymanager 3proxy
systemctl start proxymanager 3proxy

SERVER_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "=== Done! ==="
echo "ProxyManager: http://${SERVER_IP}:8080"
echo "Also accessible via Tailscale: http://100.70.185.66:8080"
