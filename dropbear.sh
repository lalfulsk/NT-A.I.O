#!/bin/bash

# Set the banner file path
DROPBEAR_BANNER="/etc/issue.net"

# Correct Dropbear service unit file with the banner
cat <<EOF > /usr/lib/systemd/system/dropbear.service
[Unit]
Description=Lightweight SSH server
Documentation=man:dropbear(8)
After=network.target

[Service]
Environment=DROPBEAR_PORT=22 DROPBEAR_RECEIVE_WINDOW=65536 DROPBEAR_BANNER="$DROPBEAR_BANNER"
EnvironmentFile=-/etc/default/dropbear
ExecStart=/usr/sbin/dropbear -EF -p "\$DROPBEAR_PORT" -W "\$DROPBEAR_RECEIVE_WINDOW" -b "\$DROPBEAR_BANNER"
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd daemon
sudo systemctl daemon-reload

# Restart Dropbear service
sudo systemctl restart dropbear.service