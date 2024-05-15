#!/bin/bash

# Define the ports and subsystem
ports="Port 22
Port 53
Port 3303"

subsystem="Subsystem sftp /usr/lib/openssh/sftp-server"

# Append the ports and update the subsystem in the SSH configuration file
echo -e "$ports\n$subsystem" | sudo tee -a /etc/ssh/sshd_config > /dev/null

# Restart the SSH service
sudo systemctl restart ssh