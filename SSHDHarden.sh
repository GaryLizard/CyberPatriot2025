#!/bin/bash

# Backup original sshd_config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Configure SSH settings using sed
sudo sed -i 's/^#\?Port .*/Port 22/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?MaxAuthTries .*/MaxAuthTries 3/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?MaxSessions .*/MaxSessions 4/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?X11Forwarding .*/X11Forwarding no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?UsePAM .*/UsePAM yes/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?AllowTcpForwarding .*/AllowTcpForwarding no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?ClientAliveInterval .*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?ClientAliveCountMax .*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?LoginGraceTime .*/LoginGraceTime 60/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?Banner .*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?Protocol .*/Protocol 2/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?IgnoreRhosts .*/IgnoreRhosts yes/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?HostbasedAuthentication .*/HostbasedAuthentication no/' /etc/ssh/sshd_config

# Create banner
echo "Authorized users only. All activity monitored." | sudo tee /etc/issue.net

# Restart SSH
sudo systemctl restart sshd

# Allow through firewall
sudo ufw allow ssh

echo "SSH hardening complete"
