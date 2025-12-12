#!/bin/bash
# Security hardening script - fixed version

# Exit on error
set -e

echo "Starting security hardening..."

# Disable SysRq key combination
echo "Disabling SysRq key..."
sudo sed -i 's/^kernel.sysrq.*/kernel.sysrq = 0/' /etc/sysctl.conf
if ! grep -q "^kernel.sysrq" /etc/sysctl.conf; then
    echo "kernel.sysrq = 0" | sudo tee -a /etc/sysctl.conf
fi
sudo sysctl -w kernel.sysrq=0

# Remove unauthorized PPAs and third-party repos
echo "Removing unauthorized repos..."
# Replace <unauthorized> with actual filename if needed
# sudo rm -f /etc/apt/sources.list.d/<unauthorized>.list

# Disable shell for service accounts
echo "Disabling shell for service accounts..."
for user in games news uucp proxy www-data backup list irc gnats nobody; do
    if id "$user" &>/dev/null; then
        sudo usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
    fi
done

# Disable guest accounts
echo "Disabling guest accounts..."
sudo mkdir -p /etc/lightdm/lightdm.conf.d/
echo -e "[Seat:*]\nallow-guest=false" | sudo tee /etc/lightdm/lightdm.conf.d/50-no-guest.conf > /dev/null

# Global password aging controls
echo "Configuring password aging..."
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# PAM password quality
echo "Configuring password quality requirements..."
sudo sed -i 's/^#\?minlen = .*/minlen = 12/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?dcredit = .*/dcredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?ucredit = .*/ucredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?lcredit = .*/lcredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?ocredit = .*/ocredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?difok = .*/difok = 3/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?maxrepeat = .*/maxrepeat = 3/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?dictcheck = .*/dictcheck = 1/' /etc/security/pwquality.conf

# Add lines if they don't exist
for setting in "minlen = 12" "dcredit = -1" "ucredit = -1" "lcredit = -1" "ocredit = -1" "difok = 3" "maxrepeat = 3" "dictcheck = 1"; do
    param=$(echo "$setting" | cut -d= -f1 | xargs)
    if ! grep -q "^$param" /etc/security/pwquality.conf; then
        echo "$setting" | sudo tee -a /etc/security/pwquality.conf > /dev/null
    fi
done

# Backup PAM files before modification
echo "Backing up PAM configuration files..."
sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.backup
sudo cp /etc/pam.d/common-auth /etc/pam.d/common-auth.backup
sudo cp /etc/pam.d/common-account /etc/pam.d/common-account.backup

# Configure faillock
echo "Configuring account lockout policy..."
sudo sed -i '/^audit/d; /^silent/d; /^deny =/d; /^fail_interval =/d; /^unlock_time =/d' /etc/security/faillock.conf
cat << 'EOF' | sudo tee -a /etc/security/faillock.conf > /dev/null
audit
silent
deny = 5
fail_interval = 900
unlock_time = 600
EOF

# Update PAM password settings
echo "Updating PAM password configuration..."
# Remove nullok and add password history
sudo sed -i 's/\(pam_unix\.so.*\)nullok/\1/' /etc/pam.d/common-password
if ! grep -q "remember=" /etc/pam.d/common-password; then
    sudo sed -i 's/\(pam_unix\.so.*\)/\1 remember=12/' /etc/pam.d/common-password
fi

# Use pam-auth-update to properly enable faillock
echo "Enabling faillock through pam-auth-update..."
if command -v pam-auth-update &> /dev/null; then
    sudo DEBIAN_FRONTEND=noninteractive pam-auth-update --package --enable pwquality faillock
else
    echo "Warning: pam-auth-update not found, using manual configuration..."
    # Manual faillock setup as fallback
    if ! grep -q "pam_faillock.so preauth" /etc/pam.d/common-auth; then
        sudo sed -i '/pam_unix.so/i auth required pam_faillock.so preauth' /etc/pam.d/common-auth
        sudo sed -i '/pam_deny.so/i auth [default=die] pam_faillock.so authfail' /etc/pam.d/common-auth
        echo "account required pam_faillock.so" | sudo tee -a /etc/pam.d/common-account > /dev/null
    fi
fi

# Stop and disable unneeded services
echo "Stopping unnecessary services..."
services=("ngircd" "inspircd" "ircd-irc2" "postfix")
for service in "${services[@]}"; do
    if systemctl list-unit-files | grep -q "^${service}.service"; then
        echo "Stopping and disabling $service..."
        sudo systemctl stop "$service" 2>/dev/null || true
        sudo systemctl disable "$service" 2>/dev/null || true
    fi
done

# Restrict hardlink creation (protected_hardlinks)
echo "Restricting hardlink creation..."
sudo sed -i 's/^fs.protected_hardlinks.*/fs.protected_hardlinks = 1/' /etc/sysctl.conf
if ! grep -q "^fs.protected_hardlinks" /etc/sysctl.conf; then
    echo "fs.protected_hardlinks = 1" | sudo tee -a /etc/sysctl.conf
fi
sudo sysctl -w fs.protected_hardlinks=1

# Restrict symlink creation (protected_symlinks)
echo "Restricting symlink creation..."
sudo sed -i 's/^fs.protected_symlinks.*/fs.protected_symlinks = 1/' /etc/sysctl.conf
if ! grep -q "^fs.protected_symlinks" /etc/sysctl.conf; then
    echo "fs.protected_symlinks = 1" | sudo tee -a /etc/sysctl.conf
fi
sudo sysctl -w fs.protected_symlinks=1

# Set mail user default shell to /usr/sbin/nologin
echo "Setting mail user shell to nologin..."
if id "mail" &>/dev/null; then
    sudo usermod -s /usr/sbin/nologin mail
fi

# Set GRUB bootloader password
echo "Setting GRUB bootloader password..."
echo ""
echo "======================================================================"
echo "BOOTLOADER PASSWORD SETUP"
echo "======================================================================"
echo "You will be prompted to enter a password for the GRUB bootloader."
echo "This password will be required to edit boot parameters."
echo ""
read -p "Press Enter to continue..."

# Generate password hash
GRUB_PASSWORD=$(grub-mkpasswd-pbkdf2 | grep -oP 'grub\.pbkdf2\.sha512\.\S+')

if [ -n "$GRUB_PASSWORD" ]; then
    # Create custom GRUB password file
    sudo tee /etc/grub.d/40_custom_password > /dev/null << EOF
#!/bin/sh
cat << 'GRUBEOF'
set superusers="admin"
password_pbkdf2 admin $GRUB_PASSWORD
GRUBEOF
EOF
    
    sudo chmod +x /etc/grub.d/40_custom_password
    
    # Update GRUB configuration
    sudo update-grub
    
    echo ""
    echo "Bootloader password has been set successfully."
    echo "Username: admin"
    echo "Remember this password - you'll need it to edit boot parameters!"
else
    echo "ERROR: Failed to set bootloader password. Skipping..."
fi

# Enable and configure UFW
echo "Configuring firewall..."
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw status

echo ""
echo "Security hardening complete!"
echo ""
echo "IMPORTANT: PAM configuration files have been backed up to:"
echo "  - /etc/pam.d/common-password.backup"
echo "  - /etc/pam.d/common-auth.backup"
echo "  - /etc/pam.d/common-account.backup"
echo ""
echo "Please test sudo access in a NEW terminal before closing this one!"
echo "If you get locked out, boot into recovery mode and restore from backups."

# 2. Enable IPv4 source route verification
if ! grep -q "net.ipv4.conf.default.accept_source_route = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.default.accept_source_route = 0" | sudo sh -c 'cat >> /etc/sysctl.conf'
fi

if ! grep -q "net.ipv4.conf.all.accept_source_route = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.accept_source_route = 0" | sudo sh -c 'cat >> /etc/sysctl.conf'
fi
echo "✓ IPv4 source route verification enabled"

# 3. Enable ASLR
if ! grep -q "kernel.randomize_va_space = 2" /etc/sysctl.conf; then
    echo "kernel.randomize_va_space = 2" | sudo sh -c 'cat >> /etc/sysctl.conf'
fi
sudo sysctl -w kernel.randomize_va_space=2
sudo sysctl -p
echo "✓ ASLR enabled"

