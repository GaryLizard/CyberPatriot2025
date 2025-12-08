#!/bin/bash

# SUDO PRIVILEGE FIXER FOR CYBERPATRIOT
# Usage: ./fix_admins.sh [authorized_user1] [authorized_user2] ...

echo "=== SUDO PRIVILEGE FIXER ==="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root!" 
    echo "Use: sudo $0 [authorized_users...]"
    exit 1
fi

# Get authorized users from command line arguments
if [[ $# -eq 0 ]]; then
    echo "ERROR: Please specify authorized admin users as arguments."
    echo "Example: $0 admin1 admin2 user1"
    exit 1
fi

AUTHORIZED=("$@")

echo "Authorized admin users: ${AUTHORIZED[*]}"
echo ""

# 1. Backup current sudoers
echo "Creating backup of sudoers files..."
cp /etc/sudoers /etc/sudoers.bak.$(date +%Y%m%d_%H%M%S)
find /etc/sudoers.d/ -type f -name "*.bak*" -mtime +7 -delete 2>/dev/null || true
echo "Backup created: /etc/sudoers.bak.*"
echo ""

# 2. Create clean sudoers configuration
echo "Configuring sudoers with authorized users only..."
cat > /tmp/new_sudoers << EOF
# SUDOERS CONFIGURATION - CYBERPATRIOT HARDENING
# Generated on $(date)
# Authorized admin users only

Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# User privilege specification
root	ALL=(ALL:ALL) ALL

EOF

# Add authorized users
for user in "${AUTHORIZED[@]}"; do
    # Check if user exists
    if id "$user" &>/dev/null; then
        echo "# $user is authorized for full sudo access" >> /tmp/new_sudoers
        echo "$user	ALL=(ALL:ALL) ALL" >> /tmp/new_sudoers
        echo "" >> /tmp/new_sudoers
    else
        echo "WARNING: User '$user' does not exist!"
    fi
done

# 3. Apply new sudoers configuration
visudo -c -f /tmp/new_sudoers
if [[ $? -eq 0 ]]; then
    cp /tmp/new_sudoers /etc/sudoers
    chmod 440 /etc/sudoers
    echo "New sudoers configuration applied successfully."
else
    echo "ERROR: Invalid sudoers syntax. Restoring backup..."
    cp /etc/sudoers.bak.* /etc/sudoers 2>/dev/null
    exit 1
fi
echo ""

# 4. Clean up sudoers.d directory (optional but recommended)
echo "Cleaning up /etc/sudoers.d/ directory..."
mkdir -p /etc/sudoers.d_backup_$(date +%Y%m%d)
mv /etc/sudoers.d/* /etc/sudoers.d_backup_$(date +%Y%m%d)/ 2>/dev/null || true
echo "Backed up existing sudoers.d files"
echo ""

# 5. Remove unauthorized users from sudo group
echo "Removing unauthorized users from sudo group..."
ALL_USERS=$(getent passwd | grep -E "/home/" | cut -d: -f1)

for user in $ALL_USERS; do
    # Skip root and authorized users
    if [[ "$user" == "root" ]] || [[ " ${AUTHORIZED[@]} " =~ " ${user} " ]]; then
        continue
    fi
    
    # Check if user is in sudo group
    if groups "$user" | grep -q "\bsudo\b"; then
        echo "  Removing $user from sudo group..."
        gpasswd -d "$user" sudo 2>/dev/null
    fi
done

# 6. Also check admin group (Ubuntu legacy)
if getent group admin >/dev/null 2>&1; then
    echo "Cleaning up admin group..."
    for user in $ALL_USERS; do
        if [[ "$user" == "root" ]] || [[ " ${AUTHORIZED[@]} " =~ " ${user} " ]]; then
            continue
        fi
        
        if groups "$user" | grep -q "\badmin\b"; then
            echo "  Removing $user from admin group..."
            gpasswd -d "$user" admin 2>/dev/null
        fi
    done
fi

echo ""
echo "=== SUMMARY ==="
echo "Authorized sudo users:"
for user in "${AUTHORIZED[@]}"; do
    if id "$user" &>/dev/null; then
        echo "  ✓ $user"
    else
        echo "  ✗ $user (user does not exist)"
    fi
done

echo ""
echo "Users with sudo access (final check):"
getent group sudo | cut -d: -f4 | tr ',' '\n' | while read user; do
    echo "  - $user"
done

echo ""
echo "=== COMPLETED ==="
echo "All unauthorized users have been demoted to standard privileges."
echo "Backup files have been created in case of issues."