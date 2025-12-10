#!/bin/bash

# Apache2 Security Hardening Script for Ubuntu
# This script modifies Apache configuration files to improve security

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Backup configuration files
echo "Creating backups..."
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.backup.$(date +%Y%m%d_%H%M%S)
cp /etc/apache2/conf-available/security.conf /etc/apache2/conf-available/security.conf.backup.$(date +%Y%m%d_%H%M%S)

echo "Modifying /etc/apache2/apache2.conf..."

# Remove or update existing ServerTokens
sed -i '/^ServerTokens/d' /etc/apache2/apache2.conf
# Remove or update existing ServerSignature
sed -i '/^ServerSignature/d' /etc/apache2/apache2.conf
# Remove or update existing TraceEnable
sed -i '/^TraceEnable/d' /etc/apache2/apache2.conf

# Add security directives at the beginning of the file
sed -i '1i ServerTokens Prod\nServerSignature Off\nTraceEnable Off' /etc/apache2/apache2.conf

# Add/modify <Directory /> block
# First, remove existing <Directory /> block if present
sed -i '/<Directory \/>/,/<\/Directory>/d' /etc/apache2/apache2.conf

# Add the new <Directory /> block after the main directives
sed -i '/^TraceEnable/a \\n<Directory />\n    Options None\n    AllowOverride None\n    Require all denied\n</Directory>' /etc/apache2/apache2.conf

echo "Modifying /etc/apache2/conf-available/security.conf..."

# Update ServerTokens
sed -i 's/^ServerTokens.*/ServerTokens Prod/' /etc/apache2/conf-available/security.conf
# If ServerTokens doesn't exist, add it
grep -q '^ServerTokens' /etc/apache2/conf-available/security.conf || echo 'ServerTokens Prod' >> /etc/apache2/conf-available/security.conf

# Update ServerSignature
sed -i 's/^ServerSignature.*/ServerSignature Off/' /etc/apache2/conf-available/security.conf
# If ServerSignature doesn't exist, add it
grep -q '^ServerSignature' /etc/apache2/conf-available/security.conf || echo 'ServerSignature Off' >> /etc/apache2/conf-available/security.conf

# Add security headers (remove existing ones first to avoid duplicates)
sed -i '/Header set X-Content-Type-Options/d' /etc/apache2/conf-available/security.conf
sed -i '/Header set X-Frame-Options/d' /etc/apache2/conf-available/security.conf
sed -i '/Header set X-XSS-Protection/d' /etc/apache2/conf-available/security.conf

# Add headers at the end
cat >> /etc/apache2/conf-available/security.conf << 'EOF'

# Security Headers
Header set X-Content-Type-Options: "nosniff"
Header set X-Frame-Options: "SAMEORIGIN"
Header set X-XSS-Protection: "1; mode=block"
EOF

# Enable headers module if not already enabled
echo "Enabling headers module..."
a2enmod headers 2>/dev/null || true

# Enable security.conf if not already enabled
echo "Enabling security configuration..."
a2enconf security 2>/dev/null || true

# Test Apache configuration
echo "Testing Apache configuration..."
if apache2ctl configtest; then
    echo "Configuration test passed!"
else
    echo "Configuration test failed! Please check the errors above."
    echo "Backups are available at:"
    echo "  /etc/apache2/apache2.conf.backup.*"
    echo "  /etc/apache2/conf-available/security.conf.backup.*"
    exit 1
fi

sudo a2enmod headers
sudo systemctl restart apache2
sudo a2enmod ssl
sudo systemctl restart apache2
sudo a2enconf security
sudo systemctl restart apache2
sudo a2dismod status
sudo systemctl restart apache2
sudo a2dismod autoindex
sudo systemctl restart apache2
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
