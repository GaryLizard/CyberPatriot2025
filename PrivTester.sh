#!/bin/bash

echo "=== PROGRAM PRIVILEGE TEST ==="
echo "Testing common services and programs..."
echo ""

# Function to test if a command runs successfully
test_command() {
    local cmd="$1"
    local desc="$2"
    local expected_user="$3"
    
    echo -n "Testing: $desc ... "
    
    # Run the command and capture exit code
    $cmd > /dev/null 2>&1
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]] || [[ $exit_code -eq 1 ]]; then
        echo "✓ OK (exit code: $exit_code)"
        
        # Check which user runs the command
        if [[ -n "$expected_user" ]]; then
            actual_user=$(ps aux | grep "$cmd" | grep -v grep | awk '{print $1}' | head -1 2>/dev/null)
            if [[ "$actual_user" == "$expected_user" ]]; then
                echo "  User context: ✓ Running as $actual_user (expected: $expected_user)"
            else
                echo "  User context: ⚠ Running as $actual_user (expected: $expected_user)"
            fi
        fi
    else
        echo "✗ FAILED (exit code: $exit_code)"
    fi
}

# Test 1: System services (should run as root or service users)
echo ""
echo "1. SYSTEM SERVICES:"
test_command "systemctl status" "Systemd status" "root"
test_command "apt update" "APT update check" "root"
test_command "ufw status" "Firewall status" "root"

# Test 2: Common services with special users
echo ""
echo "2. SERVICE-SPECIFIC TESTS:"

# Check specific service users
echo "Service user accounts:"
getent passwd | grep -E "(www-data|mysql|postgres|redis|nginx|apache)" | cut -d: -f1 | while read user; do
    echo "  Found: $user"
done

# Test network services
echo ""
echo "3. NETWORK SERVICES (if installed):"
if command -v nginx &>/dev/null; then
    test_command "nginx -t" "Nginx config test" "root"
fi

if command -v apache2 &>/dev/null; then
    test_command "apache2ctl -t" "Apache config test" "root"
fi

if command -v mysql &>/dev/null; then
    test_command "mysql --version" "MySQL version" "mysql"
fi

if command -v postgres &>/dev/null; then
    test_command "psql --version" "PostgreSQL version" "postgres"
fi

# Test 3: Critical system operations
echo ""
echo "4. CRITICAL SYSTEM OPERATIONS:"

# Package management (requires root)
echo -n "Testing package install simulation... "
if apt --simulate install nano 2>&1 | grep -q "installed"; then
    echo "✓ Package simulation works"
else
    echo "⚠ Package simulation may have issues"
fi

# User management (requires root)
echo -n "Testing user listing... "
if getent passwd | grep -q "home" 2>/dev/null; then
    echo "✓ User enumeration works"
else
    echo "✗ User enumeration failed"
fi

# Test 4: Cron jobs (should still work)
echo ""
echo "5. SCHEDULED TASKS:"
echo "Root cron jobs:"
crontab -l -u root 2>/dev/null | head -5
echo ""
echo "Checking service crontabs:"
ls /var/spool/cron/crontabs/ 2>/dev/null || echo "  No user crontabs found"

# Test 5: Verify sudo still works for authorized users
echo ""
echo "6. SUDO FUNCTIONALITY:"
AUTHORIZED_USERS=$(grep -E "^[^#].*ALL=" /etc/sudoers 2>/dev/null | awk '{print $1}' | grep -v "root")
echo "Authorized sudo users in sudoers:"
echo "$AUTHORIZED_USERS" | while read user; do
    echo "  - $user"
done

echo ""
echo "=== QUICK MANUAL TESTS TO RUN ==="
echo "Run these as a non-admin user to verify restrictions:"
echo "1. Try to install a package: sudo apt install nano"
echo "2. Try to view logs: sudo cat /var/log/auth.log"
echo "3. Try to add a user: sudo adduser testuser"
echo ""
echo "Then run as an authorized admin to verify it works."
echo ""
echo "=== TEST COMPLETE ==="