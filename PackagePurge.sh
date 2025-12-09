#!/bin/bash


PACKAGES_TO_PURGE=(
    xprobe cmospwd ophcrack fcrackzip nmap cups cups-common cups-bsd cups-client telnet
    netcat-openbsd netcat-traditional hydra john nikto wireshark aircrack-ng tcpdump p0f
    sqlmap maltego dirbuster steghide dirb recon-ng wifipumpkin3 burpsuite netdiscover
    cowpatty hashcat hping3 armitage beef-xss sherlock gobuster bloodhound ettercap
    bettercap scapy autopsy metasploit-framework mimikatz sqlninja snort lynis dnschef spiderfoot nessus
)

LOGFILE="/var/log/package_purge_$(date +%Y%m%d_%H%M%S).log"
echo "Starting package purge script. Log file: $LOGFILE" | tee -a "$LOGFILE"

# --- Main Logic ---

# Check if script is run with root privileges
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root. Use 'sudo ./PackagePurge.sh'" | tee -a "$LOGFILE"
    exit 1
fi

SUCCESS_COUNT=0
FAIL_COUNT=0

# Loop through each package in the array
for package in "${PACKAGES_TO_PURGE[@]}"; do
    echo "---" | tee -a "$LOGFILE"
    echo "Attempting to purge package: **$package**" | tee -a "$LOGFILE"

    # Check if the package is installed before attempting to purge
    dpkg -l "$package" &> /dev/null
    if [ $? -eq 0 ]; then
        # Package is installed, proceed with purge
        # The -y flag assumes 'yes' to prompts.
        # The '|| true' ensures the loop continues even if apt purge fails.
        apt purge -y "$package" >> "$LOGFILE" 2>&1
        
        if [ $? -eq 0 ]; then
            echo "✅ Successfully purged **$package**." | tee -a "$LOGFILE"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            echo "❌ Failed to purge **$package**. Check log file for details." | tee -a "$LOGFILE"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    else
        echo "⚠️ Package **$package** is not installed. Skipping." | tee -a "$LOGFILE"
    fi
done

# --- Final Cleanup ---

echo "---" | tee -a "$LOGFILE"
echo "Starting final cleanup of dependencies..." | tee -a "$LOGFILE"
# Remove any automatically installed packages that are no longer needed
apt autoremove -y >> "$LOGFILE" 2>&1

echo "---" | tee -a "$LOGFILE"
echo "Script finished." | tee -a "$LOGFILE"
echo "Summary:" | tee -a "$LOGFILE"
echo "Successful purges: $SUCCESS_COUNT" | tee -a "$LOGFILE"
echo "Failed purges: $FAIL_COUNT" | tee -a "$LOGFILE"
echo "Full details are in: $LOGFILE" | tee -a "$LOGFILE"
sudo snap remove --purge aircrack-ng
sudo snap remove --purge armitage
sudo snap remove --purge autopy
sudo snap remove --purge beef-xss
sudo snap remove --purge bettercap
sudo snap remove --purge bloodhound
sudo snap remove --purge burpsuite
sudo snap remove --purge dirb
sudo snap remove --purge dirbuster
sudo snap remove --purge dnschef
sudo snap remove --purge fcrackzip
sudo snap remove --purge ftpscan
sudo snap remove --purge gobuster
sudo snap remove --purge hashcat
sudo snap remove --purge hping3
sudo snap remove --purge hydra
sudo snap remove --purge john
sudo snap remove --purge lynis
sudo snap remove --purge maltego
sudo snap remove --purge metasploit-framework
sudo snap remove --purge mimikatz
sudo snap remove --purge nmap
sudo snap remove --purge nikto
sudo snap remove --purge p0f
sudo snap remove --purge recon-ng
sudo snap remove --purge scapy
sudo snap remove --purge sherlock
sudo snap remove --purge snort
sudo snap remove --purge spiderfoot
sudo snap remove --purge sqlmap
sudo snap remove --purge sqlninja
sudo snap remove --purge steghide
sudo snap remove --purge tcpdump
sudo snap remove --purge wireshark
sudo snap remove --purge wifipumpkin3 
sudo snap remove --purge nessus

