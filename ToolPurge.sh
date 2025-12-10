#!/bin/bash


PACKAGES_TO_PURGE=(
    xprobe cmospwd ophcrack fcrackzip nmap cups cups-common cups-bsd cups-client telnet
    netcat-openbsd netcat-traditional hydra john nikto wireshark aircrack-ng tcpdump p0f
    sqlmap maltego dirbuster steghide dirb recon-ng wifipumpkin3 burpsuite netdiscover
    cowpatty hashcat hping3 armitage beef-xss sherlock gobuster bloodhound ettercap
    bettercap scapy autopsy metasploit-framework mimikatz sqlninja snort lynis dnschef 	
    spiderfoot nessus ophcrack-cli netcat ettercap-common ettercap-graphicsal ettercap-text-only
    zenmap kismet dsniff fierce yersinia macchanger medusa cewl wfuzz enum4linux smbclient nbtclient 
    snmpwalk snmp cupp cupp3 4g8 john-the-ripper hunt nbtscan airgeddon asleap automater bind9-host
    bluelog blueranger bluesnarfer braa brutespray bully cge cisco-auditing-tool cisco-global-exploiter
    cisco-ocs cisco-torch cms-explorer crunch cryptcat cutter cymothoa davtest dbd dcflddd dc3dd ddrescue
    dex2jar dff dhcpig dmitry dnmap dns2tcp dnsenum dnsmap dnsrecon doona dos2unix dotdotpwn driftnet
    dumpzilla eapmd5pass edb-debugger enumiax etherape exploitdb eyewitness faraday fern-wifi-cracker 
    firewalk fragroute fragrouter freeradius freeradius-utils funkload galleta ghost-phisher giskismet
    golismero goofile gqrx-sdr grabber guymager hackrf hamster-sidejack hashid hexinject hexorbase 
    hotpatch httptunnel iaxflood inetsim inosuke inviteflood iodine irpas irssi johnny joomscan 
    jsql keepnote killerbee laudanum lbd libfindrtp linphone linux-exploit-suggester lldpd 
    magicrescue magictree man-in-the-middle-framework maskgen maskprocessor masscan mc
    md5deep mdbtools mdk3 mfcuk mfoc mfterm miranda mitmproxy mitmf mona mongodb mongo-tools 
    mosh msfpc msfpc-ng multimac-ng nasm ncrack ndiff nemesis netsed netsniff-ng netwag nipper-ng 
    oclgausscrack oclhashcat ohrwurm onesixtyone openvas openvas-cli openvas-manager openvas-scanner
    oscanner padbuster paros pasco patator pdf-parser pdfid pdfresurrect peepdf pev phrasendrescher pipal 
    pixiewps plecost polenum policygen-test powersploit protos-sip proxychains proxytunnel pwnat qsslcaudit 
    radare2 radamsa rainbowcrack rarcrack rcracki-mt reaver rebind recoverjpeg redsocks regripper responder rfdump 
    ridenum rsmangler rtpbreak rtpflood rtpinsertsound rtpmixsound sbd scraper scrounge-ntfs seatbelt sendemail set 
    sfuzz sidguesser siege siparmyknife sipcrack skipfish sleuthkit slowhttptest smali smbmap sniffjoke socat sparta 
    spectools spikeproxy sploitctl sqldict sqlitebrowser sslcaudit sslh sslscan sslsniff sslsplit sslstrip sslyze 
    statsprocessor sucrack swaks t50 tcpreplay tcpxtract teardrop testdisk thc-ipv6 thc-pptp-bruter thc-ssl-dos 
    theharvester tnscmd10g truecrack twofi u3-pwn ubertooth udptunnel unhide unhide.rb uniscan unix-privesc-check 
    vidalia volatility w3af wafw00f wash webshells webspa weevely wifi-honey wifiphisher wifitap windows-binaries 
    wordlists xplico xspy xsser zaproxy zaproxy-common zaproxy-core zaproxy-proxy zaproxy-scripts zaproxy-ui
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
        snap remove --purge -y "$package" >> "$LOGFILE" 2>&1
        
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

