#!/bin/bash


#Disable SysRq key combination
sudo sed -i 's/kernel.sysrq.*/kernel.sysrq = 0/' /etc/sysctl.conf
sudo sysctl -w kernel.sysrq=0

#Remove unautheorized PPAs and third-party repos
sudo rm /etc/apt/sources.list.d/<unauthorized>.list

#Disable shell for service accounts
sudo usermod -s /usr/sbin/nologin games
sudo usermod -s /usr/sbin/nologin news
sudo usermod -s /usr/sbin/nologin uucp
sudo usermod -s /usr/sbin/nologin proxy
sudo usermod -s /usr/sbin/nologin www-data
sudo usermod -s /usr/sbin/nologin backup
sudo usermod -s /usr/sbin/nologin list
sudo usermod -s /usr/sbin/nologin irc
sudo usermod -s /usr/sbin/nologin gnats
sudo usermod -s /usr/sbin/nologin nobody

#Disable guest accounts
sudo sed -i '//,+1d' /etc/lightdm/lightdm.conf.d/50-no-guest.conf 2>/dev/null || true
echo -e "[Seat:*]\nallow-guest=false" | sudo tee /etc/lightdm/lightdm.conf.d/50-no-guest.conf > /dev/null

#Global password aging controls
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

#PAM pw quality
sudo sed -i 's/^#\?minlen = .*/minlen = 12/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?dcredit = .*/dcredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?ucredit = .*/ucredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?lcredit = .*/lcredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?ocredit = .*/ocredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?difok = .*/difok = 3/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?maxrepeat = .*/maxrepeat = 3/' /etc/security/pwquality.conf
sudo sed -i 's/^#\?dictcheck = .*/dictcheck = 1/' /etc/security/pwquality.conf

#PAM password config 
sudo sed -i 's/pam_pwquality\.so.*/pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 difok=3 dictcheck=1/' /etc/pam.d/common-password
sudo sed -i 's/pam_unix\.so.*/pam_unix.so obscure yescrypt remember=12/' /etc/pam.d/common-password
sudo sed -i '/^audit/d; /^silent/d; /^deny =/d; /^fail_interval =/d; /^unlock_time =/d; $ a audit\nsilent\ndeny = 5\nfail_interval = 900\nunlock_time = 600' /etc/security/faillock.conf
sudo sed -i '/pam_faillock.so/d' /etc/pam.d/common-auth
sudo sed -i '/pam_unix.so/{s/nullok //g; s/.pam_unix.so./auth [success=2 default=ignore] pam_unix.so/;t;s/^.*$/auth [success=2 default=ignore] pam_unix.so/}' /etc/pam.d/common-auth
sudo sed -i '/auth requisite pam_deny.so/,/auth required pam_permit.so/d' /etc/pam.d/common-auth
sudo sed -i 's/^auth required pam_unix.so.*/auth required pam_faillock.so preauth\n&/' /etc/pam.d/common-auth
sudo sed -i '$ a auth [default=die] pam_faillock.so authfail onerr=fail\nauth sufficient pam_faillock.so authsucc\nauth requisite pam_deny.so\nauth required pam_permit.so' /etc/pam.d/common-auth
sudo sed -i '$ a account required pam_faillock.so' /etc/pam.d/common-account


#Stop unneeded services
sudo systemctl stop ngircd
sudo systemctl disable ngircd
sudo systemctl stop inspircd
sudo systemctl disable inspircd
sudo systemctl stop postfix
sudo systemctl disable postfix

#Enable ufw
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw status

