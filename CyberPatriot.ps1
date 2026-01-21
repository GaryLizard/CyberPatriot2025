#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CyberPatriot Windows Server 2022 Hardening Script with GUI
.DESCRIPTION
    Interactive script with checkboxes to apply security configurations
.NOTES
    Save as: CyberPatriot-Hardening.ps1
    Run as Administrator
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = 'CyberPatriot Hardening Script'
$form.Size = New-Object System.Drawing.Size(900,700)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

# Create tab control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Size = New-Object System.Drawing.Size(870,600)
$tabControl.Location = New-Object System.Drawing.Point(10,10)

# Function to create checkbox
function New-CheckBox {
    param($text, $x, $y, $checked = $true)
    $cb = New-Object System.Windows.Forms.CheckBox
    $cb.Text = $text
    $cb.Location = New-Object System.Drawing.Point($x,$y)
    $cb.AutoSize = $true
    $cb.Checked = $checked
    return $cb
}

#region Tab 1: Users & Security Policies
$tab1 = New-Object System.Windows.Forms.TabPage
$tab1.Text = 'Users & Policies'
$tab1.AutoScroll = $true

$y = 10
$tab1.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "USER MANAGEMENT"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbDisableGuest = New-CheckBox "Disable Guest Account" 10 $y
$tab1.Controls.Add($script:cbDisableGuest)
$y += 25

$script:cbDisableAdmin = New-CheckBox "Disable Built-in Administrator" 10 $y
$tab1.Controls.Add($script:cbDisableAdmin)
$y += 25

$script:cbRenameAdmin = New-CheckBox "Rename Administrator (to 'SecureAdmin')" 10 $y
$tab1.Controls.Add($script:cbRenameAdmin)
$y += 25

$script:cbRenameGuest = New-CheckBox "Rename Guest (to 'SecureGuest')" 10 $y
$tab1.Controls.Add($script:cbRenameGuest)
$y += 35

$tab1.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "PASSWORD POLICIES"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbPasswordPolicy = New-CheckBox "Configure Strong Password Policy (14 char, 90 days, complexity)" 10 $y
$tab1.Controls.Add($script:cbPasswordPolicy)
$y += 25

$script:cbLockoutPolicy = New-CheckBox "Configure Account Lockout (10 attempts, 30 min)" 10 $y
$tab1.Controls.Add($script:cbLockoutPolicy)
$y += 35

$tab1.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "AUDIT POLICIES"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbAuditPolicy = New-CheckBox "Enable All Audit Policies (Success & Failure)" 10 $y
$tab1.Controls.Add($script:cbAuditPolicy)
$y += 35

$tab1.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "USER RIGHTS ASSIGNMENT"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbUserRights = New-CheckBox "Configure Secure User Rights Assignment" 10 $y
$tab1.Controls.Add($script:cbUserRights)
$y += 35

$tab1.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "SECURITY OPTIONS"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbSecurityOptions = New-CheckBox "Apply All Security Options (UAC, Network Security, etc.)" 10 $y
$tab1.Controls.Add($script:cbSecurityOptions)

$tabControl.Controls.Add($tab1)
#endregion

#region Tab 2: Services & Software
$tab2 = New-Object System.Windows.Forms.TabPage
$tab2.Text = 'Services & Software'
$tab2.AutoScroll = $true

$y = 10
$tab2.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "DISABLE DANGEROUS SERVICES"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbDisableTelnet = New-CheckBox "Disable Telnet" 10 $y
$tab2.Controls.Add($script:cbDisableTelnet)
$y += 25

$script:cbDisableFTP = New-CheckBox "Disable FTP Service (UNCHECK if critical service!)" 10 $y $false
$tab2.Controls.Add($script:cbDisableFTP)
$y += 25

$script:cbDisableRemoteRegistry = New-CheckBox "Disable Remote Registry" 10 $y
$tab2.Controls.Add($script:cbDisableRemoteRegistry)
$y += 25

$script:cbDisableSMBv1 = New-CheckBox "Disable SMBv1" 10 $y
$tab2.Controls.Add($script:cbDisableSMBv1)
$y += 25

$script:cbDisableSSDP = New-CheckBox "Disable SSDP Discovery" 10 $y
$tab2.Controls.Add($script:cbDisableSSDP)
$y += 25

$script:cbDisableUPnP = New-CheckBox "Disable UPnP Device Host" 10 $y
$tab2.Controls.Add($script:cbDisableUPnP)
$y += 25

$script:cbDisableWebClient = New-CheckBox "Disable WebClient" 10 $y
$tab2.Controls.Add($script:cbDisableWebClient)
$y += 25

$script:cbDisableXbox = New-CheckBox "Disable Xbox Services" 10 $y
$tab2.Controls.Add($script:cbDisableXbox)
$y += 35

$tab2.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "ENABLE IMPORTANT SERVICES"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbEnableDefender = New-CheckBox "Enable Windows Defender" 10 $y
$tab2.Controls.Add($script:cbEnableDefender)
$y += 25

$script:cbEnableWindowsUpdate = New-CheckBox "Enable Windows Update" 10 $y
$tab2.Controls.Add($script:cbEnableWindowsUpdate)
$y += 25

$script:cbEnableEventLog = New-CheckBox "Enable Windows Event Log" 10 $y
$tab2.Controls.Add($script:cbEnableEventLog)

$tabControl.Controls.Add($tab2)
#endregion

#region Tab 3: Windows Defender & Firewall
$tab3 = New-Object System.Windows.Forms.TabPage
$tab3.Text = 'Defender & Firewall'
$tab3.AutoScroll = $true

$y = 10
$tab3.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "WINDOWS DEFENDER"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbDefenderRealTime = New-CheckBox "Enable Real-Time Protection" 10 $y
$tab3.Controls.Add($script:cbDefenderRealTime)
$y += 25

$script:cbDefenderCloud = New-CheckBox "Enable Cloud-Delivered Protection" 10 $y
$tab3.Controls.Add($script:cbDefenderCloud)
$y += 25

$script:cbDefenderSamples = New-CheckBox "Enable Automatic Sample Submission" 10 $y
$tab3.Controls.Add($script:cbDefenderSamples)
$y += 25

$script:cbDefenderTamper = New-CheckBox "Enable Tamper Protection" 10 $y
$tab3.Controls.Add($script:cbDefenderTamper)
$y += 25

$script:cbRemoveExclusions = New-CheckBox "Remove ALL Defender Exclusions" 10 $y
$tab3.Controls.Add($script:cbRemoveExclusions)
$y += 25

$script:cbDefenderPUA = New-CheckBox "Block Potentially Unwanted Apps" 10 $y
$tab3.Controls.Add($script:cbDefenderPUA)
$y += 25

$script:cbRunDefenderScan = New-CheckBox "Run Full Defender Scan (SLOW - Do last!)" 10 $y $false
$tab3.Controls.Add($script:cbRunDefenderScan)
$y += 35

$tab3.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "WINDOWS FIREWALL"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbEnableFirewall = New-CheckBox "Enable Firewall (All Profiles)" 10 $y
$tab3.Controls.Add($script:cbEnableFirewall)
$y += 25

$script:cbFirewallBlockInbound = New-CheckBox "Block All Inbound by Default" 10 $y
$tab3.Controls.Add($script:cbFirewallBlockInbound)

$tabControl.Controls.Add($tab3)
#endregion

#region Tab 4: Remote Access & Features
$tab4 = New-Object System.Windows.Forms.TabPage
$tab4.Text = 'Remote Access'
$tab4.AutoScroll = $true

$y = 10
$tab4.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "REMOTE DESKTOP (RDP)"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbDisableRDP = New-CheckBox "Disable RDP (UNCHECK if critical service!)" 10 $y $false
$tab4.Controls.Add($script:cbDisableRDP)
$y += 25

$script:cbRDPNLA = New-CheckBox "Require Network Level Authentication (if RDP enabled)" 10 $y
$tab4.Controls.Add($script:cbRDPNLA)
$y += 25

$script:cbRDPEncryption = New-CheckBox "Set High Encryption for RDP" 10 $y
$tab4.Controls.Add($script:cbRDPEncryption)
$y += 35

$tab4.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "REMOTE ASSISTANCE"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbDisableRemoteAssistance = New-CheckBox "Disable Remote Assistance" 10 $y
$tab4.Controls.Add($script:cbDisableRemoteAssistance)
$y += 35

$tab4.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "OTHER FEATURES"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbDisableAutoRun = New-CheckBox "Disable AutoRun/AutoPlay" 10 $y
$tab4.Controls.Add($script:cbDisableAutoRun)
$y += 25

$script:cbEnableScreenSaver = New-CheckBox "Enable Password-Protected Screen Saver (15 min)" 10 $y
$tab4.Controls.Add($script:cbEnableScreenSaver)
$y += 25

$script:cbEnableDEP = New-CheckBox "Enable Data Execution Prevention (DEP)" 10 $y
$tab4.Controls.Add($script:cbEnableDEP)

$tabControl.Controls.Add($tab4)
#endregion

#region Tab 5: Updates & Misc
$tab5 = New-Object System.Windows.Forms.TabPage
$tab5.Text = 'Updates & Misc'
$tab5.AutoScroll = $true

$y = 10
$tab5.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "WINDOWS UPDATE"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbConfigureUpdates = New-CheckBox "Configure Automatic Updates" 10 $y
$tab5.Controls.Add($script:cbConfigureUpdates)
$y += 25

$script:cbStartUpdates = New-CheckBox "Start Windows Update Check Now" 10 $y
$tab5.Controls.Add($script:cbStartUpdates)
$y += 35

$tab5.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "POWERSHELL & SCRIPTING"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbPSExecutionPolicy = New-CheckBox "Set PowerShell to Allow Only Signed Scripts" 10 $y
$tab5.Controls.Add($script:cbPSExecutionPolicy)
$y += 35

$tab5.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "FILE SHARES"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbListShares = New-CheckBox "List All Shares (opens new window)" 10 $y $false
$tab5.Controls.Add($script:cbListShares)
$y += 35

$tab5.Controls.Add((New-Object System.Windows.Forms.Label -Property @{
    Text = "FIND FILES"; Location = New-Object System.Drawing.Point(10,$y)
    Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
    AutoSize = $true
}))
$y += 25

$script:cbFindMediaFiles = New-CheckBox "Find Media Files (mp3, mp4, etc.) - opens new window" 10 $y $false
$tab5.Controls.Add($script:cbFindMediaFiles)
$y += 25

$script:cbFindNetcat = New-CheckBox "Find Netcat/Backdoors - opens new window" 10 $y $false
$tab5.Controls.Add($script:cbFindNetcat)

$tabControl.Controls.Add($tab5)
#endregion

$form.Controls.Add($tabControl)

# Create output textbox
$outputBox = New-Object System.Windows.Forms.TextBox
$outputBox.Location = New-Object System.Drawing.Point(10,615)
$outputBox.Size = New-Object System.Drawing.Size(670,40)
$outputBox.Multiline = $true
$outputBox.ScrollBars = 'Vertical'
$outputBox.ReadOnly = $true
$outputBox.Text = "Ready. Click 'Apply Selected' to execute."
$form.Controls.Add($outputBox)

# Create Apply button
$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Location = New-Object System.Drawing.Point(690,615)
$btnApply.Size = New-Object System.Drawing.Size(180,40)
$btnApply.Text = 'Apply Selected'
$btnApply.Font = New-Object System.Drawing.Font("Arial",10,[System.Drawing.FontStyle]::Bold)
$btnApply.BackColor = [System.Drawing.Color]::LightGreen

$btnApply.Add_Click({
    $outputBox.Text = "Executing selected configurations...`r`n"
    $form.Refresh()
    
    try {
        #region User Management
        if ($script:cbDisableGuest.Checked) {
            $outputBox.AppendText("Disabling Guest account...`r`n")
            Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDisableAdmin.Checked) {
            $outputBox.AppendText("Disabling Administrator account...`r`n")
            Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        }
        
        if ($script:cbRenameAdmin.Checked) {
            $outputBox.AppendText("Renaming Administrator...`r`n")
            Rename-LocalUser -Name "Administrator" -NewName "SecureAdmin" -ErrorAction SilentlyContinue
        }
        
        if ($script:cbRenameGuest.Checked) {
            $outputBox.AppendText("Renaming Guest...`r`n")
            Rename-LocalUser -Name "Guest" -NewName "SecureGuest" -ErrorAction SilentlyContinue
        }
        #endregion
        
        #region Password & Lockout Policies
        if ($script:cbPasswordPolicy.Checked) {
            $outputBox.AppendText("Configuring password policy...`r`n")
            net accounts /minpwlen:14 /maxpwage:90 /minpwage:10 /uniquepw:24 | Out-Null
            secedit /export /cfg c:\secpol.cfg | Out-Null
            (Get-Content c:\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Out-File c:\secpol.cfg
            secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY | Out-Null
            Remove-Item -force c:\secpol.cfg -confirm:$false -ErrorAction SilentlyContinue
        }
        
        if ($script:cbLockoutPolicy.Checked) {
            $outputBox.AppendText("Configuring lockout policy...`r`n")
            net accounts /lockoutthreshold:10 /lockoutduration:30 /lockoutwindow:30 | Out-Null
        }
        #endregion
        
        #region Audit Policies
        if ($script:cbAuditPolicy.Checked) {
            $outputBox.AppendText("Enabling audit policies...`r`n")
            auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
            auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
            auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
            auditpol /set /category:"Object Access" /success:enable /failure:enable | Out-Null
            auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
            auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
            auditpol /set /category:"System" /success:enable /failure:enable | Out-Null
        }
        #endregion
        
        #region Security Options via Registry
        if ($script:cbSecurityOptions.Checked) {
            $outputBox.AppendText("Applying security options...`r`n")
            
            # UAC Settings
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Force
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0 -Force
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Force
            
            # Network Security
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Force
            
            # Anonymous enumeration
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Force
        }
        #endregion
        
        #region Services
        if ($script:cbDisableTelnet.Checked) {
            $outputBox.AppendText("Disabling Telnet...`r`n")
            Set-Service -Name "TlntSvr" -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name "TlntSvr" -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDisableFTP.Checked) {
            $outputBox.AppendText("Disabling FTP...`r`n")
            Set-Service -Name "ftpsvc" -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name "ftpsvc" -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDisableRemoteRegistry.Checked) {
            $outputBox.AppendText("Disabling Remote Registry...`r`n")
            Set-Service -Name "RemoteRegistry" -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name "RemoteRegistry" -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDisableSMBv1.Checked) {
            $outputBox.AppendText("Disabling SMBv1...`r`n")
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDisableSSDP.Checked) {
            $outputBox.AppendText("Disabling SSDP...`r`n")
            Set-Service -Name "SSDPSRV" -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name "SSDPSRV" -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDisableUPnP.Checked) {
            $outputBox.AppendText("Disabling UPnP...`r`n")
            Set-Service -Name "upnphost" -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name "upnphost" -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDisableWebClient.Checked) {
            $outputBox.AppendText("Disabling WebClient...`r`n")
            Set-Service -Name "WebClient" -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name "WebClient" -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDisableXbox.Checked) {
            $outputBox.AppendText("Disabling Xbox services...`r`n")
            Set-Service -Name "XblGameSave" -StartupType Disabled -ErrorAction SilentlyContinue
            Set-Service -Name "XblAuthManager" -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name "XblGameSave" -Force -ErrorAction SilentlyContinue
            Stop-Service -Name "XblAuthManager" -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbEnableDefender.Checked) {
            $outputBox.AppendText("Enabling Windows Defender...`r`n")
            Set-Service -Name "WinDefend" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        }
        
        if ($script:cbEnableWindowsUpdate.Checked) {
            $outputBox.AppendText("Enabling Windows Update...`r`n")
            Set-Service -Name "wuauserv" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        }
        
        if ($script:cbEnableEventLog.Checked) {
            $outputBox.AppendText("Enabling Event Log...`r`n")
            Set-Service -Name "eventlog" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name "eventlog" -ErrorAction SilentlyContinue
        }
        #endregion
        
        #region Windows Defender
        if ($script:cbDefenderRealTime.Checked) {
            $outputBox.AppendText("Enabling Defender Real-Time Protection...`r`n")
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDefenderCloud.Checked) {
            $outputBox.AppendText("Enabling Cloud Protection...`r`n")
            Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDefenderSamples.Checked) {
            $outputBox.AppendText("Enabling Sample Submission...`r`n")
            Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDefenderPUA.Checked) {
            $outputBox.AppendText("Blocking PUAs...`r`n")
            Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
        }
        
        if ($script:cbRemoveExclusions.Checked) {
            $outputBox.AppendText("Removing Defender exclusions...`r`n")
            try {
                $prefs = Get-MpPreference -ErrorAction Stop
                if ($prefs.ExclusionPath) {
                    $prefs.ExclusionPath | ForEach-Object { Remove-MpPreference -ExclusionPath $_ -ErrorAction SilentlyContinue }
                }
                if ($prefs.ExclusionExtension) {
                    $prefs.ExclusionExtension | ForEach-Object { Remove-MpPreference -ExclusionExtension $_ -ErrorAction SilentlyContinue }
                }
                if ($prefs.ExclusionProcess) {
                    $prefs.ExclusionProcess | ForEach-Object { Remove-MpPreference -ExclusionProcess $_ -ErrorAction SilentlyContinue }
                }
                $outputBox.AppendText("Exclusions removed.`r`n")
            } catch {
                $outputBox.AppendText("No exclusions found or error accessing Defender.`r`n")
            }
        }
        
        if ($script:cbRunDefenderScan.Checked) {
            $outputBox.AppendText("Starting full scan (this will take a while)...`r`n")
            Start-MpScan -ScanType FullScan -AsJob
        }
        #endregion
        
        #region Firewall
        if ($script:cbEnableFirewall.Checked) {
            $outputBox.AppendText("Enabling firewall...`r`n")
            try {
                Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
            } catch {
                # Fallback to netsh if PowerShell cmdlet fails
                netsh advfirewall set allprofiles state on | Out-Null
                $outputBox.AppendText("Firewall enabled via netsh.`r`n")
            }
        }
        
        if ($script:cbFirewallBlockInbound.Checked) {
            $outputBox.AppendText("Setting firewall to block inbound...`r`n")
            try {
                Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -ErrorAction Stop
            } catch {
                # Fallback to netsh
                netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
                $outputBox.AppendText("Firewall policy set via netsh.`r`n")
            }
        }
        #endregion
        
        #region Remote Access
        if ($script:cbDisableRDP.Checked) {
            $outputBox.AppendText("Disabling RDP...`r`n")
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Force
            Set-Service -Name "TermService" -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbRDPNLA.Checked) {
            $outputBox.AppendText("Requiring NLA for RDP...`r`n")
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Force
        }
        
        if ($script:cbRDPEncryption.Checked) {
            $outputBox.AppendText("Setting high RDP encryption...`r`n")
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3 -Force
        }
        
        if ($script:cbDisableRemoteAssistance.Checked) {
            $outputBox.AppendText("Disabling Remote Assistance...`r`n")
            # Create the registry path if it doesn't exist
            $raPath = "HKLM:\System\CurrentControlSet\Control\Remote Assistance"
            if (!(Test-Path $raPath)) {
                New-Item -Path $raPath -Force | Out-Null
            }
            Set-ItemProperty -Path $raPath -Name "fAllowToGetHelp" -Value 0 -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbDisableAutoRun.Checked) {
            $outputBox.AppendText("Disabling AutoRun...`r`n")
            $autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            if (!(Test-Path $autorunPath)) {
                New-Item -Path $autorunPath -Force | Out-Null
            }
            Set-ItemProperty -Path $autorunPath -Name "NoDriveTypeAutoRun" -Value 255 -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbEnableScreenSaver.Checked) {
            $outputBox.AppendText("Enabling screen saver lock...`r`n")
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 1 -Force
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1 -Force
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value 900 -Force
        }
        
        if ($script:cbEnableDEP.Checked) {
            $outputBox.AppendText("Enabling DEP...`r`n")
            bcdedit /set nx OptOut | Out-Null
        }
        #endregion
        
        #region Updates
        if ($script:cbConfigureUpdates.Checked) {
            $outputBox.AppendText("Configuring Windows Update...`r`n")
            $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            if (!(Test-Path $wuPath)) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force -ErrorAction SilentlyContinue | Out-Null
                New-Item -Path $wuPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
            Set-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -Value 0 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $wuPath -Name "AUOptions" -Value 4 -Force -ErrorAction SilentlyContinue
        }
        
        if ($script:cbStartUpdates.Checked) {
            $outputBox.AppendText("Starting Windows Update check...`r`n")
            Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartScan" -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
            Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartDownload" -WindowStyle Hidden -ErrorAction SilentlyContinue
        }
        #endregion
        
        #region PowerShell Policy
        if ($script:cbPSExecutionPolicy.Checked) {
            $outputBox.AppendText("Setting PS execution policy...`r`n")
            $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
            if (!(Test-Path $psPath)) {
                New-Item -Path $psPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
            Set-ItemProperty -Path $psPath -Name "EnableScripts" -Value 1 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $psPath -Name "ExecutionPolicy" -Value "AllSigned" -Force -ErrorAction SilentlyContinue
        }
        #endregion
        
        #region File/Share Discovery
        if ($script:cbListShares.Checked) {
            $outputBox.AppendText("Listing shares...`r`n")
            $shares = Get-SmbShare | Out-String
            $sharesForm = New-Object System.Windows.Forms.Form
            $sharesForm.Text = 'File Shares'
            $sharesForm.Size = New-Object System.Drawing.Size(600,400)
            $sharesForm.StartPosition = 'CenterScreen'
            
            $sharesBox = New-Object System.Windows.Forms.TextBox
            $sharesBox.Multiline = $true
            $sharesBox.ScrollBars = 'Vertical'
            $sharesBox.Size = New-Object System.Drawing.Size(580,360)
            $sharesBox.Location = New-Object System.Drawing.Point(10,10)
            $sharesBox.Text = $shares
            $sharesForm.Controls.Add($sharesBox)
            $sharesForm.Show()
        }
        
        if ($script:cbFindMediaFiles.Checked) {
            $outputBox.AppendText("Searching for media files (this may take time)...`r`n")
            $mediaFiles = Get-ChildItem -Path C:\ -Include *.mp3,*.mp4,*.avi,*.mkv,*.mov,*.wmv -Recurse -ErrorAction SilentlyContinue | Select-Object FullName -First 100
            
            $mediaForm = New-Object System.Windows.Forms.Form
            $mediaForm.Text = 'Media Files Found'
            $mediaForm.Size = New-Object System.Drawing.Size(700,500)
            $mediaForm.StartPosition = 'CenterScreen'
            
            $mediaBox = New-Object System.Windows.Forms.TextBox
            $mediaBox.Multiline = $true
            $mediaBox.ScrollBars = 'Vertical'
            $mediaBox.Size = New-Object System.Drawing.Size(680,460)
            $mediaBox.Location = New-Object System.Drawing.Point(10,10)
            $mediaBox.Text = ($mediaFiles | ForEach-Object { $_.FullName }) -join "`r`n"
            $mediaForm.Controls.Add($mediaBox)
            $mediaForm.Show()
        }
        
        if ($script:cbFindNetcat.Checked) {
            $outputBox.AppendText("Searching for netcat/backdoors...`r`n")
            $backdoors = Get-ChildItem -Path C:\ -Include nc.exe,ncat.exe,netcat.exe,nc64.exe,cryptcat.exe,tini.exe -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
            
            $backdoorForm = New-Object System.Windows.Forms.Form
            $backdoorForm.Text = 'Potential Backdoors Found'
            $backdoorForm.Size = New-Object System.Drawing.Size(700,400)
            $backdoorForm.StartPosition = 'CenterScreen'
            
            $backdoorBox = New-Object System.Windows.Forms.TextBox
            $backdoorBox.Multiline = $true
            $backdoorBox.ScrollBars = 'Vertical'
            $backdoorBox.Size = New-Object System.Drawing.Size(680,360)
            $backdoorBox.Location = New-Object System.Drawing.Point(10,10)
            $backdoorBox.Text = if ($backdoors) { ($backdoors | ForEach-Object { $_.FullName }) -join "`r`n" } else { "No obvious backdoors found" }
            $backdoorForm.Controls.Add($backdoorBox)
            $backdoorForm.Show()
        }
        #endregion
        
        $outputBox.AppendText("`r`nCOMPLETE! Check each setting was applied successfully.`r`n")
        [System.Windows.Forms.MessageBox]::Show("Execution complete! Review the output and verify changes.", "Done", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        
    } catch {
        $outputBox.AppendText("ERROR: $($_.Exception.Message)`r`n")
        [System.Windows.Forms.MessageBox]::Show("An error occurred: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$form.Controls.Add($btnApply)

# Show form
[void]$form.ShowDialog()