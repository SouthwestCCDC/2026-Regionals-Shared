# ================================
# CCDC WINDOWS LOCKDOWN SCRIPT 2026
# Created by Evelyn Escalera Munoz
# Works for Windows 10/11 + Server
# ================================

# -------------------------------
# OS Detection
# -------------------------------

$OS = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "Detected OS: $OS" -ForegroundColor Cyan
$IsServer = $OS -match "Server"

# -------------------------------
# Helper Functions
# -------------------------------

function Pause-Section($Title) {
    Write-Host ""
    Write-Host "===============================" -ForegroundColor Yellow
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Yellow
    Read-Host "Press ENTER to continue"
}

# -------------------------------
# BASELINE HARDENING
# -------------------------------

function Enable-FirewallAll {
    Write-Host "Enabling Windows Firewall..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

function Block-Ports {
    Write-Host "Creating Windows Firewall Block Port Rules..."
    netsh advfirewall firewall add rule name="BlockPorts" protocol=TCP dir=in localport=137,138,139,5800,5900 action=block
    netsh advfirewall firewall add rule name="BlockPorts-UDP" protocol=UDP dir=in localport=137,138,139 action=block
}

function Disable-UnneededServices {
    $services = @(
        "RemoteRegistry",
        "SSDPSRV",
        "upnphost",
        "WerSvc",
        "Fax",
        "Spooler",
        "XblGameSave",
        "XboxNetApiSvc",
        "wisvc"
    )
    foreach ($s in $services) {
        Get-Service $s -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -ne "Stopped" } |
        ForEach-Object {
            Write-Host "Stopping $($_.Name)"
            Stop-Service $_.Name -Force
            Set-Service $_.Name -StartupType Disabled
        }
    }
}

function Lockdown-RDP {
    Write-Host "Hardening RDP..."

    $rdp = Read-Host "Enable RDP? (y/n)"
    $val = if ($rdp -eq "y") { 0 } else { 1 }
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
        -Name fDenyTSConnections -Value $val

    if ($rdp -eq "y") { Enable-NetFirewallRule -DisplayGroup "Remote Desktop" }
    else { Disable-NetFirewallRule -DisplayGroup "Remote Desktop" }

    # Require NLA
    Set-ItemProperty `
        -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name UserAuthenticationRequired -Value 1

    # Disable clipboard/drive mapping
    New-ItemProperty `
        -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name fDisableCdm -Value 1 -PropertyType DWord -Force | Out-Null
}

function Enforce-PasswordPolicy {
    Write-Host "Setting strong password policies..."
    net accounts /minpwlen:14 /maxpwage:30 /minpwage:1 /uniquepw:5 `
        /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
}

function Enable-Auditing {
    Write-Host "Enabling auditing..."
    auditpol /set /category:* /success:enable /failure:enable
}

function Disable-SMBv1 {
    Write-Host "Disabling SMBv1..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

function Disable-GuestAccount {
    Write-Host "Disabling guest account..."
    net user guest /active:no
}

function Disable-LLMNR {
    Write-Host "Disabling LLMNR..."
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    New-ItemProperty `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name EnableMulticast -Value 0 -PropertyType DWord -Force | Out-Null
}

function Disable-NetBIOS {
    Write-Host "Disabling NetBIOS over TCP/IP on all adapters..."
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
    foreach ($a in $adapters) {
        $a | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} | Out-Null
    }
}

function Enable-PSLogging {
    Write-Host "Enabling PowerShell ScriptBlock and Module logging..."
    $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

    New-Item "$psLogPath\ScriptBlockLogging" -Force | Out-Null
    Set-ItemProperty "$psLogPath\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1

    New-Item "$psLogPath\ModuleLogging" -Force | Out-Null
    Set-ItemProperty "$psLogPath\ModuleLogging" -Name EnableModuleLogging -Value 1
}

function Disable-PSv2 {
    Write-Host "Disabling PowerShell v2..."
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue
}

function Harden-LocalAdmins {
    Write-Host "Checking local administrators..."
    Write-Host "Remove unauthorized users."
    Get-LocalGroupMember -Group "Administrators"
}

function Harden-AdminAccount {
    Write-Host "Renaming built-in Administrator account..."
    $newName = Read-Host "Enter new name for Administrator account (NOTE THIS DOWN)"
    Rename-LocalUser -Name "Administrator" -NewName $newName

    $newPass = Read-Host "Enter new password for $newName (NOTE THIS DOWN)" -AsSecureString
    Set-LocalUser -Name $newName -Password $newPass
    Write-Host "Administrator account renamed and password changed." -ForegroundColor Green
}

function Harden-Defender {
    Write-Host "Hardening Microsoft Defender..."
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -PUAProtection Enabled
    Set-MpPreference -EnableControlledFolderAccess Enabled
}

# -------------------------------
# RUN BASELINE
# -------------------------------

Pause-Section "BASELINE HARDENING"

Enable-FirewallAll
Block-Ports
Disable-UnneededServices
Disable-SMBv1
Enforce-PasswordPolicy
Enable-Auditing
Lockdown-RDP
Disable-GuestAccount
Disable-LLMNR
Disable-NetBIOS
Enable-PSLogging
Disable-PSv2
Harden-LocalAdmins
Harden-AdminAccount
Harden-Defender

# -------------------------------
# SERVICE SELECTION MENU
# -------------------------------

Pause-Section "SELECT INSTALLED SERVICES"

Write-Host "[1] Active Directory Domain Services"
Write-Host "[2] DNS Server"
Write-Host "[3] DHCP Server"
Write-Host "[4] FTP (IIS)"
Write-Host "[5] Web Server (IIS)"
Write-Host "[6] File Server"
Write-Host "[7] None / Workstation only"

$selection = Read-Host "Enter numbers separated by commas (ex: 1,2,5)"
$choices = $selection -split "," | ForEach-Object { $_.Trim() }

# -------------------------------
# SERVICE HARDENING FUNCTIONS
# -------------------------------

function Harden-AD {
    Pause-Section "HARDENING ACTIVE DIRECTORY"
    
    Set-ADDefaultDomainPasswordPolicy `
        -Identity (Get-ADDomain).DNSRoot `
        -ComplexityEnabled $True `
        -MinPasswordLength 12 `
        -MinPasswordAge 1.00:00:00 `
        -MaxPasswordAge 30.00:00:00 `
        -LockoutDuration 00:10:00 `
        -LockoutObservationWindow 00:10:00 `
        -LockoutThreshold 3 `
        -ReversibleEncryptionEnabled $False `
        -PasswordHistoryCount 3

    Write-Host "Disabling anonymous LDAP binds..."
    New-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
        -Name "LDAPServerIntegrity" -Value 2 `
        -PropertyType DWord -Force | Out-Null

    Write-Host "Disabling null session / anonymous enumeration..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name RestrictAnonymous -Value 2
}

function Harden-DNS {
    Pause-Section "HARDENING DNS"
    Set-DnsServerResponseRateLimiting -Mode Enable
    
    Write-Host "Disabling DNS recursion (if not needed)..."
    $rec = Read-Host "Disable DNS recursion? (y/n)"
    if ($rec -eq "y") { Set-DnsServerRecursion -Enable $false }
}

function Harden-DHCP {
    Pause-Section "HARDENING DHCP"
    Set-DhcpServerAuditLog -Enable $true
    
    Write-Host "Enabling DHCP conflict detection..."
    Set-DhcpServerSetting -ConflictDetectionAttempts 2
}

function Harden-FTP {
    Pause-Section "HARDENING FTP"
    Import-Module WebAdministration

    Set-WebConfigurationProperty `
        -Filter "/system.applicationHost/sites/siteDefaults/ftpServer/security/authentication/anonymousAuthentication" `
        -Name enabled -Value false

    Set-WebConfigurationProperty `
        -Filter "/system.applicationHost/sites/siteDefaults/ftpServer/security/ssl" `
        -Name controlChannelPolicy -Value 2
}

function Harden-Web {
    Pause-Section "HARDENING IIS"
    Import-Module WebAdministration

    Remove-WindowsFeature Web-DAV-Publishing -ErrorAction SilentlyContinue

    Set-WebConfigurationProperty `
        -Filter /system.webServer/security/authentication/anonymousAuthentication `
        -Name enabled -Value false

    Write-Host "Removing IIS version header..."
    Set-WebConfigurationProperty `
        -Filter "system.webServer/security/requestFiltering" `
        -Name removeServerHeader -Value $true
}

function Harden-FileServer {
    Pause-Section "HARDENING FILE SERVER"
    Write-Host "Restricting SMB settings..."

    Set-SmbServerConfiguration `
        -EncryptData $true `
        -RejectUnencryptedAccess $true `
        -Force
}

# -------------------------------
# APPLY SELECTED HARDENING
# -------------------------------

foreach ($c in $choices) {
    switch ($c) {
        "1" { Harden-AD }
        "2" { Harden-DNS }
        "3" { Harden-DHCP }
        "4" { Harden-FTP }
        "5" { Harden-Web }
        "6" { Harden-FileServer }
        default { }
    }
}

# -------------------------------
# FINAL
# -------------------------------

Pause-Section "LOCKDOWN COMPLETE"
Write-Host "System hardened. Review firewall rules, services, and logs." -ForegroundColor Green