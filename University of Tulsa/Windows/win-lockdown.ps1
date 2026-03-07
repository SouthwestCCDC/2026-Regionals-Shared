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

function Enable-FirewallAll {
    Write-Host "Enabling Windows Firewall..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

function Block-Ports {
    Write-Host "Creating Windows Firewall Block Port Rule..."
    netsh advfirewall firewall add rule name="BlockPort" protocol=TCP dir=in localport=137,138,138,5800,5900 action=block
}

function Disable-UnneededServices {
    $services = @(
        "RemoteRegistry",
        "SSDPSRV",
        "upnphost",
        "WerSvc",
        "Fax",
        "Spooler"
    )

    foreach ($s in $services) {
        Get-Service $s -ErrorAction SilentlyContinue | Where-Object {$_.Status -ne "Stopped"} |
        ForEach-Object {
            Write-Host "Stopping $($_.Name)"
            Stop-Service $_.Name -Force
            Set-Service $_.Name -StartupType Disabled
        }
    }
}

function Lockdown-RDP {
    Write-Host "Hardening RDP..."

    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
        -Name fDenyTSConnections -Value 0

    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

    # Disable clipboard/drive mapping
    New-ItemProperty `
        -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name fDisableCdm -Value 1 -PropertyType DWord -Force | Out-Null
}

function Enforce-PasswordPolicy {
    Write-Host "Setting strong password policies..."

    net accounts `
        /minpwlen:14 `
        /maxpwage:30 `
        /minpwage:1 `
        /uniquepw:5 `
        /lockoutthreshold:5 `
        /lockoutduration:30 `
        /lockoutwindow:30
}

function Enable-Auditing {
    Write-Host "Enabling auditing..."

    auditpol /set /category:* /success:enable /failure:enable
}

function Disable-SMBv1 {
    Write-Host "Disabling SMBv1..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false
}

function Disable-GuestAccount {
    net user guest /active:no 
}

# -------------------------------
# BASELINE HARDENING
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
        -ComplexityEnabled $True `
        -MinPasswordLength 12 `
        -MaxPasswordAge 30.00:00:00 `
        -LockoutDuration 00.00:10:00 `
        -LockoutThreshold 3 `
        -ReversibleEncryptionEnabled $False `
        -PasswordHistoryCount 3

    Write-Host "Disabling anonymous LDAP binds..."

    New-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
        -Name "LDAPServerIntegrity" `
        -Value 2 `
        -PropertyType DWord -Force | Out-Null
}

function Harden-DNS {
    Pause-Section "HARDENING DNS"

    Set-DnsServerResponseRateLimiting -Mode Enable
}

function Harden-DHCP {
    Pause-Section "HARDENING DHCP"
    Set-DhcpServerAuditLog -Enable $true
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
