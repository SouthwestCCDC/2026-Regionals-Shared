#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Interactive Windows/AD hardening script with full change logging and rollback.
    Run locally on a Domain Controller.
.USAGE
    powershell -ExecutionPolicy Bypass -File Invoke-Harden.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir      = "$PSScriptRoot\harden_$Timestamp"
$ChangeLog   = "$OutDir\changelog_$Timestamp.txt"
$RollbackPs1 = "$OutDir\Rollback.ps1"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$RunBy   = $env:USERNAME
$RunOn   = $env:COMPUTERNAME
$RunDate = Get-Date

$ADAvailable = $false
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    $ADAvailable = $true
}

###############################################################################
# LOGGING
###############################################################################
$RollbackLines = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Text)
    $Text | Out-File -FilePath $ChangeLog -Append -Encoding UTF8
}

function Write-Header {
    $h = @"
================================================================
  HARDENING CHANGE LOG
  Run by   : $RunBy
  Machine  : $RunOn
  Date     : $RunDate
  Rollback : $RollbackPs1
================================================================
"@
    Write-Log $h
}

function Log-Change {
    param(
        [string]$Action,
        [string]$Before,
        [string]$After,
        [string]$Reason,
        [string]$UndoCmd
    )
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = @"

[$ts] [CHANGE] $Action
  Run by  : $RunBy on $RunOn
  Before  : $Before
  After   : $After
  Reason  : $Reason
  Rollback: $UndoCmd
"@
    Write-Log $entry
    $RollbackLines.Add("# Undo: $Action")
    $RollbackLines.Add($UndoCmd)
    $RollbackLines.Add("")
}

function Log-Skip {
    param([string]$Action, [string]$Reason = "Admin chose to skip")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = @"

[$ts] [SKIPPED] $Action
  Run by  : $RunBy on $RunOn
  Reason  : $Reason
"@
    Write-Log $entry
}

###############################################################################
# INTERACTIVE PROMPT
###############################################################################
# Returns: Y=yes, S=skip, A=applyAll, Q=quit
function Prompt-Action {
    param(
        [string]$Title,
        [string]$CurrentValue,
        [string]$ProposedChange,
        [string]$Risk = ""
    )
    Write-Host ""
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host " ACTION  : $Title" -ForegroundColor Cyan
    Write-Host " CURRENT : $CurrentValue" -ForegroundColor Yellow
    Write-Host " CHANGE  : $ProposedChange" -ForegroundColor Green
    if ($Risk) {
        Write-Host " RISK    : $Risk" -ForegroundColor Magenta
    }
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host " [Y] Apply   [S] Skip   [A] Apply to all remaining   [Q] Quit section" -ForegroundColor White
    Write-Host -NoNewline " Choice: "
    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    $choice = $key.Character.ToString().ToUpper()
    Write-Host $choice
    return $choice
}

function Prompt-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Blue
    Write-Host "  $Title" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor Blue
}

###############################################################################
# STARTUP - collect credentials and backdoor info
###############################################################################
Clear-Host
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "  INVOKE-HARDEN.PS1 - Interactive Windows Hardening" -ForegroundColor White
Write-Host "  Run by: $RunBy on $RunOn" -ForegroundColor Gray
Write-Host "  Output: $OutDir" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "This script will prompt before EVERY change." -ForegroundColor Yellow
Write-Host "A change log and Rollback.ps1 will be generated automatically." -ForegroundColor Yellow
Write-Host ""

Write-Header

# Backdoor domain admin account
Write-Host "--- BACKDOOR ACCOUNT SETUP ---" -ForegroundColor Cyan
Write-Host "A backdoor domain admin account will be created first." -ForegroundColor White
Write-Host "This ensures you retain access if other accounts are locked out." -ForegroundColor White
Write-Host ""
$BackdoorName = Read-Host "[?] Backdoor account username"
$BackdoorPass = Read-Host "[?] Backdoor account password" -AsSecureString
Write-Host ""

###############################################################################
# SECTION 1: BACKDOOR DOMAIN ADMIN
###############################################################################
Prompt-Section "BACKDOOR DOMAIN ADMIN ACCOUNT"

if ($ADAvailable) {
    $existing = Get-ADUser -Filter { SamAccountName -eq $BackdoorName } -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host " [!] Account '$BackdoorName' already exists - will ensure it is in Domain Admins" -ForegroundColor Yellow
        $choice = Prompt-Action `
            "Ensure '$BackdoorName' is in Domain Admins" `
            "Account exists, group membership unknown" `
            "Add to Domain Admins if not already member" `
            "Low - account already exists"
        if ($choice -in @("Y","A")) {
            try {
                Add-ADGroupMember -Identity "Domain Admins" -Members $BackdoorName -ErrorAction Stop
                Log-Change `
                    "Backdoor account '$BackdoorName' added to Domain Admins" `
                    "Not in Domain Admins" `
                    "Member of Domain Admins" `
                    "Retain admin access during competition" `
                    "Remove-ADGroupMember -Identity 'Domain Admins' -Members '$BackdoorName' -Confirm:`$false"
                Write-Host " [+] Added to Domain Admins" -ForegroundColor Green
            } catch {
                Write-Host " [!] Failed: $_" -ForegroundColor Red
            }
        } else { Log-Skip "Backdoor account group membership" }
    } else {
        $choice = Prompt-Action `
            "Create backdoor domain admin account '$BackdoorName'" `
            "Account does not exist" `
            "Create account, add to Domain Admins" `
            "Low - this is your recovery account"
        if ($choice -in @("Y","A")) {
            try {
                New-ADUser `
                    -Name $BackdoorName `
                    -SamAccountName $BackdoorName `
                    -AccountPassword $BackdoorPass `
                    -Enabled $true `
                    -PasswordNeverExpires $true `
                    -ErrorAction Stop
                Add-ADGroupMember -Identity "Domain Admins" -Members $BackdoorName
                Log-Change `
                    "Backdoor account '$BackdoorName' created and added to Domain Admins" `
                    "Account did not exist" `
                    "Account created, member of Domain Admins" `
                    "Retain admin access during competition" `
                    "Remove-ADUser -Identity '$BackdoorName' -Confirm:`$false"
                Write-Host " [+] Account '$BackdoorName' created and added to Domain Admins" -ForegroundColor Green
            } catch {
                Write-Host " [!] Failed to create account: $_" -ForegroundColor Red
            }
        } else { Log-Skip "Backdoor account creation" }
    }
} else {
    Write-Host " [!] AD module not available - creating local admin instead" -ForegroundColor Yellow
    $choice = Prompt-Action `
        "Create local backdoor admin '$BackdoorName'" `
        "Account does not exist" `
        "Create local admin account" `
        "Low - recovery account"
    if ($choice -in @("Y","A")) {
        try {
            New-LocalUser -Name $BackdoorName -Password $BackdoorPass -PasswordNeverExpires -ErrorAction Stop
            Add-LocalGroupMember -Group "Administrators" -Member $BackdoorName
            Log-Change `
                "Local backdoor admin '$BackdoorName' created" `
                "Account did not exist" `
                "Local admin account created" `
                "Retain access during competition" `
                "Remove-LocalUser -Name '$BackdoorName'"
            Write-Host " [+] Local admin '$BackdoorName' created" -ForegroundColor Green
        } catch {
            Write-Host " [!] Failed: $_" -ForegroundColor Red
        }
    } else { Log-Skip "Local backdoor account creation" }
}

###############################################################################
# SECTION 2: SMB HARDENING
###############################################################################
Prompt-Section "SMB HARDENING"

$SmbCfg = Get-SmbServerConfiguration

# SMBv1
$smb1State = $SmbCfg.EnableSMB1Protocol
$choice = Prompt-Action `
    "Disable SMBv1 Protocol" `
    "EnableSMB1Protocol = $smb1State" `
    "Set EnableSMB1Protocol = False" `
    "EternalBlue / WannaCry ransomware vector - disable unless a scored service requires it"
if ($choice -in @("Y","A")) {
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
        Log-Change `
            "SMBv1 disabled" `
            "EnableSMB1Protocol = $smb1State" `
            "EnableSMB1Protocol = False" `
            "EternalBlue / ransomware prevention" `
            "Set-SmbServerConfiguration -EnableSMB1Protocol `$true -Force"
        Write-Host " [+] SMBv1 disabled" -ForegroundColor Green
    } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
} elseif ($choice -eq "Q") { Log-Skip "SMBv1 disable - admin quit section" }
else { Log-Skip "SMBv1 disable" }

# SMB Signing
$smbSign = $SmbCfg.RequireSecuritySignature
$choice = Prompt-Action `
    "Require SMB Signing" `
    "RequireSecuritySignature = $smbSign" `
    "Set RequireSecuritySignature = True" `
    "Prevents NTLM relay attacks - safe on DCs"
if ($choice -in @("Y","A")) {
    try {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
        Log-Change `
            "SMB signing required" `
            "RequireSecuritySignature = $smbSign" `
            "RequireSecuritySignature = True" `
            "Prevent NTLM relay attacks" `
            "Set-SmbServerConfiguration -RequireSecuritySignature `$false -Force"
        Write-Host " [+] SMB signing enforced" -ForegroundColor Green
    } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
} elseif ($choice -eq "Q") { Log-Skip "SMB signing - admin quit section" }
else { Log-Skip "SMB signing" }

###############################################################################
# SECTION 3: CREDENTIAL HARDENING
###############################################################################
Prompt-Section "CREDENTIAL HARDENING"

# WDigest
$wdProp = Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name UseLogonCredential -ErrorAction SilentlyContinue
$wdVal = if ($null -eq $wdProp) { "not set (safe)" } else { $wdProp.UseLogonCredential }
$choice = Prompt-Action `
    "Disable WDigest (UseLogonCredential=0)" `
    "UseLogonCredential = $wdVal" `
    "Set UseLogonCredential = 0" `
    "Prevents plaintext passwords being cached in LSASS memory"
if ($choice -in @("Y","A")) {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name UseLogonCredential -Value 0 -Type DWord
        Log-Change `
            "WDigest UseLogonCredential disabled" `
            "UseLogonCredential = $wdVal" `
            "UseLogonCredential = 0" `
            "Prevent plaintext creds in LSASS (mimikatz defense)" `
            "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 1 -Type DWord"
        Write-Host " [+] WDigest disabled" -ForegroundColor Green
    } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
} elseif ($choice -eq "Q") { Log-Skip "WDigest - admin quit section" }
else { Log-Skip "WDigest disable" }

# LSASS PPL
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaProp = Get-ItemProperty $lsaPath -Name RunAsPPL -ErrorAction SilentlyContinue
$lsaRawVal  = $lsaProp.RunAsPPL        # null if key didn't exist
$lsaDisplay = if ($null -eq $lsaRawVal) { "not set" } else { $lsaRawVal }
$lsaUndo    = if ($null -eq $lsaRawVal) {
    "Remove-ItemProperty -Path '$lsaPath' -Name RunAsPPL -ErrorAction SilentlyContinue"
} else {
    "Set-ItemProperty -Path '$lsaPath' -Name RunAsPPL -Value $lsaRawVal -Type DWord"
}
$choice = Prompt-Action `
    "Enable LSASS Protected Process Light (RunAsPPL=1)" `
    "RunAsPPL = $lsaDisplay" `
    "Set RunAsPPL = 1 (requires reboot to take effect)" `
    "Blocks mimikatz-style LSASS memory dumps - safe on Server 2022/2025"
if ($choice -in @("Y","A")) {
    try {
        Set-ItemProperty -Path $lsaPath -Name RunAsPPL -Value 1 -Type DWord
        Log-Change `
            "LSASS RunAsPPL enabled" `
            "RunAsPPL = $lsaDisplay" `
            "RunAsPPL = 1 (reboot required)" `
            "Block LSASS memory dump attacks" `
            $lsaUndo
        Write-Host " [+] LSASS PPL enabled (reboot required)" -ForegroundColor Green
    } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
} elseif ($choice -eq "Q") { Log-Skip "LSASS PPL - admin quit section" }
else { Log-Skip "LSASS PPL enable" }

# NTLMv1
$ntlmPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$ntlmProp   = Get-ItemProperty $ntlmPath -Name LmCompatibilityLevel -ErrorAction SilentlyContinue
$ntlmRawVal = $ntlmProp.LmCompatibilityLevel   # null if key didn't exist
$ntlmDisplay = if ($null -eq $ntlmRawVal) { "not set (Windows default=0)" } else { $ntlmRawVal }
$ntlmUndo    = if ($null -eq $ntlmRawVal) {
    "Remove-ItemProperty -Path '$ntlmPath' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue"
} else {
    "Set-ItemProperty -Path '$ntlmPath' -Name LmCompatibilityLevel -Value $ntlmRawVal -Type DWord"
}
$choice = Prompt-Action `
    "Set NTLMv2 only (LmCompatibilityLevel=5)" `
    "LmCompatibilityLevel = $ntlmDisplay" `
    "Set LmCompatibilityLevel = 5 (NTLMv2 responses only)" `
    "Disables NTLMv1/LM - may break very old clients (pre-Vista)"
if ($choice -in @("Y","A")) {
    try {
        Set-ItemProperty -Path $ntlmPath -Name LmCompatibilityLevel -Value 5 -Type DWord
        Log-Change `
            "LmCompatibilityLevel set to 5 (NTLMv2 only)" `
            "LmCompatibilityLevel = $ntlmDisplay" `
            "LmCompatibilityLevel = 5" `
            "Disable NTLMv1 - prevent downgrade attacks" `
            $ntlmUndo
        Write-Host " [+] NTLMv2 only enforced" -ForegroundColor Green
    } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
} elseif ($choice -eq "Q") { Log-Skip "NTLMv1 disable - admin quit section" }
else { Log-Skip "NTLMv1 disable" }

###############################################################################
# SECTION 4: RDP HARDENING
###############################################################################
Prompt-Section "RDP HARDENING"

$nlaPath    = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$nlaProp    = Get-ItemProperty $nlaPath -Name UserAuthenticationRequired -ErrorAction SilentlyContinue
$nlaRawVal  = $nlaProp.UserAuthenticationRequired   # null if key didn't exist
$nlaDisplay = if ($null -eq $nlaRawVal) { "not set" } else { $nlaRawVal }
$nlaUndo    = if ($null -eq $nlaRawVal) {
    "Remove-ItemProperty -Path '$nlaPath' -Name UserAuthenticationRequired -ErrorAction SilentlyContinue"
} else {
    "Set-ItemProperty -Path '$nlaPath' -Name UserAuthenticationRequired -Value $nlaRawVal -Type DWord"
}
$choice = Prompt-Action `
    "Enforce RDP Network Level Authentication (NLA)" `
    "UserAuthenticationRequired = $nlaDisplay" `
    "Set UserAuthenticationRequired = 1" `
    "Requires auth before RDP session - blocks pre-auth exploits"
if ($choice -in @("Y","A")) {
    try {
        Set-ItemProperty -Path $nlaPath -Name UserAuthenticationRequired -Value 1 -Type DWord
        Log-Change `
            "RDP NLA enforced" `
            "UserAuthenticationRequired = $nlaDisplay" `
            "UserAuthenticationRequired = 1" `
            "Require NLA for RDP - block pre-auth exploits" `
            $nlaUndo
        Write-Host " [+] RDP NLA enforced" -ForegroundColor Green
    } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
} elseif ($choice -eq "Q") { Log-Skip "RDP NLA - admin quit section" }
else { Log-Skip "RDP NLA enforce" }

###############################################################################
# SECTION 5: WINDOWS FIREWALL
###############################################################################
Prompt-Section "WINDOWS FIREWALL"

$profiles = Get-NetFirewallProfile
foreach ($p in $profiles) {
    $pname  = $p.Name
    $penab  = $p.Enabled
    if (-not $penab) {
        $choice = Prompt-Action `
            "Enable Windows Firewall - $pname profile" `
            "Enabled = $penab" `
            "Set Enabled = True" `
            "Firewall is OFF on $pname - all inbound traffic unrestricted"
        if ($choice -in @("Y","A")) {
            try {
                Set-NetFirewallProfile -Name $pname -Enabled True
                Log-Change `
                    "Firewall profile $pname enabled" `
                    "Enabled = False" `
                    "Enabled = True" `
                    "Ensure inbound traffic is filtered" `
                    "Set-NetFirewallProfile -Name '$pname' -Enabled False"
                Write-Host " [+] Firewall profile $pname enabled" -ForegroundColor Green
            } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
        } elseif ($choice -eq "Q") { Log-Skip "Firewall $pname - admin quit section"; break }
        else { Log-Skip "Firewall $pname enable" }
    } else {
        Write-Host " [OK] Firewall profile $pname already enabled" -ForegroundColor Green
    }
}

###############################################################################
# SECTION 6: AUDIT POLICY
###############################################################################
Prompt-Section "AUDIT POLICY"

$AuditSettings = @(
    @{ Cat="Account Logon";     Sub="Credential Validation";           Val="Success,Failure" },
    @{ Cat="Account Management";Sub="User Account Management";         Val="Success,Failure" },
    @{ Cat="Account Management";Sub="Security Group Management";       Val="Success,Failure" },
    @{ Cat="Logon/Logoff";      Sub="Logon";                          Val="Success,Failure" },
    @{ Cat="Logon/Logoff";      Sub="Logoff";                         Val="Success" },
    @{ Cat="Object Access";     Sub="File System";                    Val="Success,Failure" },
    @{ Cat="Policy Change";     Sub="Audit Policy Change";            Val="Success,Failure" },
    @{ Cat="Privilege Use";     Sub="Sensitive Privilege Use";        Val="Success,Failure" },
    @{ Cat="System";            Sub="Security System Extension";      Val="Success,Failure" },
    @{ Cat="Detailed Tracking"; Sub="Process Creation";               Val="Success" }
)

$applyAll = $false
foreach ($setting in $AuditSettings) {
    $cat = $setting.Cat
    $sub = $setting.Sub
    $val = $setting.Val

    if ($applyAll) {
        $choice = "Y"
    } else {
        $choice = Prompt-Action `
            "Audit Policy: $sub" `
            "Current: unknown (run auditpol /get /subcategory:'$sub' to check)" `
            "Set: $val" `
            "Ensure $sub events are logged for incident response"
    }
    if ($choice -eq "A") { $applyAll = $true; $choice = "Y" }
    if ($choice -in @("Y")) {
        try {
            $sucFlag = if ($val -match "Success") { "enable" } else { "disable" }
            $failFlag = if ($val -match "Failure") { "enable" } else { "disable" }
            auditpol /set /subcategory:"$sub" /success:$sucFlag /failure:$failFlag | Out-Null
            Log-Change `
                "Audit policy: $sub" `
                "Previous setting unknown" `
                "$val" `
                "Ensure $sub events logged for IR" `
                "auditpol /set /subcategory:`"$sub`" /success:disable /failure:disable"
            Write-Host " [+] Audit: $sub = $val" -ForegroundColor Green
        } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
    } elseif ($choice -eq "Q") { Log-Skip "Audit policy - admin quit section"; break }
    else { Log-Skip "Audit policy: $sub" }
}
$applyAll = $false

###############################################################################
# SECTION 7: POWERSHELL LOGGING
###############################################################################
Prompt-Section "POWERSHELL LOGGING"

$sbPath    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$sbProp    = Get-ItemProperty $sbPath -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
$sbRawVal  = $sbProp.EnableScriptBlockLogging
$sbDisplay = if ($null -eq $sbRawVal) { "not set" } else { $sbRawVal }
$sbUndo    = if ($null -eq $sbRawVal) {
    "Remove-ItemProperty -Path '$sbPath' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue"
} else {
    "Set-ItemProperty -Path '$sbPath' -Name EnableScriptBlockLogging -Value $sbRawVal -Type DWord"
}

$choice = Prompt-Action `
    "Enable PowerShell ScriptBlock Logging" `
    "EnableScriptBlockLogging = $sbDisplay" `
    "Set EnableScriptBlockLogging = 1" `
    "Logs all PS commands to Event Log 4104 - catches attacker PS activity"
if ($choice -in @("Y","A")) {
    try {
        if (-not (Test-Path $sbPath)) { New-Item -Path $sbPath -Force | Out-Null }
        Set-ItemProperty -Path $sbPath -Name EnableScriptBlockLogging -Value 1 -Type DWord
        Log-Change `
            "PowerShell ScriptBlock logging enabled" `
            "EnableScriptBlockLogging = $sbDisplay" `
            "EnableScriptBlockLogging = 1" `
            "Log all PS commands to Event 4104 for IR" `
            $sbUndo
        Write-Host " [+] PS ScriptBlock logging enabled" -ForegroundColor Green
    } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
} elseif ($choice -eq "Q") { Log-Skip "PS logging - admin quit section" }
else { Log-Skip "PS ScriptBlock logging" }

$txPath    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$txProp    = Get-ItemProperty $txPath -Name EnableTranscripting -ErrorAction SilentlyContinue
$txRawVal  = $txProp.EnableTranscripting
$txDisplay = if ($null -eq $txRawVal) { "not set" } else { $txRawVal }
$txUndo    = if ($null -eq $txRawVal) {
    "Remove-ItemProperty -Path '$txPath' -Name EnableTranscripting -ErrorAction SilentlyContinue"
} else {
    "Set-ItemProperty -Path '$txPath' -Name EnableTranscripting -Value $txRawVal -Type DWord"
}

$choice = Prompt-Action `
    "Enable PowerShell Transcription Logging" `
    "EnableTranscripting = $txDisplay" `
    "Set EnableTranscripting = 1" `
    "Saves full PS session transcripts - very useful for IR"
if ($choice -in @("Y","A")) {
    try {
        if (-not (Test-Path $txPath)) { New-Item -Path $txPath -Force | Out-Null }
        Set-ItemProperty -Path $txPath -Name EnableTranscripting -Value 1 -Type DWord
        Log-Change `
            "PowerShell Transcription logging enabled" `
            "EnableTranscripting = $txDisplay" `
            "EnableTranscripting = 1" `
            "Log full PS session transcripts for IR" `
            $txUndo
        Write-Host " [+] PS Transcription logging enabled" -ForegroundColor Green
    } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
} elseif ($choice -eq "Q") { Log-Skip "PS transcription - admin quit section" }
else { Log-Skip "PS Transcription logging" }

###############################################################################
# SECTION 8: EVENT LOG SIZES
###############################################################################
Prompt-Section "EVENT LOG SIZE INCREASE"

$LogSizes = @(
    @{ Name="Security";    TargetMB=512 },
    @{ Name="System";      TargetMB=128 },
    @{ Name="Application"; TargetMB=128 }
)
foreach ($ls in $LogSizes) {
    $lname  = $ls.Name
    $targetKB = $ls.TargetMB * 1024
    $evtLog = Get-EventLog -List | Where-Object { $_.Log -eq $lname }
    if ($evtLog) {
        $curMB = [math]::Round($evtLog.MaximumKilobytes / 1024, 0)
        $choice = Prompt-Action `
            "Increase $lname event log size" `
            "MaxSize = ${curMB}MB" `
            "Set MaxSize = $($ls.TargetMB)MB" `
            "Larger logs retain more history during an incident"
        if ($choice -in @("Y","A")) {
            try {
                Limit-EventLog -LogName $lname -MaximumSize ($targetKB * 1024)
                Log-Change `
                    "EventLog $lname size increased" `
                    "MaxSize = ${curMB}MB" `
                    "MaxSize = $($ls.TargetMB)MB" `
                    "Retain more log history during incident" `
                    "Limit-EventLog -LogName '$lname' -MaximumSize $($curMB * 1024 * 1024)"
                Write-Host " [+] $lname log size set to $($ls.TargetMB)MB" -ForegroundColor Green
            } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
        } elseif ($choice -eq "Q") { Log-Skip "Event log sizes - admin quit section"; break }
        else { Log-Skip "EventLog $lname size increase" }
    }
}

###############################################################################
# SECTION 9: DEFENDER
###############################################################################
Prompt-Section "WINDOWS DEFENDER"

$Defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($Defender) {
    $rtpEnabled = $Defender.RealTimeProtectionEnabled
    if (-not $rtpEnabled) {
        $choice = Prompt-Action `
            "Enable Defender Real-Time Protection" `
            "RealTimeProtectionEnabled = $rtpEnabled" `
            "Enable real-time protection" `
            "Real-time protection is OFF - malware will not be caught"
        if ($choice -in @("Y","A")) {
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false
                Log-Change `
                    "Defender real-time protection enabled" `
                    "RealTimeProtectionEnabled = False" `
                    "RealTimeProtectionEnabled = True" `
                    "Ensure malware is caught in real time" `
                    "Set-MpPreference -DisableRealtimeMonitoring `$true"
                Write-Host " [+] Defender real-time protection enabled" -ForegroundColor Green
            } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
        } else { Log-Skip "Defender real-time protection" }
    } else {
        Write-Host " [OK] Defender real-time protection already enabled" -ForegroundColor Green
    }

    # Check and remove suspicious exclusions
    $Exclusions = @(Get-MpPreference | Select-Object -ExpandProperty ExclusionPath)
    if ($Exclusions.Count -gt 0) {
        Write-Host " [!] Defender exclusions found - review each:" -ForegroundColor Yellow
        foreach ($ex in $Exclusions) {
            $choice = Prompt-Action `
                "Remove Defender exclusion" `
                "Exclusion: $ex" `
                "Remove this exclusion path" `
                "Red team commonly adds exclusions to allow malware - remove unless legitimate"
            if ($choice -in @("Y","A")) {
                try {
                    Remove-MpPreference -ExclusionPath $ex
                    Log-Change `
                        "Defender exclusion removed: $ex" `
                        "Exclusion existed: $ex" `
                        "Exclusion removed" `
                        "Remove red-team-added AV exclusion" `
                        "Add-MpPreference -ExclusionPath '$ex'"
                    Write-Host " [+] Exclusion removed: $ex" -ForegroundColor Green
                } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
            } elseif ($choice -eq "Q") { break }
            else { Log-Skip "Defender exclusion removal: $ex" }
        }
    } else {
        Write-Host " [OK] No Defender exclusions found" -ForegroundColor Green
    }
} else {
    Write-Host " [!] Could not query Defender - may be 3rd party AV" -ForegroundColor Yellow
    Write-Log ""
    Write-Log "[INFO] Defender status unavailable - skipped Defender section"
}

###############################################################################
# SECTION 10: DISABLE DEFAULT ACCOUNTS
###############################################################################
Prompt-Section "DISABLE GUEST AND DEFAULT ACCOUNTS"

$DefaultAccounts = @("Guest", "DefaultAccount")
foreach ($acctName in $DefaultAccounts) {
    $localAcct = Get-LocalUser -Name $acctName -ErrorAction SilentlyContinue
    if ($localAcct -and $localAcct.Enabled) {
        $choice = Prompt-Action `
            "Disable local account: $acctName" `
            "Enabled = True" `
            "Disable account" `
            "Default accounts are common red team targets"
        if ($choice -in @("Y","A")) {
            try {
                Disable-LocalUser -Name $acctName
                Log-Change `
                    "Local account '$acctName' disabled" `
                    "Enabled = True" `
                    "Enabled = False" `
                    "Disable default/guest accounts" `
                    "Enable-LocalUser -Name '$acctName'"
                Write-Host " [+] $acctName disabled" -ForegroundColor Green
            } catch { Write-Host " [!] Failed: $_" -ForegroundColor Red }
        } elseif ($choice -eq "Q") { break }
        else { Log-Skip "Disable $acctName" }
    } else {
        Write-Host " [OK] $acctName already disabled or does not exist" -ForegroundColor Green
    }
}

###############################################################################
# SECTION 11: PASSWORD NEVER EXPIRES
###############################################################################
Prompt-Section "PASSWORD NEVER EXPIRES - PER ACCOUNT REVIEW"

if ($ADAvailable) {
    $SafeAccounts = @("krbtgt", "Administrator", $BackdoorName)
    $PNEAccounts = @(Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
        -Properties PasswordNeverExpires, PasswordLastSet, MemberOf |
        Where-Object { $_.SamAccountName -notin $SafeAccounts })

    $pneCount = $PNEAccounts.Count
    Write-Host " Found $pneCount accounts with PasswordNeverExpires (excluding $($SafeAccounts -join ', '))" -ForegroundColor Yellow
    Write-Host " Showing each with context. [A] to apply to all remaining." -ForegroundColor Gray

    $applyAll = $false
    foreach ($u in $PNEAccounts) {
        $sam   = $u.SamAccountName
        $pls   = $u.PasswordLastSet
        $groups = ($u.MemberOf | ForEach-Object {
            ($_ -split ",")[0] -replace "CN=",""
        }) -join ", "

        if ($applyAll) {
            $choice = "Y"
        } else {
            $choice = Prompt-Action `
                "Set PasswordNeverExpires = False for: $sam" `
                "PwdLastSet=$pls | Groups=$groups" `
                "PasswordNeverExpires = False" `
                "Account will follow domain password policy - may require password reset"
        }
        if ($choice -eq "A") { $applyAll = $true; $choice = "Y" }
        if ($choice -eq "Y") {
            try {
                Set-ADUser -Identity $sam -PasswordNeverExpires $false
                Log-Change `
                    "PasswordNeverExpires disabled for $sam" `
                    "PasswordNeverExpires = True | PwdLastSet=$pls" `
                    "PasswordNeverExpires = False" `
                    "Enforce password expiry per domain policy" `
                    "Set-ADUser -Identity '$sam' -PasswordNeverExpires `$true"
                Write-Host " [+] PasswordNeverExpires disabled for $sam" -ForegroundColor Green
            } catch { Write-Host " [!] Failed for $sam`: $_" -ForegroundColor Red }
        } elseif ($choice -eq "Q") { Log-Skip "PasswordNeverExpires review - admin quit section"; break }
        else { Log-Skip "PasswordNeverExpires for $sam" }
    }
    $applyAll = $false
} else {
    Write-Host " [!] AD module not available - skipping" -ForegroundColor Yellow
}

###############################################################################
# SECTION 12: GROUP POLICY CREATOR OWNERS
###############################################################################
Prompt-Section "GROUP POLICY CREATOR OWNERS CLEANUP"

if ($ADAvailable) {
    $SafeGPCO = @("Administrator")
    try {
        $GPCOMembers = @(Get-ADGroupMember -Identity "Group Policy Creator Owners" -ErrorAction Stop)
        $toRemove    = $GPCOMembers | Where-Object { $_.SamAccountName -notin $SafeGPCO }
        $removeCount = $toRemove.Count

        Write-Host " Current members: $(($GPCOMembers | Select-Object -ExpandProperty SamAccountName) -join ', ')" -ForegroundColor Yellow
        Write-Host " Safe to keep   : $($SafeGPCO -join ', ')" -ForegroundColor Gray
        Write-Host " To review      : $removeCount members" -ForegroundColor Yellow

        $applyAll = $false
        foreach ($m in $toRemove) {
            $mname = $m.SamAccountName
            if ($applyAll) { $choice = "Y" }
            else {
                $choice = Prompt-Action `
                    "Remove '$mname' from Group Policy Creator Owners" `
                    "Member of GPCO - can create/modify GPOs domain-wide" `
                    "Remove from group" `
                    "GPCO members can push malicious GPOs - keep only Administrator"
            }
            if ($choice -eq "A") { $applyAll = $true; $choice = "Y" }
            if ($choice -eq "Y") {
                try {
                    Remove-ADGroupMember -Identity "Group Policy Creator Owners" `
                        -Members $mname -Confirm:$false
                    Log-Change `
                        "Removed '$mname' from Group Policy Creator Owners" `
                        "Member of GPCO" `
                        "Removed from GPCO" `
                        "Limit GPO creation to Administrator only" `
                        "Add-ADGroupMember -Identity 'Group Policy Creator Owners' -Members '$mname'"
                    Write-Host " [+] Removed $mname from GPCO" -ForegroundColor Green
                } catch { Write-Host " [!] Failed for $mname`: $_" -ForegroundColor Red }
            } elseif ($choice -eq "Q") { Log-Skip "GPCO cleanup - admin quit section"; break }
            else { Log-Skip "GPCO removal for $mname" }
        }
        $applyAll = $false
    } catch {
        Write-Host " [!] Could not query GPCO group: $_" -ForegroundColor Red
    }
} else {
    Write-Host " [!] AD module not available - skipping" -ForegroundColor Yellow
}

###############################################################################
# WRITE ROLLBACK SCRIPT
###############################################################################
$rollbackHeader = @"
#Requires -RunAsAdministrator
<#
  AUTO-GENERATED ROLLBACK SCRIPT
  Generated : $RunDate
  Run by    : $RunBy on $RunOn
  Change log: $ChangeLog

  WARNING: Review each command before running.
  Run: powershell -ExecutionPolicy Bypass -File Rollback.ps1
#>

Write-Host "Rollback script from harden run: $RunDate" -ForegroundColor Yellow
Write-Host "This will undo all applied changes. Press Ctrl+C to abort." -ForegroundColor Red
Start-Sleep -Seconds 3

"@
$rollbackHeader | Out-File -FilePath $RollbackPs1 -Encoding UTF8
$RollbackLines | Out-File -FilePath $RollbackPs1 -Append -Encoding UTF8
'Write-Host "Rollback complete." -ForegroundColor Green' |
    Out-File -FilePath $RollbackPs1 -Append -Encoding UTF8

###############################################################################
# FINAL SUMMARY
###############################################################################
$changeCount = (Select-String -Path $ChangeLog -Pattern "\[CHANGE\]").Count
$skipCount   = (Select-String -Path $ChangeLog -Pattern "\[SKIPPED\]").Count

Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "  HARDENING COMPLETE" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "  Changes applied : $changeCount" -ForegroundColor Green
Write-Host "  Skipped         : $skipCount" -ForegroundColor Yellow
Write-Host "  Change log      : $ChangeLog" -ForegroundColor Cyan
Write-Host "  Rollback script : $RollbackPs1" -ForegroundColor Cyan
Write-Host ""
Write-Host "  NOTE: LSASS PPL requires a REBOOT to take effect." -ForegroundColor Magenta
Write-Host "  NOTE: Run Invoke-Recon.ps1 again to verify changes." -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Blue