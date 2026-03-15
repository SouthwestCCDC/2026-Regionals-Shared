#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AD/Windows recon and vulnerability advisory report.
    Run locally on a Domain Controller.
    Outputs both .txt and .html reports.
.USAGE
    powershell -ExecutionPolicy Bypass -File Invoke-Recon.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir     = "$PSScriptRoot\recon_$Timestamp"
$TxtReport  = "$OutDir\report.txt"
$HtmlReport = "$OutDir\report.html"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$CRIT = "[CRITICAL]"
$WARN = "[WARN]    "
$INFO = "[INFO]    "
$OK   = "[OK]      "

$TxtLines = [System.Collections.Generic.List[string]]::new()

function Write-Line {
    param([string]$Text = "")
    $TxtLines.Add($Text)
    Write-Host $Text
}

function Write-Section {
    param([string]$Title)
    $bar = "=" * 60
    Write-Line ""
    Write-Line $bar
    Write-Line "  $Title"
    Write-Line $bar
}

function Write-Find {
    param([string]$Sev, [string]$Msg)
    Write-Line "$Sev $Msg"
}

$ADAvailable = $false
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    $ADAvailable = $true
}

###############################################################################
# SYSTEM INFO
###############################################################################
Write-Section "SYSTEM INFORMATION"

$OS = Get-CimInstance Win32_OperatingSystem
$CS = Get-CimInstance Win32_ComputerSystem
$csname = $CS.Name
$csdomain = $CS.Domain
$oscap = $OS.Caption
$osbuild = $OS.BuildNumber
$osboot = $OS.LastBootUpTime
$osinstall = $OS.InstallDate
Write-Find $INFO "Hostname     : $csname"
Write-Find $INFO "Domain       : $csdomain"
Write-Find $INFO "OS           : $oscap Build $osbuild"
Write-Find $INFO "Last Boot    : $osboot"
Write-Find $INFO "Install Date : $osinstall"

$Roles = Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.FeatureType -eq "Role" }
$roleNames = $Roles.Name -join ", "
Write-Find $INFO "Roles        : $roleNames"

###############################################################################
# AD USERS AND PRIVILEGED GROUPS
###############################################################################
Write-Section "AD USERS AND PRIVILEGED GROUP MEMBERSHIP"

if (-not $ADAvailable) {
    Write-Find $WARN "ActiveDirectory module not available - skipping AD checks"
}
else {
    $Domain = Get-ADDomain
    $dnsroot = $Domain.DNSRoot
    $domsid  = $Domain.DomainSID
    $forest  = $Domain.Forest
    $pdc     = $Domain.PDCEmulator
    Write-Find $INFO "Domain FQDN  : $dnsroot"
    Write-Find $INFO "Domain SID   : $domsid"
    Write-Find $INFO "Forest       : $forest"
    Write-Find $INFO "PDC Emulator : $pdc"

    $AllUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties PasswordNeverExpires, PasswordNotRequired
    $userCount = $AllUsers.Count
    Write-Find $INFO "Total enabled users: $userCount"

    $PwdNeverExpires = @($AllUsers | Where-Object { $_.PasswordNeverExpires -eq $true })
    $pneCount = $PwdNeverExpires.Count
    if ($pneCount -gt 0) {
        Write-Find $WARN "Users with PasswordNeverExpires ($pneCount):"
        foreach ($u in $PwdNeverExpires) {
            $sam = $u.SamAccountName
            Write-Find $WARN "  -> $sam"
        }
    } else { Write-Find $OK "No users with PasswordNeverExpires" }

    $PwdNotReq = @($AllUsers | Where-Object { $_.PasswordNotRequired -eq $true })
    $pnrCount = $PwdNotReq.Count
    if ($pnrCount -gt 0) {
        Write-Find $CRIT "Users with PasswordNotRequired ($pnrCount):"
        foreach ($u in $PwdNotReq) {
            $sam = $u.SamAccountName
            Write-Find $CRIT "  -> $sam"
        }
    } else { Write-Find $OK "No users with PasswordNotRequired" }

    $PrivGroups = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators",
        "Print Operators", "Server Operators", "Group Policy Creator Owners"
    )
    foreach ($grp in $PrivGroups) {
        try {
            $members = @(Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop)
            $mc = $members.Count
            if ($mc -gt 0) {
                $names = ($members | Select-Object -ExpandProperty SamAccountName) -join ", "
                $sev = if ($mc -gt 3) { $WARN } else { $INFO }
                Write-Find $sev "$grp ($mc members): $names"
            }
        } catch {
            Write-Find $INFO "$grp : not found or empty"
        }
    }

    $AdminCountUsers = @(Get-ADUser -Filter { AdminCount -eq 1 } -Properties AdminCount)
    $acCount = $AdminCountUsers.Count
    $acNames = ($AdminCountUsers | Select-Object -ExpandProperty SamAccountName) -join ", "
    Write-Find $INFO "AdminCount=1 accounts ($acCount): $acNames"
}

###############################################################################
# KERBEROAST / AS-REP ROAST
###############################################################################
Write-Section "KERBEROAST AND AS-REP ROAST EXPOSURE"

if ($ADAvailable) {
    $Kerb = @(Get-ADUser -Filter { ServicePrincipalName -like "*" } `
        -Properties ServicePrincipalName, PasswordLastSet |
        Where-Object { $_.Enabled -eq $true })
    $kCount = $Kerb.Count
    if ($kCount -gt 0) {
        Write-Find $CRIT "Kerberoastable accounts ($kCount) - fix: use gMSA or 25+ char password:"
        foreach ($u in $Kerb) {
            $sam = $u.SamAccountName
            $spn = $u.ServicePrincipalName -join ";"
            $pls = $u.PasswordLastSet
            Write-Find $CRIT "  -> $sam | SPN: $spn | PwdLastSet: $pls"
        }
    } else { Write-Find $OK "No Kerberoastable user accounts found" }

    $ASREP = @(Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
        -Properties DoesNotRequirePreAuth |
        Where-Object { $_.Enabled -eq $true })
    $asCount = $ASREP.Count
    if ($asCount -gt 0) {
        Write-Find $CRIT "AS-REP Roastable accounts ($asCount) - enable Kerberos pre-auth:"
        foreach ($u in $ASREP) {
            $sam = $u.SamAccountName
            Write-Find $CRIT "  -> $sam"
        }
    } else { Write-Find $OK "No AS-REP roastable accounts found" }
}

###############################################################################
# STALE AND DEFAULT ACCOUNTS
###############################################################################
Write-Section "STALE AND DEFAULT ACCOUNTS"

if ($ADAvailable) {
    $StaleDate = (Get-Date).AddDays(-90)

    $NeverLogon = @(Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate |
        Where-Object { $null -eq $_.LastLogonDate })
    $nlCount = $NeverLogon.Count
    Write-Find $WARN "Accounts never logged in: $nlCount"

    $Inactive = @(Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate |
        Where-Object { $_.LastLogonDate -ne $null -and $_.LastLogonDate -lt $StaleDate })
    $inCount = $Inactive.Count
    if ($inCount -gt 0) {
        Write-Find $WARN "Accounts inactive 90+ days ($inCount):"
        $Inactive | Select-Object -First 10 | ForEach-Object {
            $sam = $_.SamAccountName
            $ll  = $_.LastLogonDate
            Write-Find $WARN "  -> $sam last: $ll"
        }
        if ($inCount -gt 10) {
            $more = $inCount - 10
            Write-Find $WARN "  ... and $more more"
        }
    } else { Write-Find $OK "No accounts inactive 90+ days" }

    $DefaultNames = @("Guest", "DefaultAccount", "WDAGUtilityAccount", "krbtgt", "Administrator")
    foreach ($name in $DefaultNames) {
        $acct = Get-ADUser -Filter { SamAccountName -eq $name } -Properties Enabled, PasswordLastSet
        if ($acct) {
            $state = if ($acct.Enabled) { "ENABLED" } else { "disabled" }
            $pls   = $acct.PasswordLastSet
            $sev   = if ($acct.Enabled -and $name -in @("Guest", "DefaultAccount")) { $WARN } else { $INFO }
            Write-Find $sev "Default account '$name': $state | PwdLastSet: $pls"
        }
    }

    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
    $kpls   = $krbtgt.PasswordLastSet
    if ($kpls -lt (Get-Date).AddDays(-180)) {
        Write-Find $WARN "krbtgt password last set $kpls - rotate after any red team activity"
    } else { Write-Find $OK "krbtgt password age OK: $kpls" }
}

###############################################################################
# GPO ENUMERATION
###############################################################################
Write-Section "GROUP POLICY ENUMERATION AND MISCONFIGS"

if ($ADAvailable) {
    $GPOs = Get-GPO -All
    $gpoCount = $GPOs.Count
    Write-Find $INFO "Total GPOs: $gpoCount"

    foreach ($gpo in $GPOs) {
        $gname = $gpo.DisplayName
        $rpt   = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        if ($rpt -notmatch "<LinksTo>") {
            Write-Find $WARN "Unlinked GPO: '$gname' - verify it should exist"
        }
        if ($rpt -notmatch "<q2:") {
            Write-Find $INFO "Possibly empty GPO: '$gname'"
        }
    }

    $PwdPolicy = Get-ADDefaultDomainPasswordPolicy
    $minLen    = $PwdPolicy.MinPasswordLength
    $history   = $PwdPolicy.PasswordHistoryCount
    $maxAge    = $PwdPolicy.MaxPasswordAge.Days
    $complex   = $PwdPolicy.ComplexityEnabled
    $lockout   = $PwdPolicy.LockoutThreshold
    Write-Find $INFO "Password Policy: MinLen=$minLen | History=$history | MaxAge=${maxAge}d | Complexity=$complex"
    if ($minLen -lt 12) { Write-Find $WARN "Password minimum length $minLen is below recommended 12" }
    if (-not $complex)  { Write-Find $CRIT "Password complexity is DISABLED" }
    if ($lockout -eq 0) { Write-Find $WARN "Account lockout threshold is 0 - brute force possible" }
    else                { Write-Find $INFO "Lockout threshold: $lockout attempts" }
}

###############################################################################
# DOMAIN TRUSTS
###############################################################################
Write-Section "DOMAIN TRUSTS"

if ($ADAvailable) {
    $Trusts = @(Get-ADTrust -Filter *)
    if ($Trusts.Count -gt 0) {
        foreach ($trust in $Trusts) {
            $tname  = $trust.Name
            $tdir   = $trust.Direction
            $ttype  = $trust.TrustType
            $ttrans = $trust.IsTransitive
            $sev    = if ($ttype -eq "External") { $WARN } else { $INFO }
            Write-Find $sev "Trust: $tname | Direction: $tdir | Type: $ttype | Transitive: $ttrans"
            if ($ttrans -and $tdir -eq "BiDirectional") {
                Write-Find $WARN "  ^ Bidirectional transitive trust - high risk if other domain is compromised"
            }
        }
    } else { Write-Find $INFO "No domain trusts found" }
}

###############################################################################
# LOCAL USERS AND ADMINS
###############################################################################
Write-Section "LOCAL USERS AND LOCAL ADMINISTRATORS"

$LocalUsers = Get-LocalUser
foreach ($u in $LocalUsers) {
    $uname  = $u.Name
    $uenab  = $u.Enabled
    $upls   = $u.PasswordLastSet
    $upexp  = $u.PasswordExpires
    $sev    = if ($u.Enabled -and $u.Name -in @("Guest", "DefaultAccount")) { $WARN } else { $INFO }
    Write-Find $sev "Local user: $uname | Enabled: $uenab | PwdLastSet: $upls | PwdExpires: $upexp"
}

$LocalAdmins = @(Get-LocalGroupMember -Group "Administrators")
$laCount = $LocalAdmins.Count
Write-Find $INFO "Local Administrators ($laCount):"
foreach ($m in $LocalAdmins) {
    $mname = $m.Name
    $msrc  = $m.PrincipalSource
    $sev   = if ($msrc -eq "Local") { $WARN } else { $INFO }
    Write-Find $sev "  -> $mname [$msrc]"
}

###############################################################################
# SMB SHARES
###############################################################################
Write-Section "SMB SHARES"

$Shares = Get-SmbShare
foreach ($share in $Shares) {
    $sname = $share.Name
    $spath = $share.Path
    $sdesc = $share.Description
    $perms = Get-SmbShareAccess -Name $sname
    $everyoneAccess = $perms | Where-Object { $_.AccountName -match "Everyone|ANONYMOUS" }
    $sev = if ($everyoneAccess) { $CRIT } else { $INFO }
    Write-Find $sev "Share: $sname | Path: $spath | Desc: $sdesc"
    if ($everyoneAccess) {
        Write-Find $CRIT "  ^ EVERYONE or ANONYMOUS has access - review immediately"
    }
}

$SmbCfg = Get-SmbServerConfiguration
if (-not $SmbCfg.RequireSecuritySignature) {
    Write-Find $WARN "SMB signing not REQUIRED - relay attacks possible"
} else { Write-Find $OK "SMB signing required" }
if ($SmbCfg.EnableSMB1Protocol) {
    Write-Find $CRIT "SMBv1 is ENABLED - disable immediately (EternalBlue)"
} else { Write-Find $OK "SMBv1 disabled" }

###############################################################################
# SCHEDULED TASKS
###############################################################################
Write-Section "SCHEDULED TASKS - NON-MICROSOFT"

$Tasks = @(Get-ScheduledTask | Where-Object {
    $_.TaskPath -notmatch "\\Microsoft\\" -and $_.State -ne "Disabled"
})
$tCount = $Tasks.Count
if ($tCount -eq 0) {
    Write-Find $OK "No non-Microsoft scheduled tasks found"
} else {
    Write-Find $WARN "Non-Microsoft scheduled tasks ($tCount) - review each:"
    foreach ($t in $Tasks) {
        $tname   = $t.TaskName
        $tpath   = $t.TaskPath
        $taction = ($t.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
        Write-Find $WARN "  -> $tname | Path: $tpath | Action: $taction"
    }
}

###############################################################################
# RUNNING SERVICES
###############################################################################
Write-Section "RUNNING SERVICES - NON-STANDARD ACCOUNTS"

$Services = @(Get-WmiObject Win32_Service |
    Where-Object { $_.State -eq "Running" -and
        $_.StartName -notmatch "LocalSystem|NT AUTHORITY|NT SERVICE" })
if ($Services.Count -gt 0) {
    Write-Find $WARN "Services running as non-standard accounts - verify each:"
    foreach ($svc in $Services) {
        $sname = $svc.Name
        $sacct = $svc.StartName
        $spath = $svc.PathName
        Write-Find $WARN "  -> $sname | Account: $sacct | Path: $spath"
    }
} else { Write-Find $OK "No services running as unexpected accounts" }

$UnquotedSvcs = @(Get-WmiObject Win32_Service |
    Where-Object {
        $_.PathName -notmatch '"' -and
        $_.PathName -match ' ' -and
        $_.PathName -notmatch 'svchost'
    })
if ($UnquotedSvcs.Count -gt 0) {
    Write-Find $CRIT "Unquoted service paths found (privilege escalation risk):"
    foreach ($svc in $UnquotedSvcs) {
        $sname = $svc.Name
        $spath = $svc.PathName
        Write-Find $CRIT "  -> $sname: $spath"
    }
} else { Write-Find $OK "No unquoted service paths found" }

###############################################################################
# INSTALLED SOFTWARE
###############################################################################
Write-Section "INSTALLED SOFTWARE"

$Software = @(
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" `
        -ErrorAction SilentlyContinue
    Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `
        -ErrorAction SilentlyContinue
) | Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher |
    Sort-Object DisplayName

$swCount = $Software.Count
Write-Find $INFO "Total installed software: $swCount"

$Suspicious = @("ncat","netcat","nmap","metasploit","mimikatz","wireshark",
    "putty","winscp","winpcap","npcap","python","ruby","perl","git","7-zip")
foreach ($item in $Software) {
    $iname = $item.DisplayName.ToLower()
    $iver  = $item.DisplayVersion
    $flagged = $Suspicious | Where-Object { $iname -match $_ }
    if ($flagged) {
        $dname = $item.DisplayName
        Write-Find $WARN "Suspicious software: $dname v$iver"
    }
}
Write-Find $INFO "Full software list:"
foreach ($item in $Software) {
    $dname = $item.DisplayName
    $dver  = $item.DisplayVersion
    $dpub  = $item.Publisher
    Write-Find $INFO "  $dname | $dver | $dpub"
}

###############################################################################
# WINDOWS FIREWALL
###############################################################################
Write-Section "WINDOWS FIREWALL"

$Profiles = Get-NetFirewallProfile
foreach ($p in $Profiles) {
    $pname = $p.Name
    $penab = $p.Enabled
    $pinb  = $p.DefaultInboundAction
    $pout  = $p.DefaultOutboundAction
    $sev   = if (-not $p.Enabled) { $CRIT } else { $OK }
    Write-Find $sev "Profile $pname: Enabled=$penab | Inbound=$pinb | Outbound=$pout"
}

$OpenRules = @(Get-NetFirewallRule |
    Where-Object { $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and $_.Enabled -eq "True" } |
    Where-Object {
        $filter = $_ | Get-NetFirewallAddressFilter
        $filter.RemoteAddress -eq "Any"
    })
$orCount = $OpenRules.Count
Write-Find $INFO "Inbound Allow-Any rules: $orCount"
$OpenRules | Select-Object -First 20 | ForEach-Object {
    $rname = $_.DisplayName
    $rprof = $_.Profile
    Write-Find $WARN "  -> $rname | Profile: $rprof"
}
if ($orCount -gt 20) {
    $more = $orCount - 20
    Write-Find $WARN "  ... and $more more - run Get-NetFirewallRule manually"
}

###############################################################################
# CREDENTIAL HARDENING GAPS
###############################################################################
Write-Section "CREDENTIAL HARDENING GAPS"

$WDigest = Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name UseLogonCredential -ErrorAction SilentlyContinue
if ($WDigest.UseLogonCredential -eq 1) {
    Write-Find $CRIT "WDigest UseLogonCredential=1 - plaintext creds in LSASS. Set to 0 immediately."
} else { Write-Find $OK "WDigest UseLogonCredential disabled" }

$LSAPPL = Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name RunAsPPL -ErrorAction SilentlyContinue
if ($LSAPPL.RunAsPPL -ne 1) {
    Write-Find $WARN "LSASS RunAsPPL not enabled - mimikatz-style dumps possible. Enable PPL."
} else { Write-Find $OK "LSASS RunAsPPL enabled" }

$CredGuard = Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue
if ($CredGuard.EnableVirtualizationBasedSecurity -ne 1) {
    Write-Find $WARN "Credential Guard / VBS not enabled - consider enabling if hardware supports it"
} else { Write-Find $OK "VBS/Credential Guard enabled" }

$NTLMProp = Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name LmCompatibilityLevel -ErrorAction SilentlyContinue
$NTLMLevel = $NTLMProp.LmCompatibilityLevel
if ($null -eq $NTLMLevel -or $NTLMLevel -lt 3) {
    Write-Find $WARN "LmCompatibilityLevel=$NTLMLevel - NTLMv1 may be allowed. Recommend level 5."
} else { Write-Find $OK "LmCompatibilityLevel=$NTLMLevel (NTLMv2)" }

$CachedProp = Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -Name CachedLogonsCount -ErrorAction SilentlyContinue
$CachedLogons = $CachedProp.CachedLogonsCount
Write-Find $INFO "CachedLogonsCount: $CachedLogons (recommend 0-2 on servers)"

###############################################################################
# AUDIT POLICY
###############################################################################
Write-Section "AUDIT POLICY GAPS"

$AuditOut = auditpol /get /category:* 2>$null
if ($AuditOut) {
    $NoAudit = @($AuditOut | Where-Object { $_ -match "No Auditing" })
    $naCount = $NoAudit.Count
    if ($naCount -gt 0) {
        Write-Find $WARN "Categories with No Auditing ($naCount):"
        $NoAudit | ForEach-Object { Write-Find $WARN "  -> $_" }
    } else { Write-Find $OK "All audit categories have some policy configured" }

    $CritCats = @("Logon", "Account Logon", "Privilege Use", "Process Creation", "Account Management")
    foreach ($cat in $CritCats) {
        $line = $AuditOut | Where-Object { $_ -match $cat }
        if ($line -match "No Auditing") {
            Write-Find $CRIT "Critical category '$cat' has No Auditing - must enable"
        } else {
            $lineStr = $line -join " "
            Write-Find $INFO "Audit '$cat': $lineStr"
        }
    }
} else {
    Write-Find $WARN "Could not retrieve audit policy - run auditpol /get /category:* manually"
}

$LogNames = @("Security", "System", "Application")
foreach ($logName in $LogNames) {
    $evtLog = Get-EventLog -List | Where-Object { $_.Log -eq $logName }
    if ($evtLog) {
        $mb  = [math]::Round($evtLog.MaximumKilobytes / 1024, 0)
        $cnt = $evtLog.Entries.Count
        $sev = if ($mb -lt 64) { $WARN } else { $INFO }
        Write-Find $sev "EventLog '$logName': MaxSize=${mb}MB | Entries=$cnt"
    }
}

$PSLogProp = Get-ItemProperty `
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
if ($PSLogProp.EnableScriptBlockLogging -ne 1) {
    Write-Find $WARN "PowerShell ScriptBlock logging not enabled"
} else { Write-Find $OK "PowerShell ScriptBlock logging enabled" }

$PSTxProp = Get-ItemProperty `
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name EnableTranscripting -ErrorAction SilentlyContinue
if ($PSTxProp.EnableTranscripting -ne 1) {
    Write-Find $WARN "PowerShell Transcription not enabled"
} else { Write-Find $OK "PowerShell Transcription enabled" }

###############################################################################
# RDP AND WINRM
###############################################################################
Write-Section "RDP AND WINRM CONFIGURATION"

$RDPProp = Get-ItemProperty `
    "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    -Name fDenyTSConnections
$RDPEnabled = $RDPProp.fDenyTSConnections
if ($RDPEnabled -eq 0) {
    Write-Find $INFO "RDP is ENABLED"
} else {
    Write-Find $INFO "RDP is disabled"
}

$NLAProp = Get-ItemProperty `
    "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name UserAuthenticationRequired -ErrorAction SilentlyContinue
$NLA = $NLAProp.UserAuthenticationRequired
if ($NLA -ne 1) {
    Write-Find $WARN "RDP NLA NOT required - pre-auth attacks possible"
} else { Write-Find $OK "RDP NLA required" }

$RDPPortProp = Get-ItemProperty `
    "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name PortNumber
$RDPPort = $RDPPortProp.PortNumber
$portNote = if ($RDPPort -ne 3389) { " (non-default)" } else { "" }
Write-Find $INFO "RDP Port: $RDPPort$portNote"

$WinRM = Get-Service WinRM -ErrorAction SilentlyContinue
$wmStatus = $WinRM.Status
Write-Find $INFO "WinRM service: $wmStatus"
$WinRMListeners = Get-WSManInstance -ResourceURI winrm/config/listener `
    -Enumerate -ErrorAction SilentlyContinue
if ($WinRMListeners) {
    foreach ($l in $WinRMListeners) {
        $ltrans = $l.Transport
        $laddr  = $l.Address
        $lport  = $l.Port
        $sev    = if ($ltrans -eq "HTTP") { $WARN } else { $INFO }
        Write-Find $sev "WinRM Listener: $ltrans on ${laddr}:$lport"
        if ($ltrans -eq "HTTP") {
            Write-Find $WARN "  ^ WinRM on HTTP - credentials sent unencrypted"
        }
    }
}

###############################################################################
# DEFENDER / AV
###############################################################################
Write-Section "DEFENDER AND ANTIVIRUS STATUS"

$Defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($Defender) {
    $rtpEnabled = $Defender.RealTimeProtectionEnabled
    $avEnabled  = $Defender.AntivirusEnabled
    $sigDate    = $Defender.AntivirusSignatureLastUpdated
    $sigAge     = ((Get-Date) - $sigDate).Days
    $bmEnabled  = $Defender.BehaviorMonitorEnabled
    $ioavEnab   = $Defender.IoavProtectionEnabled
    $nisEnab    = $Defender.NisEnabled

    $sev = if (-not $rtpEnabled) { $CRIT } else { $OK }
    Write-Find $sev "Real-Time Protection: $rtpEnabled"
    $sev = if (-not $avEnabled) { $CRIT } else { $OK }
    Write-Find $sev "Antivirus Enabled: $avEnabled"
    $sev = if ($sigAge -gt 7) { $WARN } else { $OK }
    Write-Find $sev "Signature Age: $sigAge days (last: $sigDate)"
    Write-Find $INFO "Behavior Monitor: $bmEnabled"
    Write-Find $INFO "IOAV Protection : $ioavEnab"
    Write-Find $INFO "Network Inspect : $nisEnab"

    $Exclusions = @(Get-MpPreference | Select-Object -ExpandProperty ExclusionPath)
    if ($Exclusions.Count -gt 0) {
        Write-Find $WARN "Defender path exclusions found - verify legitimacy:"
        foreach ($ex in $Exclusions) { Write-Find $WARN "  -> $ex" }
    } else { Write-Find $OK "No Defender path exclusions" }
} else {
    Write-Find $WARN "Could not retrieve Defender status - may be 3rd party AV"
    $AV = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct `
        -ErrorAction SilentlyContinue)
    if ($AV.Count -gt 0) {
        foreach ($av in $AV) {
            $avname  = $av.displayName
            $avstate = $av.productState
            Write-Find $INFO "AV Product: $avname | State: $avstate"
        }
    } else { Write-Find $CRIT "No AV product detected" }
}

###############################################################################
# MANUAL CHECKLIST
###############################################################################
Write-Section "MANUAL CHECKLIST - ITEMS REQUIRING HUMAN REVIEW"

Write-Find $WARN "[ ] VyOS ROUTERS - check default credentials on ALL gateways:"
Write-Find $INFO "    SSH in and run: show configuration | grep -i password"
Write-Find $INFO "    Verify ACLs between subnets are appropriate"

$GWs = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty NextHop | Sort-Object -Unique)
if ($GWs.Count -gt 0) {
    foreach ($gw in $GWs) { Write-Find $WARN "    Gateway detected: $gw" }
} else {
    Write-Find $INFO "    Could not detect gateways - check routing table manually"
}

$Adapters = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch "^127\." })
Write-Find $INFO "    Local interfaces on this machine:"
foreach ($a in $Adapters) {
    $aip  = $a.IPAddress
    $apfx = $a.PrefixLength
    $aif  = $a.InterfaceAlias
    Write-Find $INFO "      ${aip}/$apfx on $aif"
}

Write-Find $WARN "[ ] SCORED SERVICES - check the competition packet for the full list"
Write-Find $WARN "    Do NOT block scored service IPs in the firewall - you will lose points"
Write-Find $WARN "    Common scored services: DNS, MX/mail, web portals, gamecards, docs"
Write-Find $WARN "    Verify what ports they expect OPEN before hardening firewall rules"

if ($ADAvailable) {
    $AllDCs = @(Get-ADDomainController -Filter * -ErrorAction SilentlyContinue)
    $dcCount = $AllDCs.Count
    if ($dcCount -gt 1) {
        Write-Find $WARN "[ ] MULTIPLE DCs DETECTED ($dcCount) - verify each is hardened:"
        foreach ($dc in $AllDCs) {
            $dcname = $dc.Name
            $dcip   = $dc.IPv4Address
            $dcsite = $dc.Site
            $self   = if ($dc.Name -eq $env:COMPUTERNAME) { " (this machine)" } else { "" }
            Write-Find $WARN "    $dcname | $dcip | Site: $dcsite$self"
        }
        Write-Find $WARN "    Check replication health: repadmin /replsummary"
        Write-Find $WARN "    Verify GPO sync: repadmin /showrepl"
    }

    $NonWin = @(Get-ADComputer -Filter * -Properties OperatingSystem |
        Where-Object { $_.OperatingSystem -notmatch "Windows" -and $_.Enabled -eq $true })
    $nwCount = $NonWin.Count
    if ($nwCount -gt 0) {
        Write-Find $WARN "[ ] NON-WINDOWS domain computers ($nwCount) - pass to Linux team:"
        foreach ($c in $NonWin) {
            $cname = $c.Name
            $cos   = $c.OperatingSystem
            Write-Find $INFO "    $cname | OS: $cos"
        }
    } else {
        Write-Find $INFO "[ ] No non-Windows computers found in AD"
    }
}

$domainFQDN = $env:USERDNSDOMAIN
Write-Find $WARN "[ ] Review ALL GPOs manually in GPMC after running this script"
Write-Find $WARN "[ ] Check SYSVOL for cleartext passwords (Group Policy Preferences)"
Write-Find $WARN "    Look for cpassword= in: \\$domainFQDN\SYSVOL\$domainFQDN\Policies"
Write-Find $WARN "[ ] Verify no rogue domain admins were added during competition"
Write-Find $WARN "[ ] Check DNS for rogue records that could hijack scored services"
Write-Find $WARN "[ ] Create shadow copies / snapshots BEFORE running hardening scripts"
Write-Find $WARN "[ ] Review LAPS deployment status if present"
Write-Find $WARN "[ ] After hardening: rerun this script and compare findings"

###############################################################################
# WRITE TXT REPORT
###############################################################################
$compName = $env:COMPUTERNAME
$domName  = $env:USERDNSDOMAIN
$genDate  = Get-Date

$Header = @"
================================================================
  WINDOWS RECON AND VULNERABILITY ADVISORY REPORT
  Generated : $genDate
  Host      : $compName
  Domain    : $domName
================================================================
Severity Key:
  [CRITICAL] = High risk - fix immediately
  [WARN]     = Potential weakness - review and decide
  [INFO]     = Informational - no action required
  [OK]       = Check passed
================================================================
"@

$TxtContent = $Header + "`r`n" + ($TxtLines -join "`r`n")
$TxtContent | Out-File -FilePath $TxtReport -Encoding UTF8
Write-Host ""
Write-Host "TXT Report : $TxtReport" -ForegroundColor Cyan

###############################################################################
# WRITE HTML REPORT
###############################################################################
$HtmlRows = ""
foreach ($line in $TxtLines) {
    $color = "#cccccc"
    $bg    = ""
    if ($line -match "\[CRITICAL\]") { $color = "#ff4444"; $bg = "background:#1a0000;" }
    elseif ($line -match "\[WARN\]")     { $color = "#ffaa00"; $bg = "background:#1a0e00;" }
    elseif ($line -match "\[INFO\]")     { $color = "#4a9eff" }
    elseif ($line -match "\[OK\]")       { $color = "#44cc44" }

    $escaped = [System.Net.WebUtility]::HtmlEncode($line)
    if ($line -match "^=") {
        $HtmlRows += "<tr><td style='color:#ffffff;background:#1e3a5f;font-weight:bold;"
        $HtmlRows += "padding:8px 12px;font-size:13px;'>$escaped</td></tr>`n"
    } else {
        $HtmlRows += "<tr><td style='color:$color;${bg}padding:3px 12px;"
        $HtmlRows += "font-family:monospace;font-size:12px;'>$escaped</td></tr>`n"
    }
}

$Html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<title>Recon Report - $compName</title>
<style>
  body{background:#0d1117;color:#c9d1d9;font-family:monospace;margin:20px;}
  h1{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:10px;}
  h2{color:#79c0ff;margin-top:5px;font-size:13px;}
  table{width:100%;border-collapse:collapse;}
  tr:hover td{background:#161b22 !important;}
  .legend{display:flex;gap:20px;margin:10px 0 20px 0;font-size:12px;}
  .leg{padding:3px 8px;border-radius:3px;}
</style>
</head>
<body>
<h1>Windows Recon and Vulnerability Advisory</h1>
<h2>Host: $compName | Domain: $domName | $genDate</h2>
<div class='legend'>
  <span class='leg' style='color:#ff4444;background:#1a0000;'>[CRITICAL] Fix immediately</span>
  <span class='leg' style='color:#ffaa00;background:#1a0e00;'>[WARN] Review and decide</span>
  <span class='leg' style='color:#4a9eff;background:#001a2e;'>[INFO] Informational</span>
  <span class='leg' style='color:#44cc44;background:#001a00;'>[OK] Check passed</span>
</div>
<table>
$HtmlRows
</table>
</body>
</html>
"@

$Html | Out-File -FilePath $HtmlReport -Encoding UTF8
Write-Host "HTML Report: $HtmlReport" -ForegroundColor Cyan
Write-Host ""
Write-Host "Done. Open the HTML report in a browser for color-coded findings." -ForegroundColor Green