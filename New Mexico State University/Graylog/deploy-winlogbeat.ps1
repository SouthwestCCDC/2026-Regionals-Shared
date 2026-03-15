# =============================================================
# CCDC - deploy-winlogbeat.ps1
# Run on Windows machines as Administrator to install
# Winlogbeat and start shipping logs to Graylog.
#
# Usage (from elevated PowerShell):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\deploy-winlogbeat.ps1 -GraylogIP "10.0.0.X"
# =============================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$GraylogIP,
    
    [string]$GraylogPort = "5044",
    
    [string]$WinlogbeatVersion = "7.17.18",
    
    [string]$InstallDir = "C:\Program Files\Winlogbeat"
)

$ErrorActionPreference = "Stop"

function Write-Info  { Write-Host "[+] $args" -ForegroundColor Green }
function Write-Warn  { Write-Host "[!] $args" -ForegroundColor Yellow }
function Write-Err   { Write-Host "[ERROR] $args" -ForegroundColor Red; exit 1 }

# ---- Check admin ----
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "Run as Administrator!"
}

Write-Info "Deploying Winlogbeat $WinlogbeatVersion -> Graylog at $GraylogIP:$GraylogPort"

# ---- Download Winlogbeat ----
$DownloadUrl = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-$WinlogbeatVersion-windows-x86_64.zip"
$ZipPath = "$env:TEMP\winlogbeat.zip"

if (-not (Test-Path $InstallDir)) {
    Write-Info "Downloading Winlogbeat..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
    } catch {
        Write-Warn "Download failed. If no internet, manually place winlogbeat-$WinlogbeatVersion-windows-x86_64 folder at $InstallDir"
        Write-Warn "Then re-run this script."
        exit 1
    }
    
    Write-Info "Extracting..."
    Expand-Archive -Path $ZipPath -DestinationPath $env:TEMP -Force
    $ExtractedDir = Get-Item "$env:TEMP\winlogbeat-$WinlogbeatVersion-windows-x86_64"
    Move-Item $ExtractedDir.FullName $InstallDir -Force
    Remove-Item $ZipPath -Force
    Write-Info "Extracted to $InstallDir"
} else {
    Write-Warn "Install dir already exists, skipping download."
}

# ---- Write winlogbeat.yml ----
Write-Info "Writing winlogbeat.yml..."
$Config = @"
winlogbeat.event_logs:
  - name: Security
    ignore_older: 1h
    event_id: 4624,4625,4634,4647,4648,4672,4688,4697,4698,4699,4700,4701,4702,4720,4722,4724,4728,4732,4738,4756,4768,4769,4771,4776,4778,4779

  - name: System
    ignore_older: 1h

  - name: Application
    ignore_older: 1h

  - name: Microsoft-Windows-PowerShell/Operational
    ignore_older: 1h

  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 1h

  - name: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
    ignore_older: 1h

  - name: Microsoft-Windows-TaskScheduler/Operational
    ignore_older: 1h

output.logstash:
  hosts: ["${GraylogIP}:${GraylogPort}"]

fields:
  ccdc_source: winlogbeat
  hostname: $env:COMPUTERNAME
fields_under_root: true

queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 5s
"@

$Config | Out-File -FilePath "$InstallDir\winlogbeat.yml" -Encoding UTF8

# ---- Install and start service ----
Write-Info "Installing Winlogbeat service..."
Set-Location $InstallDir

# Remove old service if exists
if (Get-Service -Name winlogbeat -ErrorAction SilentlyContinue) {
    Write-Warn "Stopping existing winlogbeat service..."
    Stop-Service -Name winlogbeat -ErrorAction SilentlyContinue
    & "$InstallDir\uninstall-service-winlogbeat.ps1" | Out-Null
    Start-Sleep 2
}

& "$InstallDir\install-service-winlogbeat.ps1"
Start-Sleep 1
Start-Service -Name winlogbeat

$Status = (Get-Service -Name winlogbeat).Status
if ($Status -eq "Running") {
    Write-Info "Winlogbeat service is running!"
} else {
    Write-Warn "Service status: $Status - check logs at $InstallDir\winlogbeat"
}

# ---- Test connectivity ----
Write-Info "Testing TCP connection to ${GraylogIP}:${GraylogPort}..."
try {
    $TCPClient = New-Object System.Net.Sockets.TcpClient
    $TCPClient.Connect($GraylogIP, [int]$GraylogPort)
    $TCPClient.Close()
    Write-Info "Connection OK!"
} catch {
    Write-Warn "Could not connect to ${GraylogIP}:${GraylogPort} - check firewall rules."
}

Write-Info "Done! This machine is now shipping Windows Event Logs to Graylog."
Write-Info "Check Graylog UI -> Search to verify logs are arriving."
