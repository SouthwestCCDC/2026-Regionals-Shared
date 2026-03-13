# =============================================================
# CCDC - generate-cert-from-dc.ps1
# Run on the Windows Domain Controller as Administrator
#
# Creates a certificate signed by the DC's CA (if AD CS is
# installed) OR generates a self-signed cert usable for
# Graylog TLS.
#
# Outputs:
#   graylog-server.crt  - certificate (PEM)
#   graylog-server.key  - private key (PEM)
#   ca.crt              - CA/root cert to distribute to clients
#
# Usage:
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\generate-cert-from-dc.ps1 -GraylogIP "10.0.0.X" [-GraylogFQDN "graylog.corp.local"]
# =============================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$GraylogIP,
    
    [string]$GraylogFQDN = "graylog.corp.local",
    
    [string]$OutputDir = "C:\ccdc-certs",
    
    [int]$ValidDays = 365
)

$ErrorActionPreference = "Stop"
function Write-Info { Write-Host "[+] $args" -ForegroundColor Green }
function Write-Warn { Write-Host "[!] $args" -ForegroundColor Yellow }

# ---- Create output directory ----
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Write-Info "Output directory: $OutputDir"

# ---- Check if AD CS (Certificate Services) is available ----
$ADCSAvailable = $false
try {
    Import-Module ADCSAdministration -ErrorAction Stop
    $CA = Get-CertificationAuthority -ErrorAction Stop | Select-Object -First 1
    if ($CA) { $ADCSAvailable = $true }
} catch { }

if ($ADCSAvailable) {
    # ====================================================
    # PATH A: Domain CA exists - request a proper cert
    # ====================================================
    Write-Info "Active Directory Certificate Services found. Requesting signed certificate..."
    
    $CAName = $CA.DisplayName
    Write-Info "Using CA: $CAName"
    
    # Build SAN extension
    $SANs = "dns=$GraylogFQDN&ipaddress=$GraylogIP"
    
    # Create INF for certreq
    $InfContent = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$GraylogFQDN, O=CCDC, C=US"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = CMC
KeyUsage = 0xa0
HashAlgorithm = sha256

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1 ; Server Authentication

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$GraylogFQDN&"
_continue_ = "ipaddress=$GraylogIP&"
"@
    
    $InfPath = "$OutputDir\graylog-request.inf"
    $ReqPath = "$OutputDir\graylog-request.csr"
    $CrtPath = "$OutputDir\graylog-server.crt"
    $PfxPath = "$OutputDir\graylog-server.pfx"
    $KeyPath = "$OutputDir\graylog-server.key"
    
    $InfContent | Out-File -FilePath $InfPath -Encoding ASCII
    
    # Create CSR
    Write-Info "Creating certificate request..."
    & certreq -new $InfPath $ReqPath
    
    # Submit to CA
    Write-Info "Submitting to CA $CAName..."
    $SubmitResult = & certreq -submit -config "$env:COMPUTERNAME\$CAName" $ReqPath $CrtPath 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Info "Certificate issued."
        
        # Accept/install
        & certreq -accept $CrtPath
        
        # Export PFX
        $PfxPass = ConvertTo-SecureString -String "ccdc_temp_export" -Force -AsPlainText
        $Cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$GraylogFQDN*" } | Select-Object -First 1
        Export-PfxCertificate -Cert $Cert -FilePath $PfxPath -Password $PfxPass | Out-Null
        
        # Convert PFX -> PEM using openssl (if available) or certutil
        if (Get-Command openssl -ErrorAction SilentlyContinue) {
            Write-Info "Converting PFX to PEM with openssl..."
            & openssl pkcs12 -in $PfxPath -nocerts -nodes -passin pass:ccdc_temp_export -out $KeyPath
            & openssl pkcs12 -in $PfxPath -nokeys -passin pass:ccdc_temp_export -out $CrtPath
        } else {
            Write-Warn "openssl not found. PFX is at $PfxPath"
            Write-Warn "On your Graylog Linux box, run:"
            Write-Warn "  openssl pkcs12 -in graylog-server.pfx -nocerts -nodes -out graylog-server.key"
            Write-Warn "  openssl pkcs12 -in graylog-server.pfx -nokeys -out graylog-server.crt"
        }
        
        # Export CA cert
        Write-Info "Exporting CA certificate..."
        $CACertPath = "$OutputDir\ca.crt"
        & certutil -ca.cert $CACertPath | Out-Null
        
    } else {
        Write-Warn "CA submission failed or pending approval. Check CA for pending requests."
        Write-Warn "Falling back to self-signed certificate..."
        $ADCSAvailable = $false
    }
}

if (-not $ADCSAvailable) {
    # ====================================================
    # PATH B: No domain CA - generate self-signed cert
    # ====================================================
    Write-Info "Generating self-signed certificate (no Domain CA found)..."
    
    $CertParams = @{
        Subject            = "CN=$GraylogFQDN"
        DnsName            = @($GraylogFQDN, "graylog", "localhost")
        IPAddress          = @($GraylogIP, "127.0.0.1")
        KeyAlgorithm       = "RSA"
        KeyLength          = 2048
        HashAlgorithm      = "SHA256"
        CertStoreLocation  = "Cert:\LocalMachine\My"
        NotAfter           = (Get-Date).AddDays($ValidDays)
        KeyUsage           = @("DigitalSignature", "KeyEncipherment")
        TextExtension      = @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
    }
    
    $SelfSignedCert = New-SelfSignedCertificate @CertParams
    Write-Info "Self-signed cert created: $($SelfSignedCert.Thumbprint)"
    
    # Export to PFX
    $PfxPath = "$OutputDir\graylog-server.pfx"
    $PfxPass = ConvertTo-SecureString -String "ccdc_temp_export" -Force -AsPlainText
    Export-PfxCertificate -Cert $SelfSignedCert -FilePath $PfxPath -Password $PfxPass | Out-Null
    
    # Export just the public cert as ca.crt (for clients to trust)
    $CACertPath = "$OutputDir\ca.crt"
    Export-Certificate -Cert $SelfSignedCert -FilePath "$OutputDir\ca.der" -Type CERT | Out-Null
    & certutil -encode "$OutputDir\ca.der" $CACertPath | Out-Null
    
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        Write-Info "Exporting PEM key and cert with openssl..."
        & openssl pkcs12 -in $PfxPath -nocerts -nodes -passin pass:ccdc_temp_export -out "$OutputDir\graylog-server.key" 2>$null
        & openssl pkcs12 -in $PfxPath -nokeys -clcerts -passin pass:ccdc_temp_export -out "$OutputDir\graylog-server.crt" 2>$null
        Write-Info "PEM files created."
    } else {
        Write-Warn "openssl not in PATH - only PFX available."
        Write-Warn "On your Graylog Linux box:"
        Write-Warn "  Copy graylog-server.pfx and run:"
        Write-Warn "  openssl pkcs12 -in graylog-server.pfx -nocerts -nodes -passin pass:ccdc_temp_export -out graylog-server.key"
        Write-Warn "  openssl pkcs12 -in graylog-server.pfx -nokeys -passin pass:ccdc_temp_export -out graylog-server.crt"
    }
}

Write-Info "=============================="
Write-Info "Certificate files in: $OutputDir"
Get-ChildItem $OutputDir | Format-Table Name, Length
Write-Info ""
Write-Info "NEXT STEPS:"
Write-Info "1. Copy graylog-server.crt and graylog-server.key to your Graylog server"
Write-Info "   (put them somewhere like /etc/graylog/certs/)"
Write-Info "2. Copy ca.crt to each client machine that needs to trust Graylog"
Write-Info "   On Linux: cp ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates"
Write-Info "   On Windows: Import-Certificate -FilePath ca.crt -CertStoreLocation Cert:\LocalMachine\Root"
Write-Info "3. Update winlogbeat.yml to enable ssl.certificate_authorities"
