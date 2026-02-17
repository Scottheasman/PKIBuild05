<#
.SYNOPSIS
    PKI Lab - WEB2 Certificate Enrollment for Enroll/SCEP2 SSL

.DESCRIPTION
    Automates certificate request, issuance, installation, and validation for WEB2.
    
    SANs included:
    - enroll.lab.local (DNS round-robin)
    - scep2.lab.local  (WEB2 only)
    - web2.lab.local   (WEB2 only)

.EXAMPLE
    .\cert2.ps1 -TargetCA CA1
    .\cert2.ps1 -TargetCA CA1 -RetrieveOnly -RequestId 16 -BindToIIS -Validate
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("CA1","CA2")]
    [string]$TargetCA,
    
    [switch]$RetrieveOnly,
    [int]$RequestId,
    [switch]$BindToIIS,
    [switch]$Validate,
    [switch]$ForceOverwrite
)

# --- Logging: ensure folder and start transcript ---
$LogDir = "C:\Scripts"
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path (Join-Path $LogDir "PKILab-8c-Web2-RequestEnrollScepSsl.log") -Append -ErrorAction SilentlyContinue

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ====
# WEB2 Configuration
# ====
$HostShort  = "WEB2"
$HostFqdn   = "web2.lab.local"
$EnrollFqdn = "enroll.lab.local"
$ScepFqdn   = "scep2.lab.local"
$Template   = "IEX-MANUALCSR-EnrollWeb-SSL"

$SANs = @(
    "dns=$EnrollFqdn",
    "dns=$ScepFqdn",
    "dns=$HostFqdn"
)

$CAConfig = switch ($TargetCA) {
    "CA1" { "subca1.lab.local\Lab Issuing CA 1" }
    "CA2" { "subca2.lab.local\Lab Issuing CA 2" }
}

$WorkRoot = "C:\PKI\CertReq-$HostShort"
$InfPath  = Join-Path $WorkRoot "$HostShort-EnrollScepSsl.inf"
$ReqPath  = Join-Path $WorkRoot "$HostShort-EnrollScepSsl.req"
$CerPath  = Join-Path $WorkRoot "$HostShort-EnrollScepSsl.cer"
$LastId   = Join-Path $WorkRoot "LastRequestId.txt"

# ====
# Helper Functions
# ====
function Write-Info($m)  { Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-Ok($m)    { Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn($m)  { Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Bad($m)   { Write-Host "[FAIL]  $m" -ForegroundColor Red }
function Write-Step($m)  { Write-Host "`n>>> $m" -ForegroundColor Magenta }

function Ensure-Dir([string]$Path){
    if (-not (Test-Path $Path)) { 
        New-Item -Path $Path -ItemType Directory | Out-Null 
        Write-Info "Created directory: $Path"
    }
}

function Resolve-ARecords([string]$DnsName) {
    try {
        @(Resolve-DnsName -Name $DnsName -Type A -ErrorAction Stop | 
          Where-Object { $_.IPAddress } | 
          Select-Object -ExpandProperty IPAddress | 
          Sort-Object -Unique)
    } catch { @() }
}

function Get-RemoteTlsCertificateInfoByIp {
    param([string]$Ip, [string]$SniHost, [int]$Port = 443)
    $tcp = $null; $ssl = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($Ip, $Port)
        $ssl = New-Object System.Net.Security.SslStream(
            $tcp.GetStream(), $false, 
            ({ param($s,$c,$ch,$e) return $true })
        )
        $ssl.AuthenticateAsClient($SniHost)
        
        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        
        $dnsNames = @()
        try {
            $sanExt = $cert2.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" } | Select-Object -First 1
            if ($sanExt) {
                $asn = New-Object System.Security.Cryptography.AsnEncodedData($sanExt.Oid, $sanExt.RawData)
                $dnsNames = @(([regex]::Matches($asn.Format($false), 'DNS Name=([^\s,]+)') | 
                    ForEach-Object { $_.Groups[1].Value.Trim() }))
            }
        } catch { }
        
        return [pscustomobject]@{ 
            Ip = $Ip
            SniHost = $SniHost
            Thumbprint = $cert2.Thumbprint
            Subject = $cert2.Subject
            DnsNames = $dnsNames 
        }
    } finally { 
        if($ssl){$ssl.Dispose()}
        if($tcp){$tcp.Dispose()} 
    }
}

function Write-InfFile {
    $sanJoined = ($SANs -join "&")
    $infTemplate = @'
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=__SUBJECT__"
MachineKeySet = TRUE
KeyLength = 4096
KeySpec = 1
Exportable = FALSE
HashAlgorithm = sha256
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
KeyUsage = 0xa0

[RequestAttributes]
CertificateTemplate = __TEMPLATE__

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "__SAN__"
'@
    $inf = $infTemplate.Replace("__SUBJECT__", $HostFqdn).
                    Replace("__TEMPLATE__", $Template).
                    Replace("__SAN__", $sanJoined)
    
    $inf | Out-File -FilePath $infPath -Encoding ascii -Force
    Write-Ok "INF file written: $infPath"
}

function Invoke-CertreqNew {
    Write-Info "Generating CSR..."
    & certreq.exe -new $infPath $ReqPath | Out-Host
    if (-not (Test-Path $ReqPath)) { throw "CSR generation failed" }
    Write-Ok "CSR created: $ReqPath"
}

function Invoke-CertreqSubmit {
    Write-Info "Submitting CSR to CA: $CAConfig"
    $out = & certreq.exe -submit -config $CAConfig $ReqPath $CerPath 2>&1
    $out | Out-Host
    
    $idLine = $out | Where-Object { $_ -match '^RequestId:' } | Select-Object -Last 1
    if (-not $idLine) { throw "Could not parse RequestId from certreq output" }
    
    $id = [int](($idLine -replace '^RequestId:\s*','' -replace '"','').Trim())
    Set-Content -Path $LastId -Value $id -Encoding ascii
    
    Write-Ok "Certificate issued successfully"
    Write-Ok "RequestId: $id (saved to $LastId)"
    
    return $id
}

function Invoke-CertreqRetrieveAccept([int]$Id){
    Write-Info "Retrieving certificate for RequestId: $Id"
    & certreq.exe -retrieve -config $CAConfig $Id $CerPath | Out-Host
    if (-not (Test-Path $CerPath)) { throw "Certificate retrieval failed" }
    
    Write-Info "Installing certificate into LocalMachine\My store..."
    & certreq.exe -accept $CerPath | Out-Host
    
    $cerObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CerPath)
    $thumb = $cerObj.Thumbprint
    
    $installed = Get-ChildItem Cert:\LocalMachine\My | 
                 Where-Object { $_.Thumbprint -eq $thumb } | 
                 Select-Object -First 1
    
    if (-not $installed) { 
        throw "Certificate not found in LocalMachine\My after installation" 
    }
    
    Write-Ok "Certificate installed successfully"
    Write-Ok "Subject: $($installed.Subject)"
    Write-Ok "Thumbprint: $thumb"
    Write-Ok "Valid: $($installed.NotBefore) to $($installed.NotAfter)"
    
    return $thumb
}

function Ensure-IISBindingAndBindHttpSys([string]$Thumbprint){
    Import-Module WebAdministration
    
    Write-Info "Configuring IIS HTTPS binding on Default Web Site (port 443)..."
    $b = Get-WebBinding -Name "Default Web Site" -Protocol https -ErrorAction SilentlyContinue | 
         Where-Object { $_.BindingInformation -like "*:443:*" } |
         Select-Object -First 1
    
    if (-not $b) { 
        New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -IPAddress "*" | Out-Null
        Write-Ok "IIS HTTPS binding created on port 443"
    } else {
        Write-Ok "IIS HTTPS binding already exists on port 443"
    }
    
    Write-Info "Binding certificate to HTTP.SYS (0.0.0.0:443)..."
    $appid = "{a9b7b5b0-1c62-4b38-9b1c-8b4a9c2b7a11}"
    
    & netsh http delete sslcert ipport=0.0.0.0:443 2>$null | Out-Null
    & netsh http add sslcert ipport=0.0.0.0:443 certhash=$Thumbprint appid=$appid certstorename=MY | Out-Host
    
    Write-Ok "HTTP.SYS SSL certificate binding updated"
}

function Validate-Tls {
    Write-Step "TLS Validation (Local Node Only)"
    
    $allPassed = $true
    
    foreach ($name in @($ScepFqdn, $HostFqdn)) {
        $ips = @(Resolve-ARecords $name)
        
        if ($ips.Count -eq 0) {
            Write-Warn "No A records found for $name"
            continue
        }
        
        Write-Info "Validating $name (resolves to: $($ips -join ', '))"
        
        foreach ($ip in $ips) {
            try {
                $info = Get-RemoteTlsCertificateInfoByIp -Ip $ip -SniHost $name
                
                if ($info.DnsNames -contains $name) {
                    Write-Ok "$name via $ip -> Thumbprint: $($info.Thumbprint) | SAN: ✓"
                } else {
                    Write-Bad "$name via $ip -> Thumbprint: $($info.Thumbprint) | SAN: ✗ (missing $name)"
                    $allPassed = $false
                }
            } catch {
                Write-Bad "Failed to connect to $name via $ip - $_"
                $allPassed = $false
            }
        }
    }
    
    Write-Host ""
    if ($allPassed) {
        Write-Ok "All TLS validations passed ✓"
    } else {
        Write-Warn "Some TLS validations failed"
    }
    
    Write-Step "HTTP.SYS SSL Certificate Binding"
    & netsh http show sslcert ipport=0.0.0.0:443 | Out-Host
}

# ====
# Main Execution
# ====

Write-Host "`n====" -ForegroundColor Cyan
Write-Host "  PKI Lab - $HostShort Certificate Enrollment" -ForegroundColor Cyan
Write-Host "====" -ForegroundColor Cyan
Write-Host "Host:       $HostFqdn" -ForegroundColor Gray
Write-Host "CA:         $CAConfig" -ForegroundColor Gray
Write-Host "Template:   $Template" -ForegroundColor Gray
Write-Host "SANs:       $($SANs -join ', ')" -ForegroundColor Gray
Write-Host "====`n" -ForegroundColor Cyan

Ensure-Dir $WorkRoot

# ====
# Phase 1: Request & Submit
# ====
if (-not $RetrieveOnly) {
    Write-Step "Phase 1: Generate CSR and Submit to CA"
    
    Write-InfFile
    Invoke-CertreqNew
    $id = Invoke-CertreqSubmit
    
    Write-Host "`n====" -ForegroundColor Yellow
    Write-Host "  NEXT STEP: Retrieve, Install, Bind & Validate" -ForegroundColor Yellow
    Write-Host "====" -ForegroundColor Yellow
    Write-Host "Run the following command:`n" -ForegroundColor White
    Write-Host "  .\cert2.ps1 -TargetCA $TargetCA -RetrieveOnly -RequestId $id -BindToIIS -Validate`n" -ForegroundColor Green
    Write-Host "====`n" -ForegroundColor Yellow
    
    # --- Stop logging/transcript before exit ---
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 0
}

# ====
# Phase 2: Retrieve, Install, Bind & Validate
# ====
if ($RetrieveOnly) {
    if (-not $RequestId -and (Test-Path $LastId)) { 
        $RequestId = [int](Get-Content $LastId) 
        Write-Info "Using RequestId from last run: $RequestId"
    }
    
    if (-not $RequestId) { 
        # --- Stop logging/transcript before throw ---
        Stop-Transcript -ErrorAction SilentlyContinue
        throw "RetrieveOnly mode requires -RequestId parameter or $LastId file" 
    }
    
    Write-Step "Phase 2: Retrieve & Install Certificate"
    $thumb = Invoke-CertreqRetrieveAccept -Id $RequestId
    
    if ($BindToIIS) {
        Write-Step "Phase 3: Bind Certificate to IIS & HTTP.SYS"
        Ensure-IISBindingAndBindHttpSys -Thumbprint $thumb
    }
    
    if ($Validate) {
        Write-Step "Phase 4: Validate TLS Configuration"
        Validate-Tls
    }
    
    Write-Host "`n====" -ForegroundColor Green
    Write-Host "  Certificate Enrollment Complete ✓" -ForegroundColor Green
    Write-Host "====`n" -ForegroundColor Green
}

# --- Stop logging/transcript ---
Stop-Transcript -ErrorAction SilentlyContinue