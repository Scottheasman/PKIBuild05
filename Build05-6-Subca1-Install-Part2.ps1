## 6 - Install SubCA1 (Lab Issuing CA 1) - PART 2

### RUN THIS ENTIRE SCRIPT ON SUBCA1 SERVER (elevated PowerShell)
### This script completes the SubCA1 configuration after the certificate has been issued by the Root CA.

# --- Logging: ensure folder and start transcript ---
$LogDir = "C:\Scripts"
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path (Join-Path $LogDir "PKILab-6a-Subca1-Install-Part2.log") -Append -ErrorAction SilentlyContinue

### 1 - Common PKI Settings
$PkiHttpHost = "pki.lab.local"
$PkiHttpBase = "http://$PkiHttpHost/pkidata"
$OcspHttpBase = "http://ocsp.lab.local/ocsp"
$DfsPkiPath = "\\lab.local\share\PKIData"
$CertEnrollDir = "C:\Windows\System32\CertSrv\CertEnroll"
$LocalPkiFolder = "C:\PKIData"

# This CA's name
$SubCAName = "Lab Issuing CA 1"

### 2 - Install Issued Cert and Start CA
Write-Host "Installing the issued SubCA certificate..." -ForegroundColor Cyan
certutil -installcert $LocalPkiFolder\subca1_issued.cer
Write-Host "Issued certificate installed." -ForegroundColor Green

Write-Host "Starting CA service..." -ForegroundColor Cyan
Start-Service certsvc
Write-Host "CA service started." -ForegroundColor Green

Write-Host "Performing basic health check..." -ForegroundColor Cyan
Get-Service certsvc
certutil -ping
Write-Host "Basic health check complete." -ForegroundColor Green

### 3 - Configure Validity, CDP, and AIA
Write-Host "Configuring Validity, CDP, and AIA settings..." -ForegroundColor Cyan
Import-Module ADCSAdministration

# ---- Validity & CRL settings ----
Write-Host "   Setting validity and CRL periods..." -ForegroundColor Gray
certutil -setreg CA\ValidityPeriodUnits 1
certutil -setreg CA\ValidityPeriod "Years"
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod "Weeks"
certutil -setreg CA\CRLDeltaPeriodUnits 1
certutil -setreg CA\CRLDeltaPeriod "Days"
certutil -setreg CA\CRLOverlapPeriodUnits 3
certutil -setreg CA\CRLOverlapPeriod "Days"
certutil -setreg CA\AuditFilter 127

# ---- CDP (CRL Distribution Points) ----
Write-Host "   Setting CDP locations..." -ForegroundColor Gray
$crlList = Get-CACrlDistributionPoint
foreach ($crl in $crlList) { Remove-CACrlDistributionPoint $crl.Uri -Force }

Add-CACrlDistributionPoint `
    -Uri "$CertEnrollDir\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

Add-CACrlDistributionPoint `
    -Uri "$DfsPkiPath\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

Add-CACrlDistributionPoint `
    -Uri "$PkiHttpBase/%3%8%9.crl" `
    -AddToCertificateCdp `
    -AddToFreshestCrl `
    -Force

# ---- AIA (Authority Information Access) ----
Write-Host "   Setting AIA locations..." -ForegroundColor Gray
Get-CAAuthorityInformationAccess |
    Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' -or $_.Uri -like '\\*' } |
    Remove-CAAuthorityInformationAccess -Force

# <-- CHANGED: use flag 1 for both publish targets so they are published but NOT included in issued certs
certutil -setreg CA\CACertPublicationURLs "1:$CertEnrollDir\%3%4.crt`n1:$DfsPkiPath\%3%4.crt"

Add-CAAuthorityInformationAccess `
    -Uri "$PkiHttpBase/%3%4.crt" `
    -AddToCertificateAia `
    -Force

Add-CAAuthorityInformationAccess `
    -Uri "$OcspHttpBase" `
    -AddToCertificateOcsp `
    -Force

Restart-Service certsvc
Start-Sleep -Seconds 2
Write-Host "Validity, CDP, and AIA settings configured and service restarted." -ForegroundColor Green

### 4 - Publish Cert to AD and Copy to DFS
Write-Host "Publishing initial CRL..." -ForegroundColor Cyan
certutil -CRL
Write-Host "Initial CRL published." -ForegroundColor Green

Write-Host "Renaming SubCA certificate to a clean name..." -ForegroundColor Cyan
$cer = Get-ChildItem $CertEnrollDir -Filter "*.crt" | Select-Object -First 1
if ($cer -and $cer.Name -ne "$SubCAName.crt") {
    Rename-Item $cer.FullName "$CertEnrollDir\$SubCAName.crt" -Force
}
Write-Host "SubCA certificate renamed." -ForegroundColor Green

Write-Host "Publishing SubCA certificate to Active Directory (NTAuth and SubCA containers)..." -ForegroundColor Cyan
certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" NTAuthCA
certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" SubCA
Write-Host "SubCA certificate published to AD." -ForegroundColor Green

Write-Host "Copying SubCA certificate to DFS for HTTP AIA..." -ForegroundColor Cyan
Copy-Item "$CertEnrollDir\$SubCAName.crt" "$DfsPkiPath\$SubCAName.crt" -Force
Write-Host "SubCA certificate copied to DFS." -ForegroundColor Green

### 5 - Validation Checks (Run on SubCA1)
Write-Host "`n==== PKI Configuration Validation ====" -ForegroundColor Cyan

$expectedCDP_HTTP = $PkiHttpBase
$expectedAIA_HTTP = $PkiHttpBase
$expectedOCSP = $OcspHttpBase

$CaName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration').Active
Write-Host "`nCA Name: $CaName" -ForegroundColor Yellow

Write-Host "`n--- CRL Distribution Points ---" -ForegroundColor Yellow
$crlOutput = certutil -getreg CA\CRLPublicationURLs
$crlOutput | Where-Object { $_ -match '^\s+\d+:\s+\d+:' } | ForEach-Object {
  if ($_ -match '^\s+\d+:\s+(\d+):(.+)$' ) { 
    $flags = [int]$matches[1]
    $url = $matches[2].Trim()
    $addToCertCDP = ($flags -band 0x02) -ne 0
    
    if ($url -match [regex]::Escape($expectedCDP_HTTP) -and $addToCertCDP) {
        Write-Host "CDP OK ✅ $url" -ForegroundColor Green
    } elseif ($url -match 'ldap://|file://' -and $addToCertCDP) {
        Write-Host "Legacy CDP embedded ❌ $url" -ForegroundColor Red
    }
}
}

Write-Host "`n--- Authority Information Access ---" -ForegroundColor Yellow
$aiaOutput = certutil -getreg CA\CACertPublicationURLs
$aiaOutput | Where-Object { $_ -match '^\s+\d+:\s+\d+:' } | ForEach-Object {
if ($_ -match '^\s+\d+:\s+(\d+):(.+)$' ) {
    $flags = [int]$matches[1]
    $url = $matches[2].Trim()
    $addToAIA = ($flags -band 0x02) -ne 0
    $addToOCSP = ($flags -band 0x20) -ne 0
    
    if ($url -match [regex]::Escape($expectedAIA_HTTP) -and $addToAIA) {
        Write-Host "AIA OK ✅ $url" -ForegroundColor Green
    } elseif ($url -match [regex]::Escape($expectedOCSP) -and $addToOCSP) {
        Write-Host "OCSP OK ✅ $url" -ForegroundColor Green
    } elseif ($url -match 'ocsp' -and $url -notmatch [regex]::Escape($expectedOCSP)) {
        Write-Host "OCSP Wrong Domain ⚠️ $url (should be $expectedOCSP)" -ForegroundColor Yellow
    } elseif ($url -match 'ldap://|file://' -and ($addToAIA -or $addToOCSP)) {
        Write-Host "Legacy AIA/OCSP embedded ❌ $url" -ForegroundColor Red
    }
}
}

Write-Host "`n==== Validation Complete ====" -ForegroundColor Cyan

Write-Host "`n`n" -ForegroundColor Cyan
Write-Host "====" -ForegroundColor Green
Write-Host "SubCA1 (Lab Issuing CA 1) configuration is complete!" -ForegroundColor Green
Write-Host "====" -ForegroundColor Green

# --- Stop logging/transcript ---
Stop-Transcript -ErrorAction SilentlyContinue