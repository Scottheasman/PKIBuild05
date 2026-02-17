<#
### 4 - Install the Offline Root CA

### RUN THIS ENTIRE SCRIPT ON THE OFFLINE ROOT CA SERVER (elevated PowerShell)
### This script configures the CA and generates the cert/CRL.
### Manual steps are required afterward to move files and publish to AD.
#>

# --- Logging: ensure folder and start transcript ---
$LogDir = "C:\Scripts"
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path (Join-Path $LogDir "PKILab-5-RootCA-install.log") -Append -ErrorAction SilentlyContinue

### 1 - Common Variables
$DomainFqdn      = "lab.local"
$PkiHttpHost     = "pki.lab.local"
$RootCAName      = "Lab Root CA"

# Derived
$PkiHttpBase     = "http://$PkiHttpHost/pkidata"
$CertEnrollDir   = "C:\Windows\System32\CertSrv\CertEnroll"

### 2 - Create CAPolicy.inf
Write-Host "Creating CAPolicy.inf..." -ForegroundColor Cyan
$CaPolicyContent = @"
[Version]
Signature="`$Windows NT`$"

[PolicyStatementExtension]
Policies=InternalPolicy

[InternalPolicy]
OID=1.2.3.4.1455.67.89.5
Notice="Legal Policy Statement"
URL=$PkiHttpBase/cps.html

[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=20
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@
Set-Content -Path C:\Windows\CAPolicy.inf -Value $CaPolicyContent -Force
Write-Host "CAPolicy.inf created successfully." -ForegroundColor Green

### 3 - Install AD CS Role and Configure Root CA
Write-Host "Installing ADCS-Cert-Authority feature..." -ForegroundColor Cyan
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

Write-Host "Configuring Standalone Root CA..." -ForegroundColor Cyan
$vCaRootProperties = @{
    CACommonName                = $RootCAName
    CADistinguishedNameSuffix   = "O=Lab,L=Lauderdale,S=Florida,C=US"
    CAType                    = 'StandaloneRootCA'
    CryptoProviderName          = 'RSA#Microsoft Software Key Storage Provider'
    HashAlgorithmName           = 'SHA256'
    KeyLength                   = 4096
    ValidityPeriod              = 'Years'
    ValidityPeriodUnits         = 20
}
Install-AdcsCertificationAuthority @vCaRootProperties -Force
Write-Host "Root CA installed and configured." -ForegroundColor Green

### 4 - Configure Validity and CRL Settings
Write-Host "Setting CA validity, CRL periods, and audit filter..." -ForegroundColor Cyan
certutil -setreg CA\ValidityPeriodUnits 10
certutil -setreg CA\ValidityPeriod "Years"
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod "Years"
certutil -setreg CA\CRLDeltaPeriodUnits 0
certutil -setreg CA\CRLOverlapPeriodUnits 7
certutil -setreg CA\CRLOverlapPeriod "Days"
certutil -setreg CA\AuditFilter 127
Restart-Service certsvc
Write-Host "CA settings configured and service restarted." -ForegroundColor Green

### 5 - Configure CDP and AIA locations
Write-Host "Configuring CDP and AIA locations..." -ForegroundColor Cyan
Import-Module ADCSAdministration

# ---- CDP (CRL Distribution Points) ----
Write-Host "  Setting CDP locations..." -ForegroundColor Gray
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }
Add-CACrlDistributionPoint -Uri "$CertEnrollDir\%3%8.crl" -PublishToServer -PublishDeltaToServer -Force
Add-CACrlDistributionPoint -Uri "$PkiHttpBase/%3%8.crl" -AddToCertificateCdp -AddToFreshestCrl -Force

# ---- AIA (Authority Information Access) ----
Write-Host "  Setting AIA locations..." -ForegroundColor Gray
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' -or $_.Uri -like '\\*' } | Remove-CAAuthorityInformationAccess -Force
certutil -setreg CA\CACertPublicationURLs "1:$CertEnrollDir\%3%4.crt"
Add-CAAuthorityInformationAccess -Uri "$PkiHttpBase/%3%4.crt" -AddToCertificateAia -Force

Restart-Service certsvc
Write-Host "CDP and AIA configured, service restarted." -ForegroundColor Green

### 6 - Finalize and Prepare for Manual Steps
Write-Host "Publishing initial CRL and renaming certificate file..." -ForegroundColor Cyan
certutil -CRL
Start-Sleep -Seconds 2
Rename-Item "$CertEnrollDir\caroot1_$RootCAName.crt" "$CertEnrollDir\$RootCAName.crt" -Force
Write-Host "Initial CRL published and certificate renamed." -ForegroundColor Green

Write-Host ""
Write-Host "====" -ForegroundColor Red
Write-Host "*** MANUAL STEPS REQUIRED ***" -ForegroundColor Red
Write-Host "The Root CA is now configured. The following manual steps are CRITICAL:" -ForegroundColor Yellow
Write-Host "====" -ForegroundColor Red
Write-Host ""
Write-Host "1. MANUALLY COPY FILES FROM ROOT CA:" -ForegroundColor Cyan
Write-Host "   Location: C:\Windows\System32\CertSrv\CertEnroll\" -ForegroundColor Gray
Write-Host "   Files to Copy:" -ForegroundColor Gray
Write-Host "     - $RootCAName.crt" -ForegroundColor Gray
Write-Host "     - $RootCAName.crl" -ForegroundColor Gray
Write-Host "   Action: Copy these files to a removable media (e.g., USB drive)." -ForegroundColor Gray
Write-Host ""
Write-Host "2. TRANSFER FILES TO A DOMAIN-JOINED MACHINE:" -ForegroundColor Cyan
Write-Host "   Action: Take the media to a domain-joined machine (DC, SubCA, or WEB server)." -ForegroundColor Yellow
Write-Host "   Destination: \\$DomainFqdn\share\PKIData\" -ForegroundColor Yellow
Write-Host "   Action: Paste the .crt and .crl files into the above DFS share folder." -ForegroundColor Gray
Write-Host ""
Write-Host "3. VERIFY HTTP ACCESS (ON DOMAIN-JOINED MACHINE):" -ForegroundColor Cyan
Write-Host "   Action: Run the following commands on the domain-joined machine to verify:" -ForegroundColor Yellow
Write-Host ""
Write-Host "   `$PkiHttpBase = `"http://$PkiHttpHost/pkidata`"" -ForegroundColor Gray
Write-Host "   `$RootCAName = `"$RootCAName`"" -ForegroundColor Gray
Write-Host "   Invoke-WebRequest -Uri `"`$PkiHttpBase/`$RootCAName.crt`" -UseBasicParsing" -ForegroundColor Gray
Write-Host "   Invoke-WebRequest -Uri `"`$PkiHttpBase/`$RootCAName.crl`" -UseBasicParsing" -ForegroundColor Gray
Write-Host "   Expected Result: Both commands should return StatusCode 200." -ForegroundColor Gray
Write-Host ""
Write-Host "4. PUBLISH TO ACTIVE DIRECTORY (ON DOMAIN-JOINED MACHINE):" -ForegroundColor Cyan
Write-Host "   Action: Run the following commands on the domain-joined machine:" -ForegroundColor Yellow
Write-Host ""
Write-Host "   `$DfsPath = `"\\$DomainFqdn\share\PKIData`"" -ForegroundColor Gray
Write-Host "   `$RootCAName = `"$RootCAName`"" -ForegroundColor Gray
Write-Host "   certutil -dspublish -f `"`$DfsPath\`$RootCAName.crt`" RootCA" -ForegroundColor Gray
Write-Host "   certutil -addstore -f root `"`$DfsPath\`$RootCAName.crt`"" -ForegroundColor Gray
Write-Host "   Action: Optionally, run 'gpupdate /force' on other domain members." -ForegroundColor Gray
Write-Host ""
Write-Host "====" -ForegroundColor Red
Write-Host "DO NOT PROCEED WITH SUBCA INSTALLATION UNTIL THESE STEPS ARE COMPLETE!" -ForegroundColor Red
Write-Host "====" -ForegroundColor Red
Write-Host ""

# Open folder for easy access to files needing manual copy
explorer.exe $CertEnrollDir

# --- Stop logging/transcript ---
Stop-Transcript -ErrorAction SilentlyContinue