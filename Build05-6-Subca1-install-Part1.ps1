## 6 - Install SubCA1 (Lab Issuing CA 1)

### RUN THIS ENTIRE SCRIPT ON SUBCA1 SERVER (elevated PowerShell)

# --- Logging: ensure folder and start transcript ---
$LogDir = "C:\Scripts"
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path (Join-Path $LogDir "PKILAb-6-Subca1-install-Part1.log") -Append -ErrorAction SilentlyContinue

### 1 - Common PKI Settings
$PkiHttpHost = "pki.lab.local"
$PkiHttpBase = "http://$PkiHttpHost/pkidata"
$DfsPkiPath = "\\lab.local\share\PKIData"
$CertEnrollDir = "C:\Windows\System32\CertSrv\CertEnroll"
$LocalPkiFolder = "C:\PKIData"

# This CA's name
$SubCAName = "Lab Issuing CA 1"

Write-Host "Creating local PKI folder..." -ForegroundColor Cyan
New-Item -Path $LocalPkiFolder -ItemType Directory -Force | Out-Null

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
RenewalValidityPeriodUnits=5
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@

Set-Content -Path C:\Windows\CAPolicy.inf -Value $CaPolicyContent -Force
Write-Host "CAPolicy.inf created successfully." -ForegroundColor Green

### 3 - Install AD CS Role & Generate Request
Write-Host "Installing ADCS-Cert-Authority feature..." -ForegroundColor Cyan
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

Write-Host "Configuring Enterprise Subordinate CA and generating request..." -ForegroundColor Cyan
$vCaIssProperties = @{
    CACommonName = $SubCAName
    CADistinguishedNameSuffix = 'O=Lab,L=Fort Lauderdale,S=Florida,C=US'
    CAType = 'EnterpriseSubordinateCA'
    CryptoProviderName = 'RSA#Microsoft Software Key Storage Provider'
    HashAlgorithmName = 'SHA256'
    KeyLength = 4096
    OutputCertRequestFile = "$LocalPkiFolder\subca1_request.req"
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force
Write-Host "SubCA1 role installed and request generated." -ForegroundColor Green

### 4 - Manual Steps for Offline Root CA Processing
Write-Host ""
Write-Host "====" -ForegroundColor Red
Write-Host "*** MANUAL STEPS REQUIRED ***" -ForegroundColor Red
Write-Host "SubCA1 certificate request has been generated. The following manual steps are CRITICAL:" -ForegroundColor Yellow
Write-Host "====" -ForegroundColor Red
Write-Host ""
Write-Host "1. MANUALLY COPY REQUEST FILE FROM SUBCA1:" -ForegroundColor Cyan
Write-Host "   Source: $LocalPkiFolder\subca1_request.req" -ForegroundColor Gray
Write-Host "   Action: Copy this file to a removable media (e.g., USB drive)." -ForegroundColor Gray
Write-Host ""
Write-Host "2. PROCESS REQUEST ON OFFLINE ROOT CA:" -ForegroundColor Cyan
Write-Host "   Action: Take the media to the Offline Root CA server." -ForegroundColor Gray
Write-Host "   Destination: $CertEnrollDir\" -ForegroundColor Yellow
Write-Host "   Action: Paste the subca1_request.req file into the folder above." -ForegroundColor Gray
Write-Host ""
Write-Host "   Commands to run on Root CA (Elevated PowerShell):" -ForegroundColor Gray
Write-Host "   cd $CertEnrollDir" -ForegroundColor White
Write-Host "   certreq -submit subca1_request.req subca1_issued.cer" -ForegroundColor White
Write-Host ""
Write-Host "   # Note: Select 'Lab Root CA' if prompted. If the request goes to 'Pending':" -ForegroundColor Gray
Write-Host "   certutil -resubmit <RequestID>" -ForegroundColor White
Write-Host "   certreq -retrieve <RequestID> subca1_issued.cer" -ForegroundColor White
Write-Host ""
Write-Host "3. MANUALLY COPY ISSUED CERTIFICATE BACK TO SUBCA1:" -ForegroundColor Cyan
Write-Host "   Source on Root CA: $CertEnrollDir\subca1_issued.cer" -ForegroundColor Gray
Write-Host "   Destination on SubCA1: $LocalPkiFolder\subca1_issued.cer" -ForegroundColor Yellow
Write-Host ""
Write-Host "4. COMPLETE SUBCA1 CONFIGURATION:" -ForegroundColor Cyan
Write-Host "   Action: Once the file is back on SubCA1, run the 'ApplyIssuedCert' script." -ForegroundColor Yellow
Write-Host ""
Write-Host "====" -ForegroundColor Red
Write-Host "DO NOT PROCEED UNTIL subca1_issued.cer IS IN $LocalPkiFolder" -ForegroundColor Red
Write-Host "====" -ForegroundColor Red
Write-Host ""

# Open folder for easy access to request file
explorer.exe $LocalPkiFolder

# --- Stop logging/transcript ---
Stop-Transcript -ErrorAction SilentlyContinue