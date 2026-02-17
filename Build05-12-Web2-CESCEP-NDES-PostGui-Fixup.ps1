#Ran on web2
Import-Module WebAdministration
$ErrorActionPreference = "Stop"

$siteName = "Default Web Site"
$ndesPhysicalPath = "C:\Windows\system32\CertSrv\mscep"
$appPoolName = "SCEP"
$cesBasePath = "C:\Windows\SystemData\CES"
$cepBasePath = "C:\Windows\SystemData\CEP"

$hostname = $env:COMPUTERNAME.ToLower()
$isWeb1 = $hostname -match 'web1'
$domain = "lab.local"
$fqdn = "$hostname.$domain"

# Explicitly set the SCEP host for the final summary display
if ($isWeb1) { $scepHost = 'scep1' } else { $scepHost = 'scep2' }
$scepFqdn = "$scepHost.$domain"

Write-Host "=== Master Post-GUI Configuration for $hostname ===" -ForegroundColor Cyan

# ====
# STEP 1: Fix /certsrv Hierarchy
# ====
Write-Host "`n--- Step 1: Fixing /certsrv Hierarchy ---" -ForegroundColor Yellow
$flatApps = @("/CertSrv/mscep", "/CertSrv/mscep_admin")
foreach ($appPath in $flatApps) {
    if (Get-WebApplication -Site $siteName -Name $appPath.TrimStart('/')) {
        Write-Host "Removing flat application: $appPath" -ForegroundColor Gray
        Remove-WebApplication -Site $siteName -Name $appPath.TrimStart('/')
    }
}

if (-not (Test-Path "IIS:\Sites\$siteName\certsrv")) {
    Write-Host "Creating parent /certsrv application..." -ForegroundColor Green
    New-WebApplication -Site $siteName -Name "certsrv" -PhysicalPath $ndesPhysicalPath -ApplicationPool $appPoolName
} else {
    Write-Host "Parent /certsrv already exists" -ForegroundColor Gray
}

foreach ($sub in @("mscep", "mscep_admin")) {
    if (-not (Test-Path "IIS:\Sites\$siteName\certsrv\$sub")) {
        Write-Host "Creating child /certsrv/$sub application..." -ForegroundColor Green
        New-Item "IIS:\Sites\$siteName\certsrv\$sub" -Type Application -PhysicalPath $ndesPhysicalPath
        Set-ItemProperty "IIS:\Sites\$siteName\certsrv\$sub" -Name applicationPool -Value $appPoolName
    } else {
        Write-Host "Child /certsrv/$sub already exists" -ForegroundColor Gray
    }
}

# Auth for mscep_admin
Write-Host "Configuring Windows Authentication for mscep_admin..." -ForegroundColor Cyan
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location "$siteName/certsrv/mscep_admin" `
    -Filter "system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value False
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location "$siteName/certsrv/mscep_admin" `
    -Filter "system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value True
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location "$siteName/certsrv/mscep_admin" `
    -Filter "system.webServer/security/authentication/windowsAuthentication" -Name useKernelMode -Value False

Write-Host "[OK] /certsrv hierarchy fixed" -ForegroundColor Green

# ====
# STEP 2: NDES Registry Templates
# ====
Write-Host "`n--- Step 2: Setting NDES Registry Templates ---" -ForegroundColor Yellow
$regPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP"
Set-ItemProperty -Path $regPath -Name "EncryptionTemplate" -Value "IEX-NDES-RA"
Set-ItemProperty -Path $regPath -Name "SignatureTemplate" -Value "IEX-NDES-RA"
Set-ItemProperty -Path $regPath -Name "GeneralPurposeTemplate" -Value "IEX-NDES-Device"
Write-Host "[OK] Registry templates set" -ForegroundColor Green

# ====
# STEP 3: Clone CES and Fix URIs (The "Endpoint Fault" Fix)
# ====
Write-Host "`n--- Step 3: Cloning CES & Fixing URIs ---" -ForegroundColor Yellow

if ($isWeb1) {
    $sourceApp = "Lab Issuing CA 1_CES_Kerberos"
    $targetApp = "Lab Issuing CA 2_CES_Kerberos"
    $targetCA = "subca2.$domain\Lab Issuing CA 2"
} else {
    $sourceApp = "Lab Issuing CA 2_CES_Kerberos"
    $targetApp = "Lab Issuing CA 1_CES_Kerberos"
    $targetCA = "subca1.$domain\Lab Issuing CA 1"
}

$sourcePath = Join-Path $cesBasePath $sourceApp
$targetPath = Join-Path $cesBasePath $targetApp

if (-not (Test-Path $sourcePath)) {
    Write-Host "[WARN] Source CES not found: $sourcePath" -ForegroundColor Yellow
    Write-Host "[WARN] Skipping CES clone" -ForegroundColor Yellow
} else {
    if (Test-Path $targetPath) {
        Write-Host "Removing existing target: $targetPath" -ForegroundColor Gray
        Remove-Item $targetPath -Recurse -Force
    }
    
    Write-Host "Copying $sourceApp -> $targetApp" -ForegroundColor Cyan
    Copy-Item -Path $sourcePath -Destination $targetPath -Recurse
    
    # Update web.config CAConfig
    $webConfig = Join-Path $targetPath "web.config"
    $xml = [xml](Get-Content $webConfig)
    $caConfigNode = $xml.configuration.appSettings.add | Where-Object { $_.key -eq "CAConfig" }
    if ($caConfigNode) {
        $caConfigNode.value = $targetCA
        Write-Host "  Updated CAConfig to: $targetCA" -ForegroundColor Gray
    }
    $xml.Save($webConfig)
    
    # Create IIS app
    if (Get-WebApplication -Site $siteName -Name $targetApp) {
        Remove-WebApplication -Site $siteName -Name $targetApp
    }
    New-WebApplication -Site $siteName -Name $targetApp -PhysicalPath $targetPath -ApplicationPool "WSEnrollmentServer" | Out-Null
    
    # Fix auth
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location "$siteName/$targetApp" `
        -Filter "system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value False
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location "$siteName/$targetApp" `
        -Filter "system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value True
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location "$siteName/$targetApp" `
        -Filter "system.webServer/security/authentication/windowsAuthentication" -Name useKernelMode -Value False
    
    Write-Host "[OK] CES cloned: $targetApp" -ForegroundColor Green
}

# Fix URIs for ALL CES instances to use local FQDN
Write-Host "Fixing URIs for all CES instances..." -ForegroundColor Cyan
$allApps = @("Lab Issuing CA 1_CES_Kerberos", "Lab Issuing CA 2_CES_Kerberos")
foreach ($app in $allApps) {
    $path = Join-Path $cesBasePath $app
    if (Test-Path $path) {
        $cfg = Join-Path $path "web.config"
        $xml = [xml](Get-Content $cfg)
        
        # Update URI
        $uriNode = $xml.configuration.appSettings.add | Where-Object { $_.key -eq "URI" }
        if ($uriNode) {
            $encodedApp = $app -replace ' ', '%20'
            $newUri = "https://$fqdn/$encodedApp/service.svc/CES"
            $uriNode.value = $newUri
            Write-Host "  Fixed URI in $app -> $newUri" -ForegroundColor Gray
        }
        
        $xml.Save($cfg)
    }
}

# Fix CEP URI
Write-Host "Fixing URI for CEP..." -ForegroundColor Cyan
$cepCfg = Join-Path $cepBasePath "ADPolicyProvider_CEP_Kerberos\web.config"
if (Test-Path $cepCfg) {
    $xml = [xml](Get-Content $cepCfg)
    $uriNode = $xml.configuration.appSettings.add | Where-Object { $_.key -eq "URI" }
    if ($uriNode) {
        $cepUri = "https://$fqdn/ADPolicyProvider_CEP_Kerberos/service.svc/CEP"
        $uriNode.value = $cepUri
        Write-Host "  Fixed CEP URI -> $cepUri" -ForegroundColor Gray
    }
    $xml.Save($cepCfg)
}

Write-Host "[OK] All URIs fixed to use $fqdn" -ForegroundColor Green

# ====
# STEP 4: Enable Multiple Site Bindings
# ====
Write-Host "`n--- Step 4: Enabling Multiple Site Bindings ---" -ForegroundColor Yellow
$configs = Get-ChildItem -Path "C:\Windows\SystemData" -Filter "web.config" -Recurse
foreach ($f in $configs) {
    $xml = [xml](Get-Content $f.FullName)
    $sm = $xml.configuration."system.serviceModel"
    if ($sm) {
        $she = $sm.serviceHostingEnvironment
        if (-not $she) {
            $node = $xml.CreateElement("serviceHostingEnvironment")
            $node.SetAttribute("multipleSiteBindingsEnabled", "true")
            $sm.PrependChild($node) | Out-Null
            $xml.Save($f.FullName)
            Write-Host "  Enabled multipleSiteBindings in $($f.FullName)" -ForegroundColor Gray
        } elseif ($she.multipleSiteBindingsEnabled -ne "true") {
            $she.multipleSiteBindingsEnabled = "true"
            $xml.Save($f.FullName)
            Write-Host "  Updated multipleSiteBindings in $($f.FullName)" -ForegroundColor Gray
        }
    }
}
Write-Host "[OK] Multiple site bindings enabled" -ForegroundColor Green

# ====
# STEP 5: Automate IIS Bindings (SNI)
# ====
Write-Host "`n--- Step 5: Automating IIS Bindings ---" -ForegroundColor Yellow

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
    ($_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1") -and 
    ($_.Subject -like "*$hostname*" -or $_.DnsNameList.Unicode -contains $fqdn) -and
    ($_.DnsNameList.Unicode -contains "enroll.$domain")
} | Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $cert) {
    Write-Host "[WARN] No suitable Server Authentication certificate found for $hostname with enroll.$domain SAN" -ForegroundColor Yellow
} else {
    Write-Host "Using certificate: $($cert.Subject)" -ForegroundColor Green
    
    $bindingNames = @("enroll.$domain", $fqdn, $scepFqdn)
    $appId = "{4dc3e181-e14b-4a21-b022-59fc669b0914}"
    
    foreach ($name in $bindingNames) {
        Write-Host "Configuring binding for $name..." -ForegroundColor Cyan
        $existingBinding = Get-WebBinding -Name $siteName -Protocol https -HostHeader $name
        if ($existingBinding) {
            Remove-WebBinding -Name $siteName -Protocol https -HostHeader $name -Confirm:$false
        }
        netsh http delete sslcert hostnameport="${name}:443" 2>$null | Out-Null
        New-WebBinding -Name $siteName -Protocol https -HostHeader $name -Port 443 -SslFlags 1
        netsh http add sslcert hostnameport="${name}:443" certhash=$($cert.Thumbprint) appid=$appId certstorename=MY | Out-Null
        Write-Host "  [OK] Configured SSL binding for: $name" -ForegroundColor Green
    }
    Write-Host "[OK] IIS bindings configured" -ForegroundColor Green
}

# ====
# STEP 6: Set App Pool Identities
# ====
Write-Host "`n--- Step 6: Setting App Pool Identities ---" -ForegroundColor Yellow
$enrollCred = Get-Credential -UserName "LAB\PKIEnrollSvc" -Message "Enter PKIEnrollSvc Creds"
$ndesCred = Get-Credential -UserName "LAB\PKINDESSvc" -Message "Enter PKINDESSvc Creds"

$pools = @("WSEnrollmentPolicyServer", "WSEnrollmentServer")
foreach ($p in $pools) {
    if (Test-Path "IIS:\AppPools\$p") {
        Set-ItemProperty "IIS:\AppPools\$p" -Name processModel.identityType -Value 3
        Set-ItemProperty "IIS:\AppPools\$p" -Name processModel.userName -Value $enrollCred.UserName
        Set-ItemProperty "IIS:\AppPools\$p" -Name processModel.password -Value $enrollCred.GetNetworkCredential().Password
        Write-Host "  [OK] Configured $p App Pool" -ForegroundColor Green
    }
}

if (Test-Path "IIS:\AppPools\$appPoolName") {
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name processModel.identityType -Value 3
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name processModel.userName -Value $ndesCred.UserName
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name processModel.password -Value $ndesCred.GetNetworkCredential().Password
    Write-Host "  [OK] Configured $appPoolName App Pool" -ForegroundColor Green
}

# ====
# STEP 7: Configure NDES Admin Groups
# ====
Write-Host "`n--- Step 7: Configuring NDES Admin Groups ---" -ForegroundColor Yellow
$groupName = "NDES-Admins"
$regPathNDES = "HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\Admin"

try {
    $searcher = [ADSISearcher]"(&(objectClass=group)(name=$groupName))"
    $result = $searcher.FindOne()
    if ($result) {
        $group = $result.GetDirectoryEntry()
        $sid = (New-Object System.Security.Principal.SecurityIdentifier($group.objectSid[0], 0)).Value
        if (-not (Test-Path $regPathNDES)) { New-Item $regPathNDES -Force | Out-Null }
        Set-ItemProperty -Path $regPathNDES -Name "MSCEPAdminGroup" -Value $sid
        Write-Host "  [OK] NDES Admin Group configured in registry" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Group '$groupName' not found in AD" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [ERROR] Failed to query AD: $($_.Exception.Message)" -ForegroundColor Red
}

# ====
# STEP 8: Disable Loopback Check
# ====
Write-Host "`n--- Step 8: Disabling Loopback Check ---" -ForegroundColor Yellow
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name "DisableLoopbackCheck" -Value 1 -Type DWord
Write-Host "[OK] Loopback check disabled" -ForegroundColor Green

# ====
# STEP 9: Final Reset
# ====
Write-Host "`n--- Step 9: Restarting IIS ---" -ForegroundColor Magenta
iisreset

Write-Host "`n=== Master Configuration Complete ===" -ForegroundColor Green
Write-Host "`nTest URLs:" -ForegroundColor Cyan
Write-Host "  NDES Admin:   https://$scepFqdn/certsrv/mscep_admin/" -ForegroundColor White
Write-Host "  NDES Service: https://$scepFqdn/certsrv/mscep/mscep.dll" -ForegroundColor White
Write-Host "  CEP:          https://enroll.$domain/ADPolicyProvider_CEP_Kerberos/service.svc" -ForegroundColor White
Write-Host "  CES CA1:      https://enroll.$domain/Lab%20Issuing%20CA%201_CES_Kerberos/service.svc" -ForegroundColor White
Write-Host "  CES CA2:      https://enroll.$domain/Lab%20Issuing%20CA%202_CES_Kerberos/service.svc" -ForegroundColor White
Write-Host "`n=== Configuration Complete ===" -ForegroundColor Green