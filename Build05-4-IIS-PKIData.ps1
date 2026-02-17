<#
.SYNOPSIS
    Configure IIS PKIData publishing site on a web server (WEB1/WEB2).

.DESCRIPTION
    - Installs IIS role services needed for static content hosting
    - Creates App Pool using ApplicationPoolIdentity (no domain svc account)
    - Creates site bound to host header pki.lab.local:80
    - Creates /pkidata application pointing to a UNC path (\\file1\PKIData)
    - Sets Anonymous Auth to use App Pool identity (clears IUSR creds)
    - Enables AllowDoubleEscaping for delta CRLs with '+' in filename
    - Adds MIME types for PKI artifacts

.PARAMETER PKIDataUncPath
    UNC path to PKIData share (e.g. \\file1\PKIData)

.PARAMETER HostHeader
    Host header to bind for the site (default: pki.lab.local)

.PARAMETER SiteName
    IIS site name (default: PKIDataSite)

.PARAMETER AppPoolName
    IIS application pool name (default: PKIHttpPool)

.PARAMETER LocalSiteRoot
    Local folder for the site root (default: C:\InetPub\PKIDataSiteRoot)

.PARAMETER EnableDirectoryBrowsing
    Enable directory browsing under /pkidata (default: $true for lab)

.PARAMETER Force
    Remove/recreate existing site/app pool if present

Run
.\PKILab-4-iis-PKIData.ps1 -PKIDataUncPath "\\lab.local\share\pkidata" -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^\\\\')]
    [string]$PKIDataUncPath,
    
    [string]$HostHeader = "pki.lab.local",
    [string]$SiteName = "PKIDataSite",
    [string]$AppPoolName = "PKIHttpPool",
    [string]$LocalSiteRoot = "C:\InetPub\PKIDataSiteRoot",
    [bool]$EnableDirectoryBrowsing = $true,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Logging: ensure folder and start transcript (in addition to existing logs) ---
$LogDir = "C:\Scripts"
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path (Join-Path $LogDir "PKILab-4-iis-PKIData.log") -Append -ErrorAction SilentlyContinue

function Write-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "[ OK ] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }

# Start transcript (original script starts a transcript to ProgramData\PKI-Logs as well)
$logDir = "C:\ProgramData\PKI-Logs"
New-Item -Path $logDir -ItemType Directory -Force | Out-Null
$logPath = Join-Path $logDir ("PKIData-IIS-Setup{0}-{1}.log" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd-HHmmss'))
Start-Transcript -Path $logPath | Out-Null

try {
    Write-Info "Installing IIS role services..."
    Import-Module ServerManager
    
    $features = @(
        "Web-Server",
        "Web-WebServer",
        "Web-Common-Http",
        "Web-Static-Content",
        "Web-Default-Doc",
        "Web-Dir-Browsing",
        "Web-Http-Errors",
        "Web-Http-Logging",
        "Web-Filtering",
        "Web-Performance",
        "Web-Stat-Compression",
        "Web-Mgmt-Tools",
        "Web-Mgmt-Console",
        "Web-Scripting-Tools"
    )
    
    Install-WindowsFeature -Name $features -IncludeManagementTools | Out-Null
    Write-Ok "IIS features installed."
    
    # Remove WebDAV if present (it can interfere with some static behaviors)
    if ((Get-WindowsFeature Web-DAV-Publishing).Installed) {
        Write-Info "Removing WebDAV Publishing..."
        Remove-WindowsFeature Web-DAV-Publishing | Out-Null
        Write-Ok "WebDAV removed."
    }
    
    Import-Module WebAdministration
    
    # Optionally tear down existing
    if ($Force) {
        if (Test-Path "IIS:\Sites\$SiteName") {
            Write-Warn "Removing existing site '$SiteName' (Force)..."
            Remove-WebSite -Name $SiteName
            Write-Ok "Removed site '$SiteName'."
        }
        
        if (Test-Path "IIS:\AppPools\$AppPoolName") {
            Write-Warn "Removing existing app pool '$AppPoolName' (Force)..."
            Remove-WebAppPool -Name $AppPoolName
            Write-Ok "Removed app pool '$AppPoolName'."
        }
    }
    
    # Ensure local site root exists
    if (-not (Test-Path $LocalSiteRoot)) {
        Write-Info "Creating local site root: $LocalSiteRoot"
        New-Item -Path $LocalSiteRoot -ItemType Directory -Force | Out-Null
    }
    
    # Create app pool
    if (-not (Test-Path "IIS:\AppPools\$AppPoolName")) {
        Write-Info "Creating app pool '$AppPoolName'..."
        New-WebAppPool -Name $AppPoolName | Out-Null
    }
    Write-Ok "App pool '$AppPoolName' configured."
    
    # Configure app pool: ApplicationPoolIdentity + No Managed Code (best for static content)
    Write-Info "Configuring app pool identity to ApplicationPoolIdentity (no svc account)..."
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.identityType -Value 4 | Out-Null
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name managedRuntimeVersion -Value "" | Out-Null
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name managedPipelineMode -Value 0 | Out-Null  # 0=Integrated
    Restart-WebAppPool -Name $AppPoolName
    Write-Ok "App pool '$AppPoolName' configured."
    
    # Create site bound to HostHeader:80
    if (-not (Test-Path "IIS:\Sites\$SiteName")) {
        Write-Info "Creating site '$SiteName' bound to http://$HostHeader:80 ..."
        New-WebSite -Name $SiteName -Port 80 -HostHeader $HostHeader -PhysicalPath $LocalSiteRoot -ApplicationPool $AppPoolName | Out-Null
        Write-Ok "Site '$SiteName' created."
    } else {
        Write-Info "Site '$SiteName' already exists; ensuring app pool and binding..."
        Set-ItemProperty "IIS:\Sites\$SiteName" -Name applicationPool -Value $AppPoolName | Out-Null
    }
    
    # Ensure binding exists
    $bindingKey = "*:80:$HostHeader"
    $hasBinding = (Get-WebBinding -Name $SiteName -Protocol "http" -ErrorAction SilentlyContinue |
        Where-Object { $_.bindingInformation -eq $bindingKey }) -ne $null
    
    if (-not $hasBinding) {
        New-WebBinding -Name $SiteName -Protocol "http" -Port 80 -HostHeader $HostHeader | Out-Null
        Write-Ok "Added binding http://$HostHeader:80"
    }
    
    # Create /pkidata application mapped to UNC share
    $appPath = "/pkidata"
    $existingApp = Get-WebApplication -Site $SiteName -Name "pkidata" -ErrorAction SilentlyContinue
    
    if (-not $existingApp) {
        Write-Info "Creating application '$SiteName$appPath' -> $PKIDataUncPath"
        New-WebApplication -Site $SiteName -Name "pkidata" -PhysicalPath $PKIDataUncPath -ApplicationPool $AppPoolName | Out-Null
        Write-Ok "Application created."
    } else {
        Write-Info "Application '$SiteName$appPath' exists; enforcing path and app pool..."
        Set-ItemProperty "IIS:\Sites\$SiteName\pkidata" -Name applicationPool -Value $AppPoolName | Out-Null
        Set-ItemProperty "IIS:\Sites\$SiteName\pkidata" -Name physicalPath -Value $PKIDataUncPath | Out-Null
    }
    
    # Ensure the virtual directory uses pass-through (no stored credentials)
    Write-Info "Ensuring pass-through credentials for UNC (Connect As: Application user)..."
    Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$SiteName/pkidata" `
        -Filter "system.applicationHost/sites/site/application[@path='/pkidata']/virtualDirectory[@path='/']" `
        -Name "userName" -Value "" | Out-Null
    Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$SiteName/pkidata" `
        -Filter "system.applicationHost/sites/site/application[@path='/pkidata']/virtualDirectory[@path='/']" `
        -Name "password" -Value "" | Out-Null
    
    # Authentication: Anonymous enabled, and use App Pool identity (clear IUSR)
    Write-Info "Configuring authentication: Anonymous enabled (App Pool identity), Windows disabled..."
    Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$SiteName/pkidata" `
        -Filter "system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value $true | Out-Null
    Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$SiteName/pkidata" `
        -Filter "system.webServer/security/authentication/anonymousAuthentication" -Name userName -Value "" | Out-Null
    Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$SiteName/pkidata" `
        -Filter "system.webServer/security/authentication/anonymousAuthentication" -Name password -Value "" | Out-Null
    
    Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$SiteName/pkidata" `
        -Filter "system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value $false | Out-Null
    
    # Allow double escaping for delta CRLs with '+' in the URL
    Write-Info "Enabling allowDoubleEscaping (needed for '+' in delta CRL filenames)..."
    Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$SiteName/pkidata" `
        -Filter "system.webServer/security/requestFiltering" -Name allowDoubleEscaping -Value $true | Out-Null
    
    # MIME types for PKI artifacts
    Write-Info "Ensuring MIME types for PKI artifacts..."
    $mimeMap = @{
        ".crl" = "application/pkix-crl"
        ".cer" = "application/pkix-cert"
        ".crt" = "application/x-x509-ca-cert"
        ".p7b" = "application/x-pkcs7-certificates"
        ".pem" = "application/x-pem-file"
        ".der" = "application/octet-stream"
    }
    
    foreach ($ext in $mimeMap.Keys) {
        $mime = $mimeMap[$ext]
        $existing = Get-WebConfigurationProperty -PSPath "IIS:\" -Filter "system.webServer/staticContent/mimeMap" `
            -Name "." | Where-Object { $_.fileExtension -eq $ext }
        
        if (-not $existing) {
            Add-WebConfigurationProperty -PSPath "IIS:\" -Filter "system.webServer/staticContent" `
                -Name "." -Value @{ fileExtension = $ext; mimeType = $mime } | Out-Null
            Write-Ok "Added MIME type: $ext -> $mime"
        }
    }
    
    # Directory browsing (lab convenience)
    if ($EnableDirectoryBrowsing) {
        Write-Info "Enabling directory browsing for $SiteName/pkidata (lab setting)..."
        Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$SiteName/pkidata" `
            -Filter "system.webServer/directoryBrowse" -Name enabled -Value $true | Out-Null
    } else {
        Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$SiteName/pkidata" `
            -Filter "system.webServer/directoryBrowse" -Name enabled -Value $false | Out-Null
    }
    
    iisreset | Out-Null
    Write-Ok "IIS reset complete."
    
    Write-Info "Validation (local):"
    Write-Host "  Invoke-WebRequest `"http://localhost/pkidata/`" -Headers @{ Host=`"$HostHeader`" } -UseBasicParsing" -ForegroundColor Gray
    Write-Host "  Then test: http://$HostHeader/pkidata/<knownfile>.crl" -ForegroundColor Gray
    
    Write-Ok "PKIData IIS configuration complete on $env:COMPUTERNAME."
    Write-Info "Log: $logPath"
}
 finally {
    Stop-Transcript | Out-Null
    # also stop our top-level transcript if started
    Stop-Transcript -ErrorAction SilentlyContinue
}