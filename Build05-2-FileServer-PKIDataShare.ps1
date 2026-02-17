<#
.SYNOPSIS
    PKI Lab - File Server PKIData Share (SMB + NTFS)

.DESCRIPTION
    Creates/standardizes the PKIData folder + SMB share used for CRL/AIA publishing.
    
    Intended pattern (recommended):
    - IIS PKIDataSite serves HTTP from a UNC path using ApplicationPoolIdentity.
      When IIS points to a UNC path with ApplicationPoolIdentity, the network
      identity used is the web server machine account (WEB1$, WEB2$). Therefore,
      the web servers require READ on the SMB share + NTFS.
    - Issuing CAs publish CRL/AIA files to the DFS/SMB path and therefore require
      CHANGE (SMB) and MODIFY (NTFS).
    - OCSP responders generally only need READ access to the CRL distribution
      point (HTTP), but granting READ to the underlying share/folder is harmless
      and supports any local caching or retrieval scenarios.
    
    This script intentionally avoids using a dedicated "PKIWebSvc" account for
    serving PKIData. If you still want a legacy/transition service account, you
    may include it via -IncludeServiceAccount.

.PARAMETER ShareName
    SMB share name. Default: PKIData

.PARAMETER LocalPath
    Local path to host the share. Default: C:\PKIData

.PARAMETER DomainNetbios
    NETBIOS name of the domain. Default: LAB

.PARAMETER SubCAs
    Issuing CA computer names (short names, without trailing $). Default: subca1, subca2

.PARAMETER WebServers
    Web server computer names (short names). Default: web1, web2

.PARAMETER OcspServers
    OCSP server computer names (short names). Default: ocsp1, ocsp2

.PARAMETER ResetShareAcls
    If set (default), removes broad/default SMB principals (Everyone/Authenticated Users)
    and re-grants only the expected principals.

.PARAMETER ResetNtfsAcls
    If set (default), removes inheritance on the folder and applies a clean, explicit
    ACL for SYSTEM/Administrators plus the required machine accounts.

.PARAMETER IncludeServiceAccount
    Include an additional service account (DOMAIN\sam) with READ on the share/folder.

.PARAMETER ServiceAccountSam
    samAccountName of the optional service account. Default: PKIWebSvc

.NOTES
    Run elevated on the file server hosting the share.
    Idempotent-ish; safe to re-run. If you disable reset switches, it will only add.
#>

[CmdletBinding()]
param(
    [string]$ShareName        = "PKIData",
    [string]$LocalPath        = "C:\PKIData",
    [string]$DomainNetbios    = "LAB",
    
    [string[]]$SubCAs         = @("subca1","subca2"),
    [string[]]$WebServers     = @("web1","web2"),
    [string[]]$OcspServers    = @("ocsp1","ocsp2"),
    
    [switch]$ResetShareAcls,
    [switch]$ResetNtfsAcls,
    
    [switch]$IncludeServiceAccount,
    [string]$ServiceAccountSam = "PKIWebSvc"
)

# --- Logging: ensure folder and start transcript ---
$LogDir = "C:\Scripts"
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path (Join-Path $LogDir "PKILab-2-FileServer-PKIDataShare.log") -Append -ErrorAction SilentlyContinue

# 6 references
function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if (-not $isAdmin) { throw "Run this script elevated (Run as Administrator)." }
}

# 1 reference
function Ensure-Folder([string]$Path) {
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

# 1 reference
function Ensure-Share([string]$Name,[string]$Path) {
    $s = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue
    if (-not $s) {
        New-SmbShare -Name $Name -Path $Path -FullAccess "Administrators","SYSTEM" -ErrorAction Stop | Out-Null
    }
}

Assert-Admin

if (-not $PSBoundParameters.ContainsKey('ResetShareAcls')) { $ResetShareAcls = $true }
if (-not $PSBoundParameters.ContainsKey('ResetNtfsAcls'))  { $ResetNtfsAcls  = $true }

Write-Host "=== PKILab | PKIData Share + NTFS ===" -ForegroundColor Cyan
Write-Host "Share:  \\$env:COMPUTERNAME\$ShareName" -ForegroundColor Gray
Write-Host "Folder: $LocalPath" -ForegroundColor Gray
Write-Host ""

Ensure-Folder -Path $LocalPath
Ensure-Share  -Name $ShareName -Path $LocalPath

# 4 references
function To-Principal([string]$shortName,[switch]$Machine) {
    if ($Machine) {
        return "$($DomainNetbios)\$($shortName)$"  # machine account
    }
    return "$($DomainNetbios)\$($shortName)"
}

$subcaPrincipals = $SubCAs       | ForEach-Object { To-Principal $_ -Machine }
$webPrincipals   = $WebServers   | ForEach-Object { To-Principal $_ -Machine }
$ocspPrincipals  = $OcspServers  | ForEach-Object { To-Principal $_ -Machine }

$extraPrincipals = @()
if ($IncludeServiceAccount) {
    $extraPrincipals += (To-Principal $ServiceAccountSam)
}

if ($ResetShareAcls) {
    foreach ($broad in @('Everyone','Authenticated Users','Users')) {
        try { Revoke-SmbShareAccess -Name $ShareName -AccountName $broad -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
}

# SMB ACLs
foreach ($p in $subcaPrincipals) {
    Grant-SmbShareAccess -Name $ShareName -AccountName $p -AccessRight Change -Force -ErrorAction SilentlyContinue | Out-Null
}

foreach ($p in ($webPrincipals + $ocspPrincipals + $extraPrincipals)) {
    Grant-SmbShareAccess -Name $ShareName -AccountName $p -AccessRight Read -Force -ErrorAction SilentlyContinue | Out-Null
}

if ($ResetNtfsAcls) {
    # Remove inheritance and wipe existing explicit ACLs, then rebuild a clean ACL.
    icacls $LocalPath /inheritance:r | Out-Null
    icacls $LocalPath /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
} else {
    icacls $LocalPath /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
}

# NTFS ACLs
foreach ($p in $subcaPrincipals) {
    icacls $LocalPath /grant "${p}:(OI)(CI)M" | Out-Null
}

foreach ($p in ($webPrincipals + $ocspPrincipals + $extraPrincipals)) {
    icacls $LocalPath /grant "${p}:(OI)(CI)RX" | Out-Null
}

Write-Host ""
Write-Host "SMB Share Permissions ($ShareName)" -ForegroundColor Cyan
Get-SmbShareAccess -Name $ShareName |
    Select-Object AccountName,AccessRight,AccessControlType |
    Sort-Object AccountName |
    Format-Table -AutoSize

Write-Host ""
Write-Host "NTFS Permissions ($LocalPath)" -ForegroundColor Cyan
icacls $LocalPath

Write-Host ""
Write-Host "[+] Completed." -ForegroundColor Green

# --- Stop logging/transcript ---
Stop-Transcript -ErrorAction SilentlyContinue