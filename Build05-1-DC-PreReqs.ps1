<#
.SYNOPSIS
PKI Lab - DC Pre-Reqs (Service Accounts + SPNs + Delegation)
Creates/updates dedicated domain service accounts, registers required HTTP SPNs for Kerberos over DNS aliases,
and configures Constrained Delegation for CES to communicate with CAs.

.DESCRIPTION
Creates/updates:
    - PKIEnrollSvc  : used by CEP + CES (MSEnrollmentPolicyServer + WSEnrollmentServer)
    - PKINDESSvc    : used by NDES (SCEP app pool)

Registers SPNs:
    - HTTP/enroll
    - HTTP/enroll.lab.local
    - HTTP/web1.lab.local
    - HTTP/web2.lab.local
      -> on PKIEnrollSvc

    - HTTP/scep1
    - HTTP/scep1.lab.local
    - HTTP/scep2
    - HTTP/scep2.lab.local
      -> on PKINDESSvc

Configures Constrained Delegation:
    - PKIEnrollSvc trusted to delegate to SubCA1 and SubCA2 for RPCSS and HOST services

Also creates two optional admin groups used later for template + CA ACL scoping:
    - PKI_WebCert_Requesters
    - PKI_WebCert_Approvers
    - NDES-Admins (for NDES password retrieval)

.NOTES
    - Run elevated on a Domain Controller (or RSAT host) with ActiveDirectory module.
    - This script is idempotent; safe to re-run.
    - If an SPN is already registered to a different account, the script will stop and tell you what to clean up.

#>

[CmdletBinding()] 
param(
    [string]$DomainNetbios = "LAB",
    [string]$DomainDns    = "lab.local",

    [string]$EnrollSvcSam = "PKIEnrollSvc",
    [string]$NdesSvcSam   = "PKINDESSvc",

    # CES/CEP endpoint aliases (load-balanced + individual nodes)
    [string[]]$EnrollHostNames = @("enroll","enroll.lab.local","web1.lab.local","web2.lab.local"),

    # NDES endpoints: NO DNS RR; two independent instances
    [string[]]$ScepHostNames   = @("scep1","scep1.lab.local","scep2","scep2.lab.local"),

    [switch]$CreateGroups
)

# --- Logging: ensure folder and start transcript ---
$LogDir = "C:\Scripts"
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path (Join-Path $LogDir "PKILab-1-DC-PreReqs-UPDATED.log") -Append -ErrorAction SilentlyContinue

Import-Module ActiveDirectory -ErrorAction Stop

function Ensure-User {
    param(
        [Parameter(Mandatory)] [string]$Sam,
        [Parameter(Mandatory)] [string]$DisplayName
    )

    $u = Get-ADUser -Filter "samAccountName -eq '$Sam'" -ErrorAction SilentlyContinue
    if (-not $u) {
        Write-Host "[+] Creating service account: $DomainNetbios\$Sam" -ForegroundColor Cyan

        $pw = Read-Host "Enter password for $DomainNetbios\$Sam" -AsSecureString

        New-ADUser `
            -Name $DisplayName `
            -SamAccountName $Sam `
            -UserPrincipalName "$Sam@$DomainDns" `
            -AccountPassword $pw `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -CannotChangePassword $true `
            -Description "PKI service account ($Sam)" | Out-Null

        $u = Get-ADUser -Identity $Sam -ErrorAction Stop    
        Write-Host "[+] Created: $DomainNetbios\$Sam" -ForegroundColor Green
    } else {
        Write-Host "[+] Exists: $DomainNetbios\$Sam" -ForegroundColor Green
    }

    # Ensure flags stay enforced
    Set-ADUser -Identity $Sam -PasswordNeverExpires $true -CannotChangePassword $true | Out-Null
    return $u
}

function Get-SpnOwner {
    param([Parameter(Mandatory)][string]$Spn)
    # setspn output is easiest to parse consistently
    $out = & setspn.exe -Q $Spn 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }

    # Example line: "CN=PKIEnrollSvc,CN=Users,DC=lab,DC=local"
    $dn = ($out | Where-Object { $_ -match "^CN=" } | Select-Object -First 1)
    return $dn
}

function Ensure-Spn {
    param(
        [Parameter(Mandatory)][string]$Spn,
        [Parameter(Mandatory)][string]$AccountSam
    )
    $owner = Get-SpnOwner -Spn $Spn
    if ($owner) {
        # SPN exists somewhere; verify it's on the expected account
        $expected = Get-ADUser -Identity $AccountSam -ErrorAction SilentlyContinue
        if ($owner -notmatch [regex]::Escape($expected.DistinguishedName)) {
            throw "SPN '$Spn' is already registered to a different object: $owner. Remove/move it before continuing."
        }
        Write-Host "[+] Registered SPN: $Spn -> $DomainNetbios\$AccountSam" | Out-Null
    } else {
        & setspn.exe -S $Spn "$DomainNetbios\$AccountSam" | Out-Null
        Write-Host "[+] Registered SPN: $Spn -> $DomainNetbios\$AccountSam" -ForegroundColor Green
    }
}

function Ensure-Group ([string]$Name, [string]$Desc) {
        $g = Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
        if (-not $g) {
            New-ADGroup -Name $Name -GroupScope Global -GroupCategory Security -Description $Desc | Out-Null
            Write-Host "[+] Created group: $Name" -ForegroundColor Green
        } else {
            Write-Host "[+] Exists group: $Name" -ForegroundColor Green
        }
    }

Write-Host "=== PKILab DC Pre-Reqs (Service Accounts + SPN + Delegation) ===" -ForegroundColor Cyan
Write-Host "[INFO] Domain: $DomainNetBios ($DomainDNS)" -ForegroundColor Gray
Write-Host ""

# ====
# STEP 1: Create Service Accounts
# ====
Write-Host "[STEP 1] Creating/Verifying Service Accounts..." -ForegroundColor Green
$enrollUser = Ensure-User -Sam $EnrollSvcSam -DisplayName "PKI Enrollment Service"
$ndesUser = Ensure-User -Sam $NdesSvcSam -DisplayName "PKI NDES Service"

# ====
# STEP 2: Register SPNs for Kerberos Authentication
# ====
Write-Host ""
Write-Host "[STEP 2] Registering SPNs for Kerberos DNS aliases..." -ForegroundColor Green

Write-Host "  Registering SPNs for PKIEnrollSvc (CES/CEP)..." -ForegroundColor Cyan
foreach ($h in $EnrollHostNames) {
    Ensure-Spn -Spn "HTTP/$h" -AccountSam $EnrollSvcSam
}

Write-Host "  Registering SPNs for PKINDESSvc (NDES)..." -ForegroundColor Cyan
foreach ($h in $ScepHostNames) {
    Ensure-Spn -Spn "HTTP/$h" -AccountSam $NdesSvcSam
}

# ====
# STEP 3: Configure Kerberos Constrained Delegation
# ====
Write-Host ""
Write-Host "[STEP 3] Configuring Kerberos Constrained Delegation for PKIEnrollSvc..." -ForegroundColor Green

# Allow PKIEnrollSvc to delegate to both CAs for RPCSS and HOST
$cesSvc = Get-ADUser -Identity $EnrollSvcSam

Write-Host "  Setting delegation targets (SubCA1 and SubCA2)..." -ForegroundColor Cyan
Set-ADObject -Identity $cesSvc -Replace @{
    "msDS-AllowedToDelegateTo" = @(
        "rpcss/SubCA1.lab.local", 
        "HOST/SubCA1.lab.local",
        "rpcss/SubCA2.lab.local", 
        "HOST/SubCA2.lab.local"
    )
}

# Enable Protocol Transitioning (required for Kerberos -> NTLM fallback)
Write-Host "  Enabling Protocol Transitioning..." -ForegroundColor Cyan
Set-ADAccountControl -Identity $EnrollSvcSam -TrustedToAuthForDelegation $true

Write-Host "[+] Constrained Delegation configured for PKIEnrollSvc." -ForegroundColor Green

# ====
# STEP 4: Create Optional Admin Groups
# ====
if ($CreateGroups) {
    Write-Host ""
    Write-Host "[STEP 4] Creating optional PKI Groups..." -ForegroundColor Green
    Ensure-Group -Name "PKI_WebCert_Requesters" -Desc "Users allowed to request web certs via CEP/CES"
    Ensure-Group -Name "PKI_WebCert_Approvers"  -Desc "Users allowed to approve web cert requests"
    Ensure-Group -Name "NDES-Admins" -Desc "Users allowed to retrieve NDES one-time passwords"
}

# ====
# VERIFICATION
# ====
Write-Host ""
Write-Host "[+] DC Pre-Reqs Completed Successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "=== Verification Commands ===" -ForegroundColor Yellow
Write-Host "  setspn -L $DomainNetbios\$EnrollSvcSam" -ForegroundColor White
Write-Host "  setspn -L $DomainNetbios\$NdesSvcSam" -ForegroundColor White
Write-Host "  Get-ADUser $EnrollSvcSam -Properties msDS-AllowedToDelegateTo | Select-Object -ExpandProperty msDS-AllowedToDelegateTo" -ForegroundColor White
Write-Host ""

# --- Stop logging/transcript ---
Stop-Transcript -ErrorAction SilentlyContinue