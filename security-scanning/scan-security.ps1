<#
.SYNOPSIS
    CLZ v2 Security Maturity Scanner
.DESCRIPTION
    Scans one or more Azure subscriptions against CLZ v2 security and governance
    rules. Checks RBAC, network security, Defender, Key Vault, storage, policy
    compliance, and cross-environment (DTA/PRD) role sprawl. Assesses from both
    a hacker (attack surface) and CISO (governance) perspective.

    Generates an HTML web report with maturity scoring.

.PARAMETER SubscriptionIds
    One or more Azure subscription IDs to scan.

.PARAMETER AllSubscriptions
    Scan all subscriptions accessible to the current identity.

.PARAMETER OutputPath
    Path for the HTML report. Defaults to ./clz-security-report-<timestamp>.html

.PARAMETER EnvironmentMap
    Hashtable mapping subscription IDs to environment labels (DTA/PRD).
    Used for cross-environment RBAC sprawl detection.
    Example: @{ "sub-id-1" = "DTA"; "sub-id-2" = "PRD" }

.EXAMPLE
    # Scan specific subscriptions
    .\scan-security.ps1 -SubscriptionIds "aaaa-bbbb-cccc", "dddd-eeee-ffff"

.EXAMPLE
    # Scan all subscriptions
    .\scan-security.ps1 -AllSubscriptions

.EXAMPLE
    # Scan with environment mapping for cross-env analysis
    .\scan-security.ps1 -SubscriptionIds "sub1","sub2" -EnvironmentMap @{ "sub1"="DTA"; "sub2"="PRD" }
#>

[CmdletBinding(DefaultParameterSetName = 'Specific')]
param(
    [Parameter(ParameterSetName = 'Specific', Mandatory)]
    [string[]]$SubscriptionIds,

    [Parameter(ParameterSetName = 'All')]
    [switch]$AllSubscriptions,

    [string]$OutputPath,

    [hashtable]$EnvironmentMap = @{}
)

$ErrorActionPreference = 'Continue'
$scriptDir = $PSScriptRoot

# Import modules
Import-Module "$scriptDir\modules\check-rbac.psm1" -Force
Import-Module "$scriptDir\modules\check-network.psm1" -Force
Import-Module "$scriptDir\modules\check-extended-security.psm1" -Force
Import-Module "$scriptDir\modules\report-generator.psm1" -Force

$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC
$fileTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

if (-not $OutputPath) {
    $OutputPath = Join-Path $scriptDir "clz-security-report-$fileTimestamp.html"
}

# --- Banner ---
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
Write-Host "  ║   CLZ v2 Security Maturity Scanner                     ║" -ForegroundColor DarkCyan
Write-Host "  ║   Hacker + CISO Perspective Assessment                 ║" -ForegroundColor DarkCyan
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
Write-Host ""

# --- Verify Azure CLI login ---
Write-Host "  [Init] Verifying Azure CLI session..." -ForegroundColor Gray
$account = az account show --output json 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "  [ERROR] Not logged in to Azure CLI. Run 'az login' first." -ForegroundColor Red
    exit 1
}
Write-Host "  [Init] Authenticated as: $($account.user.name)" -ForegroundColor Green

# --- Resolve subscriptions ---
if ($AllSubscriptions) {
    Write-Host "  [Init] Enumerating all accessible subscriptions..." -ForegroundColor Gray
    $subs = az account list --output json 2>$null | ConvertFrom-Json
    $SubscriptionIds = $subs | ForEach-Object { $_.id }
    Write-Host "  [Init] Found $($SubscriptionIds.Count) subscription(s)" -ForegroundColor Green
}

$subscriptionResults = @()

foreach ($subId in $SubscriptionIds) {
    $subDetail = az account show --subscription $subId --output json 2>$null | ConvertFrom-Json
    if (-not $subDetail) {
        Write-Host "  [WARN] Cannot access subscription $subId — skipping" -ForegroundColor Yellow
        continue
    }

    $subName = $subDetail.name
    $environment = if ($EnvironmentMap.ContainsKey($subId)) {
        $EnvironmentMap[$subId]
    } elseif ($subName -match 'prod|prd') {
        'PRD'
    } elseif ($subName -match 'dev|dta|test|accept|sandbox|nonprod|non-prod') {
        'DTA'
    } else {
        'Unknown'
    }

    Write-Host ""
    Write-Host "  ════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host "  Scanning: $subName [$environment]" -ForegroundColor White
    Write-Host "  ════════════════════════════════════════════" -ForegroundColor DarkGray

    # Run all check modules
    $rbacResult    = Test-RbacSecurity -SubscriptionId $subId -SubscriptionName $subName
    $networkResult = Test-NetworkSecurity -SubscriptionId $subId -SubscriptionName $subName
    $extResult     = Test-ExtendedSecurity -SubscriptionId $subId -SubscriptionName $subName

    $overallScore = [math]::Round(($rbacResult.Score + $networkResult.Score + $extResult.Score) / 3, 0)

    $allFindings = @()
    $allFindings += $rbacResult.Findings
    $allFindings += $networkResult.Findings
    $allFindings += $extResult.Findings

    # Collect role assignments for cross-env analysis
    $roleAssignments = az role assignment list --subscription $subId --all --output json 2>$null | ConvertFrom-Json
    if (-not $roleAssignments) { $roleAssignments = @() }

    $subscriptionResults += @{
        SubscriptionId   = $subId
        SubscriptionName = $subName
        Environment      = $environment
        OverallScore     = $overallScore
        RbacScore        = $rbacResult.Score
        NetworkScore     = $networkResult.Score
        ExtendedScore    = $extResult.Score
        Findings         = $allFindings
        RoleAssignments  = $roleAssignments
        RbacStats        = $rbacResult.Stats
        NetworkStats     = $networkResult.Stats
    }

    Write-Host "  Score: RBAC=$($rbacResult.Score)% | Network=$($networkResult.Score)% | Extended=$($extResult.Score)% | Overall=$overallScore%" -ForegroundColor White
}

# --- Cross-environment RBAC analysis ---
if ($subscriptionResults.Count -gt 1) {
    Write-Host ""
    Write-Host "  [Cross-Env] Analyzing DTA ↔ PRD role sprawl..." -ForegroundColor Cyan
    $crossEnvResult = Test-CrossEnvironmentRbac -SubscriptionResults $subscriptionResults
    foreach ($sub in $subscriptionResults) {
        $sub.Findings += $crossEnvResult.Findings
        $sub.OverallScore = [math]::Round(($sub.OverallScore + $crossEnvResult.Score) / 2, 0)
    }
}

# --- Generate report ---
Write-Host ""
Write-Host "  [Report] Generating HTML report..." -ForegroundColor Cyan
$reportPath = New-SecurityReport -SubscriptionResults $subscriptionResults -OutputPath $OutputPath -ScanTimestamp $timestamp

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║   Scan Complete!                                       ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host "  Report: $reportPath" -ForegroundColor Green
Write-Host ""
