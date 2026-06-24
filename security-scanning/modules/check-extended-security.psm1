<#
.SYNOPSIS
    CLZ v2 Security Maturity Scanner — Extended Security Module
.DESCRIPTION
    Checks Defender for Cloud, Key Vault hygiene, diagnostic settings,
    storage security, managed identity usage, and policy compliance.
#>

function Test-ExtendedSecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$SubscriptionName
    )

    $findings = @()
    $score = 100

    Write-Host "  [Security] Scanning subscription: $SubscriptionName ($SubscriptionId)" -ForegroundColor Cyan

    az account set --subscription $SubscriptionId 2>$null

    # --- 1. Microsoft Defender for Cloud ---
    $defenderPricings = az security pricing list --output json 2>$null | ConvertFrom-Json
    if ($defenderPricings) {
        $disabledPlans = $defenderPricings | Where-Object {
            $_.pricingTier -eq 'Free' -and
            $_.name -in @('VirtualMachines', 'SqlServers', 'AppServices', 'StorageAccounts',
                          'KeyVaults', 'Arm', 'Containers', 'Dns')
        }
        if ($disabledPlans.Count -gt 0) {
            $score -= 15
            $findings += @{
                Category    = "Defender"
                Severity    = "Critical"
                Check       = "Microsoft Defender plans not enabled"
                Detail      = "$($disabledPlans.Count) Defender plan(s) on Free tier: $($disabledPlans.name -join ', ')"
                Remediation = "Enable Defender for Cloud Standard tier on all resource types. CLZ v2 requires Defender for Containers, Key Vaults, ARM, and Storage at minimum."
                Perspective = "CISO"
            }
        }
    } else {
        $score -= 15
        $findings += @{
            Category    = "Defender"
            Severity    = "Critical"
            Check       = "Unable to query Defender for Cloud status"
            Detail      = "Could not retrieve Defender pricing information — may lack Security Reader role"
            Remediation = "Ensure the scanning identity has Security Reader role. Enable Defender for Cloud."
            Perspective = "CISO"
        }
    }

    # --- 2. Key Vault security ---
    $keyVaults = az keyvault list --output json 2>$null | ConvertFrom-Json
    if ($keyVaults) {
        foreach ($kv in $keyVaults) {
            $kvDetail = az keyvault show --name $kv.name --output json 2>$null | ConvertFrom-Json
            if ($kvDetail) {
                # Soft-delete and purge protection
                if (-not $kvDetail.properties.enableSoftDelete) {
                    $score -= 10
                    $findings += @{
                        Category    = "Key Vault"
                        Severity    = "Critical"
                        Check       = "Key Vault '$($kv.name)' lacks soft-delete"
                        Detail      = "Accidental or malicious deletion cannot be recovered"
                        Remediation = "Enable soft-delete (now default) and purge protection on all Key Vaults."
                        Perspective = "CISO"
                    }
                }
                if (-not $kvDetail.properties.enablePurgeProtection) {
                    $score -= 5
                    $findings += @{
                        Category    = "Key Vault"
                        Severity    = "High"
                        Check       = "Key Vault '$($kv.name)' lacks purge protection"
                        Detail      = "Vault can be permanently deleted during soft-delete retention period"
                        Remediation = "Enable purge protection to prevent permanent deletion."
                        Perspective = "CISO"
                    }
                }
                # Public network access
                if ($kvDetail.properties.publicNetworkAccess -ne 'Disabled') {
                    $score -= 5
                    $findings += @{
                        Category    = "Key Vault"
                        Severity    = "High"
                        Check       = "Key Vault '$($kv.name)' allows public network access"
                        Detail      = "Secrets, keys, and certificates accessible from the internet"
                        Remediation = "Disable public network access. Use Private Endpoints exclusively."
                        Perspective = "Hacker"
                    }
                }
                # RBAC vs access policy
                if (-not $kvDetail.properties.enableRbacAuthorization) {
                    $score -= 5
                    $findings += @{
                        Category    = "Key Vault"
                        Severity    = "Medium"
                        Check       = "Key Vault '$($kv.name)' uses access policies instead of RBAC"
                        Detail      = "Access policies are less auditable and harder to manage at scale"
                        Remediation = "Migrate to RBAC authorization model for consistent access governance."
                        Perspective = "CISO"
                    }
                }
            }
        }
    }

    # --- 3. Storage account security ---
    $storageAccounts = az storage account list --output json 2>$null | ConvertFrom-Json
    if ($storageAccounts) {
        foreach ($sa in $storageAccounts) {
            if ($sa.allowBlobPublicAccess -eq $true) {
                $score -= 10
                $findings += @{
                    Category    = "Storage"
                    Severity    = "Critical"
                    Check       = "Storage account '$($sa.name)' allows public blob access"
                    Detail      = "Data exfiltration risk — blobs can be publicly accessible"
                    Remediation = "Set allowBlobPublicAccess to false. Use SAS tokens or managed identities for access."
                    Perspective = "Hacker"
                }
            }
            if ($sa.minimumTlsVersion -ne 'TLS1_2') {
                $score -= 5
                $findings += @{
                    Category    = "Storage"
                    Severity    = "High"
                    Check       = "Storage account '$($sa.name)' allows TLS < 1.2"
                    Detail      = "Older TLS versions have known vulnerabilities"
                    Remediation = "Set minimum TLS version to 1.2."
                    Perspective = "Hacker"
                }
            }
            if (-not $sa.encryption.requireInfrastructureEncryption) {
                $findings += @{
                    Category    = "Storage"
                    Severity    = "Medium"
                    Check       = "Storage '$($sa.name)' lacks infrastructure double encryption"
                    Detail      = "CLZ v2 Run phase recommends infrastructure encryption for defense-in-depth"
                    Remediation = "Enable infrastructure encryption for sensitive data workloads."
                    Perspective = "CISO"
                }
            }
        }
    }

    # --- 4. Diagnostic settings coverage ---
    $activityLogSettings = az monitor diagnostic-settings subscription list --subscription $SubscriptionId --output json 2>$null | ConvertFrom-Json
    if (-not $activityLogSettings -or ($activityLogSettings.value -and $activityLogSettings.value.Count -eq 0) -or $activityLogSettings.Count -eq 0) {
        $score -= 10
        $findings += @{
            Category    = "Monitoring"
            Severity    = "High"
            Check       = "No diagnostic settings on subscription activity log"
            Detail      = "Activity logs are not forwarded to Log Analytics or Storage — no audit trail"
            Remediation = "Configure diagnostic settings to send activity logs to a central Log Analytics workspace."
            Perspective = "CISO"
        }
    }

    # --- 5. Policy compliance ---
    $policyStates = az policy state summarize --subscription $SubscriptionId --output json 2>$null | ConvertFrom-Json
    if ($policyStates -and $policyStates.results) {
        $nonCompliant = $policyStates.results.nonCompliantResources
        $totalResources = $policyStates.results.resourceDetails.Count
        if ($nonCompliant -gt 0) {
            $pct = if ($totalResources -gt 0) { [math]::Round(($nonCompliant / $totalResources) * 100, 1) } else { 0 }
            $severity = if ($pct -gt 20) { "Critical" } elseif ($pct -gt 10) { "High" } else { "Medium" }
            if ($pct -gt 10) { $score -= 10 }
            $findings += @{
                Category    = "Policy"
                Severity    = $severity
                Check       = "Azure Policy non-compliance detected"
                Detail      = "$nonCompliant non-compliant resource(s). Compliance gap indicates governance drift."
                Remediation = "Review non-compliant resources in Azure Policy. Remediate or create exemptions with justification."
                Perspective = "CISO"
            }
        }
    }

    # --- 6. Managed Identity adoption ---
    $resources = az resource list --output json 2>$null | ConvertFrom-Json
    $appServices = $resources | Where-Object { $_.type -eq 'Microsoft.Web/sites' }
    if ($appServices) {
        foreach ($app in $appServices) {
            $appDetail = az webapp identity show --name $app.name --resource-group $app.resourceGroup --output json 2>$null | ConvertFrom-Json
            if (-not $appDetail -or -not $appDetail.principalId) {
                $findings += @{
                    Category    = "Identity"
                    Severity    = "Medium"
                    Check       = "App Service '$($app.name)' lacks managed identity"
                    Detail      = "Application may use connection strings with embedded credentials"
                    Remediation = "Enable system-assigned or user-assigned managed identity. Use it for Key Vault and database access."
                    Perspective = "Hacker"
                }
            }
        }
    }

    if ($findings.Count -eq 0) {
        $findings += @{
            Category    = "Security"
            Severity    = "Info"
            Check       = "Extended security checks passed"
            Detail      = "No critical issues found across Defender, Key Vault, Storage, and Policy"
            Remediation = "Maintain current posture. Schedule quarterly reviews."
            Perspective = "CISO"
        }
    }

    return @{
        Score    = [Math]::Max(0, $score)
        Findings = $findings
    }
}

Export-ModuleMember -Function Test-ExtendedSecurity
