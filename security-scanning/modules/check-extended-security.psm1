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

            # --- CMK/mHSM Encryption checks ---
            $keySource = $sa.encryption.keySource
            if ($keySource -ne 'Microsoft.Keyvault') {
                $score -= 10
                $findings += @{
                    Category    = "CMK/Encryption"
                    Severity    = "High"
                    Check       = "Storage '$($sa.name)' uses Microsoft-managed keys (MMK)"
                    Detail      = "Encryption key source is '$keySource'. Customer does not control key lifecycle, rotation, or revocation."
                    Remediation = "Configure Customer-Managed Keys (CMK) with Managed HSM or Key Vault. CLZ v2 requires CMK for PRD workloads."
                    Perspective = "CISO"
                    Artifacts   = @(@{ StorageAccount = $sa.name; ResourceGroup = $sa.resourceGroup; KeySource = $keySource; Location = $sa.location })
                }
            } else {
                # Has CMK — validate mHSM configuration
                $kvUri = $sa.encryption.keyVaultProperties.keyVaultUri
                $keyName = $sa.encryption.keyVaultProperties.keyName
                $keyVersion = $sa.encryption.keyVaultProperties.keyVersion
                $isMhsm = $kvUri -match 'managedhsm\.azure\.net'

                if (-not $isMhsm) {
                    $findings += @{
                        Category    = "CMK/Encryption"
                        Severity    = "Medium"
                        Check       = "Storage '$($sa.name)' uses CMK with Key Vault (not Managed HSM)"
                        Detail      = "Key Vault is software-protected (FIPS 140-2 L1). Managed HSM provides hardware isolation (FIPS 140-3 L3)."
                        Remediation = "Migrate CMK to Managed HSM for hardware-level key isolation. Required for CLZ v2 Run phase and sovereign workloads."
                        Perspective = "CISO"
                        Artifacts   = @(@{ StorageAccount = $sa.name; KeyVaultUri = $kvUri; KeyName = $keyName; HSMBacked = 'No' })
                    }
                }

                # Check if key version is pinned (prevents auto-rotation)
                if ($keyVersion -and $keyVersion -ne '') {
                    $score -= 5
                    $findings += @{
                        Category    = "CMK/Encryption"
                        Severity    = "High"
                        Check       = "Storage '$($sa.name)' has pinned key version (no auto-rotation)"
                        Detail      = "Key version '$keyVersion' is explicitly set. Auto-rotation is disabled — stale keys increase blast radius."
                        Remediation = "Remove the key version from the CMK configuration to enable automatic key rotation when the key is rotated in the HSM/vault."
                        Perspective = "Hacker"
                        Artifacts   = @(@{ StorageAccount = $sa.name; KeyName = $keyName; PinnedVersion = $keyVersion; VaultUri = $kvUri })
                    }
                }

                # Check identity type for CMK access
                $identityType = $sa.identity.type
                if ($identityType -match 'SystemAssigned' -and $identityType -notmatch 'UserAssigned') {
                    $findings += @{
                        Category    = "CMK/Encryption"
                        Severity    = "Medium"
                        Check       = "Storage '$($sa.name)' uses system-assigned identity for CMK"
                        Detail      = "System-assigned identity is tied to the resource lifecycle. If the storage account is deleted, key access is immediately lost."
                        Remediation = "Use a User-Assigned Managed Identity for CMK access. This decouples identity from resource lifecycle and enables pre-authorization."
                        Perspective = "CISO"
                        Artifacts   = @(@{ StorageAccount = $sa.name; IdentityType = $identityType; KeyVaultUri = $kvUri })
                    }
                }
            }
        }
    }

    # --- 3b. Managed HSM security posture ---
    $managedHsms = az keyvault list --resource-type hsm --output json 2>$null | ConvertFrom-Json
    if ($managedHsms -and $managedHsms.Count -gt 0) {
        foreach ($hsm in $managedHsms) {
            $hsmDetail = az rest --method get --uri "https://management.azure.com$($hsm.id)?api-version=2023-07-01" --output json 2>$null | ConvertFrom-Json

            if ($hsmDetail) {
                # Purge protection
                if (-not $hsmDetail.properties.enablePurgeProtection) {
                    $score -= 15
                    $findings += @{
                        Category    = "CMK/Encryption"
                        Severity    = "Critical"
                        Check       = "Managed HSM '$($hsm.name)' lacks purge protection"
                        Detail      = "Keys can be permanently destroyed during soft-delete period. A malicious admin could crypto-shred all encrypted data."
                        Remediation = "Enable purge protection immediately. This is non-reversible and required for CLZ v2."
                        Perspective = "Hacker"
                        Artifacts   = @(@{ HSM = $hsm.name; ResourceGroup = $hsm.resourceGroup; PurgeProtection = 'Disabled' })
                    }
                }

                # Public network access
                $publicAccess = $hsmDetail.properties.publicNetworkAccess
                if ($publicAccess -ne 'Disabled') {
                    $score -= 10
                    $findings += @{
                        Category    = "CMK/Encryption"
                        Severity    = "Critical"
                        Check       = "Managed HSM '$($hsm.name)' allows public network access"
                        Detail      = "HSM key operations (wrap/unwrap) accessible from the internet. An attacker with stolen credentials can decrypt data remotely."
                        Remediation = "Disable public network access. Use Private Endpoints exclusively for HSM connectivity."
                        Perspective = "Hacker"
                        Artifacts   = @(@{ HSM = $hsm.name; PublicAccess = $publicAccess; Location = $hsmDetail.location })
                    }
                }

                # Soft-delete retention period
                $retention = $hsmDetail.properties.softDeleteRetentionInDays
                if ($retention -and $retention -lt 90) {
                    $findings += @{
                        Category    = "CMK/Encryption"
                        Severity    = "Medium"
                        Check       = "Managed HSM '$($hsm.name)' has short soft-delete retention ($retention days)"
                        Detail      = "Short retention reduces recovery window for accidentally deleted keys. Recommended: 90 days."
                        Remediation = "Set soft-delete retention to 90 days for adequate recovery window."
                        Perspective = "CISO"
                        Artifacts   = @(@{ HSM = $hsm.name; RetentionDays = $retention; Recommended = 90 })
                    }
                }
            }
        }
    } elseif ($storageAccounts) {
        # No mHSM found but storage accounts exist
        $cmkAccounts = $storageAccounts | Where-Object { $_.encryption.keySource -eq 'Microsoft.Keyvault' }
        if ($cmkAccounts.Count -eq 0 -and $storageAccounts.Count -gt 0) {
            $findings += @{
                Category    = "CMK/Encryption"
                Severity    = "High"
                Check       = "No Managed HSM deployed and no CMK in use"
                Detail      = "$($storageAccounts.Count) storage account(s) rely entirely on Microsoft-managed keys. No customer key sovereignty."
                Remediation = "Deploy Managed HSM and configure CMK for all storage accounts containing sensitive/regulated data."
                Perspective = "CISO"
                Artifacts   = @($storageAccounts | ForEach-Object { @{ StorageAccount = $_.name; ResourceGroup = $_.resourceGroup; KeySource = $_.encryption.keySource } })
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
