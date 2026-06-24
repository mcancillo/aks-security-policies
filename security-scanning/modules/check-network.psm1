<#
.SYNOPSIS
    CLZ v2 Security Maturity Scanner — Network Security Module
.DESCRIPTION
    Checks NSGs, UDRs, Private Endpoints, Public IPs, service endpoints,
    firewall presence, and network segmentation.
#>

function Test-NetworkSecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$SubscriptionName
    )

    $findings = @()
    $score = 100

    Write-Host "  [Network] Scanning subscription: $SubscriptionName ($SubscriptionId)" -ForegroundColor Cyan

    az account set --subscription $SubscriptionId 2>$null

    # --- 1. NSGs with Allow-All inbound rules ---
    $nsgs = az network nsg list --output json 2>$null | ConvertFrom-Json
    if ($nsgs) {
        foreach ($nsg in $nsgs) {
            $rules = az network nsg rule list --nsg-name $nsg.name --resource-group $nsg.resourceGroup --output json 2>$null | ConvertFrom-Json
            $dangerousRules = $rules | Where-Object {
                $_.access -eq 'Allow' -and
                $_.direction -eq 'Inbound' -and
                ($_.sourceAddressPrefix -eq '*' -or $_.sourceAddressPrefix -eq 'Internet' -or $_.sourceAddressPrefix -eq '0.0.0.0/0') -and
                $_.destinationPortRange -in @('*', '22', '3389', '443', '80')
            }
            if ($dangerousRules.Count -gt 0) {
                $score -= 10
                $findings += @{
                    Category    = "Network"
                    Severity    = "Critical"
                    Check       = "NSG '$($nsg.name)' has dangerous inbound allow rules"
                    Detail      = "$($dangerousRules.Count) rule(s) allow inbound from Internet/Any to sensitive ports (22/3389/80/443/*) in RG '$($nsg.resourceGroup)'"
                    Remediation = "Restrict source addresses to known CIDRs. Use Azure Bastion for management access. Remove wildcard inbound rules."
                    Perspective = "Hacker"
                    Artifacts   = @($dangerousRules | ForEach-Object { @{ Rule = $_.name; Port = $_.destinationPortRange; Source = $_.sourceAddressPrefix; Priority = $_.priority } })
                }
            }
        }

        # Check for subnets without NSGs
        $vnets = az network vnet list --output json 2>$null | ConvertFrom-Json
        if ($vnets) {
            foreach ($vnet in $vnets) {
                $subnets = $vnet.subnets | Where-Object {
                    -not $_.networkSecurityGroup -and
                    $_.name -notin @('GatewaySubnet', 'AzureFirewallSubnet', 'AzureFirewallManagementSubnet', 'AzureBastionSubnet', 'RouteServerSubnet')
                }
                if ($subnets.Count -gt 0) {
                    $score -= 10
                    $findings += @{
                        Category    = "Network"
                        Severity    = "High"
                        Check       = "Subnets without NSG in VNet '$($vnet.name)'"
                        Detail      = "$($subnets.Count) subnet(s) have no NSG attached: $($subnets.name -join ', ')"
                        Remediation = "Attach NSGs to all non-gateway subnets. This is a CLZ v2 baseline requirement."
                        Perspective = "CISO"
                        Artifacts   = @($subnets | ForEach-Object { @{ Subnet = $_.name; AddressPrefix = $_.addressPrefix; VNet = $vnet.name } })
                    }
                }
            }
        }
    }

    # --- 2. Public IP addresses ---
    $publicIps = az network public-ip list --output json 2>$null | ConvertFrom-Json
    if ($publicIps.Count -gt 0) {
        $unattached = $publicIps | Where-Object { -not $_.ipConfiguration }
        $standardPublicIps = $publicIps | Where-Object { $_.sku.name -ne 'Standard' }

        if ($unattached.Count -gt 0) {
            $score -= 5
            $findings += @{
                Category    = "Network"
                Severity    = "Medium"
                Check       = "Orphaned public IP addresses"
                Detail      = "$($unattached.Count) public IP(s) are not attached to any resource — potential cost waste and attack surface"
                Remediation = "Delete unused public IPs. Each public IP is a potential entry point."
                Perspective = "Hacker"
                Artifacts   = @($unattached | ForEach-Object { @{ Name = $_.name; IP = $_.ipAddress; ResourceGroup = $_.resourceGroup; SKU = $_.sku.name } })
            }
        }

        if ($publicIps.Count -gt 5) {
            $score -= 10
            $findings += @{
                Category    = "Network"
                Severity    = "High"
                Check       = "High number of public IP addresses ($($publicIps.Count))"
                Detail      = "Large external attack surface. CLZ v2 recommends minimizing public endpoints."
                Remediation = "Consolidate behind Azure Firewall, Application Gateway, or Front Door. Use Private Link where possible."
                Perspective = "CISO"
                Artifacts   = @($publicIps | ForEach-Object { @{ Name = $_.name; IP = $_.ipAddress; ResourceGroup = $_.resourceGroup; Attached = if ($_.ipConfiguration) { 'Yes' } else { 'No' } } })
            }
        }
    }

    # --- 3. Azure Firewall presence ---
    $firewalls = az network firewall list --output json 2>$null | ConvertFrom-Json
    if (-not $firewalls -or $firewalls.Count -eq 0) {
        $findings += @{
            Category    = "Network"
            Severity    = "Medium"
            Check       = "No Azure Firewall detected"
            Detail      = "CLZ v2 Walk/Run phases require centralized firewall for egress filtering"
            Remediation = "Deploy Azure Firewall in the hub VNet for centralized egress control and threat intelligence filtering."
            Perspective = "CISO"
        }
    }

    # --- 4. Private Endpoints adoption ---
    $privateEndpoints = az network private-endpoint list --output json 2>$null | ConvertFrom-Json
    $storageAccounts = az storage account list --output json 2>$null | ConvertFrom-Json
    $keyVaults = az keyvault list --output json 2>$null | ConvertFrom-Json
    $sqlServers = az sql server list --output json 2>$null | ConvertFrom-Json

    $plEligibleCount = ($storageAccounts.Count + $keyVaults.Count + $sqlServers.Count)
    $peCount = if ($privateEndpoints) { $privateEndpoints.Count } else { 0 }

    if ($plEligibleCount -gt 0 -and $peCount -lt $plEligibleCount) {
        $score -= 10
        $findings += @{
            Category    = "Network"
            Severity    = "High"
            Check       = "Insufficient Private Endpoint coverage"
            Detail      = "$peCount Private Endpoint(s) for $plEligibleCount Private-Link-eligible resources (Storage, Key Vault, SQL)"
            Remediation = "Enable Private Endpoints for all PaaS services. Disable public network access on storage accounts, Key Vaults, and SQL servers."
            Perspective = "Hacker"
            Artifacts   = @(
                @($storageAccounts | ForEach-Object { @{ Type = "Storage"; Name = $_.name; ResourceGroup = $_.resourceGroup } }) +
                @($keyVaults | ForEach-Object { @{ Type = "KeyVault"; Name = $_.name; ResourceGroup = $_.resourceGroup } }) +
                @($sqlServers | ForEach-Object { @{ Type = "SQL"; Name = $_.name; ResourceGroup = $_.resourceGroup } })
            )
        }
    }

    # --- 5. UDR enforcement ---
    if ($vnets) {
        foreach ($vnet in $vnets) {
            $subnetsNoUdr = $vnet.subnets | Where-Object {
                -not $_.routeTable -and
                $_.name -notin @('GatewaySubnet', 'AzureFirewallSubnet', 'AzureFirewallManagementSubnet', 'AzureBastionSubnet', 'RouteServerSubnet')
            }
            if ($subnetsNoUdr.Count -gt 0) {
                $score -= 5
                $findings += @{
                    Category    = "Network"
                    Severity    = "Medium"
                    Check       = "Subnets without UDR in VNet '$($vnet.name)'"
                    Detail      = "$($subnetsNoUdr.Count) subnet(s) lack forced-tunneling via UDR: $($subnetsNoUdr.name -join ', ')"
                    Remediation = "Attach UDRs to force egress through Azure Firewall. Required for CLZ v2 Walk phase."
                    Perspective = "CISO"
                }
            }
        }
    }

    # --- 6. DDoS Protection ---
    if ($vnets) {
        $vnetsNoDdos = $vnets | Where-Object { -not $_.ddosProtectionPlan }
        if ($vnetsNoDdos.Count -gt 0) {
            $score -= 5
            $findings += @{
                Category    = "Network"
                Severity    = "Medium"
                Check       = "VNets without DDoS Protection Plan"
                Detail      = "$($vnetsNoDdos.Count) VNet(s) lack DDoS Protection Plan"
                Remediation = "Enable Azure DDoS Network Protection on production VNets with public-facing workloads."
                Perspective = "CISO"
            }
        }
    }

    if ($findings.Count -eq 0) {
        $findings += @{
            Category    = "Network"
            Severity    = "Info"
            Check       = "Network security posture looks healthy"
            Detail      = "No critical network issues found"
            Remediation = "Continue monitoring with Network Watcher and NSG flow logs"
            Perspective = "CISO"
        }
    }

    return @{
        Score    = [Math]::Max(0, $score)
        Findings = $findings
        Stats    = @{
            NsgCount            = if ($nsgs) { $nsgs.Count } else { 0 }
            PublicIpCount       = if ($publicIps) { $publicIps.Count } else { 0 }
            FirewallCount       = if ($firewalls) { $firewalls.Count } else { 0 }
            PrivateEndpointCount = $peCount
            VNetCount           = if ($vnets) { $vnets.Count } else { 0 }
        }
    }
}

Export-ModuleMember -Function Test-NetworkSecurity
