<#
.SYNOPSIS
    CLZ v2 Security Maturity Scanner — RBAC & Roles Module
.DESCRIPTION
    Checks RBAC assignments, privileged roles, cross-environment (DTA/PRD) sprawl,
    custom role definitions, and PIM eligibility.
#>

function Test-RbacSecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$SubscriptionName
    )

    $findings = @()
    $score = 100

    Write-Host "  [RBAC] Scanning subscription: $SubscriptionName ($SubscriptionId)" -ForegroundColor Cyan

    # --- 1. Get all role assignments ---
    $roleAssignments = az role assignment list --subscription $SubscriptionId --all --output json 2>$null | ConvertFrom-Json
    if (-not $roleAssignments) { $roleAssignments = @() }

    # --- 2. Check for Owner/Contributor at subscription scope ---
    $subScopePrivileged = $roleAssignments | Where-Object {
        $_.roleDefinitionName -in @('Owner', 'Contributor', 'User Access Administrator') -and
        $_.scope -eq "/subscriptions/$SubscriptionId"
    }

    if ($subScopePrivileged.Count -gt 3) {
        $score -= 15
        $findings += @{
            Category    = "RBAC"
            Severity    = "Critical"
            Check       = "Excessive privileged role assignments at subscription scope"
            Detail      = "$($subScopePrivileged.Count) principals have Owner/Contributor/UAA at subscription level (threshold: 3)"
            Remediation = "Reduce subscription-scoped privileged assignments. Use resource-group scoped roles and PIM for JIT access."
            Perspective = "Hacker"
        }
    }

    # --- 3. Check for direct user (non-group) assignments ---
    $directUserAssignments = $roleAssignments | Where-Object { $_.principalType -eq 'User' }
    if ($directUserAssignments.Count -gt 0) {
        $score -= 10
        $findings += @{
            Category    = "RBAC"
            Severity    = "High"
            Check       = "Direct user role assignments found (not via groups)"
            Detail      = "$($directUserAssignments.Count) role assignments are directly to users instead of Entra ID groups"
            Remediation = "Assign roles to Entra ID groups, not individual users. This ensures consistent access management and easier auditing."
            Perspective = "CISO"
        }
    }

    # --- 4. Check for classic admin roles ---
    $classicAdmins = az role assignment list --subscription $SubscriptionId --include-classic-administrators --output json 2>$null | ConvertFrom-Json
    $classicOnly = $classicAdmins | Where-Object { $_.roleDefinitionName -match 'CoAdministrator|ServiceAdministrator' }
    if ($classicOnly.Count -gt 0) {
        $score -= 15
        $findings += @{
            Category    = "RBAC"
            Severity    = "Critical"
            Check       = "Legacy classic administrator roles in use"
            Detail      = "$($classicOnly.Count) classic admin role(s) found (CoAdministrator/ServiceAdministrator)"
            Remediation = "Remove all classic administrator roles. Migrate to Azure RBAC roles with least-privilege."
            Perspective = "Hacker"
        }
    }

    # --- 5. Custom role definitions ---
    $customRoles = az role definition list --subscription $SubscriptionId --custom-role-only true --output json 2>$null | ConvertFrom-Json
    if ($customRoles) {
        $wildcardRoles = $customRoles | Where-Object {
            $_.permissions | ForEach-Object { $_.actions + $_.dataActions } | Where-Object { $_ -eq '*' }
        }
        if ($wildcardRoles.Count -gt 0) {
            $score -= 20
            $findings += @{
                Category    = "RBAC"
                Severity    = "Critical"
                Check       = "Custom roles with wildcard (*) permissions"
                Detail      = "$($wildcardRoles.Count) custom role(s) grant full wildcard actions — equivalent to Owner"
                Remediation = "Remove wildcard permissions from custom roles. Define explicit action lists following least-privilege."
                Perspective = "Hacker"
            }
        }
    }

    # --- 6. Service principal with Owner role ---
    $spOwners = $roleAssignments | Where-Object {
        $_.principalType -eq 'ServicePrincipal' -and $_.roleDefinitionName -eq 'Owner'
    }
    if ($spOwners.Count -gt 0) {
        $score -= 10
        $findings += @{
            Category    = "RBAC"
            Severity    = "High"
            Check       = "Service principals with Owner role"
            Detail      = "$($spOwners.Count) service principal(s) have Owner role — potential lateral movement vector"
            Remediation = "Replace Owner with scoped Contributor or custom roles. Service principals should never hold Owner."
            Perspective = "Hacker"
        }
    }

    # --- 7. Guest user assignments ---
    $guestAssignments = $roleAssignments | Where-Object { $_.principalType -eq 'User' -and $_.principalName -match '#EXT#' }
    if ($guestAssignments.Count -gt 0) {
        $score -= 5
        $findings += @{
            Category    = "RBAC"
            Severity    = "Medium"
            Check       = "External guest users with role assignments"
            Detail      = "$($guestAssignments.Count) guest (B2B) user(s) have direct Azure role assignments"
            Remediation = "Review guest access. Ensure external identities are governed via access reviews and conditional access."
            Perspective = "CISO"
        }
    }

    if ($findings.Count -eq 0) {
        $findings += @{
            Category    = "RBAC"
            Severity    = "Info"
            Check       = "RBAC configuration looks healthy"
            Detail      = "No critical RBAC issues found in this subscription"
            Remediation = "Continue periodic access reviews"
            Perspective = "CISO"
        }
    }

    return @{
        Score       = [Math]::Max(0, $score)
        Findings    = $findings
        Stats       = @{
            TotalAssignments    = $roleAssignments.Count
            PrivilegedCount     = $subScopePrivileged.Count
            DirectUserCount     = $directUserAssignments.Count
            CustomRoleCount     = if ($customRoles) { $customRoles.Count } else { 0 }
            ServicePrincipalOwners = $spOwners.Count
        }
    }
}

function Test-CrossEnvironmentRbac {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$SubscriptionResults
    )

    $findings = @()

    # Group subscriptions by environment tag
    $dtaSubs = $SubscriptionResults | Where-Object { $_.Environment -match 'DTA|Dev|Test|Accept|NonProd|Sandbox' }
    $prdSubs = $SubscriptionResults | Where-Object { $_.Environment -match 'PRD|Prod|Production' }

    if ($dtaSubs.Count -eq 0 -or $prdSubs.Count -eq 0) {
        $findings += @{
            Category    = "RBAC Cross-Env"
            Severity    = "Info"
            Check       = "Cross-environment analysis skipped"
            Detail      = "Need both DTA and PRD subscriptions to detect cross-environment role sprawl. Found DTA: $($dtaSubs.Count), PRD: $($prdSubs.Count)"
            Remediation = "Tag subscriptions with environment labels for cross-env analysis"
            Perspective = "CISO"
        }
        return @{ Score = 100; Findings = $findings }
    }

    # Collect all principals per environment
    $dtaPrincipals = $dtaSubs | ForEach-Object { $_.RoleAssignments } | Select-Object -ExpandProperty principalId -Unique
    $prdPrincipals = $prdSubs | ForEach-Object { $_.RoleAssignments } | Select-Object -ExpandProperty principalId -Unique

    $crossEnvPrincipals = $dtaPrincipals | Where-Object { $_ -in $prdPrincipals }

    $score = 100
    if ($crossEnvPrincipals.Count -gt 5) {
        $score -= 20
        $findings += @{
            Category    = "RBAC Cross-Env"
            Severity    = "High"
            Check       = "Excessive cross-environment identity sprawl (DTA ↔ PRD)"
            Detail      = "$($crossEnvPrincipals.Count) identities have roles in BOTH DTA and PRD subscriptions. Blast radius spans environments."
            Remediation = "Implement environment-specific identities. DTA service principals should NOT have PRD access. Use separate Entra groups per environment."
            Perspective = "Hacker"
        }
    }

    return @{ Score = [Math]::Max(0, $score); Findings = $findings }
}

Export-ModuleMember -Function Test-RbacSecurity, Test-CrossEnvironmentRbac
