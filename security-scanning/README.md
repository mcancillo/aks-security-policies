# CLZ v2 Security Maturity Scanner

Scans one or more Azure subscriptions against **Confidential Landing Zone (CLZ) v2** security and governance rules. Generates an HTML web report with maturity scoring.

## What It Checks

### 🔐 RBAC & Roles
- Excessive privileged role assignments (Owner/Contributor/UAA) at subscription scope
- Direct user assignments instead of Entra ID groups
- Legacy classic administrator roles (CoAdministrator/ServiceAdministrator)
- Custom roles with wildcard (`*`) permissions
- Service principals with Owner role
- External guest (B2B) user assignments
- **Cross-environment sprawl**: identities spanning both DTA and PRD subscriptions

### 🌐 Network Security
- NSGs with dangerous inbound allow rules (Internet → 22/3389/80/443/*)
- Subnets without NSGs attached
- Public IP exposure and orphaned IPs
- Azure Firewall presence (CLZ v2 Walk/Run requirement)
- Private Endpoint coverage for PaaS services
- UDR enforcement for forced-tunneling
- DDoS Protection Plan coverage

### 🛡️ Extended Security
- Microsoft Defender for Cloud plan status (per resource type)
- Key Vault: soft-delete, purge protection, public access, RBAC mode
- Storage accounts: public blob access, TLS version, infrastructure encryption
- Subscription activity log diagnostic settings
- Azure Policy compliance state
- Managed identity adoption on App Services

### 🎭 Perspectives
Every finding is tagged with a perspective:
- **🎭 Hacker** — exploitability, attack surface, lateral movement
- **🏢 CISO** — governance, compliance, risk management, audit readiness

## Prerequisites

- **Azure CLI** (`az`) installed and logged in
- **PowerShell 7+** (cross-platform)
- Required RBAC roles on target subscriptions:
  - `Reader` (minimum for resource enumeration)
  - `Security Reader` (for Defender for Cloud status)

## Usage

```powershell
# Scan specific subscriptions
.\scan-security.ps1 -SubscriptionIds "aaaa-bbbb-cccc", "dddd-eeee-ffff"

# Scan ALL accessible subscriptions
.\scan-security.ps1 -AllSubscriptions

# With environment mapping (enables DTA ↔ PRD cross-env analysis)
.\scan-security.ps1 -SubscriptionIds "sub1","sub2" `
    -EnvironmentMap @{ "sub1" = "DTA"; "sub2" = "PRD" }

# Custom output path
.\scan-security.ps1 -AllSubscriptions -OutputPath "C:\reports\security-report.html"
```

## Output

An HTML report is generated with:
- **Overall maturity score** mapped to CLZ phase (Pre-Crawl / Crawl / Walk / Run)
- **KPI counters** for Critical, High, Medium, and Info findings
- **Per-subscription breakdown** with individual RBAC, Network, and Extended scores
- **Detailed findings table** with severity, category, description, remediation, and perspective

## Maturity Scoring

| Score  | CLZ Phase  | Description |
|--------|-----------|-------------|
| 80-100 | **Run**   | Full policy enforcement, confidential workloads ready |
| 60-79  | **Walk**  | Networking and security operations in place |
| 40-59  | **Crawl** | Baseline identity and policies established |
| 0-39   | **Pre-Crawl** | Significant governance gaps |

## Project Structure

```
security-scanning/
├── scan-security.ps1                  # Main orchestrator
├── README.md                          # This file
└── modules/
    ├── check-rbac.psm1                # RBAC & roles checks
    ├── check-network.psm1             # Network security checks
    ├── check-extended-security.psm1   # Defender, KV, storage, policy checks
    └── report-generator.psm1          # HTML report generator
```
