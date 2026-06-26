# Storage Account Encryption with Managed HSM — Data Flow

## End-to-End Encryption Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    CONTROL PLANE (Setup)                                      │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                               │
│  ┌──────────────┐         ┌─────────────────────────┐         ┌──────────────────────┐      │
│  │  Platform     │ deploys │  User-Assigned          │  RBAC   │   Managed HSM         │      │
│  │  Engineer     │────────▶│  Managed Identity       │────────▶│   (FIPS 140-3 L3)    │      │
│  │  (Bicep/TF)  │         │  (for Storage ↔ HSM)    │         │                      │      │
│  └──────────────┘         └─────────────────────────┘         │  Roles assigned:     │      │
│         │                          │                           │  • Crypto Service    │      │
│         │ configures               │ assigned to               │    Encryption User   │      │
│         ▼                          ▼                           │    (wrap/unwrap only) │      │
│  ┌─────────────────────────────────────────┐                  │                      │      │
│  │  Storage Account                         │                  │  Key: RSA-HSM 3072   │      │
│  │  encryption.keySource = Microsoft.Keyvault│                  │  Auto-rotation: 90d  │      │
│  │  encryption.keyvaultproperties:          │                  │  Purge protection: ✓ │      │
│  │    keyVaultUri = https://<mhsm>.mhsm..  │                  └──────────────────────┘      │
│  │    keyName = storage-cmk-key             │                                                │
│  │    keyVersion = (empty = auto-rotate)    │                                                │
│  │  identity = <user-assigned MI>           │                                                │
│  └──────────────────────────────────────────┘                                                │
│                                                                                               │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Data Plane — Write Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              DATA PLANE — WRITE FLOW                                         │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                               │
│  ┌────────┐   HTTPS/TLS 1.2+    ┌──────────────────────────────────────────────────────┐    │
│  │ Client │ ──────────────────▶  │              STORAGE STAMP                           │    │
│  │ (App)  │  PUT Blob            │                                                      │    │
│  └────────┘                      │  ┌──────────────┐                                    │    │
│                                  │  │  Front-End   │  1. Auth (Entra ID / SAS)          │    │
│                                  │  │  Layer (FE)  │  2. Route to Partition Server       │    │
│                                  │  └──────┬───────┘                                    │    │
│                                  │         │                                             │    │
│                                  │         ▼                                             │    │
│                                  │  ┌──────────────┐                                    │    │
│                                  │  │  Partition   │  3. Generate random AES-256 DEK    │    │
│                                  │  │  Server (PS) │     (per blob or per 4MB chunk)    │    │
│                                  │  └──────┬───────┘                                    │    │
│                                  │         │                                             │    │
│                                  │         │ 4. Wrap DEK request                         │    │
│                                  │         │    (DEK plaintext → mHSM)                   │    │
│                                  │         ▼                                             │    │
│  ┌─────────────────────────────────────────────────────────────────────┐                │    │
│  │                      MANAGED HSM                                     │                │    │
│  │                                                                      │                │    │
│  │   ┌───────────────────────────────────────────────────────┐         │                │    │
│  │   │  5. HSM performs RSA-OAEP wrap operation:             │         │                │    │
│  │   │     EncryptedDEK = RSA_Wrap(KEK_private, DEK)        │         │                │    │
│  │   │                                                       │         │                │    │
│  │   │  • KEK private key NEVER leaves HSM boundary          │         │                │    │
│  │   │  • Operation logged in HSM audit log                  │         │                │    │
│  │   │  • Rate: ~1000 wrap ops/sec per HSM partition         │         │                │    │
│  │   └───────────────────────────────────────────────────────┘         │                │    │
│  │                         │                                            │                │    │
│  │                         │ Returns: EncryptedDEK (wrapped)            │                │    │
│  └─────────────────────────┼────────────────────────────────────────────┘                │    │
│                            │                                                             │    │
│                            ▼                                                             │    │
│                   ┌──────────────┐                                                       │    │
│                   │  Partition   │  6. Store EncryptedDEK in blob metadata               │    │
│                   │  Server      │  7. Encrypt blob data: AES-256-XTS(DEK, plaintext)   │    │
│                   └──────┬───────┘  8. Discard plaintext DEK from memory                │    │
│                          │                                                               │    │
│                          ▼                                                               │    │
│                   ┌──────────────────────────────────────────┐                           │    │
│                   │  Stream Layer (Extent Nodes)              │                           │    │
│                   │                                          │                           │    │
│                   │  9. Write encrypted extent to 3 replicas │                           │    │
│                   │     ┌─────┐  ┌─────┐  ┌─────┐           │                           │    │
│                   │     │ EN₁ │  │ EN₂ │  │ EN₃ │           │                           │    │
│                   │     │Rack1│  │Rack2│  │Rack3│           │                           │    │
│                   │     └─────┘  └─────┘  └─────┘           │                           │    │
│                   │                                          │                           │    │
│                   │  Written to disk: [EncryptedData] +      │                           │    │
│                   │                   [EncryptedDEK in meta]  │                           │    │
│                   └──────────────────────────────────────────┘                           │    │
│                                                                                          │    │
│  10. Return HTTP 201 Created to client                                                   │    │
│                                                                                          │    │
└──────────────────────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Data Plane — Read Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              DATA PLANE — READ FLOW                                          │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                               │
│  ┌────────┐   HTTPS/TLS 1.2+    ┌──────────────────────────────────────────────────────┐    │
│  │ Client │ ──────────────────▶  │              STORAGE STAMP                           │    │
│  │ (App)  │  GET Blob            │                                                      │    │
│  └────────┘                      │  ┌──────────────┐                                    │    │
│       ▲                          │  │  Front-End   │  1. Auth + route                   │    │
│       │                          │  └──────┬───────┘                                    │    │
│       │                          │         │                                             │    │
│       │                          │         ▼                                             │    │
│       │                          │  ┌──────────────┐                                    │    │
│       │                          │  │  Partition   │  2. Read EncryptedDEK from         │    │
│       │                          │  │  Server      │     blob metadata                  │    │
│       │                          │  └──────┬───────┘                                    │    │
│       │                          │         │                                             │    │
│       │                          │         │ 3. Unwrap DEK request                       │    │
│       │                          │         │    (EncryptedDEK → mHSM)                    │    │
│       │                          │         ▼                                             │    │
│       │    ┌───────────────────────────────────────────────────────────┐                 │    │
│       │    │                  MANAGED HSM                               │                 │    │
│       │    │                                                           │                 │    │
│       │    │  4. HSM performs RSA-OAEP unwrap:                         │                 │    │
│       │    │     DEK = RSA_Unwrap(KEK_private, EncryptedDEK)          │                 │    │
│       │    │                                                           │                 │    │
│       │    │  Returns: DEK (plaintext, in-memory only)                 │                 │    │
│       │    └───────────────────────────────────────────────────────────┘                 │    │
│       │                          │         │                                             │    │
│       │                          │         ▼                                             │    │
│       │                          │  ┌──────────────┐                                    │    │
│       │                          │  │  Stream      │  5. Read encrypted extent           │    │
│       │                          │  │  Layer       │  6. Decrypt: AES-256(DEK, cipher)  │    │
│       │                          │  └──────┬───────┘  7. Discard DEK from memory        │    │
│       │                          │         │                                             │    │
│       │                          └─────────┼─────────────────────────────────────────────┘    │
│       │                                    │                                                  │
│       │          8. Return plaintext       │                                                  │
│       │◀───────────────────────────────────┘                                                  │
│                                                                                               │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Key Rotation Flow (Automatic)

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           KEY ROTATION FLOW (Automatic)                                       │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                               │
│  ┌──────────────────┐    policy triggers     ┌──────────────────────┐                        │
│  │  mHSM Key        │ ────────────────────▶  │  New KEK version     │                        │
│  │  Rotation Policy │   (every 90 days)      │  generated in HSM    │                        │
│  │  (auto)          │                        │  (v2, v3, v4...)     │                        │
│  └──────────────────┘                        └──────────┬───────────┘                        │
│                                                          │                                    │
│                                                          │ Event Grid notification            │
│                                                          ▼                                    │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐       │
│  │  Storage Account (background re-wrap)                                              │       │
│  │                                                                                    │       │
│  │  For each blob DEK:                                                                │       │
│  │    1. Unwrap EncryptedDEK with OLD KEK version                                    │       │
│  │    2. Re-wrap DEK with NEW KEK version                                            │       │
│  │    3. Update blob metadata with new EncryptedDEK                                  │       │
│  │                                                                                    │       │
│  │  • Transparent to clients (no downtime)                                            │       │
│  │  • Data itself is NOT re-encrypted (DEK unchanged)                                 │       │
│  │  • Old KEK version retained until all DEKs re-wrapped                             │       │
│  │  • Process can take hours for large accounts                                       │       │
│  └───────────────────────────────────────────────────────────────────────────────────┘       │
│                                                                                               │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Infrastructure Double Encryption

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                        INFRASTRUCTURE DOUBLE ENCRYPTION                                       │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                               │
│            ┌─────────────────────────────────────────────────────────────┐                   │
│            │                     Blob Data (plaintext)                    │                   │
│            └─────────────────────────────┬───────────────────────────────┘                   │
│                                          │                                                    │
│                                          ▼                                                    │
│            ┌─────────────────────────────────────────────────────────────┐                   │
│            │  Layer 1: Service-level encryption                           │                   │
│            │  • DEK₁ (AES-256) wrapped by CMK in mHSM                   │                   │
│            │  • Customer-controlled key lifecycle                         │                   │
│            └─────────────────────────────┬───────────────────────────────┘                   │
│                                          │                                                    │
│                                          ▼                                                    │
│            ┌─────────────────────────────────────────────────────────────┐                   │
│            │  Layer 2: Infrastructure encryption                          │                   │
│            │  • DEK₂ (AES-256) wrapped by Microsoft-managed key          │                   │
│            │  • Different cipher algorithm or implementation              │                   │
│            │  • Protects against algorithm-level vulnerability            │                   │
│            └─────────────────────────────┬───────────────────────────────┘                   │
│                                          │                                                    │
│                                          ▼                                                    │
│            ┌─────────────────────────────────────────────────────────────┐                   │
│            │              Encrypted at rest on disk (Extent Node)         │                   │
│            │              Double-encrypted: Enc₂(Enc₁(data))             │                   │
│            └─────────────────────────────────────────────────────────────┘                   │
│                                                                                               │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Network Path — mHSM ↔ Storage

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                          NETWORK PATH — mHSM ↔ STORAGE                                       │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐    │
│  │                            Customer VNet (Hub)                                       │    │
│  │                                                                                      │    │
│  │   ┌─────────────────┐              ┌──────────────────┐                             │    │
│  │   │ Private Endpoint │              │ Private Endpoint  │                             │    │
│  │   │ (mHSM)          │              │ (Storage)         │                             │    │
│  │   │ 10.0.1.10       │              │ 10.0.2.20         │                             │    │
│  │   └────────┬────────┘              └────────┬──────────┘                             │    │
│  │            │                                 │                                        │    │
│  │            │   Private DNS Zones:            │                                        │    │
│  │            │   *.managedhsm.azure.net        │                                        │    │
│  │            │   *.blob.core.windows.net        │                                        │    │
│  │            │                                 │                                        │    │
│  └────────────┼─────────────────────────────────┼────────────────────────────────────────┘    │
│               │                                 │                                             │
│               │  Azure Backbone (private)       │                                             │
│               ▼                                 ▼                                             │
│  ┌─────────────────────┐          ┌────────────────────────────┐                             │
│  │   Managed HSM       │◀────────▶│   Storage Stamp            │                             │
│  │   (3 HSM partitions)│  wrap/   │   (Partition Server calls  │                             │
│  │                     │  unwrap  │    HSM for key ops)         │                             │
│  │   Region: West EU   │  via     │                            │                             │
│  │   Paired: North EU  │  mTLS    │   Traffic: internal Azure  │                             │
│  └─────────────────────┘          │   backbone (never public)  │                             │
│                                   └────────────────────────────┘                             │
│                                                                                               │
│  NOTE: Storage ↔ mHSM communication uses Azure-internal service-to-service path.            │
│  The Private Endpoint is for CUSTOMER access to mHSM (management, key creation).            │
│  Storage service itself uses trusted first-party service access (ARM-internal).              │
│                                                                                               │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Key Hierarchy Summary

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           KEY HIERARCHY SUMMARY                                               │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                               │
│  Level 0 (Root)     │  mHSM Security Domain                                                 │
│  ──────────────     │  • 3-of-5 quorum for recovery                                         │
│                     │  • Never exportable in plaintext                                       │
│                     │  • Defines HSM trust boundary                                          │
│                                                                                               │
│  Level 1 (KEK)     │  Customer RSA-HSM Key (in mHSM)                                       │
│  ──────────────     │  • RSA-3072 or RSA-4096                                               │
│                     │  • Auto-rotated every 90 days                                          │
│                     │  • Multiple versions retained                                          │
│                     │  • Wrap/unwrap only (no export)                                        │
│                                                                                               │
│  Level 2 (DEK)     │  AES-256-XTS Data Encryption Key                                      │
│  ──────────────     │  • Generated per storage account (or per-blob for large objects)       │
│                     │  • Stored encrypted (wrapped by KEK)                                   │
│                     │  • Plaintext exists only in-memory during I/O                          │
│                                                                                               │
│  Level 3 (Data)    │  Encrypted blob/file/table/queue data                                  │
│  ──────────────     │  • At rest on Extent Node SSDs                                        │
│                     │  • 3 replicas (LRS) or 6+ (ZRS/GRS)                                   │
│                     │  • Inaccessible without DEK → KEK → mHSM                              │
│                                                                                               │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Failure & Revocation Scenarios

| Scenario | Impact |
|----------|--------|
| **mHSM unavailable** (region outage) | Storage reads/writes FAIL (can't unwrap/wrap DEKs). Data intact but inaccessible until HSM recovers. |
| **KEK disabled in mHSM** | All wrap/unwrap ops denied. Storage returns 403. Re-enable key to restore access (instant). |
| **KEK deleted (soft-delete)** | Access denied. Recover key within retention period (7-90 days) to restore. After purge → PERMANENT DATA LOSS. |
| **KEK purged** (purge protection OFF) | PERMANENT CRYPTO-SHRED. Data mathematically irrecoverable. No backup, no Microsoft support path. |
| **Managed Identity removed** | Storage can't authenticate to mHSM. Reads/writes fail. Re-assign identity + RBAC role to restore. |
| **RBAC role revoked on mHSM** | Immediate denial of wrap/unwrap. Storage I/O fails. Re-assign Crypto Service Encryption User to restore. |
| **Key rotation (normal)** | Transparent. Old version used until background re-wrap completes. No data loss or downtime. |
