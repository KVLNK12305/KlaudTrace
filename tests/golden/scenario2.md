# KlaudTrace Incident Reconstruction Report

## Executive Summary

> **Assessment:** CloudTrail evidence establishes activity involving identities [Alice, PaymentServiceRole/Alice-AdHoc]. Access or modification to classified resources was observed: [alias/payment-token-key (payment_credentials / CRITICAL)]. The supplied CloudTrail evidence by itself does not establish that data was exfiltrated beyond the AWS environment.

| Metric | Value |
| :--- | :--- |
| **Time Window** | `2026-09-15T15:00:00Z` to `2026-09-15T15:02:30Z` (2m30s) |
| **Total Log Records** | `2` |
| **Error / Denied Events** | `0` |
| **Identities Tracked** | `2` |
| **Classified Assets Affected** | `1` |

## Identified Principals & Sessions

| Principal / Session | Type | Account ID | Session Issuer | Lineage Confidence |
| :--- | :--- | :--- | :--- | :--- |
| `Alice` | IAMUser | `123456789012` | `-` | **OBSERVED** |
| `PaymentServiceRole/Alice-AdHoc` | AssumedRole | `123456789012` | `PaymentServiceRole` | **CORRELATED** |

## Affected Classified Assets

| Resource | Type | Domain | Asset Type | Sensitivity |
| :--- | :--- | :--- | :--- | :--- |
| `alias/payment-token-key` | `kms:key` | fintech | `payment_credentials` | **CRITICAL** |

## Observed Activity & Attack Paths

### Observed Path #1: Alice activity

**Confidence Level:** `OBSERVED`  
**Summary:** Identity Alice executed 1 observed actions across 1 resources.

```mermaid
flowchart TD
    N0_Alice["Alice<br/><small>IAMUser:Alice</small>"]
    N1_sts_AssumeRole["sts:AssumeRole"]
    N0_Alice --> N1_sts_AssumeRole
    N2_PaymentServiceRole["PaymentServiceRole<br/><small>iam:role</small>"]
    N1_sts_AssumeRole --> N2_PaymentServiceRole
```

### Observed Path #2: PaymentServiceRole/Alice-AdHoc activity

**Confidence Level:** `CORRELATED`  
**Summary:** Identity PaymentServiceRole/Alice-AdHoc executed 1 observed actions across 1 resources.

```mermaid
flowchart TD
    N0_Alice["Alice<br/><small>IAMUser:Alice</small>"]
    N1_PaymentServiceRole["PaymentServiceRole<br/><small>AssumeRole -> PaymentServiceRole</small>"]
    N0_Alice --> N1_PaymentServiceRole
    N2_PaymentServiceRole_A["PaymentServiceRole/Alice-AdHoc<br/><small>Session: Alice-AdHoc</small>"]
    N1_PaymentServiceRole --> N2_PaymentServiceRole_A
    N3_kms_Decrypt["kms:Decrypt"]
    N2_PaymentServiceRole_A --> N3_kms_Decrypt
    N4_alias_payment_token_["alias/payment-token-key<br/><small>kms:key [payment_credentials - CRITICAL]</small>"]
    N3_kms_Decrypt --> N4_alias_payment_token_
```

## Impact Findings

### [CRITICAL] Observed Cryptographic Decryption of Sensitive Keys

- **Description:** CloudTrail evidence records 1 kms:Decrypt operations involving cryptographic keys.
- **Evidence Basis:** Direct kms:Decrypt API call successfully processed.
- **Confidence:** `OBSERVED`
- **Limitations:** Evidence confirms decryption was performed; decrypted plain-text content is not stored in CloudTrail logs.

