# KlaudTrace

```
 _  __ _                 _ _____                     
| |/ /| |               | |_   _|                    
| ' / | | __ _ _   _  __| | | |_ __ __ _  ___ ___    
|  <  | |/ _` | | | |/ _` | | | '__/ _` |/ __/ _ \   
| . \ | | (_| | |_| | (_| | | | | | (_| | (_|  __/   
|_|\_\|_|\__,_|\__,_|\__,_| |_/_|  \__,_|\___\___|   
AWS Incident Reconstruction for Fintech Environments
```

[![Go Version](https://img.shields.io/badge/go-1.22+-blue.svg?style=flat-square)](https://golang.org)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg?style=flat-square)](https://github.com/klaudtrace/klaudtrace)
[![Determinism](https://img.shields.io/badge/analysis-100%25%20deterministic-blueviolet.svg?style=flat-square)](https://github.com/klaudtrace/klaudtrace)
[![Offline First](https://img.shields.io/badge/runtime-offline--first-success.svg?style=flat-square)](https://github.com/klaudtrace/klaudtrace)
[![License](https://img.shields.io/badge/license-Apache--2.0-lightgrey.svg?style=flat-square)](LICENSE)

> Turn thousands of raw AWS CloudTrail records into an airtight, defensible incident reconstruction. No hallucinations. No guessing. Zero theoretical noise.

---

## The 3 AM Cloud Incident Problem

When an alert fires in your AWS environment, every engineer and executive asks the exact same question:

> **"What did the attacker actually touch?"**

Most cloud security platforms respond with a 50-page theoretical graph showing everything the compromised role *could* have done. They calculate a terrifying theoretical blast radius, predict four hypothetical privilege-escalation loops, and leave you staring at 50,000 lines of raw CloudTrail JSON.

Turning raw log evidence into an audit-proof timeline of actual events is still painfully manual.

**KlaudTrace automates the first layer of investigation.**

It ingests local CloudTrail JSON, correlates temporary STS sessions back to their originating identities, classifies targeted assets by financial sensitivity, and reconstructs the verified sequence of actions.

```
CloudTrail Logs (JSON / JSONL / GZ)
              |
              v
     Event Normalization
              |
              v
 Identity & STS Session Tracking
              |
              v
Resource & Fintech Classification
              |
              v
  Deterministic Chronology
              |
              v
   Observed Activity Path
              |
              v
     Actual Impact Engine
              |
              v
  Terminal / Markdown / JSON Report
```

---

## The Iron Rule: Evidence vs Speculation

In security incident response, credibility is everything. The moment an automated tool claims *"the attacker exfiltrated all customer records"* without evidence, engineers stop trusting it and compliance teams panic unnecessarily.

KlaudTrace enforces a strict four-tier confidence taxonomy:

```
[OBSERVED]     --> Explicitly witnessed in a single event record
[CORRELATED]   --> Tied across events via temporary credentials (accessKeyId, session ARN)
[INFERRED]     --> Plausible operational relationship (e.g. S3 read immediately followed by KMS key decrypt)
[UNDETERMINED] --> Session exists, but assumption event is outside the log window (never faked!)
```

### Contrast Table

| Raw Activity | Bad Security Tool Claim | KlaudTrace Defensible Output |
| :--- | :--- | :--- |
| `s3:GetObject` on `payflow-transaction-data` | "Attacker exfiltrated critical transaction data!" | **[OBSERVED]** Access to critical transaction data observed. Exfiltration cannot be established from CloudTrail alone. |
| `kms:Decrypt` on `payment-token-key` | "Customer credit cards compromised!" | **[OBSERVED]** Cryptographic decryption requested on payment credential key. Decrypted plaintext content is not captured in CloudTrail. |
| `sts:AssumeRole` without prior event in log | "Attacker compromised admin credentials!" | **[UNDETERMINED]** Assumed-role session active. Parent assumption event was not present in the ingested log window. |
| `s3:GetObject` bucket A + `s3:PutObject` bucket B | "Data stolen to unauthorized external bucket!" | **[CORRELATED]** Cross-bucket data movement observed within the same session. |

---

## Demo Environment: PayFlow

KlaudTrace comes with synthetic scenarios based on **PayFlow**, a fictional modern fintech:

```
Customer
   |
API Gateway
   |
Payment Service  <--- (Compromised DevJoe assumes PaymentServiceRole)
   |
   +---> S3: payflow-transaction-data  [CRITICAL / transaction_data]
   |
   +---> KMS: payment-token-key        [CRITICAL / payment_credentials]
   |
   +---> S3: payflow-account-data      [HIGH / account_data]
   |
   +---> SQS: payment-events           [HIGH / payment_data]
```

### The Flagship Incident (Scenario 1)

An engineer identity (`DevJoe`) assumes `PaymentServiceRole`. Over the next five minutes, that session fetches a transaction batch, calls KMS to decrypt the token key, and accesses account routing tables.

Running `klaudtrace analyze`:

```bash
$ klaudtrace analyze fixtures/cloudtrail/scenario1/events.json
```

```
==================================================
             KLAUDTRACE INCIDENT ANALYSIS         
==================================================

Time Window:
  2026-09-15 14:20:00 UTC to 2026-09-15 14:25:05 UTC (5m5s)
  Events: 4 ingested | 0 errors/denials

Identities:
  - DevJoe (IAMUser)
  - PaymentServiceRole/DevJoe (AssumedRole)

Affected Assets:
  - alias/payment-token-key (kms:key / payment_credentials - CRITICAL)
  - payflow-account-data/2026/09/ledger-accounts.json (s3:object / account_data - HIGH)
  - payflow-transaction-data/2026/09/settlement-batch-001.csv (s3:object / transaction_data - CRITICAL)

Observed Attack / Activity Paths:
  [path-1] Observed Path #1: DevJoe activity (Confidence: OBSERVED)
    DevJoe (IAMUser:DevJoe)
      ↓ sts:AssumeRole
      ↓ PaymentServiceRole (iam:role)

  [path-2] Observed Path #2: PaymentServiceRole/DevJoe activity (Confidence: CORRELATED)
    DevJoe (IAMUser:DevJoe)
      ↓ PaymentServiceRole (AssumeRole -> PaymentServiceRole)
      ↓ PaymentServiceRole/DevJoe (Session: DevJoe)
      ↓ s3:GetObject
      ↓ payflow-transaction-data/2026/09/settlement-batch-001.csv (s3:object [transaction_data - CRITICAL])
      ↓ kms:Decrypt
      ↓ alias/payment-token-key (kms:key [payment_credentials - CRITICAL])
      ↓ s3:GetObject
      ↓ payflow-account-data/2026/09/ledger-accounts.json (s3:object [account_data - HIGH])

Impact Findings:
  - [CRITICAL] Observed Access to Sensitive Fintech Data [OBSERVED]
    Details:     CloudTrail evidence confirms access to sensitive resources: payflow-transaction-data/2026/09/settlement-batch-001.csv (transaction_data / CRITICAL), payflow-account-data/2026/09/ledger-accounts.json (account_data / HIGH).
    Evidence:    Direct s3:GetObject API calls recorded with success response.
    Limitations: The supplied CloudTrail evidence establishes resource access. It does not by itself establish data exfiltration beyond the AWS environment.
    Source Refs: 2 event(s)

  - [CRITICAL] Observed Cryptographic Decryption of Sensitive Keys [OBSERVED]
    Details:     CloudTrail evidence records 1 kms:Decrypt operations involving cryptographic keys.
    Evidence:    Direct kms:Decrypt API call successfully processed.
    Limitations: Evidence confirms decryption was performed; decrypted plain-text content is not stored in CloudTrail logs.
    Source Refs: 1 event(s)

Assessment:
  "CloudTrail evidence establishes activity involving identities [DevJoe, PaymentServiceRole/DevJoe]. Access or modification to classified resources was observed: [alias/payment-token-key (payment_credentials / CRITICAL), payflow-account-data/2026/09/ledger-accounts.json (account_data / HIGH), payflow-transaction-data/2026/09/settlement-batch-001.csv (transaction_data / CRITICAL)]. The supplied CloudTrail evidence by itself does not establish that data was exfiltrated beyond the AWS environment."

==================================================
```

---

## Command Center

KlaudTrace is CLI-first, offline-first, and requires zero cloud credentials to run.

### 1. Reconstruct Incident
```bash
klaudtrace analyze <logfile>
```
Produces the executive summary: identities, timeline window, affected classified assets, reconstructed paths, and concrete impact findings.

### 2. Chronological Timeline
```bash
klaudtrace timeline <logfile>
```
Outputs a sequential, human-readable timeline showing each API call, caller session, targeted resource, execution status, and source IP.

### 3. Visualized Activity Paths
```bash
klaudtrace paths <logfile>
```
Displays identity chains and sequential resource interactions with confidence indicators.

### 4. Audit-Ready Reports
```bash
# GitHub-flavored Markdown with interactive Mermaid flowcharts
klaudtrace report <logfile> --format=markdown --output=incident.md

# Machine-readable JSON for integration into internal tooling
klaudtrace report <logfile> --format=json --output=incident.json
```

---

## Included Test Scenarios

The `fixtures/cloudtrail/` directory includes synthetic scenarios covering distinct security patterns:

| Scenario | File | Pattern | Key Verification |
| :--- | :--- | :--- | :--- |
| **Scenario 1** | `fixtures/cloudtrail/scenario1/events.json` | Sensitive Data Access | `AssumeRole` $\rightarrow$ S3 transaction read $\rightarrow$ KMS decrypt $\rightarrow$ account read. Traces back to root `DevJoe`. |
| **Scenario 2** | `fixtures/cloudtrail/scenario2/events.json` | KMS Token Key Misuse | Ad-hoc session calls `kms:Decrypt` directly on payment credentials. |
| **Scenario 3** | `fixtures/cloudtrail/scenario3/events.json` | Privilege Escalation & Evasion | `ConsoleLogin` $\rightarrow$ `CreateRole` $\rightarrow$ `PutRolePolicy` $\rightarrow$ `AssumeRole` $\rightarrow$ `DeleteTrail`. Identifies trail deletion as destructive. |
| **Scenario 4** | `fixtures/cloudtrail/scenario4/events.json` | Cross-Bucket Data Movement | Paired `GetObject` from bucket A and `PutObject` to bucket B within the same session. |
| **Benign** | `fixtures/cloudtrail/benign/events.json` | Routine Operations | Normal EventBridge scheduler and worker queues. Confirms zero false positive alerts. |

---

## Fintech Asset Classification Engine

Generic cloud tools report:
```
s3:GetObject -> S3 Bucket
```

KlaudTrace reports:
```
s3:GetObject -> payflow-transaction-data (transaction_data / CRITICAL)
```

### Built-in Categories

- `transaction_data` (`CRITICAL`): Settlement records, ledger archives, transaction logs
- `payment_credentials` (`CRITICAL`): Token keys, cardholder data keys, encryption keys
- `customer_pii` (`CRITICAL`): Passports, identity files, personal records
- `kyc_data` (`CRITICAL`): KYC compliance documents
- `kyb_data` (`HIGH`): Corporate verification records
- `account_data` (`HIGH`): Account balances and routing data
- `audit_data` (`HIGH`): CloudTrail archives, compliance logs
- `application_logs` (`LOW`): Routine application logs

### Custom Configurations

Pass your own rules via `--config <path>`:

```json
{
  "rules": [
    {
      "pattern": "acme-settlement.*",
      "domain": "fintech",
      "asset_type": "transaction_data",
      "sensitivity": "CRITICAL",
      "description": "Daily settlement files"
    },
    {
      "pattern": "acme-cards-key",
      "domain": "fintech",
      "asset_type": "payment_credentials",
      "sensitivity": "CRITICAL",
      "description": "Card encryption master key"
    }
  ]
}
```

---

## Determinism & Performance

KlaudTrace is built for speed and determinism:

- **100% Deterministic**: Running the same file 100 times produces byte-for-byte identical output.
- **Zero Hallucinations**: Analysis is performed by deterministic Go algorithms, not an LLM guessing in a loop.
- **Memory Efficient**: Streaming and buffered ingestion parses large log records without bloating memory.
- **Offline & Private**: Never phones home. Never leaks CloudTrail payloads to external endpoints.

Run the test suite:
```bash
go test -v -race ./...
```

---

## Roadmap

- [x] **Phase 1: Post-Attack Analysis MVP** (Deterministic reconstruction, session tracking, fintech classification, multi-format reports)
- [ ] **Phase 2: Pre-Attack Analysis** (IAM permission mapping, theoretical attack paths, blast-radius baselines)
- [ ] **Phase 3: Potential vs. Actual Delta** (Diffing what the identity could do vs what it actually executed)
- [ ] **Phase 4: Live CloudTrail Stream Ingestion** (Read-only S3 log queue / EventBridge ingestion)
- [ ] **Phase 5: Model Context Protocol (MCP)** (Native server for Claude, Cursor, and DFIR copilots)

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
