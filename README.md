# KlaudTrace

> **An AWS post-attack analysis tool for reconstructing cloud incidents from evidence and determining what actually happened.**

---

## Overview

Cloud incidents can generate thousands of AWS API events across identities, roles, services, and resources.

The first problem after a suspected compromise is not:

> "What *could* this attacker have done?"

It is:

> **"What did the attacker actually do?"**

**KlaudTrace** focuses on answering that question.

Given AWS CloudTrail activity, KlaudTrace analyzes and correlates events to reconstruct an incident by identifying:

- Which identity was involved
- What actions were performed
- Which AWS resources were targeted
- When the activity occurred
- How identities and sessions changed
- What sequence of actions occurred
- What attack path can be observed from the evidence
- What impact can be established from the observed activity

The project will eventually expand into **pre-attack attack-surface and blast-radius analysis**, but that is intentionally outside the current scope.

---

# Current Phase — Post-Attack Analysis

```mermaid
flowchart LR
    A[CloudTrail Logs]
    --> B[Event Normalization]

    B --> C[Identity Identification]

    C --> D[API Activity]

    D --> E[Resource Mapping]

    E --> F[Timeline Reconstruction]

    F --> G[Observed Attack Path]

    G --> H[Actual Impact]
