# Automated PCI-DSS Compliance Checker for AWS

A Python-based tool that scans an AWS environment against 10 PCI-DSS-inspired security controls and generates a compliance report. The scanner runs on a schedule via AWS Lambda and EventBridge, uploading results to S3 automatically, with no manual intervention required after deployment.

Each check maps to a real PCI-DSS requirement number, and the tool was built and tested against intentionally misconfigured AWS resources to verify it catches real-world failures, not just theoretical ones.

<!-- IMAGE: HTML compliance report screenshot (the polished one with summary cards) -->

---

## Why This Project

PCI-DSS compliance isn't optional for any company that stores, processes, or transmits credit card data, it's enforced by the card networks and payment processors, and failing it can mean fines or loss of the ability to process payments at all.

In practice, most PCI-DSS violations in the wild aren't sophisticated attacks, they're misconfigurations: a public S3 bucket someone forgot about, a security group left open during testing, IAM users without MFA, stale access keys. Traditional compliance audits catch this stuff quarterly or annually at best. This project automates that detection so drift gets caught daily instead of once a year.

---

## Architecture

```
EventBridge (daily schedule)
        │
        ▼
   Lambda Function ──── boto3 ────► AWS Resources (S3, EC2, IAM, RDS, CloudTrail, VPC)
        │
        ▼
  HTML Report ──► S3 Report Bucket
```

The scanner runs as a Lambda function, triggered daily by an EventBridge scheduled rule. It queries AWS via boto3 across 10 controls, generates a formatted HTML report, and uploads it to a dedicated S3 bucket. The Lambda runs under a custom IAM role scoped to least-privilege, read-only access to the resources it scans, plus write access to only the report bucket.

---

## The 10 Controls

| # | Control | PCI-DSS Requirement |
|---|---------|---------------------|
| 1 | S3 bucket public access | 1.3 / 7.1 |
| 2 | S3 bucket encryption | 3.4 |
| 3 | EBS volume encryption | 3.4 |
| 4 | Security groups (high-risk ports open to 0.0.0.0/0) | 1.2 / 1.3 |
| 5 | IAM MFA enrollment | 8.3 |
| 6 | IAM access key age (90-day rotation) | 8.2.4 |
| 7 | RDS encryption & public accessibility | 3.4 / 1.3 |
| 8 | CloudTrail logging (active, multi-region) | 10.1 / 10.2 |
| 9 | VPC flow logs | 10.1 |
| 10 | IAM account password policy | 8.2 |

---

## Project Phases

### Phase 1: Environment Setup

Created a dedicated IAM user (`pcidss-scanner-admin`) instead of working as root, configured the AWS CLI, and deliberately built three misconfigured test resources so the scanner would have real failures to catch:

- A public S3 bucket (block-public-access disabled, public-read policy attached)
- A security group with SSH (port 22) open to 0.0.0.0/0
- An unencrypted EBS volume

CloudTrail and VPC flow logs were left disabled on purpose, giving the scanner a genuine "before" state to detect.

<!-- IMAGE: IAM users list (pcidss-scanner-admin) -->
<!-- IMAGE: S3 permissions overview showing "Block all public access: Off" -->
<!-- IMAGE: S3 bucket policy JSON (public read) -->
<!-- IMAGE: Security group inbound rules (SSH open to 0.0.0.0/0) -->
<!-- IMAGE: EBS volume details showing "Not encrypted" -->

### Phase 2: Control Checks

Wrote all 10 control functions in `checks.py` using boto3. Each function queries the relevant AWS resource(s), evaluates them against the compliance rule, and returns a structured result (`resource`, `status`, `detail`, `pci_requirement`).

Notable finding during this phase: the S3 encryption check initially "passed" unexpectedly, it turned out AWS enables SSE-S3 encryption by default on all new buckets since January 2023, so the check was working correctly, my assumption about the test setup was just outdated. Kept as a documented nuance rather than treated as a bug.

<!-- IMAGE: Terminal output of all 10 checks running in checks.py -->

### Phase 3: Reporting Layer

Built `main.py` to run all 10 checks together and aggregate results, plus a compliance score summary (total/passed/failed/percentage). Also built `report.py`, which generates a styled, standalone HTML report with color-coded pass/fail rows and summary cards.

Caught and fixed a real bug here: the compliance percentage was calculating as 0% due to a parentheses error (`round(passed/total) * 100` instead of `round((passed/total) * 100)`), rounding the fraction to a whole number before multiplying instead of after.

<!-- IMAGE: main.py terminal output with compliance summary block -->

### Phase 4: Automation (Lambda + EventBridge)

Packaged the scanner into a Lambda function (`lambda_function.py`) with its own least-privilege IAM role, granting only the specific read permissions each check needs plus write access to the report bucket, no admin-level access. Deployed via AWS CLI, tested with a manual invocation to confirm the full pipeline (scan → report → S3 upload) worked end to end, then wired it to an EventBridge rule running on a 1-day fixed-rate schedule.

<!-- IMAGE: Lambda invoke + S3 upload confirmation (terminal) -->
<!-- IMAGE: EventBridge rule review page showing schedule + target -->



## Known Limitations

- The S3 public access check flags any bucket without full block-public-access enabled, regardless of whether a public policy is actually attached. This means it can report a bucket as "failing" even if nothing is currently exposed, it's measuring hardening posture, not just active exposure. A more advanced version would separate "not hardened" from "actively public" as different severities.
- RDS and password policy checks return a clean PASS on accounts with no RDS instances or no custom password policy in place. This is correct behavior (avoids false failures on N/A resources) but worth noting when interpreting a 100% RDS score, it may just mean nothing exists to fail.
- PCI-DSS requirement numbering referenced here follows v4.0.

---

## Tech Stack

- Python 3.12, boto3
- AWS: S3, EC2, IAM, EBS, RDS, CloudTrail, VPC, Lambda, EventBridge
- Local development: Windows, PowerShell, VS Code

---

