# Cloud IAM Security Simulation Platform

A full-stack, multi-user web application that simulates cloud IAM activity, detects threats in real time, provides a complete audit trail, and can run read-only AWS CSPM scans for IAM, S3, EC2 security groups, and CloudTrail.

Hosted at : https://cloud-sentinel-bl37.onrender.com

> **Portfolio, research, and demo tool only. AWS integration is read-only and does not create, modify, delete, or remediate cloud resources.**

---

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11 + FastAPI |
| Database | SQLite (dev) / SQLAlchemy ORM + Alembic |
| Auth | JWT (python-jose) + bcrypt |
| Realtime | FastAPI WebSockets |
| Frontend | Single HTML — Vanilla JS + Tailwind CDN |
| Deploy | Railway (Procfile) |

---

## Quick Start

```bash
# 1. Clone and enter
git clone <repo> && cd Cloud-IAM

# 2. Create virtual environment
python3 -m venv venv && source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
uvicorn main:app --reload --port 8000
```

Open **http://localhost:8000** — the dashboard loads automatically.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./cloud_iam.db` | SQLAlchemy database URL |
| `SECRET_KEY` | `super-secret-dev-key-change-in-production` | JWT signing key — **change in production** |
| `PORT` | `8000` | Server port (used by Procfile) |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | `us-east-1` | Default AWS region for CSPM scans |
| AWS credential env vars | unset | Optional. You can use `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`, but IAM role/profile credentials through boto3's default credential chain are preferred. |

---

## Demo Credentials

| Email | Password | Role |
|---|---|---|
| admin@demo.com | Admin@123 | Admin |
| user1@demo.com | User@123 | Normal User |
| user2@demo.com | User@123 | Power User |
| user3@demo.com | User@123 | Read Only |
| svc@demo.com | Svc@123 | Service Account |

---

## API Overview

### Authentication — `/auth`

| Method | Path | Description |
|---|---|---|
| POST | `/auth/register` | Register new user, returns token pair |
| POST | `/auth/login` | Login, returns access + refresh tokens |
| POST | `/auth/refresh` | Rotate token pair |
| POST | `/auth/logout` | Revoke current session |
| POST | `/auth/mfa/setup` | Generate TOTP secret + QR URI |
| POST | `/auth/mfa/verify` | Verify TOTP code |

### IAM — `/iam`

| Method | Path | Description |
|---|---|---|
| GET | `/iam/policy` | Effective permissions for caller |
| PUT | `/iam/policy/{userId}` | Update user role (Admin only) |
| GET | `/iam/check?resource=s3&action=get` | Ad-hoc permission check |

### Simulation — `/simulate`

| Method | Path | Description |
|---|---|---|
| POST | `/simulate/action` | Execute simulated cloud action |
| GET | `/simulate/resources` | List resources and valid actions |

### Audit — `/audit`

| Method | Path | Description |
|---|---|---|
| GET | `/audit/logs` | Paginated logs (filter by user/resource/status/date) |
| GET | `/audit/export?format=csv\|json` | Download full audit log |

### Threats — `/alerts`, `/risk`, `/analyze`

| Method | Path | Description |
|---|---|---|
| GET | `/alerts` | List security alerts |
| POST | `/alerts/{id}/resolve` | Dismiss an alert |
| GET | `/risk` | Current risk score |
| GET | `/analyze/permissions` | IAM analyzer findings |

### Administration — `/admin`

| Method | Path | Description |
|---|---|---|
| GET | `/admin/users` | All users |
| POST | `/admin/users` | Create user |
| PUT | `/admin/users/{id}/role` | Change role |
| DELETE | `/admin/users/{id}` | Deactivate user |
| POST | `/admin/users/{id}/reset` | Force password reset |
| GET | `/admin/sessions` | Active sessions |
| DELETE | `/admin/sessions/{id}` | Revoke session |
| GET | `/admin/system/health` | System metrics |

### WebSockets

| Path | Stream |
|---|---|
| `ws://host/ws/events` | Audit events + security alerts |
| `ws://host/ws/risk` | Risk score updates |

### AWS CSPM — `/aws`, `/cspm`

| Method | Path | Description |
|---|---|---|
| GET | `/aws/identity?region=us-east-1` | Validate current AWS identity through STS |
| POST | `/cspm/scan` | Run read-only scan: `full`, `iam`, `s3`, `ec2`, or `cloudtrail` |
| GET | `/cspm/scans` | List previous scans |
| GET | `/cspm/scans/{scan_id}` | Scan metadata and findings |
| GET | `/cspm/findings` | Filter findings by severity, service, status, or resource type |
| POST | `/cspm/findings/{finding_id}/status` | Mark finding `open`, `resolved`, or `ignored` |
| GET | `/cspm/risk` | CSPM risk score |
| GET | `/cspm/report?format=json\|csv` | Export CSPM findings |
| POST | `/cspm/demo/load` | Load realistic sample CSPM findings |
| DELETE | `/cspm/demo/clear` | Clear demo CSPM data only |

Admin and Power User roles can run scans and change finding status. Read Only users can view CSPM scans, findings, risk, and reports.

---

## Example curl Commands

```bash
# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@demo.com","password":"Admin@123"}'

# Set TOKEN from login response
TOKEN="<access_token>"

# Simulate an S3 list action for user 2
curl -X POST http://localhost:8000/simulate/action \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":2,"resource":"s3","action":"list"}'

# Get paginated audit logs
curl "http://localhost:8000/audit/logs?page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"

# Get active alerts
curl http://localhost:8000/alerts \
  -H "Authorization: Bearer $TOKEN"

# Run IAM analyzer
curl http://localhost:8000/analyze/permissions \
  -H "Authorization: Bearer $TOKEN"

# Get system health (admin only)
curl http://localhost:8000/admin/system/health \
  -H "Authorization: Bearer $TOKEN"

# Export audit log as CSV
curl "http://localhost:8000/audit/export?format=csv" \
  -H "Authorization: Bearer $TOKEN" -o audit_logs.csv

# Validate AWS identity
curl "http://localhost:8000/aws/identity?region=us-east-1" \
  -H "Authorization: Bearer $TOKEN"

# Run a full read-only CSPM scan
curl -X POST http://localhost:8000/cspm/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scan_type":"full","region":"us-east-1"}'

# List high-severity open findings
curl "http://localhost:8000/cspm/findings?severity=HIGH&status=open" \
  -H "Authorization: Bearer $TOKEN"
```

---

## AWS CSPM Setup

The platform now supports four clear operating modes:

| Mode | Purpose |
|---|---|
| Simulation Mode | Existing Cloud IAM simulation, RBAC, audit, alerts, risk, and WebSocket workflows. |
| Demo Mode | Loads realistic sample AWS CSPM findings without any AWS credentials. Best for portfolio walkthroughs. |
| Real AWS Mode | Uses server-side read-only AWS credentials from boto3's default credential chain. |
| AssumeRole Mode | Uses `AWS_ROLE_ARN` and optional `AWS_EXTERNAL_ID` to assume a read-only scanning role. |

The app never asks users to type AWS secrets into the browser and never stores AWS secrets in the database. It stores only account identity, scan metadata, and findings.

### Demo Mode

Use this when presenting the platform without connecting a real AWS account:

1. Start the app.
2. Login as `admin@demo.com`.
3. Open **AWS CSPM**.
4. Click **Load Demo CSPM Data**.
5. Review risk score, findings, recommendations, evidence JSON, and scan history.

Demo findings are clearly labeled as sample data and can be cleared by an Admin.

### Real AWS Mode

The platform uses boto3's default credential chain. For local development, use read-only credentials:

```bash
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="ap-south-1"
```

Then restart the app, validate identity in the AWS CSPM tab, and run a scan.

### AssumeRole Mode

Set these server-side variables when scanning a separate AWS account through STS:

```bash
export AWS_ROLE_ARN="arn:aws:iam::<account-id>:role/<read-only-role>"
export AWS_EXTERNAL_ID="optional-external-id"
export AWS_ROLE_SESSION_NAME="CloudIAMCSPMReadOnlySession"
export AWS_DEFAULT_REGION="ap-south-1"
```

`sts:AssumeRole` is only required for this mode.

### Railway Variables

Set these in Railway service variables as needed:

```text
SECRET_KEY
DATABASE_URL
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_DEFAULT_REGION
AWS_ROLE_ARN
AWS_EXTERNAL_ID
AWS_ROLE_SESSION_NAME
```

Minimum read-only IAM policy for scanning:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "sts:AssumeRole",
        "iam:Get*",
        "iam:List*",
        "s3:Get*",
        "s3:List*",
        "ec2:Describe*",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:LookupEvents",
        "cloudtrail:ListTrails",
        "cloudtrail:GetEventSelectors"
      ],
      "Resource": "*"
    }
  ]
}
```

Security limitations:

- The scanner is read-only and reports findings only; it does not remediate resources.
- Do not use admin AWS credentials. Use a dedicated read-only principal or role.
- Prefer a sandbox/demo AWS account for portfolio testing.
- Do not expose production AWS account metadata in public demos.
- Do not type AWS secrets into the browser.
- CSPM checks are intentionally conservative for a portfolio/demo project and should not replace a production CSPM, SIEM, or AWS Security Hub deployment.
- CloudTrail `LookupEvents` is rate-limited by AWS and only covers recent management events.
- Cross-account and organization-wide scanning require running the app with an appropriately scoped read-only role in each target account.

Optional safe AWS lab resources are provided in `infra/aws-demo-lab/`. They create a private S3 bucket with missing hardening controls and an unattached security group with intentionally open ingress rules. Deploy only in a sandbox account and delete after testing.

---

## Threat Detection Rules

| Rule | Condition | Severity |
|---|---|---|
| R1 | Failed logins > 5 in 60 s | HIGH |
| R2 | Non-Admin calls IAM endpoint | HIGH |
| R3 | Any action between 00:00–05:00 UTC | MEDIUM |
| R4 | Same user > 50 actions / 5 min | MEDIUM |
| R5 | Role changed on own account | HIGH |
| R6 | Denied action retried > 3× | MEDIUM |
| R7 | ServiceAccount calls EC2/RDS | LOW |
| R8 | Sensitive resource accessed without MFA | HIGH |

Risk score = `(HIGH×20) + (MEDIUM×10) + (LOW×3)` — decays 5 pts per 5 min of inactivity.

---

## Project Structure

```
Cloud-IAM/
├── main.py              # App entry point, lifespan, WebSocket endpoints, seed data
├── models.py            # SQLAlchemy ORM models
├── schemas.py           # Pydantic request/response schemas
├── database.py          # Engine, SessionLocal, Base
├── auth/                # Registration, login, MFA, brute-force
├── iam/                 # RBAC, ABAC, policy management
├── simulate/            # Action handler, background activity generator
├── audit/               # Append-only log writer, export, compliance flags
├── threats/             # Rule engine (R1–R8), risk scoring, IAM analyzer
├── admin/               # User/session management, system health
├── aws_integration/     # Read-only AWS identity, CSPM scanners, API routes
├── websocket/           # ConnectionManager broadcast helpers
├── tests/               # Pytest scanner and RBAC coverage
├── frontend/index.html  # Single-file Tailwind dashboard
├── requirements.txt
└── Procfile
```
