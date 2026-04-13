# Cloud IAM Security Simulation Platform

A full-stack, multi-user web application that simulates cloud IAM activity, detects threats in real time, and provides a complete audit trail. Covers all five IAM pillars: Authentication, Authorization, Audit, Administration, and Analysis.

> **Education & research tool only — no real cloud provider is connected.**

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
```

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
├── websocket/           # ConnectionManager broadcast helpers
├── frontend/index.html  # Single-file Tailwind dashboard
├── requirements.txt
└── Procfile
```
