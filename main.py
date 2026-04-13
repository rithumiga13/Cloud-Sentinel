"""Cloud IAM Security Simulation Platform — FastAPI application entry point."""

from __future__ import annotations
import asyncio
import random
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import os

from database import engine, SessionLocal, Base
from models import (
    User, Session as UserSession, AuditLog, Alert, Permission,
    RiskSnapshot, RoleEnum,
)
from websocket.manager import manager
from simulate.engine import start_background_simulator, stop_background_simulator
from threats.engine import _update_risk


# ---------------------------------------------------------------------------
# Application lifespan: DB init + seed + background tasks
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Set up database, seed demo data, and start background simulator."""
    Base.metadata.create_all(bind=engine)
    _seed_database()
    start_background_simulator()
    yield
    stop_background_simulator()


def _seed_database() -> None:
    """Seed demo users, permissions, audit logs, and alerts if the DB is empty."""
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return  # Already seeded

        from passlib.context import CryptContext
        pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

        # --- Users ---
        users_data = [
            ("admin@demo.com",  "Admin@123",  "admin"),
            ("user1@demo.com",  "User@123",   "normal_user"),
            ("user2@demo.com",  "User@123",   "power_user"),
            ("user3@demo.com",  "User@123",   "read_only"),
            ("svc@demo.com",    "Svc@123",    "service_account"),
        ]
        created_users: list[User] = []
        for email, password, role in users_data:
            u = User(email=email, password_hash=pwd_ctx.hash(password), role=role)
            db.add(u)
            created_users.append(u)
        db.commit()
        for u in created_users:
            db.refresh(u)

        # --- Permissions + default groups ---
        from iam.service import seed_permissions, add_group_member
        seed_permissions(db)

        # Assign users to default groups for demo
        # data-engineers: user1 (normal), user2 (power)
        # ops-team: user2 (power)
        # security-review: user3 (read-only)
        from models import Group, GroupMembership
        def _assign(group_name: str, user_email: str) -> None:
            grp = db.query(Group).filter(Group.name == group_name).first()
            usr = next((u for u in created_users if u.email == user_email), None)
            if grp and usr:
                existing = db.query(GroupMembership).filter(
                    GroupMembership.group_id == grp.id,
                    GroupMembership.user_id == usr.id,
                ).first()
                if not existing:
                    db.add(GroupMembership(
                        group_id=grp.id, user_id=usr.id,
                        assigned_by=created_users[0].id,
                    ))
        _assign("data-engineers", "user1@demo.com")
        _assign("data-engineers", "user2@demo.com")
        _assign("ops-team",       "user2@demo.com")
        _assign("security-review","user3@demo.com")
        db.commit()

        # --- Sample audit logs (last 30 min) ---
        resources = ["s3", "ec2", "lambda", "rds", "iam", "vpc"]
        actions_map = {
            "s3": ["list", "get", "put"],
            "ec2": ["describe", "start", "stop"],
            "lambda": ["list", "invoke"],
            "rds": ["describe"],
            "iam": ["list-users", "attach-policy"],
            "vpc": ["describe"],
        }
        statuses = ["safe", "safe", "safe", "suspicious", "blocked"]
        ips = ["10.0.0.1", "192.168.1.5", "172.16.0.3", "10.0.0.2"]

        for i in range(20):
            minutes_ago = random.randint(1, 30)
            resource = random.choice(resources)
            action = random.choice(actions_map[resource])
            user = random.choice(created_users[1:])  # exclude admin for variety
            log = AuditLog(
                user_id=user.id,
                action=action,
                resource=resource,
                status=random.choice(statuses),
                ip_address=random.choice(ips),
                timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago),
                risk_delta=round(random.uniform(0, 10), 2),
                details=f"Seeded demo activity",
            )
            db.add(log)

        db.commit()

        # --- Pre-existing alerts ---
        alert_high = Alert(
            rule_id="R2",
            user_id=created_users[1].id,
            severity="HIGH",
            message="Non-Admin user accessed IAM resource 'iam' (seeded demo alert)",
            created_at=datetime.utcnow() - timedelta(minutes=20),
        )
        alert_medium = Alert(
            rule_id="R3",
            user_id=created_users[2].id,
            severity="MEDIUM",
            message="Off-hours activity detected at 02:15 UTC (seeded demo alert)",
            created_at=datetime.utcnow() - timedelta(minutes=10),
        )
        db.add(alert_high)
        db.add(alert_medium)
        db.commit()

        # --- Seed risk score at 35 ---
        snapshot = RiskSnapshot(score=35.0, timestamp=datetime.utcnow())
        db.add(snapshot)
        db.commit()

        # Sync in-memory risk state
        import threats.engine as te
        te._current_risk = 35.0

    finally:
        db.close()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Cloud IAM Security Simulation Platform",
    description="Multi-user IAM simulation with threat detection, audit, and real-time dashboard.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

from auth.router import router as auth_router
from iam.router import router as iam_router
from simulate.router import router as simulate_router
from audit.router import router as audit_router
from threats.router import router as threats_router
from admin.router import router as admin_router

app.include_router(auth_router)
app.include_router(iam_router)
app.include_router(simulate_router)
app.include_router(audit_router)
app.include_router(threats_router)
app.include_router(admin_router)


# ---------------------------------------------------------------------------
# WebSocket endpoints
# ---------------------------------------------------------------------------

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    """Stream all new audit log entries and security alerts to connected clients."""
    await manager.connect_events(websocket)
    try:
        while True:
            # Keep connection alive; server pushes data proactively
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect_events(websocket)


@app.websocket("/ws/risk")
async def ws_risk(websocket: WebSocket):
    """Stream risk score updates to connected clients."""
    await manager.connect_risk(websocket)
    # Send current score immediately on connect
    from threats.engine import get_current_risk
    await websocket.send_text(
        f'{{"type":"risk_update","score":{get_current_risk()},"ts":"{datetime.utcnow().isoformat()}"}}'
    )
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect_risk(websocket)


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_dashboard():
    """Serve the single-file dashboard."""
    path = os.path.join(os.path.dirname(__file__), "frontend", "index.html")
    with open(path) as f:
        return HTMLResponse(content=f.read())


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def serve_auth():
    """Serve the authentication page."""
    path = os.path.join(os.path.dirname(__file__), "frontend", "auth.html")
    with open(path) as f:
        return HTMLResponse(content=f.read())


@app.get("/health")
async def health():
    """Basic health check endpoint."""
    return {"status": "ok", "service": "cloud-iam-platform"}
