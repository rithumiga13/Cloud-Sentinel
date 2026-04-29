import json

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth.dependencies import get_current_user
from aws_integration.client import get_aws_credential_status
import aws_integration.routes as cspm_routes
from database import Base, get_db
from main import app
from models import CloudAccount, CSPMFinding, CSPMScan, User


def _user(role: str) -> User:
    return User(id=1, email=f"{role}@example.com", role=role, password_hash="x", is_active=True)


def _client(role: str = "admin"):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionTesting = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionTesting()

    def override_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: _user(role)
    return TestClient(app), db


def _cleanup(db):
    db.close()
    app.dependency_overrides.clear()


def test_credential_status_missing(monkeypatch):
    class FakeSession:
        def __init__(self, region_name=None):
            self.region_name = region_name

        def get_credentials(self):
            return None

    class FakeBoto3:
        Session = FakeSession

    monkeypatch.delenv("AWS_ROLE_ARN", raising=False)
    monkeypatch.setattr("aws_integration.client.boto3", FakeBoto3)
    status = get_aws_credential_status("us-east-1")
    assert status["configured"] is False
    assert status["source"] == "missing"
    assert status["next_steps"]


def test_aws_identity_returns_200_when_credentials_missing(monkeypatch):
    client, db = _client("admin")
    monkeypatch.setattr(cspm_routes, "get_aws_credential_status", lambda region=None: {
        "configured": False,
        "source": "missing",
        "region": region or "us-east-1",
        "account_id": None,
        "arn": None,
        "user_id": None,
        "error_message": "AWS credentials were not found in the default credential chain.",
        "next_steps": ["Set AWS_ACCESS_KEY_ID"],
    })
    try:
        response = client.get("/aws/identity?region=us-east-1")
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["data"]["configured"] is False
    finally:
        _cleanup(db)


def test_admin_can_load_demo_data_and_risk_is_nonzero():
    client, db = _client("admin")
    try:
        response = client.post("/cspm/demo/load?region=us-east-1")
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["mode"] == "demo"
        assert data["scan"]["finding_count"] > 0
        assert data["risk_score"]["total_score"] > 0
        assert db.query(CSPMFinding).count() == data["scan"]["finding_count"]
    finally:
        _cleanup(db)


def test_power_user_can_load_demo_data():
    client, db = _client("power_user")
    try:
        response = client.post("/cspm/demo/load?region=us-east-1")
        assert response.status_code == 200
        assert response.json()["data"]["scan"]["finding_count"] > 0
    finally:
        _cleanup(db)


def test_read_only_cannot_load_demo_data():
    client, db = _client("read_only")
    try:
        response = client.post("/cspm/demo/load?region=us-east-1")
        assert response.status_code == 403
    finally:
        _cleanup(db)


def test_admin_clear_demo_removes_only_demo_data():
    client, db = _client("admin")
    try:
        client.post("/cspm/demo/load?region=us-east-1")
        real_account = CloudAccount(account_id="111111111111", arn="arn:aws:iam::111111111111:role/Real", region="us-east-1")
        db.add(real_account)
        db.flush()
        real_scan = CSPMScan(cloud_account_id=real_account.id, scan_type="iam", status="completed", finding_count=1, high_count=1, medium_count=0, low_count=0)
        db.add(real_scan)
        db.flush()
        db.add(CSPMFinding(
            scan_id=real_scan.id,
            cloud_account_id=real_account.id,
            provider="aws",
            service="iam",
            resource_type="iam_policy",
            resource_id="real-policy",
            title="Real finding",
            description="Real finding",
            severity="HIGH",
            recommendation="Review",
            evidence_json=json.dumps({"demo": False}),
            compliance_tags_json="[]",
            status="open",
        ))
        db.commit()
        response = client.delete("/cspm/demo/clear")
        assert response.status_code == 200
        assert db.query(CSPMFinding).count() == 1
        assert db.query(CSPMFinding).first().resource_id == "real-policy"
    finally:
        _cleanup(db)


def test_power_user_cannot_clear_demo_data():
    client, db = _client("power_user")
    try:
        response = client.delete("/cspm/demo/clear")
        assert response.status_code == 403
    finally:
        _cleanup(db)
