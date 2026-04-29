from fastapi.testclient import TestClient

from auth.dependencies import get_current_user
from main import app
from models import User


def test_read_only_user_cannot_run_cspm_scan():
    def fake_user():
        return User(id=10, email="reader@example.com", role="read_only", password_hash="x", is_active=True)

    app.dependency_overrides[get_current_user] = fake_user
    try:
        client = TestClient(app)
        response = client.post("/cspm/scan", json={"scan_type": "iam", "region": "us-east-1"})
        assert response.status_code == 403
    finally:
        app.dependency_overrides.clear()
