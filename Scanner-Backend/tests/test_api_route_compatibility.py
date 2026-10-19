from fastapi.testclient import TestClient


def test_api_compatibility_routes_are_exposed(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173")

    from app.main import app

    client = TestClient(app)
    response = client.get("/api/admin/tools/semgrep")

    assert response.status_code != 404
