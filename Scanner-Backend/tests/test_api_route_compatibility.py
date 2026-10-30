from fastapi.testclient import TestClient


def test_api_compatibility_routes_are_exposed(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173")

    from app.main import app

    client = TestClient(app)
    response = client.get(
        "/api/admin/tools/semgrep",
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.status_code != 404
    assert response.headers["server-timing"].startswith("app;dur=")
    assert ", db;dur=" in response.headers["server-timing"]
    assert response.headers["access-control-expose-headers"] == "Server-Timing"
