from app.core.rate_limit import allowed_websocket_origins


def test_allowed_websocket_origins_includes_cors_and_frontend_urls(monkeypatch):
    monkeypatch.setenv(
        "CORS_ORIGINS",
        " https://app.example.com/ , https://admin.example.com ",
    )
    monkeypatch.setenv("FRONTEND_URL", " https://portal.example.com/ ")

    assert allowed_websocket_origins() == {
        "https://app.example.com",
        "https://admin.example.com",
        "https://portal.example.com",
    }


def test_allowed_websocket_origins_allows_frontend_url_without_cors_origins(monkeypatch):
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    monkeypatch.setenv("FRONTEND_URL", "https://app.example.com/")

    assert allowed_websocket_origins() == {"https://app.example.com"}
