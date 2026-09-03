import importlib


def test_jwt_secret_has_fallback(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    import app.config as config
    importlib.reload(config)

    assert config.JWT_SECRET_KEY
    assert config.JWT_ALGORITHM == "HS256"
