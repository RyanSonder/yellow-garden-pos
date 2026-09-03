import importlib


def test_jwt_secret_has_fallback(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    import app.config as config
    importlib.reload(config)

    assert config.JWT_SECRET_KEY
    assert config.JWT_ALGORITHM == "HS256"


def test_production_rejects_default_jwt_secret(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)

    import app.config as config

    try:
        importlib.reload(config)
    except RuntimeError as error:
        assert "JWT_SECRET_KEY" in str(error)
    else:
        raise AssertionError(
            "Production configuration accepted the default JWT secret"
        )
    finally:
        monkeypatch.setenv("APP_ENV", "development")
        importlib.reload(config)
