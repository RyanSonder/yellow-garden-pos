import os

from dotenv import load_dotenv

load_dotenv()

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
DEFAULT_JWT_SECRET_KEY = "dev-secret-key-change-me-in-production"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", DEFAULT_JWT_SECRET_KEY)

if APP_ENV == "production" and (
    JWT_SECRET_KEY == DEFAULT_JWT_SECRET_KEY
    or len(JWT_SECRET_KEY) < 32
):
    raise RuntimeError(
        "JWT_SECRET_KEY must be a unique value of at least 32 characters "
        "in production"
    )

JWT_ALGORITHM = "HS256"

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500"
        if APP_ENV != "production"
        else "",
    ).split(",")
    if origin.strip()
]
