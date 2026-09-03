import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from .models import Base

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)


def ensure_schema_compatibility() -> None:
    """Ensure older databases include columns and tables added by newer app versions."""
    Base.metadata.create_all(bind=engine)

    with engine.begin() as connection:
        inspector = inspect(connection)
        if "products" not in inspector.get_table_names():
            return

        columns = {
            column["name"]
            for column in inspector.get_columns("products")
        }

        if "is_active" not in columns:
            connection.execute(
                text(
                    "ALTER TABLE products "
                    "ADD COLUMN IF NOT EXISTS is_active BOOLEAN "
                    "NOT NULL DEFAULT true"
                )
            )

        connection.execute(
            text(
                "ALTER TABLE products "
                "DROP CONSTRAINT IF EXISTS products_type_check"
            )
        )


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

ensure_schema_compatibility()