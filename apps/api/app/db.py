from collections.abc import Generator
import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://ai_security:ai_security_dev@localhost:5432/ai_security",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_db_schema() -> None:
    from app import db_models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS source_path VARCHAR(1000)"))
        connection.execute(text("ALTER TABLE components ADD COLUMN IF NOT EXISTS vulnerability_ids JSONB NOT NULL DEFAULT '[]'::jsonb"))
        connection.execute(text("ALTER TABLE components ADD COLUMN IF NOT EXISTS severity VARCHAR(40)"))
        connection.execute(text("ALTER TABLE components ADD COLUMN IF NOT EXISTS risk_summary TEXT"))
        connection.execute(text("ALTER TABLE components ADD COLUMN IF NOT EXISTS remediation TEXT"))
        connection.execute(text("ALTER TABLE components ADD COLUMN IF NOT EXISTS license_risk VARCHAR(40)"))
        connection.execute(text("ALTER TABLE components ADD COLUMN IF NOT EXISTS risk_source VARCHAR(80)"))
        connection.execute(text("ALTER TABLE components ADD COLUMN IF NOT EXISTS osv_checked BOOLEAN NOT NULL DEFAULT FALSE"))
        connection.execute(text("ALTER TABLE components ADD COLUMN IF NOT EXISTS osv_error TEXT"))
        connection.execute(text("ALTER TABLE findings ALTER COLUMN rule_id TYPE VARCHAR(300)"))
        connection.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_owner VARCHAR(120)"))
        connection.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_note TEXT"))
        connection.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_due_at TIMESTAMP"))
        connection.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"))

