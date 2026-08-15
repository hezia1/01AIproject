"""Separate automated DAST observations from manual validation verdicts.

Revision ID: 20260815_0009
Revises: 20260809_0008
"""
from alembic import op
from sqlalchemy import text


revision = "20260815_0009"
down_revision = "20260809_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    for statement in [
        "ALTER TABLE dast_validations ADD COLUMN IF NOT EXISTS validation_mode VARCHAR(80) NOT NULL DEFAULT 'manual_validation'",
        "ALTER TABLE dast_validations ADD COLUMN IF NOT EXISTS connection_confirmed BOOLEAN NOT NULL DEFAULT FALSE",
    ]:
        bind.execute(text(statement))


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(text("ALTER TABLE dast_validations DROP COLUMN IF EXISTS connection_confirmed"))
    bind.execute(text("ALTER TABLE dast_validations DROP COLUMN IF EXISTS validation_mode"))
