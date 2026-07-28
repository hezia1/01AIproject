"""Persist DAST strategy and SANDBOX evidence context.

Revision ID: 20260728_0002
Revises: 20260726_0001
Create Date: 2026-07-28
"""

from alembic import op
from sqlalchemy import text

revision = "20260728_0002"
down_revision = "20260726_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    statements = [
        "ALTER TABLE dast_validations ADD COLUMN IF NOT EXISTS strategy_id VARCHAR(80) NOT NULL DEFAULT 'web-baseline'",
        "ALTER TABLE dast_validations ADD COLUMN IF NOT EXISTS strategy_name VARCHAR(160)",
        "ALTER TABLE dast_validations ADD COLUMN IF NOT EXISTS scope_summary TEXT",
        "ALTER TABLE dast_validations ADD COLUMN IF NOT EXISTS limitations TEXT",
        "ALTER TABLE sandbox_evidence ADD COLUMN IF NOT EXISTS strategy_name VARCHAR(160)",
        "ALTER TABLE sandbox_evidence ADD COLUMN IF NOT EXISTS purpose TEXT",
        "ALTER TABLE sandbox_evidence ADD COLUMN IF NOT EXISTS limitations TEXT",
    ]
    for statement in statements:
        op.get_bind().execute(text(statement))


def downgrade() -> None:
    statements = [
        "ALTER TABLE sandbox_evidence DROP COLUMN IF EXISTS limitations",
        "ALTER TABLE sandbox_evidence DROP COLUMN IF EXISTS purpose",
        "ALTER TABLE sandbox_evidence DROP COLUMN IF EXISTS strategy_name",
        "ALTER TABLE dast_validations DROP COLUMN IF EXISTS limitations",
        "ALTER TABLE dast_validations DROP COLUMN IF EXISTS scope_summary",
        "ALTER TABLE dast_validations DROP COLUMN IF EXISTS strategy_name",
        "ALTER TABLE dast_validations DROP COLUMN IF EXISTS strategy_id",
    ]
    for statement in statements:
        op.get_bind().execute(text(statement))
