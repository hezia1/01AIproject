"""Persist SCA vulnerability intelligence evidence on component snapshots.

Revision ID: 20260801_0005
Revises: 20260801_0004
"""
from alembic import op
from sqlalchemy import text


revision = "20260801_0005"
down_revision = "20260801_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.get_bind().execute(text("ALTER TABLE components ADD COLUMN IF NOT EXISTS risk_metadata JSONB NOT NULL DEFAULT '{}'::jsonb"))


def downgrade() -> None:
    op.get_bind().execute(text("ALTER TABLE components DROP COLUMN IF EXISTS risk_metadata"))
