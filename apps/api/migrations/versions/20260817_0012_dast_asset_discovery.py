"""Persist project-scoped DAST runtime asset discoveries.

Revision ID: 20260817_0012
Revises: 20260816_0011
"""
from alembic import op


revision = "20260817_0012"
down_revision = "20260816_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS dast_asset_discoveries (
            id UUID PRIMARY KEY,
            project_id UUID NOT NULL REFERENCES projects(id),
            target_url VARCHAR(1000) NOT NULL,
            status VARCHAR(40) NOT NULL,
            result JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_dast_asset_discoveries_project_id ON dast_asset_discoveries (project_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS dast_asset_discoveries")
