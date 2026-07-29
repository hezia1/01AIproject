"""Persist SCA policy exception approvals.

Revision ID: 20260729_0003
Revises: 20260728_0002
"""
from alembic import op
from sqlalchemy import text

revision = "20260729_0003"
down_revision = "20260728_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.get_bind().execute(text("""
    CREATE TABLE IF NOT EXISTS sca_policy_exceptions (
      id UUID PRIMARY KEY, project_id UUID NOT NULL REFERENCES projects(id), ecosystem VARCHAR(40) NOT NULL,
      package_name VARCHAR(300) NOT NULL, package_version VARCHAR(160), exception_type VARCHAR(80) NOT NULL,
      reason TEXT NOT NULL, status VARCHAR(40) NOT NULL DEFAULT 'pending', requester VARCHAR(120), approver VARCHAR(120),
      expires_at TIMESTAMP, approval_note TEXT, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL
    )"""))
    op.get_bind().execute(text("CREATE INDEX IF NOT EXISTS ix_sca_policy_exceptions_project_id ON sca_policy_exceptions(project_id)"))


def downgrade() -> None:
    op.get_bind().execute(text("DROP TABLE IF EXISTS sca_policy_exceptions"))
