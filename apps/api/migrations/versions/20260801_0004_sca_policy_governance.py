"""Add persistent SCA policy overrides and an append-only local audit trail.

Revision ID: 20260801_0004
Revises: 20260729_0003
"""
from alembic import op
from sqlalchemy import text


revision = "20260801_0004"
down_revision = "20260729_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(text("""
    CREATE TABLE IF NOT EXISTS sca_policy_overrides (
      id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id), policy_kind VARCHAR(40) NOT NULL,
      policy_id VARCHAR(160) NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE, config JSONB NOT NULL DEFAULT '{}'::jsonb,
      actor VARCHAR(120), change_note TEXT, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL
    )"""))
    bind.execute(text("CREATE INDEX IF NOT EXISTS ix_sca_policy_overrides_scope ON sca_policy_overrides(project_id, policy_kind, policy_id)"))
    bind.execute(text("""
    CREATE TABLE IF NOT EXISTS sca_policy_audit (
      id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id), policy_override_id UUID,
      event_type VARCHAR(80) NOT NULL, actor VARCHAR(120), details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMP NOT NULL
    )"""))
    bind.execute(text("CREATE INDEX IF NOT EXISTS ix_sca_policy_audit_project_created ON sca_policy_audit(project_id, created_at DESC)"))


def downgrade() -> None:
    op.execute(text("DROP TABLE IF EXISTS sca_policy_audit"))
    op.execute(text("DROP TABLE IF EXISTS sca_policy_overrides"))
