"""Add SCA VEX conclusions and durable exception approval context.

Revision ID: 20260801_0006
Revises: 20260801_0005
"""
from alembic import op
from sqlalchemy import text


revision = "20260801_0006"
down_revision = "20260801_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    statements = [
        "ALTER TABLE sca_policy_exceptions ADD COLUMN IF NOT EXISTS requester_role VARCHAR(40)",
        "ALTER TABLE sca_policy_exceptions ADD COLUMN IF NOT EXISTS approver_role VARCHAR(40)",
        "ALTER TABLE sca_policy_exceptions ADD COLUMN IF NOT EXISTS approval_history JSONB NOT NULL DEFAULT '[]'::jsonb",
        """CREATE TABLE IF NOT EXISTS sca_vex_statements (
          id UUID PRIMARY KEY, project_id UUID NOT NULL REFERENCES projects(id), ecosystem VARCHAR(40) NOT NULL,
          package_name VARCHAR(300) NOT NULL, package_version VARCHAR(160), vulnerability_id VARCHAR(160) NOT NULL,
          status VARCHAR(40) NOT NULL DEFAULT 'under_investigation', justification TEXT, action_statement TEXT,
          evidence TEXT, actor VARCHAR(120), expires_at TIMESTAMP, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS ix_sca_vex_project_component ON sca_vex_statements(project_id, ecosystem, package_name, vulnerability_id)",
    ]
    for statement in statements:
        bind.execute(text(statement))


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(text("DROP TABLE IF EXISTS sca_vex_statements"))
    bind.execute(text("ALTER TABLE sca_policy_exceptions DROP COLUMN IF EXISTS approval_history"))
    bind.execute(text("ALTER TABLE sca_policy_exceptions DROP COLUMN IF EXISTS approver_role"))
    bind.execute(text("ALTER TABLE sca_policy_exceptions DROP COLUMN IF EXISTS requester_role"))
