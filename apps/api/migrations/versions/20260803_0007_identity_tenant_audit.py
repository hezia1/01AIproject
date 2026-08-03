"""Add local identity, tenant membership, and audit foundations.

Revision ID: 20260803_0007
Revises: 20260801_0006
"""
from alembic import op
from sqlalchemy import text


revision = "20260803_0007"
down_revision = "20260801_0006"
branch_labels = None
depends_on = None

LEGACY_TENANT_ID = "00000000-0000-0000-0000-000000000001"


def upgrade() -> None:
    bind = op.get_bind()
    statements = [
        """CREATE TABLE IF NOT EXISTS tenants (
          id UUID PRIMARY KEY, name VARCHAR(120) NOT NULL UNIQUE, created_at TIMESTAMP NOT NULL
        )""",
        f"INSERT INTO tenants (id, name, created_at) VALUES ('{LEGACY_TENANT_ID}', 'Legacy Workspace', CURRENT_TIMESTAMP) ON CONFLICT (id) DO NOTHING",
        """CREATE TABLE IF NOT EXISTS users (
          id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id), username VARCHAR(120) NOT NULL,
          password_hash TEXT NOT NULL, role VARCHAR(40) NOT NULL DEFAULT 'viewer', enabled BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMP NOT NULL, CONSTRAINT uq_user_tenant_username UNIQUE (tenant_id, username)
        )""",
        "ALTER TABLE projects ADD COLUMN IF NOT EXISTS tenant_id UUID",
        f"UPDATE projects SET tenant_id = '{LEGACY_TENANT_ID}' WHERE tenant_id IS NULL",
        "ALTER TABLE projects ALTER COLUMN tenant_id SET NOT NULL",
        """DO $$ BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'fk_projects_tenant'
          ) THEN
            ALTER TABLE projects ADD CONSTRAINT fk_projects_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
          END IF;
        END $$""",
        """CREATE TABLE IF NOT EXISTS project_memberships (
          id UUID PRIMARY KEY, project_id UUID NOT NULL REFERENCES projects(id), user_id UUID NOT NULL REFERENCES users(id),
          role VARCHAR(40) NOT NULL DEFAULT 'viewer', created_at TIMESTAMP NOT NULL,
          CONSTRAINT uq_project_member UNIQUE (project_id, user_id)
        )""",
        """CREATE TABLE IF NOT EXISTS audit_events (
          id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id), user_id UUID REFERENCES users(id),
          project_id UUID REFERENCES projects(id), action VARCHAR(160) NOT NULL, outcome VARCHAR(40) NOT NULL,
          detail JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMP NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS ix_projects_tenant_id ON projects (tenant_id)",
        "CREATE INDEX IF NOT EXISTS ix_project_memberships_user_project ON project_memberships (user_id, project_id)",
        "CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_created ON audit_events (tenant_id, created_at DESC)",
    ]
    for statement in statements:
        bind.execute(text(statement))


def downgrade() -> None:
    bind = op.get_bind()
    for statement in [
        "DROP TABLE IF EXISTS audit_events",
        "DROP TABLE IF EXISTS project_memberships",
        "ALTER TABLE projects DROP CONSTRAINT IF EXISTS fk_projects_tenant",
        "ALTER TABLE projects DROP COLUMN IF EXISTS tenant_id",
        "DROP TABLE IF EXISTS users",
        "DROP TABLE IF EXISTS tenants",
    ]:
        bind.execute(text(statement))
