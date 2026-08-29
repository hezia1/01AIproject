"""Add governed enterprise knowledge entries and version history.

Revision ID: 20260828_0014
Revises: 20260817_0013
"""
from alembic import op


revision = "20260828_0014"
down_revision = "20260817_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE IF NOT EXISTS knowledge_entries (
        id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id),
        source_project_id UUID NOT NULL REFERENCES projects(id),
        source_finding_id UUID NOT NULL REFERENCES findings(id), knowledge_type VARCHAR(40) NOT NULL,
        title VARCHAR(300) NOT NULL, summary TEXT NOT NULL, rule_id VARCHAR(300) NOT NULL,
        source_module VARCHAR(80) NOT NULL, severity VARCHAR(40) NOT NULL, category VARCHAR(160),
        status VARCHAR(40) NOT NULL DEFAULT 'pending_review', applicability JSONB NOT NULL DEFAULT '{}'::jsonb,
        evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb, tags JSONB NOT NULL DEFAULT '[]'::jsonb,
        version INTEGER NOT NULL DEFAULT 1, submitted_by VARCHAR(120) NOT NULL,
        reviewer VARCHAR(120), review_note TEXT, reviewed_at TIMESTAMP, published_at TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uq_knowledge_tenant_finding UNIQUE (tenant_id, source_finding_id)
    )""")
    op.execute("""CREATE TABLE IF NOT EXISTS knowledge_entry_versions (
        id UUID PRIMARY KEY, entry_id UUID NOT NULL REFERENCES knowledge_entries(id), version INTEGER NOT NULL,
        snapshot JSONB NOT NULL DEFAULT '{}'::jsonb, change_action VARCHAR(40) NOT NULL,
        changed_by VARCHAR(120) NOT NULL, change_note TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uq_knowledge_entry_version UNIQUE (entry_id, version)
    )""")
    op.execute("CREATE INDEX IF NOT EXISTS ix_knowledge_entries_tenant_status ON knowledge_entries (tenant_id, status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_knowledge_entries_project ON knowledge_entries (source_project_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_knowledge_versions_entry ON knowledge_entry_versions (entry_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS knowledge_entry_versions")
    op.execute("DROP TABLE IF EXISTS knowledge_entries")
