"""Add DAST verification plans, documentation runs, and evidence index.

Revision ID: 20260815_0010
Revises: 20260815_0009
"""
from alembic import op


revision = "20260815_0010"
down_revision = "20260815_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE dast_verification_plans (
            id UUID PRIMARY KEY,
            project_id UUID NOT NULL REFERENCES projects(id),
            finding_id UUID REFERENCES findings(id),
            component_id UUID REFERENCES components(id),
            title VARCHAR(200) NOT NULL,
            target_url VARCHAR(1000) NOT NULL,
            authorized_scope TEXT NOT NULL,
            allowed_paths JSONB NOT NULL DEFAULT '[]'::jsonb,
            allowed_methods JSONB NOT NULL DEFAULT '[]'::jsonb,
            strategy_id VARCHAR(80) NOT NULL,
            strategy_name VARCHAR(160),
            limitations TEXT,
            requester VARCHAR(120) NOT NULL,
            approval_status VARCHAR(40) NOT NULL DEFAULT 'draft',
            approval_reference VARCHAR(240),
            approved_by VARCHAR(120),
            approved_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("""
        CREATE TABLE dast_verification_runs (
            id UUID PRIMARY KEY,
            project_id UUID NOT NULL REFERENCES projects(id),
            plan_id UUID NOT NULL REFERENCES dast_verification_plans(id),
            validation_id UUID REFERENCES dast_validations(id),
            status VARCHAR(40) NOT NULL DEFAULT 'prepared',
            execution_mode VARCHAR(80) NOT NULL DEFAULT 'documentation_only',
            operator VARCHAR(120) NOT NULL,
            purpose TEXT,
            started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("""
        CREATE TABLE dast_run_evidence (
            id UUID PRIMARY KEY,
            project_id UUID NOT NULL REFERENCES projects(id),
            plan_id UUID NOT NULL REFERENCES dast_verification_plans(id),
            run_id UUID NOT NULL REFERENCES dast_verification_runs(id),
            evidence_type VARCHAR(80) NOT NULL,
            content_summary TEXT NOT NULL,
            content_hash VARCHAR(64) NOT NULL,
            source_reference VARCHAR(1000),
            collected_by VARCHAR(120),
            redaction_applied BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS dast_run_evidence")
    op.execute("DROP TABLE IF EXISTS dast_verification_runs")
    op.execute("DROP TABLE IF EXISTS dast_verification_plans")
