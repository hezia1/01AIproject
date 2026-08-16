"""Add independent DAST business-flow verification records.

Revision ID: 20260816_0011
Revises: 20260815_0010
"""
from alembic import op


revision = "20260816_0011"
down_revision = "20260815_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE dast_business_flows (
            id UUID PRIMARY KEY,
            project_id UUID NOT NULL REFERENCES projects(id),
            finding_id UUID REFERENCES findings(id),
            name VARCHAR(200) NOT NULL,
            target_url VARCHAR(1000) NOT NULL,
            flow_mode VARCHAR(40) NOT NULL DEFAULT 'hybrid',
            strategy_source VARCHAR(40) NOT NULL DEFAULT 'manual',
            authorized_scope TEXT NOT NULL,
            allowed_paths JSONB NOT NULL DEFAULT '[]'::jsonb,
            roles JSONB NOT NULL DEFAULT '[]'::jsonb,
            steps JSONB NOT NULL DEFAULT '[]'::jsonb,
            sufficiency_criteria JSONB NOT NULL DEFAULT '{}'::jsonb,
            status VARCHAR(40) NOT NULL DEFAULT 'draft',
            requester VARCHAR(120) NOT NULL,
            approval_reference VARCHAR(240),
            approved_by VARCHAR(120),
            approved_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("""
        CREATE TABLE dast_business_runs (
            id UUID PRIMARY KEY,
            project_id UUID NOT NULL REFERENCES projects(id),
            flow_id UUID NOT NULL REFERENCES dast_business_flows(id),
            status VARCHAR(40) NOT NULL DEFAULT 'queued',
            execution_mode VARCHAR(40) NOT NULL DEFAULT 'dry_run',
            operator VARCHAR(120) NOT NULL,
            verdict VARCHAR(40),
            verdict_reason TEXT,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("""
        CREATE TABLE dast_business_snapshots (
            id UUID PRIMARY KEY,
            project_id UUID NOT NULL REFERENCES projects(id),
            flow_id UUID NOT NULL REFERENCES dast_business_flows(id),
            run_id UUID NOT NULL REFERENCES dast_business_runs(id),
            step_id VARCHAR(120) NOT NULL,
            step_kind VARCHAR(80) NOT NULL,
            role_alias VARCHAR(120),
            status VARCHAR(40) NOT NULL,
            request_summary TEXT,
            response_summary TEXT,
            detail JSONB NOT NULL DEFAULT '{}'::jsonb,
            evidence_hash VARCHAR(64) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS dast_business_snapshots")
    op.execute("DROP TABLE IF EXISTS dast_business_runs")
    op.execute("DROP TABLE IF EXISTS dast_business_flows")
