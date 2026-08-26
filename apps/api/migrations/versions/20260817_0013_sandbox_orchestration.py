"""Add SANDBOX target instances and execution queue.

Revision ID: 20260817_0013
Revises: 20260817_0012
"""
from alembic import op


revision = "20260817_0013"
down_revision = "20260817_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE IF NOT EXISTS sandbox_target_instances (
        id UUID PRIMARY KEY, project_id UUID NOT NULL REFERENCES projects(id), mode VARCHAR(40) NOT NULL,
        status VARCHAR(40) NOT NULL, runtime_url VARCHAR(1000) NOT NULL, internal_url VARCHAR(1000),
        image VARCHAR(300), command VARCHAR(1000), container_id VARCHAR(160), container_name VARCHAR(160),
        network_name VARCHAR(160), container_port INTEGER, health_path VARCHAR(300) NOT NULL DEFAULT '/',
        health_detail JSONB NOT NULL DEFAULT '{}'::jsonb, policy JSONB NOT NULL DEFAULT '{}'::jsonb,
        operator VARCHAR(120) NOT NULL, expires_at TIMESTAMP, stopped_at TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")
    op.execute("""CREATE TABLE IF NOT EXISTS sandbox_tasks (
        id UUID PRIMARY KEY, project_id UUID NOT NULL REFERENCES projects(id),
        target_instance_id UUID REFERENCES sandbox_target_instances(id), source_module VARCHAR(40) NOT NULL,
        source_task_id VARCHAR(160) NOT NULL, strategy_id VARCHAR(160) NOT NULL, finding_id UUID REFERENCES findings(id),
        status VARCHAR(40) NOT NULL, required_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
        contract JSONB NOT NULL DEFAULT '{}'::jsonb, callback_token VARCHAR(200) NOT NULL,
        execution_id VARCHAR(200), evidence JSONB NOT NULL DEFAULT '[]'::jsonb, result_summary TEXT, error TEXT,
        operator VARCHAR(120), started_at TIMESTAMP, completed_at TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uq_sandbox_source_task UNIQUE (source_module, source_task_id)
    )""")
    op.execute("""CREATE TABLE IF NOT EXISTS sandbox_task_events (
        id UUID PRIMARY KEY, task_id UUID NOT NULL REFERENCES sandbox_tasks(id), state VARCHAR(60) NOT NULL,
        status VARCHAR(40) NOT NULL, detail JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")
    op.execute("CREATE INDEX IF NOT EXISTS ix_sandbox_targets_project ON sandbox_target_instances (project_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_sandbox_tasks_project ON sandbox_tasks (project_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_sandbox_task_events_task ON sandbox_task_events (task_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS sandbox_task_events")
    op.execute("DROP TABLE IF EXISTS sandbox_tasks")
    op.execute("DROP TABLE IF EXISTS sandbox_target_instances")
