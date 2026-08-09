"""Add auditable DeepSeek SAST multi-agent runs.

Revision ID: 20260809_0008
Revises: 20260803_0007
"""
from alembic import op
from sqlalchemy import text


revision = "20260809_0008"
down_revision = "20260803_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    for statement in [
        """CREATE TABLE IF NOT EXISTS sast_agent_runs (
          id UUID PRIMARY KEY,
          project_id UUID NOT NULL REFERENCES projects(id),
          scan_task_id UUID REFERENCES scan_tasks(id),
          status VARCHAR(40) NOT NULL DEFAULT 'running',
          provider VARCHAR(80) NOT NULL DEFAULT 'deepseek',
          model VARCHAR(160) NOT NULL,
          review_model VARCHAR(160) NOT NULL,
          trigger VARCHAR(40) NOT NULL DEFAULT 'scan',
          agent_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
          result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
          token_usage JSONB NOT NULL DEFAULT '{}'::jsonb,
          error TEXT,
          started_at TIMESTAMP NOT NULL,
          finished_at TIMESTAMP,
          created_at TIMESTAMP NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS ix_sast_agent_runs_project_created ON sast_agent_runs (project_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS ix_sast_agent_runs_scan_task ON sast_agent_runs (scan_task_id)",
    ]:
        bind.execute(text(statement))


def downgrade() -> None:
    op.get_bind().execute(text("DROP TABLE IF EXISTS sast_agent_runs"))
