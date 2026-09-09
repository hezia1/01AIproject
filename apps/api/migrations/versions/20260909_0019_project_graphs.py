"""Add versioned code and business knowledge graph snapshots."""
from alembic import op

revision = "20260909_0019"
down_revision = "20260909_0018"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""CREATE TABLE IF NOT EXISTS project_graph_snapshots (
        id UUID PRIMARY KEY,
        project_id UUID NOT NULL REFERENCES projects(id),
        graph_type VARCHAR(40) NOT NULL,
        version INTEGER NOT NULL,
        source_fingerprint VARCHAR(64) NOT NULL,
        generator_version VARCHAR(40) NOT NULL,
        status VARCHAR(40) NOT NULL DEFAULT 'completed',
        nodes JSONB NOT NULL DEFAULT '[]'::jsonb,
        edges JSONB NOT NULL DEFAULT '[]'::jsonb,
        summary JSONB NOT NULL DEFAULT '{}'::jsonb,
        limitations JSONB NOT NULL DEFAULT '[]'::jsonb,
        created_by VARCHAR(120) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uq_project_graph_version UNIQUE (project_id, graph_type, version)
    )""")
    op.execute("CREATE INDEX IF NOT EXISTS ix_project_graph_latest ON project_graph_snapshots (project_id, graph_type, version DESC)")


def downgrade():
    op.execute("DROP INDEX IF EXISTS ix_project_graph_latest")
    op.execute("DROP TABLE IF EXISTS project_graph_snapshots")
