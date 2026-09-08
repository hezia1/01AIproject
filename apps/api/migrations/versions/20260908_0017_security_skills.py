"""Add governed declarative Security Skill registry and execution history."""
from alembic import op

revision = "20260908_0017"
down_revision = "20260904_0016"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""CREATE TABLE IF NOT EXISTS security_skills (
        id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id),
        slug VARCHAR(120) NOT NULL, name VARCHAR(200) NOT NULL, description TEXT NOT NULL,
        module VARCHAR(40) NOT NULL, status VARCHAR(40) NOT NULL DEFAULT 'draft',
        active_version INTEGER, created_by VARCHAR(120) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uq_security_skill_tenant_slug UNIQUE (tenant_id, slug)
    )""")
    op.execute("""CREATE TABLE IF NOT EXISTS security_skill_versions (
        id UUID PRIMARY KEY, skill_id UUID NOT NULL REFERENCES security_skills(id) ON DELETE CASCADE,
        version INTEGER NOT NULL, manifest JSONB NOT NULL, status VARCHAR(40) NOT NULL DEFAULT 'draft',
        change_note TEXT, created_by VARCHAR(120) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, published_at TIMESTAMP,
        CONSTRAINT uq_security_skill_version UNIQUE (skill_id, version)
    )""")
    op.execute("""CREATE TABLE IF NOT EXISTS security_skill_runs (
        id UUID PRIMARY KEY, skill_id UUID NOT NULL REFERENCES security_skills(id),
        skill_version_id UUID NOT NULL REFERENCES security_skill_versions(id),
        project_id UUID NOT NULL REFERENCES projects(id), status VARCHAR(40) NOT NULL,
        matched_finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        result_summary JSONB NOT NULL DEFAULT '{}'::jsonb, requested_by VARCHAR(120) NOT NULL,
        started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        finished_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")
    op.execute("CREATE INDEX IF NOT EXISTS ix_security_skills_tenant_status ON security_skills (tenant_id, status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_security_skill_runs_project ON security_skill_runs (project_id, started_at)")


def downgrade():
    op.drop_table("security_skill_runs")
    op.drop_table("security_skill_versions")
    op.drop_table("security_skills")
