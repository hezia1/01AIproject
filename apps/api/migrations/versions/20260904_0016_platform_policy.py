"""Persist administrator maintenance and sandbox image policy."""
from alembic import op

revision = "20260904_0016"
down_revision = "20260903_0015"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""CREATE TABLE IF NOT EXISTS platform_policies (
        id VARCHAR(80) PRIMARY KEY, config JSONB NOT NULL,
        version INTEGER NOT NULL DEFAULT 1, actor VARCHAR(120) NOT NULL,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")


def downgrade():
    op.drop_table("platform_policies")
