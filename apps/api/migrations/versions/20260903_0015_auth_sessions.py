"""Add authenticated user sessions and normalize the two-role model.

Revision ID: 20260903_0015
Revises: 20260828_0014
"""
from alembic import op


revision = "20260903_0015"
down_revision = "20260828_0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE users SET role = CASE WHEN lower(role) = 'admin' THEN 'admin' ELSE 'user' END")
    op.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(64) NOT NULL UNIQUE,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_sessions_user ON user_sessions (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_sessions_expires ON user_sessions (expires_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS user_sessions")
