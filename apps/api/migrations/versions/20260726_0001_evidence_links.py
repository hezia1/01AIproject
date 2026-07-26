"""Establish schema baseline and add explicit evidence links.

Revision ID: 20260726_0001
Revises:
Create Date: 2026-07-26
"""

from alembic import op
from sqlalchemy import inspect, text

from app.db import Base
from app import db_models  # noqa: F401

revision = "20260726_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    had_existing_schema = inspect(bind).has_table("projects")
    Base.metadata.create_all(bind=bind)
    if not had_existing_schema:
        return

    statements = [
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS component_id UUID",
        "ALTER TABLE dast_validations ADD COLUMN IF NOT EXISTS finding_id UUID",
        "ALTER TABLE dast_validations ADD COLUMN IF NOT EXISTS component_id UUID",
        "ALTER TABLE dast_validations ADD COLUMN IF NOT EXISTS link_source VARCHAR(40) NOT NULL DEFAULT 'unlinked'",
        "ALTER TABLE dast_validations ADD COLUMN IF NOT EXISTS link_confidence INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sandbox_evidence ADD COLUMN IF NOT EXISTS finding_id UUID",
        "ALTER TABLE sandbox_evidence ADD COLUMN IF NOT EXISTS component_id UUID",
        "ALTER TABLE sandbox_evidence ADD COLUMN IF NOT EXISTS validation_id UUID",
        "ALTER TABLE sandbox_evidence ADD COLUMN IF NOT EXISTS link_source VARCHAR(40) NOT NULL DEFAULT 'unlinked'",
        "ALTER TABLE sandbox_evidence ADD COLUMN IF NOT EXISTS link_confidence INTEGER NOT NULL DEFAULT 0",
        "CREATE INDEX IF NOT EXISTS ix_findings_component_id ON findings (component_id)",
        "CREATE INDEX IF NOT EXISTS ix_dast_validations_finding_id ON dast_validations (finding_id)",
        "CREATE INDEX IF NOT EXISTS ix_dast_validations_component_id ON dast_validations (component_id)",
        "CREATE INDEX IF NOT EXISTS ix_sandbox_evidence_finding_id ON sandbox_evidence (finding_id)",
        "CREATE INDEX IF NOT EXISTS ix_sandbox_evidence_component_id ON sandbox_evidence (component_id)",
        "CREATE INDEX IF NOT EXISTS ix_sandbox_evidence_validation_id ON sandbox_evidence (validation_id)",
    ]
    for statement in statements:
        bind.execute(text(statement))

    add_foreign_key_if_missing(
        "findings",
        "fk_findings_component_id_components",
        "component_id",
        "components",
    )
    add_foreign_key_if_missing(
        "dast_validations",
        "fk_dast_validations_component_id_components",
        "component_id",
        "components",
    )
    add_foreign_key_if_missing(
        "sandbox_evidence",
        "fk_sandbox_evidence_component_id_components",
        "component_id",
        "components",
    )
    add_foreign_key_if_missing(
        "sandbox_evidence",
        "fk_sandbox_evidence_validation_id_dast_validations",
        "validation_id",
        "dast_validations",
    )


def downgrade() -> None:
    for table, constraint in [
        ("sandbox_evidence", "fk_sandbox_evidence_validation_id_dast_validations"),
        ("sandbox_evidence", "fk_sandbox_evidence_component_id_components"),
        ("dast_validations", "fk_dast_validations_component_id_components"),
        ("findings", "fk_findings_component_id_components"),
    ]:
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {constraint}")

    statements = [
        "DROP INDEX IF EXISTS ix_sandbox_evidence_validation_id",
        "DROP INDEX IF EXISTS ix_sandbox_evidence_component_id",
        "DROP INDEX IF EXISTS ix_dast_validations_component_id",
        "DROP INDEX IF EXISTS ix_findings_component_id",
        "ALTER TABLE sandbox_evidence DROP COLUMN IF EXISTS validation_id",
        "ALTER TABLE sandbox_evidence DROP COLUMN IF EXISTS component_id",
        "ALTER TABLE sandbox_evidence DROP COLUMN IF EXISTS link_source",
        "ALTER TABLE sandbox_evidence DROP COLUMN IF EXISTS link_confidence",
        "ALTER TABLE dast_validations DROP COLUMN IF EXISTS component_id",
        "ALTER TABLE dast_validations DROP COLUMN IF EXISTS link_source",
        "ALTER TABLE dast_validations DROP COLUMN IF EXISTS link_confidence",
        "ALTER TABLE findings DROP COLUMN IF EXISTS component_id",
    ]
    for statement in statements:
        op.execute(statement)


def add_foreign_key_if_missing(
    table_name: str,
    constraint_name: str,
    column_name: str,
    target_table: str,
) -> None:
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = '{constraint_name}'
            ) THEN
                ALTER TABLE {table_name}
                ADD CONSTRAINT {constraint_name}
                FOREIGN KEY ({column_name}) REFERENCES {target_table}(id);
            END IF;
        END
        $$;
        """
    )
