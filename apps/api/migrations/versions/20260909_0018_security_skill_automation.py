"""Add automatic Skill triggers and tenant-wide built-in Skills."""
from alembic import op

revision = "20260909_0018"
down_revision = "20260908_0017"
branch_labels = None
depends_on = None


BUILTINS = (
    ("critical-high-cross-module-triage", "跨模块高危风险优先复核", "cross", '["sca","sast","agent"]',
     '{"action":"review_existing_findings","selectors":{"sources":["SCA","SAST","AGENT"],"severities":["critical","high"],"statuses":["open","pending","confirmed","fixing","retest"]},"evidence_required":[]}'),
    ("sca-critical-high-priority", "SCA 高危组件风险复核", "sca", '["sca"]',
     '{"action":"review_existing_findings","selectors":{"sources":["SCA"],"severities":["critical","high"],"statuses":["open","pending","confirmed","fixing","retest"]},"evidence_required":[]}'),
    ("sast-evidence-backed-code-review", "SAST 有证据代码风险复核", "sast", '["sast"]',
     '{"action":"review_existing_findings","selectors":{"sources":["SAST"],"severities":["critical","high","medium"],"statuses":["open","pending","confirmed","fixing","retest"]},"evidence_required":["finding_location","finding_evidence"]}'),
    ("agent-privilege-boundary-review", "AGENT 高风险权限边界复核", "agent", '["agent"]',
     '{"action":"review_existing_findings","selectors":{"sources":["AGENT"],"severities":["critical","high"],"statuses":["open","pending","confirmed","fixing","retest"]},"evidence_required":["finding_location"]}'),
    ("confirmed-remediation-followup", "跨模块整改跟踪复核", "cross", '["sca","sast","agent"]',
     '{"action":"review_existing_findings","selectors":{"sources":["SCA","SAST","AGENT"],"statuses":["confirmed","fixing","retest"]},"evidence_required":[]}'),
)


def upgrade():
    connection = op.get_bind()
    op.execute("ALTER TABLE security_skills ADD COLUMN IF NOT EXISTS is_builtin BOOLEAN NOT NULL DEFAULT FALSE")
    op.execute("ALTER TABLE security_skills ADD COLUMN IF NOT EXISTS auto_trigger_scan_types JSONB NOT NULL DEFAULT '[]'::jsonb")
    op.execute("ALTER TABLE security_skill_runs ADD COLUMN IF NOT EXISTS trigger VARCHAR(40) NOT NULL DEFAULT 'manual'")
    op.execute("ALTER TABLE security_skill_runs ADD COLUMN IF NOT EXISTS trigger_scan_task_id UUID REFERENCES scan_tasks(id)")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_security_skill_auto_run ON security_skill_runs (skill_id, trigger_scan_task_id) WHERE trigger_scan_task_id IS NOT NULL")
    for slug, name, module, triggers, manifest in BUILTINS:
        description = {
            "critical-high-cross-module-triage": "汇总当前项目各静态模块中尚需处置的高危和严重 Finding。",
            "sca-critical-high-priority": "从最新 SCA 结果中筛选需要优先处置的高危和严重组件风险。",
            "sast-evidence-backed-code-review": "筛选具有代码位置和原始证据的中高危 SAST Finding。",
            "agent-privilege-boundary-review": "筛选 Agent、MCP、工具或插件配置中的高风险权限边界 Finding。",
            "confirmed-remediation-followup": "汇总已确认、修复中或等待复测的跨模块 Finding。",
        }[slug]
        connection.exec_driver_sql(f"""INSERT INTO security_skills
            (id, tenant_id, slug, name, description, module, status, active_version, is_builtin,
             auto_trigger_scan_types, created_by, created_at, updated_at)
            SELECT md5(t.id::text || ':{slug}')::uuid, t.id, '{slug}', '{name}', '{description}',
                   '{module}', 'published', 1, TRUE, '{triggers}'::jsonb, 'platform', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            FROM tenants t ON CONFLICT (tenant_id, slug) DO NOTHING""")
        connection.exec_driver_sql(f"""INSERT INTO security_skill_versions
            (id, skill_id, version, manifest, status, change_note, created_by, created_at, published_at)
            SELECT md5(s.id::text || ':v1')::uuid, s.id, 1, '{manifest}'::jsonb, 'published',
                   '平台内置通用基线', 'platform', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            FROM security_skills s WHERE s.slug = '{slug}' AND s.is_builtin = TRUE
              AND NOT EXISTS (SELECT 1 FROM security_skill_versions v WHERE v.skill_id=s.id AND v.version=1)""")


def downgrade():
    op.execute("""DELETE FROM security_skill_runs
        WHERE skill_id IN (SELECT id FROM security_skills WHERE is_builtin = TRUE)""")
    for slug, *_ in BUILTINS:
        op.execute(f"DELETE FROM security_skills WHERE slug = '{slug}' AND is_builtin = TRUE")
    op.execute("DROP INDEX IF EXISTS uq_security_skill_auto_run")
    op.execute("ALTER TABLE security_skill_runs DROP COLUMN IF EXISTS trigger_scan_task_id")
    op.execute("ALTER TABLE security_skill_runs DROP COLUMN IF EXISTS trigger")
    op.execute("ALTER TABLE security_skills DROP COLUMN IF EXISTS auto_trigger_scan_types")
    op.execute("ALTER TABLE security_skills DROP COLUMN IF EXISTS is_builtin")
