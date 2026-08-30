import React, { useEffect, useMemo, useState } from "react";
import ReactDOM from "react-dom/client";
import { Activity, ArrowRight, BookOpen, Boxes, Bug, Check, FlaskConical, FolderKanban, GitBranch, LoaderCircle, Lock, Network, Play, Plus, ShieldCheck, SlidersHorizontal } from "lucide-react";
import "./styles.css";

type ViewKey = "projects" | "assets" | "detection" | "governance" | "knowledge" | "modules" | "sca" | "sast" | "agent" | "dast" | "sandbox" | "tasks" | "aspm";
type ModuleKey = "sast" | "sca" | "agent" | "dast" | "sandbox" | "aspm";
type ExecutableModuleKey = Exclude<ModuleKey, "aspm">;
type ModuleLoadingState = Record<ExecutableModuleKey, boolean>;
type Severity = "critical" | "high" | "medium" | "low" | "info";
type FindingStatus = "open" | "pending" | "confirmed" | "fixing" | "fixed" | "accepted_risk" | "false_positive" | "retest" | "closed";
const LAST_PROJECT_STORAGE_KEY = "ai-security-platform:last-project-id";

type SecurityModule = { key: ModuleKey; code: string; name: string; subtitle: string; category: string; description: string; capabilities: { title: string; description: string }[]; dependencies: ModuleKey[]; default_config: Record<string, unknown> };
type Project = { id: string; name: string; business_owner: string | null; security_owner: string | null; repository_url: string | null; source_path: string | null; runtime_url: string | null; api_base_url: string | null; sandbox_command: string | null; sandbox_image: string | null; default_branch: string; risk_score: number; created_at: string };
type ProjectDraft = { name: string; business_owner: string; security_owner: string; repository_url: string; source_path: string; runtime_url: string; api_base_url: string; sandbox_command: string; sandbox_image: string; default_branch: string };
type ProjectAssetDraft = Pick<ProjectDraft, "runtime_url" | "api_base_url" | "sandbox_command" | "sandbox_image">;
type ProjectImportMode = "local" | "git" | "zip";
type ProjectReadinessCheck = { key: string; title: string; status: "ready" | "warning" | "blocked" | "optional"; detail: string; remediation: string };
type ProjectReadiness = { project_id: string; overall_status: "ready" | "warning" | "blocked"; recommended_tasks: ("sca" | "sast" | "agent")[]; inventory: { source_path?: string | null; path_exists?: boolean; dependency_file_count?: number; source_file_count?: number; agent_file_count?: number; inspected_file_count?: number; inspected_bytes?: number; truncated?: boolean }; quick_scan: { available?: boolean; mode?: string; limits?: Record<string, number>; statement?: string }; checks: ProjectReadinessCheck[] };
type ProjectImportResult = { project: Project; readiness: ProjectReadiness; import_mode: ProjectImportMode; managed_source: boolean };
type ScanMode = "quick" | "deep";
type ProjectModule = { project_id: string; module_key: ModuleKey; enabled: boolean; config: Record<string, unknown> };
type ProjectAssetProbe = { project_id: string; source_path: string | null; path_exists: boolean; sca_files: string[]; source_files: string[]; agent_files: string[]; recommended_tasks: ("sca" | "sast" | "agent")[]; message: string };
type Component = { id: string; ecosystem: string; name: string; version: string | null; dependency_type: string; source_file: string; package_manager: string | null; license?: string | null; risk_status?: string; vulnerability_ids?: string[]; severity?: Severity | null; risk_summary?: string | null; remediation?: string | null; license_risk?: string | null; risk_source?: string | null; osv_checked?: boolean; osv_error?: string | null; risk_metadata?: { risk_score?: number; kev?: boolean; known_exploited?: boolean; max_epss?: number | null; fixed_versions?: string[]; advisories?: Record<string, unknown>[]; vex?: ScaVex[] } };
type ScaToolStatus = { enabled: boolean; status: string; syft_component_count: number; grype_vulnerability_count: number; trivy_vulnerability_count?: number; grype_input?: string | null; syft_status?: string; syft_detail?: string | null; grype_status?: string; grype_detail?: string | null; trivy_status?: string; trivy_detail?: string | null; errors: string[] };
type ScaToolHealthCheck = { name: string; status: string; detail: string | null; remediation: string | null };
type ScaToolHealth = { status: string; recommended_grype_input: string; checks: ScaToolHealthCheck[] };
type ScanAssurance = { status?: string; execution_status?: string; confidence?: string; component_count?: number; resolved_component_count?: number; lock_or_environment_component_count?: number; declared_exact_component_count?: number; constraint_component_count?: number; verified_component_count?: number; unverified_component_count?: number; vulnerability_coverage_percent?: number; reasons?: string[]; statement?: string; completed_engines?: string[]; enabled_engines?: string[]; limitations?: string[] };
type SastEngineStatus = { status?: string; execution_status?: string; detail?: string; statement?: string; config?: string; confidence?: string; expected_agent_count?: number; agent_count?: number; incomplete_roles?: string[]; limitations?: string[]; completed_engines?: string[]; enabled_engines?: string[] };
type ScaScanResult = { project_id: string; scan_task_id: string; source_path: string; scanned_files: string[]; component_count: number; components: Component[]; tool_status?: ScaToolStatus | null; assurance?: ScanAssurance };
type SastCustomRule = { id: string; rule_id: string; title: string; severity: Severity; category: string; pattern: string; file_extensions: string[]; description: string; remediation: string; enabled: boolean; version: number; created_at: string };
type SastSemgrepRule = { id: string; name: string; content: string; rule_ids: string[]; sha256: string; enabled: boolean; status: "draft" | "published" | "archived"; approved_by?: string | null; version: number; created_at: string };
type SastQualityGate = { enabled: boolean; threshold: "critical" | "high" | "medium" | "low" | "info" | "none"; block_new_only: boolean; max_blocking_findings: number; branch_patterns: string[]; excluded_rule_ids: string[] };
type SastProfile = { profile_version: number; rule_pack_version: string; semgrep_enabled: boolean; semgrep_config: string; include_local_rules: boolean; clear_previous: boolean; git_baseline_ref: string; scan_git_history_secrets: boolean; changed_files_only: boolean; ai_enabled: boolean; ai_auto_scan: boolean; ai_max_input_chars: number; ai_confidence_threshold: number; ai_include_fix_drafts: boolean; quality_gate: SastQualityGate; suppressions: SastSuppression[]; custom_rules: SastCustomRule[]; semgrep_rules: SastSemgrepRule[] };
type SastSuppression = { id: string; rule_id: string; path_pattern: string; reason: string; expires_at: string | null; enabled: boolean; created_at: string };
type SastToolHealth = { semgrep_cli: { available: boolean; version: string | null; path: string | null }; docker: { available: boolean; version: string | null; path: string | null }; docker_image: { available: boolean; image: string }; can_run_semgrep: boolean };
type SastScanHistoryItem = { scan_task_id: string; status: string; created_at: string; started_at: string | null; finished_at: string | null; finding_count: number; suppressed_count: number; engine_status: Record<string, SastEngineStatus>; profile: Partial<SastProfile> };
type SastScanDiff = { target_scan_id: string; base_scan_id: string | null; summary: { added: number; removed: number; severity_changed: number; unchanged: number }; added: Record<string, unknown>[]; removed: Record<string, unknown>[]; severity_changed: Record<string, unknown>[] };
type SastReport = { project_id: string; scan: SastScanHistoryItem; summary: { finding_count: number; severity: Record<string, number>; categories: Record<string, number> }; trend: SastScanDiff; git: { available?: boolean; baseline_ref?: string | null; changed_files?: string[]; history_secret_files?: string[]; history_secret_count?: number }; quality_gate: { status: string; threshold: string; blocking_finding_count: number }; validation_suggestions: { finding_id: string; recommended_module: string; next_step: string; automatic_execution: boolean }[] };
type SastFixDraft = { finding_id: string; status: string; category: string; patch: string; recommended_change: string; limitations: string[]; regression_scan: { endpoint: string; required_fields: string[] } };
type SastAiHealth = { configured: boolean; provider: string; status: string; base_url?: string; model?: string; review_model?: string; thinking_enabled?: boolean; timeout_seconds?: number; max_retries?: number; api_key_location?: string; agent_roles?: string[]; detail?: string };
type SastAgentStep = { role: string; status: string; model?: string; prompt_tokens?: number; completion_tokens?: number; latency_ms?: number; estimated_cost_usd?: number | null; error?: string };
type SastAgentRun = { id: string; scan_task_id: string | null; status: string; provider: string; model: string; review_model: string; trigger: string; agent_steps: SastAgentStep[]; result_summary: { candidate_count?: number; confirmed_count?: number; disagreement_count?: number; expected_agent_count?: number; completed_agent_count?: number; incomplete_roles?: string[]; context_summary?: { uploaded_file_count?: number; uploaded_char_count?: number; redaction_count?: number; truncated?: boolean }; disagreements?: Array<{ subject?: string; detail?: string }> }; token_usage: { call_count?: number; prompt_tokens?: number; completion_tokens?: number; estimated_cost_usd?: number | null }; error: string | null; started_at: string; finished_at: string | null };
type ScanTask = { id: string; project_id: string; scan_type: string; status: "queued" | "running" | "completed" | "failed" | "cancelled"; metadata: Record<string, unknown>; progress: number; stage: string | null; attempt: number; error: string | null; created_at: string };
type ScaScanHistoryItem = { scan_task_id: string; status: string; started_at: string | null; finished_at: string | null; created_at: string; component_count: number; direct_dependency_count: number; transitive_dependency_count: number; critical_count: number; high_count: number; vulnerable_count: number; license_risk_count: number; tool_status?: ScaToolStatus | null; osv_status: string; osv_error_count: number; assurance?: ScanAssurance };
type ScaScanDiffItem = { ecosystem: string; name: string; change_type: string; base_version: string | null; target_version: string | null; base_risk_status: string | null; target_risk_status: string | null; base_severity: Severity | null; target_severity: Severity | null; base_license_risk: string | null; target_license_risk: string | null; base_vulnerability_ids: string[]; target_vulnerability_ids: string[]; summary: string };
type ScaScanDiffSummary = { added_components: number; removed_components: number; version_changes: number; risk_added: number; risk_removed: number; license_risk_changes: number; total_changes: number };
type ScaScanDiff = { project_id: string; base_scan_id: string | null; target_scan_id: string; has_comparison: boolean; summary: ScaScanDiffSummary; changes: ScaScanDiffItem[] };
type DependencyGraphNode = { id: string; label: string; kind: string; risk_status?: string | null; severity?: Severity | null; dependency_type?: string | null; ecosystem?: string | null; version?: string | null };
type DependencyGraphEdge = { source: string; target: string; quality: string };
type UpgradeLever = { component_id: string; component: string; ecosystem: string; version: string | null; risk_transitive_count: number; highest_severity: Severity | null; affected_components: string[]; recommendation: string };
type DependencyGraph = { project_id: string; nodes: DependencyGraphNode[]; edges: DependencyGraphEdge[]; upgrade_levers: UpgradeLever[]; impact_paths?: { component: string; severity: Severity | null; risk_status: string; paths: string[][] }[]; summary: Record<string, number> };
type ScaException = { id: string; ecosystem: string; package_name: string; package_version: string | null; exception_type: string; reason: string; status: string; requester: string | null; requester_role?: string | null; approver: string | null; approver_role?: string | null; expires_at: string | null; approval_note: string | null; approval_history?: Record<string, unknown>[] };
type ScaVex = { id: string; ecosystem: string; package_name: string; package_version: string | null; vulnerability_id: string; status: "not_affected" | "affected" | "fixed" | "under_investigation"; justification: string | null; action_statement: string | null; evidence: string | null; actor: string | null; expires_at: string | null; created_at?: string; updated_at?: string };
type ScaGatePolicy = { enabled: boolean; block_severities: string[]; block_license_policies: string[]; min_risk_score: number; block_kev: boolean; max_scan_age_hours: number; require_intelligence_for_critical: boolean; block_unverified_components?: boolean; source?: string };
type ScaPolicies = { scope?: string; override_count?: number; vulnerability_rules: { id: string; ecosystem: string; package: string; enabled: boolean; severity: Severity; affected?: string; fixed_version?: string; source?: string }[]; license_policies: { id: string; policy: string; keywords: string[]; approval_required: boolean; enabled?: boolean; source?: string }[]; gate_policy?: ScaGatePolicy };
type ScaPolicyAudit = { id: string; event_type: string; actor: string | null; details: Record<string, unknown>; created_at: string };
type ScaGate = { decision: "pass" | "block"; exit_code: number; reason: string; blocked_component_count: number; accepted_risk_count: number; ci_usage: string; scan_stale_or_missing?: boolean; policy?: ScaGatePolicy; blocked_components: { name: string; version: string | null; ecosystem: string; severity: Severity | null; vulnerability_ids: string[]; reasons?: string[] }[] };
type ScaEvidence = { scan_task_id: string; artifact_hashes: Record<string, unknown>; osv_mirror: Record<string, unknown>; intelligence?: Record<string, unknown>; native_dependency_sources: Record<string, { status: string; manifest: string; tool: string; edge_count: number; detail: string }>; policy_snapshot: Record<string, unknown>; assurance?: ScanAssurance; gate: ScaGate };
type AiReview = { summary: string; false_positive_likelihood: string; remediation: string; category?: string | null; cwe?: string | null; owasp?: string | null; language?: string | null; description?: string | null; trust_impact?: string | null; review_status?: string | null; analysis_source?: string | null; agent_pipeline?: string[]; review_verdict?: string | null; evidence_summary?: string | null; fix_strategy?: string | null; priority?: string | null; ai_provider?: string | null; ai_confidence?: number | null; ai_review_source?: string | null; fix_draft?: { recommended_change?: string; patch?: string; tests?: string[]; limitations?: string[] } };
type Finding = { id: string; component_id?: string | null; source: string; rule_id: string; title: string; severity: Severity; file_path: string | null; line_start: number | null; status: FindingStatus; evidence: string | null; ai_review?: AiReview | null; remediation_owner?: string | null; remediation_note?: string | null; remediation_due_at?: string | null; updated_at?: string | null };
type DastStrategy = { id: string; name: string; description: string; scope_summary: string; check_items: string[]; limitations: string[] };
type DastValidation = { id: string; finding_id?: string | null; component_id?: string | null; link_source: string; link_confidence: number; target_url: string; verdict: string; validator: string | null; strategy_id: string; strategy_name?: string | null; scope_summary?: string | null; limitations?: string | null; evidence_summary: string | null; request_summary?: string | null; response_summary?: string | null; reproduction_steps?: string | null; remediation_hint?: string | null; validation_mode: "manual_validation" | "automated_web_baseline"; connection_confirmed: boolean; created_at: string };
type ManualDastValidationDraft = { target_url: string; verdict: "exploitable" | "uncertain" | "not_exploitable"; evidence_summary: string; reproduction_steps: string; response_summary: string; remediation_hint: string };
type DastVerificationPlan = { id: string; project_id: string; finding_id?: string | null; component_id?: string | null; title: string; target_url: string; authorized_scope: string; allowed_paths: string[]; allowed_methods: string[]; strategy_id: string; strategy_name?: string | null; limitations?: string | null; requester: string; approval_status: "draft" | "approved" | "archived"; approval_reference?: string | null; approved_by?: string | null; approved_at?: string | null; created_at: string };
type DastVerificationRun = { id: string; project_id: string; plan_id: string; validation_id?: string | null; status: "prepared" | "evidence_recorded" | "reviewed"; execution_mode: "documentation_only"; operator: string; purpose?: string | null; started_at: string; completed_at?: string | null; created_at: string };
type DastRunEvidence = { id: string; project_id: string; plan_id: string; run_id: string; evidence_type: string; content_summary: string; content_hash: string; source_reference?: string | null; collected_by?: string | null; redaction_applied: boolean; created_at: string };
type DastBusinessCandidate = { id: string; source: "SAST" | "AGENT"; scan_task_id?: string | null; rule_id: string; title: string; severity: Severity; vulnerability_type: string; cwe?: string | null; file_path?: string | null; line_start?: number | null; line_end?: number | null; evidence?: string | null; attack_surface: { urls: string[]; methods: string[]; parameters: string[]; injection_points?: { name: string; location: string }[] }; preconditions: { required_roles: string[]; required_fixtures: string[]; business_notes: string[] }; missing: string[]; requires_human_input: boolean; readiness: "ready" | "needs_context" | "blocked"; target_status: "configured" | "not_configured"; recommended_strategy_id: string; recommended_strategy_name: string; strategy_description: string; strategy_match: "builtin" | "ai_required"; evidence_requirements: string[]; required_capabilities: string[]; auto_filled: string[]; validation_status: "unverified" | "verifying" | "verified" | "failed"; validation_count: number; latest_flow_id?: string | null; latest_run_id?: string | null; latest_run_status?: string | null; latest_verdict?: "exploitable" | "not_exploitable" | "uncertain" | null; latest_verdict_reason?: string | null; latest_verified_at?: string | null };
type DastBusinessFlow = { id: string; project_id: string; finding_id?: string | null; name: string; target_url: string; flow_mode: "api" | "browser" | "hybrid"; strategy_source: "manual" | "recorded" | "template" | "ai_draft" | "learned_template"; authorized_scope: string; allowed_paths: string[]; roles: Record<string, unknown>[]; steps: Record<string, unknown>[]; sufficiency_criteria: Record<string, unknown>; requester: string; status: "draft" | "approved" | "archived"; approval_reference?: string | null; approved_by?: string | null; approved_at?: string | null; created_at: string };
type DastBusinessRun = { id: string; project_id: string; flow_id: string; status: string; execution_mode: "dry_run" | "api_execution" | "sandbox_handoff"; operator: string; verdict?: "exploitable" | "not_exploitable" | "uncertain" | null; verdict_reason?: string | null; started_at?: string | null; completed_at?: string | null; created_at: string };
type DastBusinessSnapshot = { id: string; project_id: string; flow_id: string; run_id: string; step_id: string; step_kind: string; role_alias?: string | null; status: string; request_summary?: string | null; response_summary?: string | null; detail: Record<string, unknown>; evidence_hash: string; created_at: string };
type DastDiscovery = { task_id: string; status: string; target_url: string; urls: string[]; forms: { form_id: string; action: string; method: string; parameters: Record<string, unknown>[]; source_url: string }[]; api_urls: string[]; parameters: Record<string, unknown>[]; request_logs: { request_id: string; method: string; url: string; status_code?: number; status?: string; duration_ms: number; response_bytes: number }[]; environment: Record<string, unknown>; errors: string[]; scope: Record<string, unknown> };
type DastReport = { schema: string; generated_at: string; project_id: string; summary: { record_count: number; automated_baseline_count: number; manual_validation_count: number; linked_record_count: number; by_verdict: Record<string, number>; verification_plan_count: number; approved_plan_count: number; documentation_run_count: number; reviewed_run_count: number; evidence_item_count: number; business_flow_count?: number; business_run_count?: number; tri_color?: { total: number; exploitable: number; uncertain: number; not_exploitable: number }; unverified_count?: number; execution_status?: Record<string, number>; evidence_coverage?: Record<string, number> }; records: DastValidation[]; verification_plans: DastVerificationPlan[]; verification_runs: DastVerificationRun[]; evidence_index: DastRunEvidence[]; vulnerability_details?: Record<string, unknown>[]; execution_log_summary?: Record<string, unknown>[]; capability_boundaries: string[] };
type DastPreflight = { status: "ready" | "blocked" | "waiting_sandbox"; can_execute_local: boolean; can_handoff_sandbox: boolean; required_capabilities: string[]; checks: { code: string; label: string; status: "passed" | "blocked" | "waiting"; detail: string; remediation?: string | null }[] };
type SandboxExecutionPlan = { strategyName: string; purpose: string; limitations: string };
type SandboxEvidence = { id: string; finding_id?: string | null; component_id?: string | null; validation_id?: string | null; link_source: string; link_confidence: number; run_command: string; runtime_profile: string | null; network_policy: string; filesystem_policy: string; observed_files: Record<string, unknown>[]; observed_network: Record<string, unknown>[]; observed_processes: Record<string, unknown>[]; observed_tool_calls: Record<string, unknown>[]; evidence_summary: string | null; operator: string | null; strategy_name?: string | null; purpose?: string | null; limitations?: string | null; created_at: string };
type SandboxTemplate = { name: string; command: string; command_type: string; image: string; risk_level: string; description: string; container_port?: number | null };
type SandboxSupportService = { name: string; kind: string; image: string; source: string; healthcheck: string };
type SandboxLaunchCandidate = { name: string; image: string; command: string; container_port: number; health_path: string; source: string; source_subdir?: string; confidence: number; rationale: string; approved: boolean; services?: SandboxSupportService[] };
type SandboxLaunchPlan = { schema: string; project_id?: string; status: string; recommended: SandboxLaunchCandidate | null; candidates: SandboxLaunchCandidate[]; orchestration?: { mode: "single_service" | "multi_service"; support_services: SandboxSupportService[] }; ai: { status: string; configured: boolean; model?: string | null; rationale?: string | null; missing_services?: string[]; environment_variables?: string[] }; message: string };
type SandboxCapabilityHealth = { status: string; docker: { available: boolean; ready: boolean; detail: string }; executor_image: string; browser_image: string; capabilities: Record<string, { status: string; detail: string }>; checked_at: string };
type SandboxTarget = { id: string; project_id: string; mode: "external" | "docker"; status: string; runtime_url: string; internal_url: string | null; image: string | null; command: string | null; container_port: number | null; health_path: string; health_detail: Record<string, unknown>; policy: Record<string, unknown>; operator: string; expires_at: string | null; stopped_at: string | null; created_at: string; updated_at: string };
type SandboxTask = { id: string; project_id: string; target_instance_id: string | null; source_module: string; source_task_id: string; strategy_id: string; finding_id: string | null; status: string; required_capabilities: string[]; contract: Record<string, unknown>; execution_id: string | null; evidence: Record<string, unknown>[]; result_summary: string | null; error: string | null; operator: string | null; started_at: string | null; completed_at: string | null; created_at: string; updated_at: string };
type SandboxTaskEvent = { id: string; task_id: string; state: string; status: string; detail: Record<string, unknown>; created_at: string };
type AttackChainStep = { module: string; title: string; evidence: string | null; node_id?: string | null; relation_type?: string | null; confidence?: number | null; created_at?: string | null };
type AttackChain = { id: string; name: string; severity: Severity; modules: string[]; evidence_count: number; confidence: number; correlation_basis: string[]; summary: string; recommended_action: string; steps: AttackChainStep[] };
type EvidenceGraphNode = { id: string; kind: string; module: string; label: string; severity?: Severity | null; status?: string | null; detail?: string | null; created_at?: string | null };
type EvidenceGraphEdge = { id: string; source: string; target: string; relation_type: string; basis: string; confidence: number; created_at?: string | null };
type EvidenceGraph = { project_id: string; nodes: EvidenceGraphNode[]; edges: EvidenceGraphEdge[]; summary: Record<string, number> };
type LinkSuggestion = { finding_id?: string | null; component_id?: string | null; validation_id?: string | null; confidence: number; confidence_level: "high" | "medium" | "low"; reasons: string[]; label: string; source: string };
type ExecutionStatus = "waiting" | "running" | "completed" | "failed" | "skipped";
type ExecutionStep = { module: Exclude<ModuleKey, "aspm">; status: ExecutionStatus; detail: string };
type RetestResult = "still_present" | "resolved" | "new" | "changed";
type FindingRetestItem = { identity: string; result: RetestResult; title: string; file_path?: string | null; previous_line_start?: number | null; current_line_start?: number | null; previous_severity?: Severity | null; current_severity?: Severity | null; previous_finding_id?: string | null; current_finding_id?: string | null };
type FindingRetestComparison = { project_id: string; source: string; has_comparison: boolean; previous_scan_id?: string | null; current_scan_id?: string | null; previous_scan_at?: string | null; current_scan_at?: string | null; still_present_count: number; resolved_count: number; new_count: number; changed_count: number; items: FindingRetestItem[] };
type AgentConfigAdapterCoverage = { asset_count: number; parsed_asset_count: number; failed_asset_count: number; label: string; validation_level: string; status: string; schema_reference_count: number; schema_references_not_validated: number; limitation: string };
type AgentScanCoverage = { discovered_asset_count: number; parsed_asset_count: number; failed_asset_count: number; skipped_file_count: number; findings_by_asset_type: Record<string, number>; asset_types: Record<string, number>; adapter_coverage: Record<string, AgentConfigAdapterCoverage>; generic_parser_asset_count: number; schema_references_not_validated: number };
type AgentQualityGate = { decision?: "pass" | "block"; exit_code?: number; reasons?: string[]; blocking_finding_count?: number; blocking_permission_count?: number; blocking_asset_count?: number; blocking_intelligence_count?: number; blocking_dataflow_count?: number; blocking_coverage_count?: number; trust_score?: { score?: number; grade?: string; confidence?: string; trust_sha256?: string }; policy?: AgentGatePolicy };
type AgentGatePolicy = { enabled: boolean; threshold: "critical" | "high" | "medium" | "low" | "info" | "none"; block_new_only: boolean; max_blocking_findings: number; block_wildcard_permissions: boolean; block_parse_failures: boolean; block_skipped_files: boolean; block_generic_config_validation: boolean; block_unvalidated_schema_references: boolean; block_permission_expansion: boolean; require_approval_for_high_risk: boolean; block_unpinned_sources: boolean; block_insecure_sources: boolean; block_unknown_sources: boolean; block_partial_integrity: boolean; block_integrity_changes: boolean; block_source_changes: boolean; block_known_vulnerabilities: boolean; block_malicious_packages: boolean; block_package_confusion: boolean; block_intelligence_gaps: boolean; block_stale_intelligence: boolean; max_intelligence_age_days: number; block_high_risk_dataflow_paths: boolean; block_low_trust_score: boolean; minimum_trust_score: number };
type AgentAllowlistItem = { id?: string; path_pattern: string; subject_pattern: string; capability: string; scope_pattern: string; reason: string };
type AgentException = { id: string; kind: "finding" | "permission"; disposition: "suppress" | "accept_risk"; rule_id?: string; path_pattern: string; subject_pattern?: string; capability?: string; scope_pattern?: string; reason: string; expires_at?: string | null; status: "pending" | "approved" | "rejected" | "revoked"; requester?: string | null; approver?: string | null; approval_note?: string | null; created_at?: string | null };
type AgentAuditItem = { id: string; action: string; actor: string; at: string; detail: Record<string, unknown> };
type AgentProfile = { profile_version: number; rule_version: string; disabled_rule_ids: string[]; excluded_paths: string[]; permission_allowlist: AgentAllowlistItem[]; required_approval_capabilities: string[]; target_runtime_execution_enabled: boolean; exceptions: AgentException[]; audit_log: AgentAuditItem[]; quality_gate: AgentGatePolicy };
type AgentAuditHistorySummary = { available: boolean; schema: string | null; mode: string | null; model_status: string | null; external_model_invoked: boolean; review_item_count: number; active_finding_count: number };
type AgentScanHistoryItem = { scan_task_id: string; status: string; created_at: string; started_at: string | null; finished_at: string | null; source_path: string | null; finding_count: number; rule_version: string | null; coverage: AgentScanCoverage; gate_decision?: string | null; audit_summary?: AgentAuditHistorySummary };
type AgentPermission = { asset_path: string; subject: string; capability: string; access: string; resource_type: string; scope: string; approval: string; risk_level: string; source: string };
type AgentProvenance = { subject: string; package_name: string | null; package_version: string | null; source_type: string; source_ref: string | null; installation_method: string; version_status: string; publisher_claim: string | null; publisher_status: string; source_visibility: string; authentication_status: string; onboarding_status: string; connection_status: string; issues: string[] };
type AgentAsset = { path: string; asset_type: string; format: string; parser: string; status: string; checks: string[]; finding_count: number; detail: string | null; name: string | null; version: string | null; publisher: string | null; transport: string | null; entrypoint: string | null; declared_tools: string[]; declared_resources: string[]; declared_prompts: string[]; permission_count: number; provenance: AgentProvenance[]; file_sha256: string | null; directory_sha256: string | null; integrity_status: string; integrity_issues: string[]; metadata: Record<string, unknown> };
type AgentIntelligenceMatch = { id?: string; severity?: string; summary?: string; source?: string; protected_package?: string; distance?: number };
type AgentIntelligencePackage = { asset_path: string; subject: string; ecosystem: string; package_name: string; package_version: string | null; version_status: string; version_resolved: boolean; purl: string | null; lookup_status: string; coverage_sources: string[]; vulnerabilities: AgentIntelligenceMatch[]; threats: AgentIntelligenceMatch[]; confusion_signals: AgentIntelligenceMatch[] };
type AgentIntelligenceSource = { status: string; path: string; entry_count: number; protected_package_count?: number; updated_at: string | null; age_days: number | null; detail?: string };
type AgentIntelligence = { mode: string; generated_at: string; sources: Record<string, AgentIntelligenceSource>; summary: Record<string, number>; packages: AgentIntelligencePackage[]; limitations: string[] };
type AgentDataflowNode = { id: string; kind: string; label: string; asset_path: string; trust: string; attributes: Record<string, unknown> };
type AgentDataflowEdge = { id: string; source: string; target: string; relation: string; confidence: "low" | "medium" | "high"; evidence: string; basis: string };
type AgentDataflowPath = { id: string; kind: string; title: string; severity: Severity; confidence: "low" | "medium" | "high"; asset_path: string; tool_asset_path?: string; source_trust: string; capability: string; resource_type: string; resource_scope: string; approval: string; node_ids: string[]; edge_ids: string[]; controls: { type: string; reference?: string; runtime_verified?: boolean }[]; missing_controls: string[]; evidence: string[] };
type AgentDataflow = { schema: string; mode: string; summary: Record<string, number>; nodes: AgentDataflowNode[]; edges: AgentDataflowEdge[]; paths: AgentDataflowPath[]; limitations: string[] };
type AgentTrustDeduction = { id: string; points: number; count: number; detail: string; dimension_id?: string; dimension_label?: string };
type AgentTrustDimension = { id: string; label: string; score: number; max_score: number; status: string; deductions: AgentTrustDeduction[]; positive_evidence: string[]; limitations: string[] };
type AgentTrustScore = { schema: string; algorithm_version: string; score: number; uncapped_score: number; score_cap: number; grade: string; confidence: "low" | "medium" | "high"; evidence_completeness: number; dimensions: AgentTrustDimension[]; top_deductions: AgentTrustDeduction[]; improvements: { id: string; title: string; action: string }[]; score_caps: { id: string; maximum_score: number; detail: string }[]; evidence_summary: Record<string, number | boolean>; limitations: string[]; trust_sha256: string };
type AgentRuntimeCheck = { id: string; status: "pass" | "warn" | "block"; detail: string; remediation: string | null };
type AgentRuntimePath = { id: string; kind: string; title: string; severity: Severity; confidence: string; asset_path: string; tool_asset_path?: string | null; capability: string; resource_type: string; resource_scope: string };
type AgentRuntimePlan = { schema: string; mode: string; execution_enabled: boolean; decision: "blocked" | "awaiting_explicit_execution_approval"; plan_sha256: string; source_path: string | null; proposed_command: string | null; proposed_image: string | null; timeout_seconds: number; staging: { status: string; path: string; source_mode: string; container_mount: string; sensitive_file_count: number; sensitive_categories: Record<string, number>; inventory_truncated: boolean }; isolation_policy: { network: string; root_filesystem: string; workspace: string; environment_injection: string; privileged: boolean; capabilities: string; no_new_privileges: boolean; host_sockets: string; resource_limits: Record<string, string | number> }; checks: AgentRuntimeCheck[]; summary: Record<string, number | boolean>; candidate_dataflow_paths: AgentRuntimePath[]; evidence_template: { status: string; observations: Record<string, unknown[]>; path_results: { dataflow_path_id: string; runtime_status: string; reason: string }[]; redaction: { applied: boolean; secret_values_stored: boolean } }; evidence?: AgentTargetEvidence; next_action: string; limitations: string[] };
type AgentStagingResult = { schema: string; status: string; execution_enabled: boolean; runtime_status: string; plan_sha256: string; staging: { build_id: string; destination_path: string; staging_sha256: string; manifest_sha256: string; summary: { copied_file_count: number; copied_bytes: number; excluded_count: number; exclusion_records_truncated: boolean; runtime_executed: boolean }; verification: { status: string; file_count: number; total_bytes: number; staging_sha256: string; manifest_sha256: string; runtime_executed: boolean }; security: { links_followed: boolean; secret_values_returned: boolean; existing_destination_overwritten: boolean; container_or_agent_executed: boolean } }; next_action: string };
type AgentFixtureStatus = { available: boolean; images: { reference: string; repository: string; digest: string; image_id: string; size: string }[]; download_performed: boolean; recommended_image: string | null; message: string };
type AgentFixtureEvidence = { schema: string; scope: string; decision: "pass" | "block"; execution_enabled_for_real_agents: boolean; run_id: string; started_at: string; elapsed_ms: number; evidence_sha256: string; evidence_path: string; image: { reference: string; digest: string; local_image_id: string; download_performed: boolean }; staging: { path: string; staging_sha256: string; manifest_sha256: string }; container: { command: string[]; exit_code: number | null; timed_out: boolean; removed_after_run: boolean }; policy_checks: Record<string, boolean>; limitations: string[] };
type AgentTargetBuild = { build_id: string; created_at: string; destination_path: string; staging_sha256: string; manifest_sha256: string; scan_task_id: string; plan_sha256: string; command_sha256: string; image: string; timeout_seconds: number; file_count: number };
type AgentTargetStatus = { schema: string; execution_enabled_by_project_policy: boolean; authorization_phrase: string; current_scan_task_id: string | null; builds: AgentTargetBuild[]; download_performed: boolean; message: string };
type AgentMcpLedgerEvent = { event_id: string; event_type: string; method?: string; subject_kind?: string; subject?: string; outcome?: string; duration_ms?: number; payload_bytes?: number; phase?: string; executable?: string; exit_code?: number; event_sha256: string };
type AgentMcpLedger = { schema: string; transport: string; source: string; observer_version: string; integrity: string; content_stored: boolean; rejected_event_count: number; summary: Record<string, number | Record<string, number>>; events: AgentMcpLedgerEvent[] };
type AgentTargetEvidence = { schema: string; scope: string; status: string; decision: "pass" | "attention"; execution_id: string; started_at: string; finished_at: string; elapsed_ms: number; policy_verified: boolean; behavioral_telemetry_complete: boolean; evidence_sha256: string; evidence_path: string; image: { reference: string; digest: string; local_image_id: string; download_performed: boolean }; staging: { build_id: string; path: string; staging_sha256: string; manifest_sha256: string; unchanged_after_run: boolean }; container: { command_sha256: string; command_preview: string; exit_code: number | null; timed_out: boolean; removed_after_run: boolean }; policy_checks: Record<string, boolean>; telemetry_coverage: Record<string, string>; observations?: { processes?: Record<string, unknown>[]; tool_calls?: Record<string, unknown>[] }; mcp_ledger?: AgentMcpLedger; path_results: { dataflow_path_id: string; runtime_status: string; reason: string }[]; output: { stdout_char_count: number; stderr_char_count: number; stdout_sha256: string; stderr_sha256: string; truncated: boolean; redacted_before_hashing: boolean; content_stored: boolean }; limitations: string[]; trust_score?: AgentTrustScore };
type AgentMcpProbeCandidate = { candidate_id: string; config_path: string; config_sha256: string; server_name: string; transport: string; command_preview: string | null; command_sha256: string | null; eligible: boolean; checks: Record<string, boolean>; rejection_reasons: string[] };
type AgentMcpProbeBuild = { build_id: string; created_at: string; staging_sha256: string; manifest_sha256: string; scan_task_id: string; plan_sha256: string; image: string; timeout_seconds: number; candidates: AgentMcpProbeCandidate[] };
type AgentMcpProbeStatus = { schema: string; execution_enabled_by_project_policy: boolean; authorization_phrase: string; current_scan_task_id: string | null; builds: AgentMcpProbeBuild[]; download_performed: boolean; limitations: string[] };
type AgentMcpProbeEvidence = { schema: string; status: string; decision: "pass" | "attention"; execution_id: string; elapsed_ms: number; policy_verified: boolean; evidence_sha256: string; evidence_path: string; candidate: AgentMcpProbeCandidate; capability_probe: { status: string; protocol_version: string; server_name: string; server_version: string; tool_names: string[]; resource_schemes: string[]; prompt_names: string[]; method_outcomes: Record<string, string>; content_actions_performed: boolean; content_stored: boolean }; mcp_ledger: AgentMcpLedger; image: { reference: string; download_performed: boolean }; staging: { build_id: string; unchanged_after_run: boolean }; container: { exit_code: number | null; timed_out: boolean; removed_after_run: boolean }; limitations: string[]; trust_score?: AgentTrustScore };
type AgentRemoteMcpProbeCandidate = { candidate_id: string; config_path: string; config_sha256: string; server_name: string; transport: string; endpoint_preview: string; endpoint_sha256: string; hostname: string; eligible: boolean; checks: Record<string, boolean>; rejection_reasons: string[] };
type AgentRemoteMcpProbeBuild = { build_id: string; created_at: string; staging_sha256: string; manifest_sha256: string; scan_task_id: string; plan_sha256: string; image: string; timeout_seconds: number; candidates: AgentRemoteMcpProbeCandidate[] };
type AgentRemoteMcpProbeStatus = { schema: string; execution_enabled_by_project_policy: boolean; authorization_phrase: string; current_scan_task_id: string | null; builds: AgentRemoteMcpProbeBuild[]; download_performed: boolean; limitations: string[] };
type AgentRemoteMcpProbeEvidence = { schema: string; status: string; decision: "pass" | "attention"; execution_id: string; elapsed_ms: number; policy_verified: boolean; evidence_sha256: string; evidence_path: string; candidate: AgentRemoteMcpProbeCandidate; capability_probe: { status: string; transport_mode: string; protocol_version: string; server_name: string; server_version: string; endpoint: string; approved_ips: string[]; redirects: string[]; tool_names: string[]; resource_schemes: string[]; prompt_names: string[]; method_outcomes: Record<string, string>; authentication_sent: boolean; configured_headers_used: boolean; content_actions_performed: boolean; content_stored: boolean }; network_policy: { hostname: string; port: number; approved_ips: string[]; dns_resolved_immediately_before_run: boolean; private_and_metadata_destinations_blocked: boolean; cross_origin_redirects_blocked: boolean; transport_enforcement: string }; image: { reference: string; download_performed: boolean }; staging: { build_id: string; unchanged_after_run: boolean }; container: { exit_code: number | null; timed_out: boolean; removed_after_run: boolean }; limitations: string[]; trust_score?: AgentTrustScore };
type AgentOfflineAuditItem = { id: string; kind: string; priority: Severity | string; title: string; rationale: string; evidence_refs: string[]; review_questions: string[]; review_status: string; model_status: string };
type AgentOfflineAudit = { schema: string; mode: string; generated_at: string; model_status: string; external_model_invoked: boolean; summary: { active_finding_count: number; review_item_count: number; critical_or_high_finding_count: number; coverage_gap_count: number; private_source_preflight_gap_count: number; high_risk_static_path_count: number; local_intelligence_gap_count: number; trust_score: number; trust_grade: string }; items: AgentOfflineAuditItem[]; limitations: string[]; audit_sha256: string };
type AgentAiReview = { schema: string; status: string; provider: string; model: string; mode: string; external_model_invoked: boolean; input_sha256: string; input_summary: { candidate_count: number; input_char_count: number; source_code_included: boolean; prompt_content_included: boolean; credential_values_included: boolean; tool_parameters_included: boolean; target_data_included: boolean }; summary: string; reviews: { audit_item_id: string; review_status: string; review_priority: Severity; rationale: string; review_questions: string[]; recommended_actions: string[]; limitations: string[] }[]; usage: { call_count: number; prompt_tokens: number; completion_tokens: number; cache_hit_tokens: number; latency_ms: number; estimated_cost_usd: number | null; maximum_estimated_cost_usd: number | null }; limitations: string[] };
type AgentOfflineAuditDiffItem = { id: string; result: "new" | "still-pending" | "not-current-candidate"; kind: string; priority: Severity | string; title: string; evidence_refs: string[] };
type AgentOfflineAuditDiff = { schema: string; project_id: string; target_scan_id: string; base_scan_id: string | null; has_comparison: boolean; comparison_status: string; summary: { new_count: number; still_pending_count: number; not_current_candidate_count: number }; items: AgentOfflineAuditDiffItem[]; limitations: string[] };
type AgentScanSnapshot = { project_id: string; scan_task_id: string; created_at: string; source_path: string | null; rule_version: string | null; assets: AgentAsset[]; permissions: AgentPermission[]; skipped_files: { path: string; reason: string }[]; quality_gate?: AgentQualityGate; intelligence?: AgentIntelligence; dataflow?: AgentDataflow; audit?: AgentOfflineAudit; ai_review?: AgentAiReview; runtime_validation?: AgentRuntimePlan; trust_score?: AgentTrustScore };
type AgentAssetDiffItem = { identity: string; change_type: "added" | "removed" | "changed"; path: string; asset_type: string; changes: string[] };
type AgentPermissionDiffItem = { identity: string; change_type: "added" | "removed" | "changed"; direction: "expanded" | "reduced" | "changed"; permission: AgentPermission };
type AgentScanDiff = { project_id: string; target_scan_id: string; base_scan_id: string | null; has_comparison: boolean; summary: { assets_added: number; assets_removed: number; assets_changed: number; permissions_added: number; permissions_removed: number; permissions_changed: number; source_changes: number; integrity_changes: number }; assets: AgentAssetDiffItem[]; permissions: AgentPermissionDiffItem[] };

function agentSnapshotSection<T>(value: unknown, schema?: string, mode?: string): T | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const candidate = value as Record<string, unknown>;
  if (schema && candidate.schema !== schema) return undefined;
  if (mode && candidate.mode !== mode) return undefined;
  return value as T;
}
type ScaGovernanceComponent = { ecosystem: string; name: string; version: string | null; risk_status: string; severity: Severity | null; vulnerability_count: number; license_risk: string | null; risk_source: string | null; remediation: string | null };
type ScaGovernanceSummary = { latest_scan_id: string | null; latest_scan_status: string | null; latest_scan_finished_at: string | null; component_count: number; risky_component_count: number; vulnerable_component_count: number; critical_high_component_count: number; total_finding_count: number; latest_scan_finding_count: number; vulnerability_finding_count: number; license_finding_count: number; version_review_finding_count: number; tool_status: ScaToolStatus | null; top_components: ScaGovernanceComponent[] };
type AspmSummary = { project_id: string; project_name: string; enabled_modules: ModuleKey[]; risk_score: number; component_count: number; finding_count: number; dast_validation_count: number; sandbox_evidence_count: number; scan_task_count: number; findings_by_source: Record<string, number>; findings_by_severity: Record<string, number>; findings_by_status: Record<string, number>; dast_by_verdict: Record<string, number>; sca_governance: ScaGovernanceSummary; attack_chains: AttackChain[] };
type SecurityReport = { generated_at: string; project: Project; summary: AspmSummary; components: Component[]; findings: Finding[]; validations: DastValidation[]; sandbox_evidence: SandboxEvidence[]; dependency_graph: DependencyGraph; evidence_graph: EvidenceGraph; retest_comparisons: Record<string, FindingRetestComparison>; capability_boundaries: Record<string, string[]> };
type KnowledgeEntry = { id: string; tenant_id: string; source_project_id: string; source_project_name: string; source_finding_id: string; knowledge_type: string; title: string; summary: string; rule_id: string; source_module: string; severity: Severity; category: string | null; status: "pending_review" | "published" | "rejected" | "archived"; applicability: Record<string, unknown>; evidence_refs: Record<string, unknown>[]; tags: string[]; version: number; submitted_by: string; reviewer: string | null; review_note: string | null; reviewed_at: string | null; published_at: string | null; publish_ready: boolean; created_at: string; updated_at: string };
type KnowledgeRecommendation = { entry: KnowledgeEntry; score: number; reasons: string[]; matched_finding_ids: string[] };
type KnowledgeWorkspace = { project_id: string; project_name: string; entries: KnowledgeEntry[]; recommendations: KnowledgeRecommendation[]; enterprise_published_count: number; status_counts: Record<string, number> };
type ReportRow = { id: string; title: string; subtitle: string; summary: string; details: [string, string][] };

const API_BASE = "http://127.0.0.1:8000/api";
const DEFAULT_ENABLED_MODULES: ModuleKey[] = ["sast", "sca", "aspm"];
const OPTIONAL_MODULES: ModuleKey[] = ["sast", "sca", "agent", "dast", "sandbox"];
const EMPTY_MODULE_LOADING: ModuleLoadingState = { sca: false, sast: false, agent: false, dast: false, sandbox: false };
const DEFAULT_SOURCE_PATH = "D:\\project\\PYproject\\AI网安项目\\outputs\\sca-sample";
const DEFAULT_SAST_PATH = "D:\\project\\PYproject\\AI网安项目\\outputs\\sast-sample";
const DEFAULT_AGENT_PATH = "D:\\project\\PYproject\\AI网安项目\\outputs\\agent-sample";
const FINDING_WORKFLOW_STATUSES: FindingStatus[] = ["open", "confirmed", "fixing", "fixed", "accepted_risk", "false_positive"];
const SANDBOX_BROWSER_SESSION_KEY = "ai-security-platform:sandbox-browser-session";
const SANDBOX_UNLOAD_PROJECTS_KEY = "ai-security-platform:sandbox-unload-projects";
const SANDBOX_BROWSER_SESSION_ID = (() => {
  try {
    const existing = window.sessionStorage.getItem(SANDBOX_BROWSER_SESSION_KEY);
    if (existing) return existing;
    const created = window.crypto.randomUUID();
    window.sessionStorage.setItem(SANDBOX_BROWSER_SESSION_KEY, created);
    return created;
  } catch { return window.crypto.randomUUID(); }
})();
const sandboxUnloadProjects = (() => {
  try { return new Set<string>(JSON.parse(window.sessionStorage.getItem(SANDBOX_UNLOAD_PROJECTS_KEY) ?? "[]") as string[]); }
  catch { return new Set<string>(); }
})();

function registerSandboxUnloadProject(projectId: string) {
  sandboxUnloadProjects.add(projectId);
  try { window.sessionStorage.setItem(SANDBOX_UNLOAD_PROJECTS_KEY, JSON.stringify([...sandboxUnloadProjects])); }
  catch { /* Page-close cleanup still works with the in-memory registry. */ }
}

function stopSandboxBrowserSessionTargets() {
  for (const projectId of sandboxUnloadProjects) {
    const url = `${API_BASE}/sandbox/projects/${projectId}/browser-sessions/${SANDBOX_BROWSER_SESSION_ID}/stop`;
    if (!navigator.sendBeacon(url)) void fetch(url, { method: "POST", keepalive: true }).catch(() => undefined);
  }
}

type ProjectResource<T> = { value: T; warning: string | null };
async function captureProjectResource<T>(label: string, operation: Promise<T>, fallback: T): Promise<ProjectResource<T>> {
  try { return { value: await operation, warning: null }; }
  catch (error) { console.error(`项目资源加载失败：${label}`, error); return { value: fallback, warning: label }; }
}

const fallbackModules: SecurityModule[] = [
  { key: "sast", code: "SAST", name: "智能静态审计", subtitle: "项目规则治理 + 有限语义分析 + 可选七角色 AI 复核", category: "detection", description: "面向代码仓库执行本地与项目规则、有限数据流、Git 基线和历史密钥检查；配置模型密钥后可执行七角色 AI 辅助复核。", capabilities: [{ title: "项目规则包", description: "管理本地规则、项目规则与 Semgrep YAML 配置。" }, { title: "有限语义与 Git 证据", description: "执行有限数据流、扫描基线和历史密钥检查。" }, { title: "可选七角色复核", description: "模型可用时生成辅助解释、证据复核和修复草案。" }, { title: "项目历史关联", description: "关联当前项目历史 Finding；尚不提供跨项目行业知识库。" }], dependencies: [], default_config: {} },
  { key: "sca", code: "SCA", name: "供应链风险分析", subtitle: "SBOM + 组件漏洞匹配 + 许可证风险归一化 + 依赖影响分析", category: "detection", description: "解析多语言工程依赖，生成 SBOM，识别漏洞、许可证和直接/传递依赖风险，并给出修复优先级。", capabilities: [{ title: "SBOM 生成", description: "生成项目组件清单和依赖来源。" }, { title: "组件漏洞匹配", description: "匹配 CVE、受影响版本和修复版本。" }, { title: "许可证风险归一化", description: "识别许可证类型并归一化风险等级。" }, { title: "依赖影响分析", description: "分析直接/传递依赖、版本归一化和修复影响。" }], dependencies: [], default_config: {} },
  { key: "agent", code: "AGENT", name: "Agent 供应链安全", subtitle: "统一资产模型 + 能力权限矩阵 + 语义差异", category: "detection", description: "结构化解析 Agent 指令、MCP、工具和插件配置，形成资产、能力、资源范围、审批边界和批次变化。", capabilities: [{ title: "多格式资产解析", description: "解析 Markdown Frontmatter、JSON、YAML 与 TOML。" }, { title: "能力权限矩阵", description: "归一化工具、文件、网络、命令、凭据和审批边界。" }, { title: "证据脱敏", description: "保存发现和快照前遮蔽凭据和值。" }, { title: "语义差异", description: "比较资产新增/移除、配置变化与权限扩大/收缩。" }], dependencies: [], default_config: {} },
  { key: "dast", code: "DAST", name: "漏洞动态验证", subtitle: "SAST / AGENT 联动 + 专用策略 + 证据驱动三色裁决", category: "validation", description: "把当前项目中符合类型和上下文要求的 SAST/AGENT Finding 转换为运行时验证策略，经审批后由 DAST 有界 HTTP 执行器或 SANDBOX 隔离执行器完成验证、证据归档和报告。", capabilities: [{ title: "运行资产发现", description: "同源抓取 URL、表单、JavaScript API 和 OpenAPI 参数并持久化。" }, { title: "专用验证策略", description: "SQL 注入、XSS、越权、SSRF、命令注入等类型使用独立证据规则。" }, { title: "隔离执行合同", description: "浏览器、OAST、时延和 Agent 运行验证通过一次性 SANDBOX 合同交接。" }, { title: "证据驱动裁决", description: "可利用、不确定、不可利用与未验证分开统计并生成专项报告。" }], dependencies: ["sast"], default_config: {} },
  { key: "sandbox", code: "SANDBOX", name: "沙箱动态证据链", subtitle: "Docker 隔离目标 + 固定探针 + 受控证据归档", category: "evidence", description: "在受限 Docker 网络中启动已审批目标，由固定 HTTP、浏览器、上传、时延或 Agent 合同探针采集证据；不提供完整系统行为监控。", capabilities: [{ title: "受限 Docker 目标", description: "使用内部网络、只读根文件系统、能力删除和资源上限。" }, { title: "固定证据探针", description: "按合同执行 HTTP、浏览器、上传、时延和 Agent 合成探针。" }, { title: "目标生命周期", description: "管理启动、健康检查、过期停止、事件和受管容器清理。" }, { title: "结构化证据", description: "归档 HAR、截图、控制台、时延和目标主动上报的合成工具事件。" }], dependencies: ["agent"], default_config: {} },
  { key: "aspm", code: "ASPM", name: "平台治理与交付", subtitle: "单项目汇总 + 显式证据链 + 整改复测 + 项目报告", category: "governance", description: "聚合当前项目的组件、Finding、动态验证和沙箱证据，提供显式关系图、攻击链、整改复测和项目级安全报告。", capabilities: [{ title: "项目风险汇总", description: "按单项目汇总组件、Finding、验证、证据和模块状态。" }, { title: "显式证据关系", description: "只基于已保存关联生成证据图和攻击链。" }, { title: "整改与复测", description: "跟踪 Finding 状态并比较 SCA、SAST、AGENT 扫描批次。" }, { title: "项目安全报告", description: "导出项目级结果、证据、边界和复测快照。" }], dependencies: [], default_config: {} },
];

const moduleIcons: Record<ModuleKey, React.ReactNode> = { sast: <Bug size={20} />, sca: <Boxes size={20} />, agent: <Network size={20} />, dast: <Activity size={20} />, sandbox: <FlaskConical size={20} />, aspm: <ShieldCheck size={20} /> };

function Root() {
  useEffect(() => {
    let dispatched = false;
    const cleanup = () => { if (!dispatched) { dispatched = true; stopSandboxBrowserSessionTargets(); } };
    window.addEventListener("pagehide", cleanup);
    window.addEventListener("beforeunload", cleanup);
    return () => { window.removeEventListener("pagehide", cleanup); window.removeEventListener("beforeunload", cleanup); };
  }, []);
  return <App />;
}

function App() {
  const [activeView, setActiveView] = useState<ViewKey>("detection");
  const [modules, setModules] = useState<SecurityModule[]>(fallbackModules);
  const [projects, setProjects] = useState<Project[]>([]);
  const [project, setProject] = useState<Project | null>(null);
  const emptyProjectDraft: ProjectDraft = { name: "", business_owner: "", security_owner: "", repository_url: "", source_path: "", runtime_url: "", api_base_url: "", sandbox_command: "", sandbox_image: "", default_branch: "main" };
  const [projectDraft, setProjectDraft] = useState<ProjectDraft>(emptyProjectDraft);
  const [projectImportMode, setProjectImportMode] = useState<ProjectImportMode>("local");
  const [projectZipFile, setProjectZipFile] = useState<File | null>(null);
  const [assetProbe, setAssetProbe] = useState<ProjectAssetProbe | null>(null);
  const [projectReadiness, setProjectReadiness] = useState<ProjectReadiness | null>(null);
  const [enabledModules, setEnabledModules] = useState<Set<ModuleKey>>(() => new Set(DEFAULT_ENABLED_MODULES));
  const [components, setComponents] = useState<Component[]>([]);
  const [scaScanHistory, setScaScanHistory] = useState<ScaScanHistoryItem[]>([]);
  const [agentScanHistory, setAgentScanHistory] = useState<AgentScanHistoryItem[]>([]);
  const [agentSnapshot, setAgentSnapshot] = useState<AgentScanSnapshot | null>(null);
  const [agentScanDiff, setAgentScanDiff] = useState<AgentScanDiff | null>(null);
  const [agentAuditDiff, setAgentAuditDiff] = useState<AgentOfflineAuditDiff | null>(null);
  const [selectedScaScanId, setSelectedScaScanId] = useState<string | null>(null);
  const [scaScanDiff, setScaScanDiff] = useState<ScaScanDiff | null>(null);
  const [dependencyGraph, setDependencyGraph] = useState<DependencyGraph | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [validations, setValidations] = useState<DastValidation[]>([]);
  const [dastStrategies, setDastStrategies] = useState<DastStrategy[]>([]);
  const [dastStrategyId, setDastStrategyId] = useState("web-baseline");
  const [dastTargetConfirmation, setDastTargetConfirmation] = useState("");
  const [evidence, setEvidence] = useState<SandboxEvidence[]>([]);
  const [sandboxTemplates, setSandboxTemplates] = useState<SandboxTemplate[]>([]);
  const [summary, setSummary] = useState<AspmSummary | null>(null);
  const [evidenceGraph, setEvidenceGraph] = useState<EvidenceGraph | null>(null);
  const [sourcePath, setSourcePath] = useState(DEFAULT_SOURCE_PATH);
  const [scaToolScanEnabled, setScaToolScanEnabled] = useState(true);
  const [scanMode, setScanMode] = useState<ScanMode>("quick");
  const [sastPath, setSastPath] = useState(DEFAULT_SAST_PATH);
  const [agentPath, setAgentPath] = useState(DEFAULT_AGENT_PATH);
  const [targetUrl, setTargetUrl] = useState("https://example.com/login");
  const [runCommand, setRunCommand] = useState("python agent_runner.py");
  const [sandboxImage, setSandboxImage] = useState("python:3.12-slim");
  const [correlationFindingId, setCorrelationFindingId] = useState("");
  const [correlationComponentId, setCorrelationComponentId] = useState("");
  const [correlationValidationId, setCorrelationValidationId] = useState("");
  const [correlationLinkSource, setCorrelationLinkSource] = useState("unlinked");
  const [correlationLinkConfidence, setCorrelationLinkConfidence] = useState(0);
  const [dastLinkSuggestions, setDastLinkSuggestions] = useState<LinkSuggestion[]>([]);
  const [sandboxLinkSuggestions, setSandboxLinkSuggestions] = useState<LinkSuggestion[]>([]);
  const [executionSteps, setExecutionSteps] = useState<ExecutionStep[]>([]);
  const [retestComparisons, setRetestComparisons] = useState<Record<"sca" | "sast" | "agent", FindingRetestComparison | null>>({ sca: null, sast: null, agent: null });
  const [status, setStatus] = useState("正在连接 API...");
  const [loading, setLoading] = useState(false);
  const [unifiedLoading, setUnifiedLoading] = useState(false);
  const [moduleLoading, setModuleLoading] = useState<ModuleLoadingState>(EMPTY_MODULE_LOADING);
  const unifiedLoadingRef = React.useRef(false);
  const moduleLoadingRef = React.useRef<ModuleLoadingState>({ ...EMPTY_MODULE_LOADING });
  const projectSwitchEpochRef = React.useRef(0);
  const activeProjectIdRef = React.useRef<string | null>(null);
  const [savingKey, setSavingKey] = useState<ModuleKey | null>(null);
  const anyModuleLoading = Object.values(moduleLoading).some(Boolean);
  const projectControlsLoading = loading || unifiedLoading || anyModuleLoading;

  function setModuleBusy(moduleKey: ExecutableModuleKey, busy: boolean) {
    moduleLoadingRef.current = { ...moduleLoadingRef.current, [moduleKey]: busy };
    setModuleLoading((current) => ({ ...current, [moduleKey]: busy }));
  }

  function setUnifiedBusy(busy: boolean) {
    unifiedLoadingRef.current = busy;
    setUnifiedLoading(busy);
  }

  function isAnyModuleBusy() {
    return Object.values(moduleLoadingRef.current).some(Boolean);
  }

  useEffect(() => { void bootstrap(); }, []);
  useEffect(() => {
    if (!project || (activeView !== "dast" && activeView !== "sandbox")) return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      const path = activeView === "dast" ? "/dast/link-suggestions" : "/sandbox/link-suggestions";
      const body = activeView === "dast"
        ? { project_id: project.id, target_url: targetUrl }
        : {
            project_id: project.id,
            run_command: runCommand,
            finding_id: emptyToNull(correlationFindingId),
            component_id: emptyToNull(correlationComponentId),
          };
      void request<LinkSuggestion[]>(path, { method: "POST", body: JSON.stringify(body) })
        .then((items) => {
          if (cancelled) return;
          if (activeView === "dast") setDastLinkSuggestions(items);
          else setSandboxLinkSuggestions(items);
          const top = items[0];
          const canPreselect = activeView === "dast"
            ? !correlationFindingId && !correlationComponentId
            : !correlationValidationId;
          if (top?.confidence >= 80 && canPreselect) {
            applyLinkSuggestion(top);
          }
        })
        .catch((error) => {
          if (cancelled) return;
          console.error(error);
          if (activeView === "dast") setDastLinkSuggestions([]);
          else setSandboxLinkSuggestions([]);
        });
    }, 350);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [activeView, project?.id, targetUrl, runCommand]);

  useEffect(() => {
    if (!project || !enabledModules.has("dast")) { setDastStrategies([]); return; }
    let cancelled = false;
    const findingQuery = correlationFindingId ? `?finding_id=${correlationFindingId}` : "";
    void request<DastStrategy[]>(`/dast/projects/${project.id}/strategies${findingQuery}`)
      .then((items) => {
        if (cancelled) return;
        setDastStrategies(items);
        if (items.length && !items.some((item) => item.id === dastStrategyId)) setDastStrategyId(items[0].id);
      })
      .catch(() => { if (!cancelled) setDastStrategies([]); });
    return () => { cancelled = true; };
  }, [project?.id, correlationFindingId, enabledModules, dastStrategyId]);

  const optionalModules = useMemo(() => modules.filter((module) => OPTIONAL_MODULES.includes(module.key)), [modules]);
  const selectedModules = useMemo(() => optionalModules.filter((module) => enabledModules.has(module.key)), [enabledModules, optionalModules]);
  const ecosystemSummary = useMemo(() => countBy(components, "ecosystem"), [components]);
  const scaRiskSummary = useMemo(() => countBy(components, "risk_status"), [components]);
  const sastFindings = useMemo(() => findings.filter((finding) => finding.source === "SAST"), [findings]);
  const sastCategorySummary = useMemo(() => countBy(sastFindings.map((finding) => ({ category: finding.ai_review?.category ?? "unknown" })), "category"), [sastFindings]);
  const agentFindings = useMemo(() => findings.filter((finding) => finding.source === "AGENT"), [findings]);
  const agentCategorySummary = useMemo(() => countBy(agentFindings.map((finding) => ({ category: finding.ai_review?.category ?? "unknown" })), "category"), [agentFindings]);

  async function bootstrap() {
    setLoading(true);
    try {
      const moduleData = await request<SecurityModule[]>("/modules");
      setModules(moduleData);
      const projectData = await request<Project[]>("/projects");
      setProjects(projectData);
      if (projectData.length === 0) {
        persistLastProjectId(null);
        activeProjectIdRef.current = null;
        projectSwitchEpochRef.current += 1;
        clearProjectData();
        setProject(null);
        setStatus("API 已连接，请先创建项目");
        return;
      }
      const rememberedProjectId = activeProjectIdRef.current ?? project?.id ?? readLastProjectId();
      const nextProject = projectData.find((item) => item.id === rememberedProjectId) ?? projectData[0];
      await selectProject(nextProject, projectData);
      setStatus("API 已连接，已加载当前项目数据");
    } catch (error) {
      console.error(error);
      setStatus("API 未连接，当前只能查看本地预览结构");
    } finally {
      setLoading(false);
    }
  }

  function clearProjectData() {
    setEnabledModules(new Set(["aspm"]));
    setComponents([]);
    setScaScanHistory([]);
    setAgentScanHistory([]);
    setAgentSnapshot(null);
    setAgentScanDiff(null);
    setAgentAuditDiff(null);
    setSelectedScaScanId(null);
    setScaScanDiff(null);
    setDependencyGraph(null);
    setFindings([]);
    setValidations([]);
    setDastStrategies([]);
    setDastStrategyId("web-baseline");
    setDastTargetConfirmation("");
    setEvidence([]);
    setSandboxTemplates([]);
    setSummary(null);
    setEvidenceGraph(null);
    setCorrelationFindingId("");
    setCorrelationComponentId("");
    setCorrelationValidationId("");
    setCorrelationLinkSource("unlinked");
    setCorrelationLinkConfidence(0);
    setDastLinkSuggestions([]);
    setSandboxLinkSuggestions([]);
    setExecutionSteps([]);
    setRetestComparisons({ sca: null, sast: null, agent: null });
    setAssetProbe(null);
    setProjectReadiness(null);
  }

  async function selectProject(nextProject: Project, knownProjects = projects) {
    const switchEpoch = ++projectSwitchEpochRef.current;
    activeProjectIdRef.current = nextProject.id;
    persistLastProjectId(nextProject.id);
    setLoading(true);
    clearProjectData();
    setProject(nextProject);
    setProjects(knownProjects.length ? knownProjects : projects);
    setSourcePath(nextProject.source_path ?? "");
    setSastPath(nextProject.source_path ?? "");
    setAgentPath(nextProject.source_path ?? "");
    setTargetUrl(nextProject.runtime_url ?? nextProject.api_base_url ?? "");
    setRunCommand(nextProject.sandbox_command ?? "");
    setSandboxImage(nextProject.sandbox_image ?? "");
    try {
      const nextProjects = knownProjects.length ? knownProjects : await request<Project[]>("/projects");
      if (switchEpoch !== projectSwitchEpochRef.current) return;
      setProjects(nextProjects);
      const warnings = await refreshProjectContext(nextProject.id, null);
      if (switchEpoch !== projectSwitchEpochRef.current) return;
      setStatus(warnings.length ? `已切换到项目：${nextProject.name}；${warnings.join("、")}暂时不可用` : `已切换到项目：${nextProject.name}`);
    } catch (error) {
      console.error(error);
      if (switchEpoch === projectSwitchEpochRef.current) setStatus(`已切换到项目：${nextProject.name}，但项目数据暂时加载失败：${errorMessage(error)}`);
    } finally {
      if (switchEpoch === projectSwitchEpochRef.current) setLoading(false);
    }
  }

  async function refreshProjectContext(projectId = project?.id, scaScanId: string | null = selectedScaScanId): Promise<string[]> {
    if (!projectId) return [];
    const [moduleResource, probeResource, readinessResource] = await Promise.all([
      captureProjectResource("模块配置", request<ProjectModule[]>(`/modules/projects/${projectId}`), []),
      captureProjectResource<ProjectAssetProbe | null>("资产画像", request<ProjectAssetProbe>(`/projects/${projectId}/asset-probe`), null),
      captureProjectResource<ProjectReadiness | null>("接入准备度", request<ProjectReadiness>(`/projects/${projectId}/readiness`), null),
    ]);
    if (activeProjectIdRef.current !== projectId) return [];
    const warnings = [moduleResource.warning, probeResource.warning, readinessResource.warning].filter((item): item is string => Boolean(item));
    const projectModules = moduleResource.value;
    if (!moduleResource.warning && !projectModules.some((item) => item.module_key === "aspm" && item.enabled)) {
      try { await enableProjectModule(projectId, "aspm", true); }
      catch (error) { console.error("ASPM 自动接入失败", error); warnings.push("ASPM 配置"); }
    }
    if (activeProjectIdRef.current !== projectId) return [];
    setEnabledModules(new Set([...projectModules.filter((item) => item.enabled).map((item) => item.module_key), "aspm"]));
    setAssetProbe(probeResource.value);
    setProjectReadiness(readinessResource.value);
    warnings.push(...await refreshProjectData(projectId, scaScanId));
    return uniqueValues(warnings);
  }

  async function refreshProjectData(projectId = project?.id, scaScanId: string | null = selectedScaScanId): Promise<string[]> {
    if (!projectId) return [];
    const historyResources = await Promise.all([
      captureProjectResource("SCA 扫描历史", request<ScaScanHistoryItem[]>(`/sca/projects/${projectId}/scan-history`), []),
      captureProjectResource("AGENT 扫描历史", request<AgentScanHistoryItem[]>(`/agent/projects/${projectId}/scan-history`), []),
      captureProjectResource<AgentScanSnapshot | null>("AGENT 快照", request<AgentScanSnapshot>(`/agent/projects/${projectId}/snapshot`), null),
      captureProjectResource<AgentScanDiff | null>("AGENT 扫描差异", request<AgentScanDiff>(`/agent/projects/${projectId}/scan-diff`), null),
      captureProjectResource<AgentOfflineAuditDiff | null>("AGENT 审计差异", request<AgentOfflineAuditDiff>(`/agent/projects/${projectId}/audit-diff`), null),
    ]);
    if (activeProjectIdRef.current !== projectId) return [];
    const [historyData, agentHistoryData, agentSnapshotData, agentDiffData, agentAuditDiffData] = historyResources.map((item) => item.value) as [ScaScanHistoryItem[], AgentScanHistoryItem[], AgentScanSnapshot | null, AgentScanDiff | null, AgentOfflineAuditDiff | null];
    const warnings = historyResources.flatMap((item) => item.warning ? [item.warning] : []);
    const effectiveScaScanId = scaScanId ?? historyData[0]?.scan_task_id ?? null;
    const scaQuery = effectiveScaScanId ? `?scan_task_id=${effectiveScaScanId}` : "";
    const diffQuery = effectiveScaScanId ? `?target_scan_id=${effectiveScaScanId}` : "";
    const dataResources = await Promise.all([
      captureProjectResource("SCA 组件", request<Component[]>(`/sca/projects/${projectId}/components${scaQuery}`), []),
      captureProjectResource<DependencyGraph | null>("依赖图", request<DependencyGraph>(`/sca/projects/${projectId}/dependency-graph${scaQuery}`), null),
      captureProjectResource<ScaScanDiff | null>("SCA 扫描差异", request<ScaScanDiff>(`/sca/projects/${projectId}/scan-diff${diffQuery}`), null),
      captureProjectResource("风险清单", request<Finding[]>(`/findings?project_id=${projectId}`), []),
      captureProjectResource("DAST 验证", request<DastValidation[]>(`/dast/projects/${projectId}/validations`), []),
      captureProjectResource("SANDBOX 证据", request<SandboxEvidence[]>(`/sandbox/projects/${projectId}/evidence`), []),
      captureProjectResource("SANDBOX 模板", request<SandboxTemplate[]>(`/sandbox/projects/${projectId}/templates`), []),
      captureProjectResource<AspmSummary | null>("治理摘要", request<AspmSummary>(`/aspm/projects/${projectId}/summary`), null),
      captureProjectResource<EvidenceGraph | null>("证据图谱", request<EvidenceGraph>(`/aspm/projects/${projectId}/evidence-graph`), null),
    ]);
    if (activeProjectIdRef.current !== projectId) return [];
    const [componentData, graphData, diffData, findingData, validationData, evidenceData, templateData, summaryData, evidenceGraphData] = dataResources.map((item) => item.value) as [Component[], DependencyGraph | null, ScaScanDiff | null, Finding[], DastValidation[], SandboxEvidence[], SandboxTemplate[], AspmSummary | null, EvidenceGraph | null];
    warnings.push(...dataResources.flatMap((item) => item.warning ? [item.warning] : []));
    setScaScanHistory(historyData);
    setAgentScanHistory(agentHistoryData);
    setAgentSnapshot(agentSnapshotData);
    setAgentScanDiff(agentDiffData);
    setAgentAuditDiff(agentAuditDiffData);
    setSelectedScaScanId(effectiveScaScanId);
    setComponents(componentData);
    setDependencyGraph(graphData);
    setScaScanDiff(diffData);
    setFindings(findingData);
    setValidations(validationData);
    setEvidence(evidenceData);
    setSandboxTemplates(templateData);
    setSummary(summaryData);
    setEvidenceGraph(evidenceGraphData);
    const retestResources = await Promise.all([
      captureProjectResource<FindingRetestComparison | null>("SCA 复测", request<FindingRetestComparison>(`/findings/projects/${projectId}/retest-comparison?source=SCA`), null),
      captureProjectResource<FindingRetestComparison | null>("SAST 复测", request<FindingRetestComparison>(`/findings/projects/${projectId}/retest-comparison?source=SAST`), null),
      captureProjectResource<FindingRetestComparison | null>("AGENT 复测", request<FindingRetestComparison>(`/findings/projects/${projectId}/retest-comparison?source=AGENT`), null),
    ]);
    if (activeProjectIdRef.current !== projectId) return [];
    const [scaRetest, sastRetest, agentRetest] = retestResources.map((item) => item.value) as [FindingRetestComparison | null, FindingRetestComparison | null, FindingRetestComparison | null];
    warnings.push(...retestResources.flatMap((item) => item.warning ? [item.warning] : []));
    setRetestComparisons({ sca: scaRetest, sast: sastRetest, agent: agentRetest });
    return uniqueValues(warnings);
  }

  async function refreshGovernanceOverview(projectId: string) {
    const [summaryData, evidenceGraphData] = await Promise.all([
      request<AspmSummary>(`/aspm/projects/${projectId}/summary`),
      request<EvidenceGraph>(`/aspm/projects/${projectId}/evidence-graph`),
    ]);
    setSummary(summaryData);
    setEvidenceGraph(evidenceGraphData);
  }

  async function refreshSingleModuleData(moduleKey: ExecutableModuleKey, projectId: string, scaScanId: string | null = selectedScaScanId) {
    if (moduleKey === "sca") {
      const historyData = await request<ScaScanHistoryItem[]>(`/sca/projects/${projectId}/scan-history`).catch(() => []);
      const effectiveScaScanId = scaScanId ?? historyData[0]?.scan_task_id ?? null;
      const scaQuery = effectiveScaScanId ? `?scan_task_id=${effectiveScaScanId}` : "";
      const diffQuery = effectiveScaScanId ? `?target_scan_id=${effectiveScaScanId}` : "";
      const [componentData, graphData, diffData, findingData, retestData] = await Promise.all([
        request<Component[]>(`/sca/projects/${projectId}/components${scaQuery}`),
        request<DependencyGraph>(`/sca/projects/${projectId}/dependency-graph${scaQuery}`).catch(() => null),
        request<ScaScanDiff>(`/sca/projects/${projectId}/scan-diff${diffQuery}`).catch(() => null),
        request<Finding[]>(`/findings?project_id=${projectId}`),
        request<FindingRetestComparison>(`/findings/projects/${projectId}/retest-comparison?source=SCA`).catch(() => null),
      ]);
      setScaScanHistory(historyData);
      setSelectedScaScanId(effectiveScaScanId);
      setComponents(componentData);
      setDependencyGraph(graphData);
      setScaScanDiff(diffData);
      setFindings((current) => [...current.filter((item) => item.source !== "SCA"), ...findingData.filter((item) => item.source === "SCA")]);
      setRetestComparisons((current) => ({ ...current, sca: retestData }));
      await refreshGovernanceOverview(projectId);
      return;
    }

    if (moduleKey === "sast" || moduleKey === "agent") {
      const source = moduleKey.toUpperCase();
      const [findingData, retestData, agentHistoryData, agentSnapshotData, agentDiffData] = await Promise.all([
        request<Finding[]>(`/findings?project_id=${projectId}`),
        request<FindingRetestComparison>(`/findings/projects/${projectId}/retest-comparison?source=${source}`).catch(() => null),
        moduleKey === "agent" ? request<AgentScanHistoryItem[]>(`/agent/projects/${projectId}/scan-history`).catch(() => []) : Promise.resolve([]),
        moduleKey === "agent" ? request<AgentScanSnapshot>(`/agent/projects/${projectId}/snapshot`).catch(() => null) : Promise.resolve(null),
        moduleKey === "agent" ? request<AgentScanDiff>(`/agent/projects/${projectId}/scan-diff`).catch(() => null) : Promise.resolve(null),
      ]);
      setFindings((current) => [...current.filter((item) => item.source !== source), ...findingData.filter((item) => item.source === source)]);
      setRetestComparisons((current) => ({ ...current, [moduleKey]: retestData }));
      if (moduleKey === "agent") {
        setAgentScanHistory(agentHistoryData);
        setAgentSnapshot(agentSnapshotData);
        setAgentScanDiff(agentDiffData);
      }
      await refreshGovernanceOverview(projectId);
      return;
    }

    if (moduleKey === "dast") {
      setValidations(await request<DastValidation[]>(`/dast/projects/${projectId}/validations`));
      await refreshGovernanceOverview(projectId);
      return;
    }

    const [evidenceData, templateData] = await Promise.all([
      request<SandboxEvidence[]>(`/sandbox/projects/${projectId}/evidence`),
      request<SandboxTemplate[]>(`/sandbox/projects/${projectId}/templates`),
    ]);
    setEvidence(evidenceData);
    setSandboxTemplates(templateData);
    await refreshGovernanceOverview(projectId);
  }

  async function createProject(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!projectDraft.name.trim()) return setStatus("项目名称不能为空");
    if (projectImportMode === "local" && !projectDraft.source_path.trim()) return setStatus("请选择或填写本地源码路径");
    if (projectImportMode === "git" && !projectDraft.repository_url.trim()) return setStatus("请填写 HTTP(S) Git 仓库地址");
    if (projectImportMode === "zip" && !projectZipFile) return setStatus("请选择 ZIP 项目文件");
    setLoading(true);
    try {
      const result = projectImportMode === "zip"
        ? await uploadZipProject(projectZipFile!, projectDraft)
        : await request<ProjectImportResult>("/projects/import", {
          method: "POST",
          body: JSON.stringify({
            name: projectDraft.name.trim(),
            import_mode: projectImportMode,
            source: projectImportMode === "git" ? projectDraft.repository_url.trim() : projectDraft.source_path.trim(),
            business_owner: emptyToNull(projectDraft.business_owner),
            security_owner: emptyToNull(projectDraft.security_owner),
            runtime_url: emptyToNull(projectDraft.runtime_url),
            api_base_url: emptyToNull(projectDraft.api_base_url),
            sandbox_command: emptyToNull(projectDraft.sandbox_command),
            sandbox_image: emptyToNull(projectDraft.sandbox_image),
            default_branch: projectDraft.default_branch.trim() || "main",
          }),
        });
      const projectData = await request<Project[]>("/projects");
      setProjectDraft(emptyProjectDraft);
      setProjectZipFile(null);
      setProjectReadiness(result.readiness);
      await selectProject(result.project, projectData);
      setActiveView("assets");
      setStatus(`项目已接入：${result.project.name}；准备度 ${readinessStatusLabel(result.readiness.overall_status)}`);
    } catch (error) {
      console.error(error);
      setStatus(`项目接入失败：${errorMessage(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function updateProjectAssets(draft: ProjectAssetDraft) {
    if (!project) return setStatus("请先选择项目");
    setLoading(true);
    try {
      const updated = await request<Project>(`/projects/${project.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          runtime_url: emptyToNull(draft.runtime_url),
          api_base_url: emptyToNull(draft.api_base_url),
          sandbox_command: emptyToNull(draft.sandbox_command),
          sandbox_image: emptyToNull(draft.sandbox_image),
        }),
      });
      const projectData = await request<Project[]>("/projects");
      await selectProject(updated, projectData);
      setStatus("项目资产配置已保存");
    } catch (error) {
      console.error(error);
      setStatus("项目资产配置保存失败");
    } finally {
      setLoading(false);
    }
  }

  async function deleteProject(projectId: string) {
    setLoading(true);
    try {
      await request(`/projects/${projectId}`, { method: "DELETE" });
      const projectData = await request<Project[]>("/projects");
      setProjects(projectData);
      if (project?.id === projectId) {
        if (projectData.length > 0) {
          await selectProject(projectData[0], projectData);
        } else {
          activeProjectIdRef.current = null;
          persistLastProjectId(null);
          projectSwitchEpochRef.current += 1;
          setProject(null);
          clearProjectData();
        }
      }
      setStatus("项目已删除");
    } catch (error) {
      console.error(error);
      setStatus("项目删除失败");
    } finally {
      setLoading(false);
    }
  }

  async function toggleModule(module: SecurityModule) {
    const nextEnabled = !enabledModules.has(module.key);
    const next = new Set(enabledModules);
    if (nextEnabled) next.add(module.key); else next.delete(module.key);
    setEnabledModules(next);
    if (!project) return;
    setSavingKey(module.key);
    try {
      if (nextEnabled) {
        await enableProjectModule(project.id, module.key, true);
      } else {
        await updateProjectModule(project.id, module.key, false);
      }
      await refreshProjectContext(project.id);
      setStatus(`${module.code} 已${nextEnabled ? "接入" : "停用"}`);
    } catch (error) { console.error(error); setStatus("模块配置保存失败"); } finally { setSavingKey(null); }
  }

  async function enableRelatedModules(moduleKeys: ModuleKey[]) {
    if (!project) return setStatus("请先选择项目");
    setLoading(true);
    try {
      await Promise.all(moduleKeys.map((moduleKey) => enableProjectModule(project.id, moduleKey, true)));
      await refreshProjectContext(project.id);
      setStatus(`已接入推荐模块：${moduleKeys.map((item) => item.toUpperCase()).join(" + ")}`);
    } catch (error) {
      console.error(error);
      setStatus("推荐模块接入失败");
    } finally {
      setLoading(false);
    }
  }

  async function performModuleCheck(moduleKey: Exclude<ModuleKey, "aspm">): Promise<{ status: "completed" | "skipped"; detail: string; scanId?: string | null }> {
    if (!project) throw new Error("请先选择项目");
    if (moduleKey === "sca" || moduleKey === "sast" || moduleKey === "agent") {
      const configuredSource = moduleKey === "sca" ? sourcePath : moduleKey === "sast" ? sastPath : agentPath;
      if (!configuredSource.trim()) return { status: "skipped", detail: "未配置源码路径" };
      const result = await requestWithTimeout<ScaScanResult | unknown>(`/${moduleKey}/scan`, {
        method: "POST",
        body: JSON.stringify({
          project_id: project.id,
          source_path: configuredSource,
          ...(moduleKey === "sast" ? { quick_mode: scanMode === "quick" } : moduleKey === "sca" ? { clear_previous: false, quick_mode: scanMode === "quick", enable_tool_scan: scanMode === "deep" && scaToolScanEnabled } : { clear_previous: true }),
        }),
      }, scanMode === "quick" ? 75_000 : 360_000);
      return {
        status: "completed",
        detail: moduleKey === "agent" ? "扫描完成，批次结果与覆盖信息已保存" : `${scanMode === "quick" ? "快速" : "深度"}扫描完成，已更新批次对比`,
        scanId: moduleKey === "sca" ? (result as ScaScanResult).scan_task_id : selectedScaScanId,
      };
    }
    if (moduleKey === "dast") {
      return { status: "skipped", detail: "DAST 需要在治理页选择风险、核对同源项目目标并输入精确确认短语；一键执行不会发起网络请求。" };
    }
    return { status: "skipped", detail: "SANDBOX 只接收 DAST 审批后自动入队的固定策略；请在治理页启动目标并执行队列任务。" };
  }

  async function runUnifiedSecurityCheck() {
    if (!project) return setStatus("请先选择项目");
    if (loading || unifiedLoadingRef.current || isAnyModuleBusy()) return setStatus("已有任务正在执行，请等待完成后再运行一键检测");
    const order: Array<Exclude<ModuleKey, "aspm">> = ["sca", "sast", "agent", "dast", "sandbox"];
    const selected = order.filter((moduleKey) => enabledModules.has(moduleKey));
    if (selected.length === 0) return setStatus("请至少接入一个安全模块");

    const initialSteps = selected.map((moduleKey) => ({ module: moduleKey, status: "waiting" as ExecutionStatus, detail: "等待执行" }));
    setExecutionSteps(initialSteps);
    setUnifiedBusy(true);
    let nextScaScanId = selectedScaScanId;
    let completedCount = 0;

    const updateStep = (moduleKey: Exclude<ModuleKey, "aspm">, statusValue: ExecutionStatus, detail: string) => {
      setExecutionSteps((steps) => steps.map((step) => step.module === moduleKey ? { ...step, status: statusValue, detail } : step));
    };

    try {
      for (const moduleKey of selected) {
        updateStep(moduleKey, "running", "正在执行");
        try {
          const result = await performModuleCheck(moduleKey);
          if (result.status === "skipped") {
            updateStep(moduleKey, "skipped", result.detail);
            continue;
          }
          if (moduleKey === "sca") nextScaScanId = result.scanId ?? nextScaScanId;
          completedCount += 1;
          updateStep(moduleKey, "completed", result.detail);
        } catch (error) {
          console.error(error);
          updateStep(moduleKey, "failed", errorMessage(error));
        }
      }
      setSelectedScaScanId(nextScaScanId);
      await refreshProjectContext(project.id, nextScaScanId).catch((error) => console.error(error));
      setStatus(`一键检测完成：${completedCount} / ${selected.length} 个模块执行成功`);
    } finally {
      setUnifiedBusy(false);
    }
  }

  async function runSingleModuleCheck(moduleKey: Exclude<ModuleKey, "aspm">) {
    if (!project) return setStatus("请先选择项目");
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current[moduleKey]) return setStatus(`${MODULE_DISPLAY[moduleKey].name}已有任务正在执行`);
    setModuleBusy(moduleKey, true);
    setExecutionSteps((steps) => [...steps.filter((step) => step.module !== moduleKey), { module: moduleKey, status: "running", detail: "正在单独执行" }]);
    try {
      const result = await performModuleCheck(moduleKey);
      setExecutionSteps((steps) => steps.map((step) => step.module === moduleKey ? { module: moduleKey, status: result.status, detail: result.detail } : step));
      const nextScaScanId = moduleKey === "sca" ? result.scanId ?? selectedScaScanId : selectedScaScanId;
      if (moduleKey === "sca") setSelectedScaScanId(nextScaScanId);
      await refreshSingleModuleData(moduleKey, project.id, nextScaScanId);
      setStatus(`${MODULE_DISPLAY[moduleKey].name}：${result.detail}`);
    } catch (error) {
      console.error(error);
      setExecutionSteps((steps) => steps.map((step) => step.module === moduleKey ? { module: moduleKey, status: "failed", detail: errorMessage(error) } : step));
      setStatus(`${MODULE_DISPLAY[moduleKey].name}执行失败：${errorMessage(error)}`);
    } finally {
      setModuleBusy(moduleKey, false);
    }
  }

  async function runAgentDeepseekReview(confirmationPhrase: string) {
    if (!project) return setStatus("请先选择项目");
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current.agent) return setStatus("AGENT 已有任务正在执行");
    setModuleBusy("agent", true);
    try {
      const result = await request<AgentAiReview & { scan_task_id: string }>(`/agent/projects/${project.id}/ai-review`, {
        method: "POST",
        body: JSON.stringify({ confirmation_phrase: confirmationPhrase }),
      });
      await refreshProjectData(project.id);
      setStatus(`AGENT DeepSeek 审计完成：${result.reviews.length} 条人工复核建议，估算费用 $${result.usage.estimated_cost_usd ?? "-"}`);
    } catch (error) {
      console.error(error);
      setStatus(`AGENT DeepSeek 审计未完成：${errorMessage(error)}；本地审计草案保持不变。`);
    } finally {
      setModuleBusy("agent", false);
    }
  }

  async function runScan(kind: "sca" | "sast" | "agent") {
    if (!project) return setStatus("API 未连接，无法执行任务");
    const source = kind === "sca" ? sourcePath : kind === "sast" ? sastPath : agentPath;
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current[kind]) return setStatus(`${kind.toUpperCase()} 已有任务正在执行`);
    setModuleBusy(kind, true);
    try {
      const result = await requestWithTimeout<ScaScanResult | unknown>(`/${kind}/scan`, { method: "POST", body: JSON.stringify({ project_id: project.id, source_path: source, ...(kind === "sast" ? { quick_mode: scanMode === "quick" } : kind === "sca" ? { clear_previous: false, quick_mode: scanMode === "quick", enable_tool_scan: scanMode === "deep" && scaToolScanEnabled } : { clear_previous: true }) }) }, scanMode === "quick" ? 75_000 : 360_000);
      const nextScaScanId = kind === "sca" ? (result as ScaScanResult).scan_task_id : selectedScaScanId;
      if (kind === "sca") setSelectedScaScanId(nextScaScanId);
      await refreshSingleModuleData(kind, project.id, nextScaScanId);
      setStatus(`${kind.toUpperCase()} 扫描完成`);
    } catch (error) { console.error(error); setStatus(`${kind.toUpperCase()} 扫描失败：${errorMessage(error)}`); } finally { setModuleBusy(kind, false); }
  }

  async function runRecommendedScans() {
    if (!project || !assetProbe) return;
    const runnable = assetProbe.recommended_tasks.filter((kind) => enabledModules.has(kind));
    if (runnable.length === 0) return setStatus("没有可执行的推荐任务，请先配置源码路径并启用对应模块");
    if (loading || unifiedLoadingRef.current || isAnyModuleBusy()) return setStatus("已有任务正在执行，请等待完成后再运行推荐任务");
    setUnifiedBusy(true);
    try {
      let nextScaScanId = selectedScaScanId;
      for (const kind of runnable) {
        const result = await requestWithTimeout<ScaScanResult | unknown>(`/${kind}/scan`, { method: "POST", body: JSON.stringify({ project_id: project.id, source_path: project.source_path ?? sourcePath, ...(kind === "sast" ? { quick_mode: scanMode === "quick" } : kind === "sca" ? { clear_previous: false, quick_mode: scanMode === "quick", enable_tool_scan: scanMode === "deep" && scaToolScanEnabled } : { clear_previous: true }) }) }, scanMode === "quick" ? 75_000 : 360_000);
        if (kind === "sca") nextScaScanId = (result as ScaScanResult).scan_task_id;
      }
      setSelectedScaScanId(nextScaScanId);
      await refreshProjectContext(project.id, nextScaScanId);
      setStatus(`推荐任务已完成：${runnable.map((item) => item.toUpperCase()).join(" + ")}`);
    } catch (error) {
      console.error(error);
      setStatus("推荐任务执行失败，请确认模块已启用、路径可访问");
    } finally {
      setUnifiedBusy(false);
    }
  }

  async function createDastValidation() {
    if (!project) return;
    if (!correlationFindingId && !correlationComponentId) return setStatus("请先选择一条待验证风险，再执行 DAST");
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current.dast) return setStatus("DAST 已有任务正在执行");
    setModuleBusy("dast", true);
    try {
      await request("/dast/probe", { method: "POST", body: JSON.stringify({
        project_id: project.id,
        target_url: targetUrl,
        validator: "auto-dast",
        finding_id: emptyToNull(correlationFindingId),
        component_id: emptyToNull(correlationComponentId),
        link_source: correlationLinkSource,
        link_confidence: correlationLinkConfidence,
        strategy_id: dastStrategyId,
        target_confirmation: dastTargetConfirmation,
      }) });
      await refreshSingleModuleData("dast", project.id);
      setStatus("DAST 基础 Web 观察已完成；结果不构成漏洞可利用性裁决");
      setDastTargetConfirmation("");
    } catch (error) { console.error(error); setStatus(`DAST 基础观察未执行：${errorMessage(error)}`); } finally { setModuleBusy("dast", false); }
  }

  async function createManualDastValidation(draft: ManualDastValidationDraft) {
    if (!project) return;
    if (!correlationFindingId && !correlationComponentId) return setStatus("请先选择一条待验证风险，再记录人工 DAST 验证");
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current.dast) return setStatus("DAST 已有任务正在执行");
    setModuleBusy("dast", true);
    try {
      await request("/dast/validations", { method: "POST", body: JSON.stringify({
        project_id: project.id,
        target_url: draft.target_url,
        verdict: draft.verdict,
        validator: "manual-security-review",
        finding_id: emptyToNull(correlationFindingId),
        component_id: emptyToNull(correlationComponentId),
        link_source: correlationLinkSource,
        link_confidence: correlationLinkConfidence,
        strategy_id: dastStrategyId,
        evidence_summary: draft.evidence_summary,
        request_summary: "人工记录：平台未发起网络请求。",
        response_summary: draft.response_summary || null,
        reproduction_steps: draft.reproduction_steps,
        remediation_hint: draft.remediation_hint || null,
      }) });
      await refreshSingleModuleData("dast", project.id);
      setStatus("人工 DAST 验证已记录；结论仅适用于所填范围与证据");
    } catch (error) { console.error(error); setStatus(`人工 DAST 验证未保存：${errorMessage(error)}`); } finally { setModuleBusy("dast", false); }
  }

  async function updateManualDastValidation(validationId: string, draft: ManualDastValidationDraft) {
    if (!project) return;
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current.dast) return setStatus("DAST 已有任务正在执行");
    setModuleBusy("dast", true);
    try {
      await request(`/dast/validations/${validationId}`, { method: "PATCH", body: JSON.stringify({
        target_url: draft.target_url,
        verdict: draft.verdict,
        evidence_summary: draft.evidence_summary,
        reproduction_steps: draft.reproduction_steps,
        response_summary: draft.response_summary || null,
        remediation_hint: draft.remediation_hint || null,
      }) });
      await refreshSingleModuleData("dast", project.id);
      setStatus("人工 DAST 验证已复核更新；自动基础观察保持只读");
    } catch (error) { console.error(error); setStatus(`人工 DAST 验证未更新：${errorMessage(error)}`); } finally { setModuleBusy("dast", false); }
  }

  async function exportDastReport() {
    if (!project) return setStatus("请先选择项目");
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current.dast) return setStatus("DAST 已有任务正在执行");
    setModuleBusy("dast", true);
    try {
      const response = await fetch(`${API_BASE}/dast/projects/${project.id}/report.html`);
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `${safeFilename(project.name)}-dast-report.html`;
      link.click();
      URL.revokeObjectURL(url);
      setStatus("DAST HTML 专项报告已导出；内容仅来自已保存证据，导出过程不会连接目标");
    } catch (error) { console.error(error); setStatus(`DAST 报告导出失败：${errorMessage(error)}`); } finally { setModuleBusy("dast", false); }
  }

  async function createSandboxEvidence(plan: SandboxExecutionPlan) {
    if (!project) return;
    if (!correlationFindingId && !correlationComponentId && !correlationValidationId) return setStatus("请先选择一条风险或 DAST 验证，再执行 SANDBOX");
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current.sandbox) return setStatus("SANDBOX 已有任务正在执行");
    setModuleBusy("sandbox", true);
    try {
      await request("/sandbox/run", { method: "POST", body: JSON.stringify({
        project_id: project.id,
        run_command: runCommand,
        image: sandboxImage,
        timeout_seconds: 10,
        operator: "security-user",
        finding_id: emptyToNull(correlationFindingId),
        component_id: emptyToNull(correlationComponentId),
        validation_id: emptyToNull(correlationValidationId),
        link_source: correlationLinkSource,
        link_confidence: correlationLinkConfidence,
        strategy_name: plan.strategyName,
        purpose: plan.purpose,
        limitations: plan.limitations,
      }) });
      await refreshSingleModuleData("sandbox", project.id);
      setStatus("SANDBOX 受控执行已完成");
    } catch (error) { console.error(error); setStatus("SANDBOX 执行失败，请确认模块已启用且命令未被安全策略阻止"); } finally { setModuleBusy("sandbox", false); }
  }

  function applyLinkSuggestion(suggestion: LinkSuggestion) {
    setCorrelationFindingId(suggestion.finding_id ?? "");
    setCorrelationComponentId(suggestion.component_id ?? "");
    setCorrelationValidationId(suggestion.validation_id ?? "");
    setCorrelationLinkSource(suggestion.source);
    setCorrelationLinkConfidence(suggestion.confidence);
  }

  function markExplicitLink() {
    setCorrelationLinkSource("explicit-selection");
    setCorrelationLinkConfidence(100);
  }

  function selectDastRisk(findingId: string) {
    const finding = findings.find((item) => item.id === findingId);
    setCorrelationFindingId(findingId);
    setCorrelationComponentId(finding?.component_id ?? "");
    setCorrelationValidationId("");
    markExplicitLink();
  }

  function selectSandboxRisk(findingId: string) {
    const finding = findings.find((item) => item.id === findingId);
    setCorrelationFindingId(findingId);
    setCorrelationComponentId(finding?.component_id ?? "");
    setCorrelationValidationId("");
    markExplicitLink();
  }

  function selectSandboxValidation(validationId: string) {
    const validation = validations.find((item) => item.id === validationId);
    setCorrelationValidationId(validationId);
    setCorrelationFindingId(validation?.finding_id ?? "");
    setCorrelationComponentId(validation?.component_id ?? "");
    markExplicitLink();
  }

  async function updateFindingGovernance(findingId: string, patch: Partial<Pick<Finding, "status" | "remediation_owner" | "remediation_note" | "remediation_due_at">>) {
    if (!project) return;
    try {
      await request<Finding>(`/findings/${findingId}/governance`, { method: "PATCH", body: JSON.stringify(patch) });
      await refreshProjectData(project.id);
      setStatus("整改信息已更新");
    } catch (error) {
      console.error(error);
      setStatus("整改信息更新失败");
    }
  }

  async function runSastAgentReview() {
    if (!project) return;
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current.sast) return setStatus("SAST 已有任务正在执行");
    setModuleBusy("sast", true);
    try {
      await request<Finding[]>(`/sast/projects/${project.id}/agent-review`, { method: "POST" });
      await refreshSingleModuleData("sast", project.id);
      setStatus("SAST Sub-agent 编排复核已完成");
    } catch (error) {
      console.error(error);
      setStatus(`SAST Sub-agent 编排失败：${errorMessage(error)}`);
    } finally {
      setModuleBusy("sast", false);
    }
  }

  async function selectScaScanSnapshot(scanTaskId: string) {
    if (!project) return;
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current.sca) return setStatus("SCA 已有任务正在执行");
    setModuleBusy("sca", true);
    try {
      setSelectedScaScanId(scanTaskId);
      await refreshSingleModuleData("sca", project.id, scanTaskId);
      setStatus("SCA 历史快照已切换");
    } catch (error) {
      console.error(error);
      setStatus(`SCA 历史快照切换失败：${errorMessage(error)}`);
    } finally {
      setModuleBusy("sca", false);
    }
  }

  async function exportScaSbom(format: "cyclonedx" | "spdx") {
    if (!project) return setStatus("请先选择项目");
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current.sca) return setStatus("SCA 已有任务正在执行");
    setModuleBusy("sca", true);
    try {
      const scanQuery = selectedScaScanId ? `&scan_task_id=${selectedScaScanId}` : "";
      const response = await fetch(`${API_BASE}/sca/projects/${project.id}/sbom?format=${format}${scanQuery}`);
      if (!response.ok) {
        let detail = `${response.status} ${response.statusText}`;
        try {
          const payload = await response.json();
          detail = typeof payload.detail === "string" ? payload.detail : detail;
        } catch { /* keep HTTP status */ }
        throw new Error(detail);
      }
      const sbom = await response.json();
      const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      const scanSuffix = selectedScaScanId ? `-${selectedScaScanId.slice(0, 8)}` : "";
      link.download = `${project.name || "project"}${scanSuffix}-${format}-sbom.json`;
      link.click();
      URL.revokeObjectURL(url);
      setStatus(`${format === "cyclonedx" ? "CycloneDX" : "SPDX"} SBOM 已导出`);
    } catch (error) {
      console.error(error);
      setStatus(`SBOM 导出失败：${errorMessage(error)}`);
    } finally {
      setModuleBusy("sca", false);
    }
  }

  async function exportScaReport() {
    if (!project) return setStatus("请先选择项目");
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current.sca) return setStatus("SCA 已有任务正在执行");
    setModuleBusy("sca", true);
    try {
      const scanQuery = selectedScaScanId ? `?scan_task_id=${selectedScaScanId}` : "";
      const response = await fetch(`${API_BASE}/sca/projects/${project.id}/report.html${scanQuery}`);
      if (!response.ok) {
        let detail = `${response.status} ${response.statusText}`;
        try {
          const payload = await response.json();
          detail = typeof payload.detail === "string" ? payload.detail : detail;
        } catch { /* keep HTTP status */ }
        throw new Error(detail);
      }
      const report = await response.text();
      const blob = new Blob([report], { type: "text/html;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      const scanSuffix = selectedScaScanId ? `-${selectedScaScanId.slice(0, 8)}` : "";
      link.download = `${project.name || "project"}${scanSuffix}-sca-report.html`;
      link.click();
      URL.revokeObjectURL(url);
      setStatus("SCA HTML 报告已导出；可用浏览器“打印为 PDF”交付");
    } catch (error) {
      console.error(error);
      setStatus(`SCA 报告导出失败：${errorMessage(error)}`);
    } finally {
      setModuleBusy("sca", false);
    }
  }

  return (
    <main className="app-shell">
      <aside className="sidebar"><div className="brand"><ShieldCheck size={26} /><div><strong>AI 安全平台</strong><span>Application Security</span></div></div><nav className="nav-list">
        <NavButton active={activeView === "projects"} onClick={() => setActiveView("projects")} icon={<FolderKanban size={18} />} label="项目管理" />
        <NavButton active={activeView === "assets"} onClick={() => setActiveView("assets")} icon={<GitBranch size={18} />} label="项目资产" />
        <NavButton active={activeView === "detection"} onClick={() => setActiveView("detection")} icon={<Play size={18} />} label="安全检测" />
        <NavButton active={activeView === "governance"} onClick={() => setActiveView("governance")} icon={<ShieldCheck size={18} />} label="治理总览" />
        <NavButton active={activeView === "knowledge"} onClick={() => setActiveView("knowledge")} icon={<BookOpen size={18} />} label="安全知识中枢" />
      </nav></aside>
      <section className="workspace"><header className="topbar"><div><p className="eyebrow">{viewEyebrow(activeView)}</p><h1>{viewTitle(activeView)}</h1></div><div className="topbar-actions"><div className="current-project-pill"><span>当前项目</span><strong>{project?.name ?? "未选择"}</strong></div><button className="primary-action" onClick={() => void bootstrap()} disabled={projectControlsLoading}>刷新数据</button></div></header>
        <div className={`api-status ${status.includes("失败") || status.includes("未连接") ? "warning" : "ok"}`}>{status}</div>
        {activeView === "projects" && <ProjectOnboardingWorkspace projects={projects} project={project} draft={projectDraft} importMode={projectImportMode} zipFile={projectZipFile} loading={projectControlsLoading} onDraftChange={setProjectDraft} onImportModeChange={setProjectImportMode} onZipFileChange={setProjectZipFile} onCreate={createProject} onSelect={(nextProject) => void selectProject(nextProject)} onDelete={deleteProject} />}
        {activeView === "assets" && <><ProjectReadinessPanel project={project} readiness={projectReadiness} onOpenDetection={() => setActiveView("detection")} /><ProjectAssetConfig project={project} loading={projectControlsLoading} onSave={updateProjectAssets} /><ProjectAssets project={project} assetProbe={assetProbe} enabledModules={enabledModules} components={components} findings={findings} validations={validations} evidence={evidence} summary={summary} onOpenTasks={() => setActiveView("detection")} onOpenModules={() => setActiveView("detection")} /></>}
        {activeView === "detection" && <SecurityDetectionCenter modules={optionalModules} project={project} enabledModules={enabledModules} savingKey={savingKey} loading={loading || unifiedLoading} runBlocked={anyModuleLoading} moduleLoading={moduleLoading} executionSteps={executionSteps} scanMode={scanMode} sourcePath={sourcePath} targetUrl={targetUrl} runCommand={runCommand} sandboxImage={sandboxImage} onToggle={toggleModule} onEnableRelated={enableRelatedModules} onScanModeChange={setScanMode} onSourcePathChange={(value) => { setSourcePath(value); setSastPath(value); setAgentPath(value); }} onTargetUrlChange={setTargetUrl} onRunCommandChange={setRunCommand} onSandboxImageChange={setSandboxImage} onRun={runUnifiedSecurityCheck} />}
    {activeView === "governance" && <GovernanceCenter project={project} enabledModules={enabledModules} summary={summary} components={components} findings={findings} validations={validations} evidence={evidence} graph={evidenceGraph} retestComparisons={retestComparisons} scaScanHistory={scaScanHistory} agentScanHistory={agentScanHistory} agentSnapshot={agentSnapshot} agentScanDiff={agentScanDiff} agentAuditDiff={agentAuditDiff} selectedScaScanId={selectedScaScanId} scaScanDiff={scaScanDiff} dependencyGraph={dependencyGraph} scaToolScanEnabled={scaToolScanEnabled} sandboxTemplates={sandboxTemplates} dastStrategies={dastStrategies} dastStrategyId={dastStrategyId} dastTargetConfirmation={dastTargetConfirmation} loading={loading} unifiedLoading={unifiedLoading} moduleLoading={moduleLoading} targetUrl={targetUrl} runCommand={runCommand} sandboxImage={sandboxImage} selectedFindingId={correlationFindingId} selectedValidationId={correlationValidationId} onTargetUrlChange={setTargetUrl} onRunCommandChange={setRunCommand} onSandboxImageChange={setSandboxImage} onDastStrategyChange={setDastStrategyId} onDastTargetConfirmationChange={setDastTargetConfirmation} onScaToolScanChange={setScaToolScanEnabled} onSelectScaScan={selectScaScanSnapshot} onExportScaSbom={exportScaSbom} onExportScaReport={exportScaReport} onRunSastAgentReview={runSastAgentReview} onRunAgentAiReview={runAgentDeepseekReview} onSelectDastRisk={selectDastRisk} onSelectSandboxRisk={selectSandboxRisk} onSelectSandboxValidation={selectSandboxValidation} onRunDast={createDastValidation} onCreateManualDast={createManualDastValidation} onUpdateManualDast={updateManualDastValidation} onExportDastReport={exportDastReport} onRunSandbox={createSandboxEvidence} onRunModule={runSingleModuleCheck} onUpdateFinding={updateFindingGovernance} />}
        {activeView === "knowledge" && <KnowledgeHubView project={project} findings={findings} validations={validations} evidence={evidence} summary={summary} />}
      </section>
    </main>
  );
}

function NavButton({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) { return <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}>{icon}{label}</button>; }
function viewEyebrow(view: ViewKey) { return view === "projects" ? "项目空间" : view === "assets" ? "项目资产画像" : view === "detection" ? "模块接入与统一执行" : view === "knowledge" ? "可学习、可传递、可治理" : "项目安全治理"; }
function viewTitle(view: ViewKey) { return view === "projects" ? "创建项目并切换当前项目" : view === "assets" ? "确认待检测的项目资产" : view === "detection" ? "选择安全模块并一键执行检测" : view === "knowledge" ? "安全知识中枢" : "从风险发现到修复复测的完整闭环"; }

function ProjectOnboardingWorkspace({ projects, project, draft, importMode, zipFile, loading, onDraftChange, onImportModeChange, onZipFileChange, onCreate, onSelect, onDelete }: { projects: Project[]; project: Project | null; draft: ProjectDraft; importMode: ProjectImportMode; zipFile: File | null; loading: boolean; onDraftChange: (draft: ProjectDraft) => void; onImportModeChange: (mode: ProjectImportMode) => void; onZipFileChange: (file: File | null) => void; onCreate: (event: React.FormEvent<HTMLFormElement>) => Promise<void>; onSelect: (project: Project) => void; onDelete: (projectId: string) => Promise<void> }) {
  return <section className="project-workspace onboarding-workspace">
    <div className="panel project-create onboarding-create">
      <div className="panel-header"><div><h2>陌生项目接入</h2><p>选择一种来源，系统完成受控导入、资产识别和准备度检查。</p></div><span>SCA + SAST + ASPM 默认启用</span></div>
      <div className="import-mode-switch" role="tablist" aria-label="项目接入方式">
        {(["local", "git", "zip"] as ProjectImportMode[]).map((mode) => <button type="button" role="tab" aria-selected={importMode === mode} className={importMode === mode ? "active" : ""} onClick={() => onImportModeChange(mode)} key={mode}>{mode === "local" ? "本地文件夹" : mode === "git" ? "Git 仓库" : "ZIP 上传"}</button>)}
      </div>
      <form className="project-form" onSubmit={(event) => void onCreate(event)}>
        <label>项目名称<input value={draft.name} onChange={(event) => onDraftChange({ ...draft, name: event.target.value })} placeholder="例如：导师现场项目" /></label>
        <label>默认分支<input value={draft.default_branch} onChange={(event) => onDraftChange({ ...draft, default_branch: event.target.value })} placeholder="main" /></label>
        {importMode === "local" ? <label className="wide-field">本地源码目录<input value={draft.source_path} onChange={(event) => onDraftChange({ ...draft, source_path: event.target.value })} placeholder="D:\\project\\advisor-demo" /></label> : null}
        {importMode === "git" ? <label className="wide-field">HTTP(S) Git 地址<input value={draft.repository_url} onChange={(event) => onDraftChange({ ...draft, repository_url: event.target.value })} placeholder="https://github.com/team/project.git" /></label> : null}
        {importMode === "zip" ? <label className="wide-field">ZIP 项目文件<input type="file" accept=".zip,application/zip" onChange={(event) => onZipFileChange(event.target.files?.[0] ?? null)} /><small>{zipFile ? `${zipFile.name} · ${formatBytes(zipFile.size)}` : "最大 500 MiB；上传后执行路径穿越、符号链接和解压体积校验。"}</small></label> : null}
        <details className="onboarding-advanced wide-field"><summary>运行目标与负责人（可选）</summary><div className="project-form advanced-grid">
          <label>业务负责人<input value={draft.business_owner} onChange={(event) => onDraftChange({ ...draft, business_owner: event.target.value })} placeholder="业务系统部" /></label>
          <label>安全负责人<input value={draft.security_owner} onChange={(event) => onDraftChange({ ...draft, security_owner: event.target.value })} placeholder="应用安全组" /></label>
          <label>运行地址<input value={draft.runtime_url} onChange={(event) => onDraftChange({ ...draft, runtime_url: event.target.value })} placeholder="http://localhost:3000" /></label>
          <label>API 地址<input value={draft.api_base_url} onChange={(event) => onDraftChange({ ...draft, api_base_url: event.target.value })} placeholder="http://localhost:3000/api" /></label>
          <label>沙箱命令<input value={draft.sandbox_command} onChange={(event) => onDraftChange({ ...draft, sandbox_command: event.target.value })} placeholder="npm run start" /></label>
          <label>沙箱镜像<input value={draft.sandbox_image} onChange={(event) => onDraftChange({ ...draft, sandbox_image: event.target.value })} placeholder="node:20-alpine" /></label>
        </div></details>
        <button className="primary-action wide-field" disabled={loading || !draft.name.trim()}><Plus size={16} />{loading ? "正在安全接入" : "接入并检查准备度"}</button>
      </form>
    </div>
    <div className="panel project-directory"><div className="panel-header"><h2>项目列表</h2><span>{projects.length} 个项目</span></div><div className="project-list">{projects.length === 0 ? <div className="empty-project">暂无项目。接入后，检测与治理数据会按项目隔离。</div> : projects.map((item) => <div className={`project-row ${project?.id === item.id ? "active" : ""}`} key={item.id}><button className="project-main" onClick={() => onSelect(item)} disabled={loading}><div><strong>{item.name}</strong><span>{item.repository_url ?? "本地 / ZIP 来源"} · {item.default_branch}</span><span>{item.source_path ?? "未配置本地源码路径"}</span></div><span>{item.business_owner ?? "未配置业务负责人"}</span><span>{item.security_owner ?? "未配置安全负责人"}</span></button><button className="danger-action" disabled={loading} onClick={() => void onDelete(item.id)}>删除</button></div>)}</div></div>
    <div className="panel current-project"><div className="panel-header"><h2>当前项目</h2><span>{project ? "已选择" : "未选择"}</span></div>{project ? <div className="project-detail"><strong>{project.name}</strong><span>源码路径：{project.source_path ?? "未配置"}</span><span>仓库：{project.repository_url ?? "本地或 ZIP 导入"}</span><span>运行地址：{project.runtime_url ?? "未配置；仅影响 DAST"}</span><span>分支：{project.default_branch}</span></div> : <div className="empty-project">请先接入或选择一个项目。</div>}</div>
  </section>;
}

function ProjectWorkspace({ projects, project, draft, loading, onDraftChange, onCreate, onSelect, onDelete }: { projects: Project[]; project: Project | null; draft: ProjectDraft; loading: boolean; onDraftChange: (draft: ProjectDraft) => void; onCreate: (event: React.FormEvent<HTMLFormElement>) => Promise<void>; onSelect: (project: Project) => void; onDelete: (projectId: string) => Promise<void> }) {
  return <section className="project-workspace"><div className="panel project-create"><div className="panel-header"><h2>项目创建向导</h2><span>ASPM 默认内置，SCA + SAST 默认启用</span></div><form className="project-form" onSubmit={(event) => void onCreate(event)}><label>项目名称<input value={draft.name} onChange={(event) => onDraftChange({ ...draft, name: event.target.value })} placeholder="例如：政企门户应用" /></label><label>业务负责人<input value={draft.business_owner} onChange={(event) => onDraftChange({ ...draft, business_owner: event.target.value })} placeholder="业务系统部" /></label><label>安全负责人<input value={draft.security_owner} onChange={(event) => onDraftChange({ ...draft, security_owner: event.target.value })} placeholder="应用安全组" /></label><label>代码仓库<input value={draft.repository_url} onChange={(event) => onDraftChange({ ...draft, repository_url: event.target.value })} placeholder="git.example.com/team/repo" /></label><label>本地源码路径<input value={draft.source_path} onChange={(event) => onDraftChange({ ...draft, source_path: event.target.value })} placeholder="D:\\project\\demo-repo" /></label><label>运行地址<input value={draft.runtime_url} onChange={(event) => onDraftChange({ ...draft, runtime_url: event.target.value })} placeholder="http://localhost:3000" /></label><label>API 地址<input value={draft.api_base_url} onChange={(event) => onDraftChange({ ...draft, api_base_url: event.target.value })} placeholder="http://localhost:3000/api" /></label><label>沙箱命令<input value={draft.sandbox_command} onChange={(event) => onDraftChange({ ...draft, sandbox_command: event.target.value })} placeholder="npm test" /></label><label>沙箱镜像<input value={draft.sandbox_image} onChange={(event) => onDraftChange({ ...draft, sandbox_image: event.target.value })} placeholder="node:20-alpine" /></label><label>默认分支<input value={draft.default_branch} onChange={(event) => onDraftChange({ ...draft, default_branch: event.target.value })} placeholder="main" /></label><button className="primary-action" disabled={loading || !draft.name.trim()}><Plus size={16} />创建项目</button></form></div><div className="panel project-directory"><div className="panel-header"><h2>项目列表</h2><span>{projects.length} 个项目</span></div><div className="project-list">{projects.length === 0 ? <div className="empty-project">暂无项目。创建项目后，安全检测配置和治理结果会按项目隔离。</div> : projects.map((item) => <div className={`project-row ${project?.id === item.id ? "active" : ""}`} key={item.id}><button className="project-main" onClick={() => onSelect(item)} disabled={loading}><div><strong>{item.name}</strong><span>{item.repository_url ?? "未配置仓库"} · {item.default_branch}</span><span>{item.source_path ?? "未配置本地源码路径"}</span></div><span>{item.business_owner ?? "未配置业务负责人"}</span><span>{item.security_owner ?? "未配置安全负责人"}</span></button><button className="danger-action" disabled={loading} onClick={() => void onDelete(item.id)}>删除</button></div>)}</div></div><div className="panel current-project"><div className="panel-header"><h2>当前项目</h2><span>{project ? "已选择" : "未选择"}</span></div>{project ? <div className="project-detail"><strong>{project.name}</strong><span>业务：{project.business_owner ?? "未配置"}</span><span>安全：{project.security_owner ?? "未配置"}</span><span>仓库：{project.repository_url ?? "未配置"}</span><span>源码路径：{project.source_path ?? "未配置"}</span><span>运行地址：{project.runtime_url ?? "未配置"}</span><span>API 地址：{project.api_base_url ?? "未配置"}</span><span>沙箱命令：{project.sandbox_command ?? "未配置"}</span><span>沙箱镜像：{project.sandbox_image ?? "未配置"}</span><span>分支：{project.default_branch}</span></div> : <div className="empty-project">请先创建或选择一个项目。</div>}</div></section>;
}

function ProjectReadinessPanel({ project, readiness, onOpenDetection }: { project: Project | null; readiness: ProjectReadiness | null; onOpenDetection: () => void }) {
  if (!project) return <section className="panel readiness-panel empty-project">请先接入项目，系统会在这里给出可执行任务、阻塞原因和降级边界。</section>;
  if (!readiness) return <section className="panel readiness-panel"><div className="panel-header"><h2>新项目接入准备度</h2><span>正在读取检查结果</span></div></section>;
  return <section className={`panel readiness-panel ${readiness.overall_status}`}>
    <div className="readiness-heading"><div><span className={`readiness-badge ${readiness.overall_status}`}>{readinessStatusLabel(readiness.overall_status)}</span><h2>{project.name} 接入准备度</h2><p>{readiness.overall_status === "blocked" ? "当前存在静态扫描阻塞项，请先按建议补齐源码输入。" : `可执行推荐：${readiness.recommended_tasks.map((item) => item.toUpperCase()).join(" + ") || "暂无"}`}</p></div><button className="primary-action" disabled={!readiness.quick_scan.available} onClick={onOpenDetection}>进入快速检测</button></div>
    <div className="readiness-check-grid">{readiness.checks.map((check) => <article className={`readiness-check ${check.status}`} key={check.key}><div><i>{check.status === "ready" ? <Check size={15} /> : check.status === "blocked" ? "!" : "·"}</i><strong>{check.title}</strong><span>{readinessCheckLabel(check.status)}</span></div><p>{check.detail}</p>{check.remediation ? <small>{check.remediation}</small> : null}</article>)}</div>
    <div className="quick-scan-boundary"><strong>快速模式边界</strong><span>{readiness.quick_scan.statement}</span></div>
  </section>;
}

function ProjectAssetConfig({ project, loading, onSave }: { project: Project | null; loading: boolean; onSave: (draft: ProjectAssetDraft) => Promise<void> }) {
  const [draft, setDraft] = useState<ProjectAssetDraft>({ runtime_url: "", api_base_url: "", sandbox_command: "", sandbox_image: "" });

  useEffect(() => {
    setDraft({
      runtime_url: project?.runtime_url ?? "",
      api_base_url: project?.api_base_url ?? "",
      sandbox_command: project?.sandbox_command ?? "",
      sandbox_image: project?.sandbox_image ?? "",
    });
  }, [project?.id, project?.runtime_url, project?.api_base_url, project?.sandbox_command, project?.sandbox_image]);

  return <section className="panel full asset-config"><div className="panel-header"><h2>项目资产配置</h2><span>{project ? "影响 DAST 与 SANDBOX 默认参数" : "请先选择项目"}</span></div><div className="asset-config-grid"><label>运行地址<input value={draft.runtime_url} onChange={(event) => setDraft({ ...draft, runtime_url: event.target.value })} placeholder="http://localhost:3000" disabled={!project || loading} /></label><label>API 地址<input value={draft.api_base_url} onChange={(event) => setDraft({ ...draft, api_base_url: event.target.value })} placeholder="http://localhost:3000/api" disabled={!project || loading} /></label><label>隔离目标启动命令<input value={draft.sandbox_command} onChange={(event) => setDraft({ ...draft, sandbox_command: event.target.value })} placeholder="例如：npm run start -- --host 0.0.0.0" disabled={!project || loading} /></label><label>隔离目标镜像<input value={draft.sandbox_image} onChange={(event) => setDraft({ ...draft, sandbox_image: event.target.value })} placeholder="例如：node:20-alpine" disabled={!project || loading} /></label></div><div className="asset-config-actions"><button className="primary-action" disabled={!project || loading} onClick={() => void onSave(draft)}>保存资产配置</button></div></section>;
}

function ProjectAssets({ project, assetProbe, enabledModules, components, findings, validations, evidence, summary, onOpenTasks, onOpenModules }: { project: Project | null; assetProbe: ProjectAssetProbe | null; enabledModules: Set<ModuleKey>; components: Component[]; findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; summary: AspmSummary | null; onOpenTasks: () => void; onOpenModules: () => void }) {
  const recommended = assetProbe?.recommended_tasks ?? [];
  const runnable = recommended.filter((kind) => enabledModules.has(kind));
  const blocked = recommended.filter((kind) => !enabledModules.has(kind));
  const sourcePath = project?.source_path ?? assetProbe?.source_path ?? "未配置本地源码路径";
  const pathStatus = assetProbe ? assetProbe.path_exists ? "路径可访问" : "路径不可访问" : "未探测";
  const enabledNames = OPTIONAL_MODULES.filter((moduleKey) => enabledModules.has(moduleKey)).map((moduleKey) => moduleKey.toUpperCase());

  return <section className="asset-workspace"><section className="module-summary"><Metric label="资产路径" value={pathStatus} /><Metric label="依赖清单" value={assetProbe?.sca_files.length ?? 0} /><Metric label="源码文件" value={assetProbe?.source_files.length ?? 0} /><Metric label="推荐任务" value={recommended.length} /></section><div className="asset-grid"><div className="panel asset-hero full"><div><div className="panel-header"><h2>{project?.name ?? "未选择项目"}</h2><span>{project?.default_branch ?? "main"}</span></div><div className="asset-path">{sourcePath}</div><div className="asset-tags"><span>{project?.repository_url ?? "未配置仓库"}</span><span>业务：{project?.business_owner ?? "未配置"}</span><span>安全：{project?.security_owner ?? "未配置"}</span></div></div><div className="asset-actions"><button className="primary-action" onClick={onOpenTasks} disabled={!project || runnable.length === 0}>执行推荐任务</button><button className="secondary-action" onClick={onOpenModules}>配置模块</button></div></div><div className="panel"><div className="panel-header"><h2>识别结果</h2><span>{assetProbe?.message ?? "暂无探测结果"}</span></div><div className="output-strip"><div><span>SCA</span><strong>{assetProbe?.sca_files.length ?? 0}</strong></div><div><span>SAST</span><strong>{assetProbe?.source_files.length ?? 0}</strong></div><div><span>AGENT</span><strong>{assetProbe?.agent_files.length ?? 0}</strong></div></div><div className="asset-note">{runnable.length ? `当前可直接执行：${runnable.map((item) => item.toUpperCase()).join(" + ")}` : "暂无可直接执行的推荐任务"}</div>{blocked.length ? <div className="asset-warning">需先启用模块：{blocked.map((item) => item.toUpperCase()).join(" + ")}</div> : null}</div><div className="panel"><div className="panel-header"><h2>模块准备度</h2><span>{enabledNames.length} 个已启用</span></div><div className="readiness-list">{OPTIONAL_MODULES.map((moduleKey) => <div className="readiness-row" key={moduleKey}><span>{moduleKey.toUpperCase()}</span><strong className={enabledModules.has(moduleKey) ? "ready" : "muted"}>{enabledModules.has(moduleKey) ? "已接入" : "未接入"}</strong></div>)}</div></div><div className="panel full"><div className="panel-header"><h2>资产文件</h2><span>来自本地源码路径自动识别</span></div><div className="asset-file-grid"><AssetFileList title="依赖清单" files={assetProbe?.sca_files ?? []} /><AssetFileList title="源码文件" files={assetProbe?.source_files ?? []} /><AssetFileList title="Agent 配置" files={assetProbe?.agent_files ?? []} /></div></div><div className="panel full"><div className="panel-header"><h2>当前项目结果</h2><span>进入 ASPM 治理总览前的资产侧摘要</span></div><div className="output-strip wide"><div><span>组件</span><strong>{summary?.component_count ?? components.length}</strong></div><div><span>Findings</span><strong>{summary?.finding_count ?? findings.length}</strong></div><div><span>DAST 验证</span><strong>{summary?.dast_validation_count ?? validations.length}</strong></div><div><span>Sandbox 证据</span><strong>{summary?.sandbox_evidence_count ?? evidence.length}</strong></div></div></div></div></section>;
}

function AssetFileList({ title, files }: { title: string; files: string[] }) {
  return <div className="asset-file-list"><h3>{title}</h3>{files.length === 0 ? <span className="empty-inline">暂无文件</span> : <ul>{files.slice(0, 8).map((file) => <li key={file}>{file}</li>)}{files.length > 8 ? <li>还有 {files.length - 8} 个文件</li> : null}</ul>}</div>;
}

const MODULE_DISPLAY: Record<Exclude<ModuleKey, "aspm">, { name: string; purpose: string }> = {
  sca: { name: "SCA 供应链风险", purpose: "检查第三方组件、已知漏洞和许可证风险" },
  sast: { name: "SAST 代码安全", purpose: "检查源代码中的高风险实现和安全缺陷" },
  agent: { name: "AGENT 智能体安全", purpose: "检查已识别的 Agent 指令、MCP、工具与插件配置风险" },
  dast: { name: "DAST 动态验证", purpose: "对已确认的项目同源目标进行基础 Web 观察，并关联人工验证记录" },
  sandbox: { name: "SANDBOX 沙箱证据", purpose: "在受限 Docker 目标中执行固定探针，归档运行证据并回传 DAST" },
};

const AGENT_RULE_TITLES: Record<string, string> = {
  "AGENT.SECRET.READ_ENV": "指令允许读取环境变量或密钥",
  "AGENT.TOOL.SHELL_EXEC": "Agent 暴露 Shell 或命令执行能力",
  "AGENT.FS.WRITE_ACCESS": "Agent 可写入或删除文件",
  "AGENT.NET.EXTERNAL_REQUEST": "Agent 可发起外部网络请求",
  "AGENT.MCP.WILDCARD_PERMISSION": "Agent 或插件权限范围过宽",
  "AGENT.PROMPT.INSTRUCTION_OVERRIDE": "指令包含覆盖上级约束的行为",
  "AGENT.SECRET.INLINE_TOKEN": "Agent 配置包含内联凭据",
  "AGENT.CONFIG.INVALID_JSON": "Agent 配置不是有效 JSON",
  "AGENT.CONFIG.INVALID_YAML": "Agent 配置不是有效 YAML",
  "AGENT.CONFIG.INVALID_YML": "Agent 配置不是有效 YAML",
  "AGENT.CONFIG.INVALID_TOML": "Agent 配置不是有效 TOML",
  "AGENT.CONFIG.INVALID_YAML_FRONTMATTER": "Markdown Frontmatter 不是有效 YAML",
  "AGENT.MCP.INVALID_JSON": "MCP 配置不是有效 JSON",
  "AGENT.MCP.DANGEROUS_COMMAND": "MCP Server 使用高风险启动命令",
  "AGENT.MCP.DANGEROUS_ARGS": "MCP Server 参数可能启动子进程或 Shell",
  "AGENT.MCP.SECRET_ENV": "MCP 配置包含明文凭据",
  "AGENT.MCP.SENSITIVE_PATH": "MCP Server 可访问敏感路径",
  "AGENT.MCP.NETWORK_CAPABILITY": "MCP Server 具备外部网络能力",
  "AGENT.SUPPLY.UNPINNED_VERSION": "Agent 依赖版本未不可变锁定",
  "AGENT.SUPPLY.INSECURE_SOURCE": "Agent 依赖使用不安全来源",
  "AGENT.SUPPLY.SOURCE_CREDENTIALS": "Agent 来源 URL 包含凭据",
  "AGENT.SUPPLY.LOCAL_PATH_ESCAPE": "Agent 本地依赖超出项目边界",
  "AGENT.SUPPLY.SOURCE_UNKNOWN": "Agent 依赖来源未声明",
  "AGENT.SUPPLY.INTEGRITY_PARTIAL": "Agent 目录完整性证据不完整",
  "AGENT.INTEL.KNOWN_VULNERABILITY": "Agent 依赖命中本地漏洞情报",
  "AGENT.INTEL.MALICIOUS_PACKAGE": "Agent 依赖命中本地恶意包情报",
  "AGENT.INTEL.PACKAGE_CONFUSION": "Agent 依赖疑似包名混淆",
  "AGENT.FLOW.POTENTIAL_SECRET_EXFILTRATION": "Agent 声明形成潜在密钥外传路径",
  "AGENT.FLOW.UNTRUSTED_TO_HIGH_RISK_TOOL": "可疑指令可能影响高风险工具",
  "AGENT.FLOW.PROMPT_TO_SENSITIVE_RESOURCE": "Prompt 上下文可能到达敏感资源",
};

const AGENT_CATEGORY_LABELS: Record<string, string> = {
  "secret-exposure": "凭据暴露",
  "tool-abuse": "工具滥用",
  "permission-overreach": "权限过宽",
  "network-egress": "网络外联",
  "prompt-injection": "指令覆盖",
  "configuration-integrity": "配置完整性",
  "supply-chain-integrity": "来源与完整性",
  "agent-vulnerability-intelligence": "漏洞情报",
  "agent-threat-intelligence": "恶意包与混淆情报",
  "agent-dataflow": "Prompt 工具资源路径",
  "unknown": "未分类",
};

const AGENT_ASSET_TYPE_LABELS: Record<string, string> = {
  "instruction": "指令文件",
  "prompt": "Prompt",
  "skill": "Skill",
  "mcp-config": "MCP 配置",
  "plugin-manifest": "插件清单",
  "tool-schema": "工具定义",
  "agent-config": "Agent 配置",
};

const AGENT_CAPABILITY_LABELS: Record<string, string> = {
  "all-capabilities": "全部能力",
  "shell-execution": "Shell 执行",
  "server-process": "服务进程启动",
  "filesystem-access": "文件系统访问",
  "filesystem-read": "文件读取",
  "filesystem-write": "文件写入",
  "network-egress": "网络外联",
  "secret-access": "凭据访问",
  "tool-invocation": "工具调用",
};

const AGENT_ACCESS_LABELS: Record<string, string> = {
  "admin": "完全控制",
  "execute": "执行",
  "read": "只读",
  "write": "写入",
  "read-write": "读写",
  "connect": "连接",
  "inject": "注入",
  "use": "调用",
};

const AGENT_DIFF_FIELD_LABELS: Record<string, string> = {
  "asset-added": "新增资产",
  "asset-removed": "移除资产",
  "status": "解析状态",
  "parser": "解析器",
  "version": "版本",
  "publisher": "发布者",
  "transport": "传输方式",
  "entrypoint": "启动入口",
  "declared_tools": "工具声明",
  "declared_resources": "资源范围",
  "declared_prompts": "Prompt 声明",
  "permission_count": "权限数量",
  "provenance": "来源或安装声明",
  "file_sha256": "配置文件 SHA-256",
  "directory_sha256": "本地目录 SHA-256",
  "integrity_status": "完整性状态",
  "integrity_issues": "完整性问题",
};

function agentCategoryLabel(value: string) { return AGENT_CATEGORY_LABELS[value] ?? value; }
function agentAssetTypeLabel(value: string) { return AGENT_ASSET_TYPE_LABELS[value] ?? value; }
function agentCapabilityLabel(value: string) { return AGENT_CAPABILITY_LABELS[value] ?? value; }
function agentAccessLabel(value: string) { return AGENT_ACCESS_LABELS[value] ?? value; }
function agentApprovalLabel(value: string) { return value === "required" ? "需要审批" : value === "not-required" ? "无需审批" : "审批未知"; }
function agentVersionStatusLabel(value: string) { return value === "locked" ? "不可变锁定" : value === "tagged" ? "已固定标签（非不可变）" : value === "floating" ? "浮动版本" : value === "missing" ? "未声明版本" : "不适用"; }
function agentSourceTypeLabel(value: string) { return ({ registry: "包注册表", git: "Git 仓库", container: "容器镜像", "remote-url": "远程服务", local: "本地实现", unknown: "来源未知" } as Record<string, string>)[value] ?? value; }
function agentIntelligenceStatusLabel(value: string) { return ({ vulnerable: "命中漏洞", checked_no_match: "本地源未命中", not_covered: "本地源未覆盖", version_unresolved: "版本未解析", unsupported_ecosystem: "暂不支持" } as Record<string, string>)[value] ?? value; }
function agentIntelligenceSourceLabel(value: string) { return ({ builtin_rules: "内置离线规则", osv_mirror: "本地 OSV 镜像", threat_intelligence: "本地恶意包情报" } as Record<string, string>)[value] ?? value; }
function agentDataflowConfidenceLabel(value: string) { return value === "high" ? "高置信" : value === "medium" ? "中置信" : "低置信 / 保守推断"; }
function agentDataflowControlLabel(value: string) { return ({ "human-approval-declared": "已声明人工审批", "scoped-resource": "已声明资源范围", "content-validation-declared": "已声明内容过滤/校验", "network-destination-allowlist-declared": "已声明网络目的地 Allowlist", "sandbox-isolation-declared": "已声明沙箱/隔离策略", "governance-exemption": "治理例外（非运行时防护）", "human-approval": "人工审批", "resource-scope-restriction": "资源范围限制", "network-destination-allowlist": "网络目的地 Allowlist", "verified-network-destination-allowlist": "已验证的网络目的地 Allowlist", "untrusted-content-validation": "不可信内容校验", "verified-untrusted-content-validation": "已验证的不可信内容校验", "verified-data-egress-policy": "已验证的数据外发策略" } as Record<string, string>)[value] ?? value; }
function agentProvenanceIssueLabel(value: string) { return ({ "version-unpinned": "版本未锁定", "insecure-http-source": "HTTP 不安全来源", "embedded-source-credentials": "来源 URL 含凭据", "local-path-escape": "路径超出项目", "source-unknown": "来源未知" } as Record<string, string>)[value] ?? value; }
function findingTitle(finding: Finding) { return finding.source === "AGENT" ? AGENT_RULE_TITLES[finding.rule_id] ?? finding.title : finding.title; }

function SecurityDetectionCenter({
  modules,
  project,
  enabledModules,
  savingKey,
  loading,
  runBlocked,
  moduleLoading,
  executionSteps,
  scanMode,
  sourcePath,
  targetUrl,
  runCommand,
  sandboxImage,
  onToggle,
  onEnableRelated,
  onScanModeChange,
  onSourcePathChange,
  onTargetUrlChange,
  onRunCommandChange,
  onSandboxImageChange,
  onRun,
}: {
  modules: SecurityModule[];
  project: Project | null;
  enabledModules: Set<ModuleKey>;
  savingKey: ModuleKey | null;
  loading: boolean;
  runBlocked: boolean;
  moduleLoading: ModuleLoadingState;
  executionSteps: ExecutionStep[];
  scanMode: ScanMode;
  sourcePath: string;
  targetUrl: string;
  runCommand: string;
  sandboxImage: string;
  onToggle: (module: SecurityModule) => Promise<void>;
  onEnableRelated: (moduleKeys: ModuleKey[]) => Promise<void>;
  onScanModeChange: (mode: ScanMode) => void;
  onSourcePathChange: (value: string) => void;
  onTargetUrlChange: (value: string) => void;
  onRunCommandChange: (value: string) => void;
  onSandboxImageChange: (value: string) => void;
  onRun: () => Promise<void>;
}) {
  const selected = modules.filter((module) => enabledModules.has(module.key));
  const sourceEnabled = ["sca", "sast", "agent"].some((key) => enabledModules.has(key as ModuleKey));
  const relationNotices: Array<{ text: string; action?: string; modules?: ModuleKey[] }> = [];
  if (enabledModules.has("dast")) {
    if (!enabledModules.has("sast") && !enabledModules.has("sca")) {
      relationNotices.push({ text: "DAST 可以独立探测网站，但接入 SAST 或 SCA 后才能针对已发现风险进行验证。", action: "同时接入 SAST", modules: ["sast"] });
    } else {
      relationNotices.push({ text: "DAST 将在静态或供应链检查之后执行，用于补充动态验证结论。" });
    }
  }
  if (enabledModules.has("sandbox")) {
    if (!enabledModules.has("agent") && !enabledModules.has("dast")) {
      relationNotices.push({ text: "SANDBOX 不再独立接收手工命令；请接入 DAST，由已审批策略自动生成隔离任务。", action: "同时接入 DAST", modules: ["dast"] });
    } else {
      relationNotices.push({ text: "SANDBOX 将接收 DAST 审批后的固定策略，在项目目标实例中执行并回传证据。" });
    }
  }

  return <section className="security-center">
    <div className="panel detection-intro">
      <div><h2>安全能力接入</h2><p>按项目需要选择模块。ASPM 治理底座始终启用，检测结果会自动进入治理总览。</p></div>
      <div className="detection-selection-count"><strong>{selected.length}</strong><span>个检测模块已接入</span></div>
    </div>

    <div className="detection-module-grid">
      {modules.map((module) => {
        const enabled = enabledModules.has(module.key);
        const display = MODULE_DISPLAY[module.key as Exclude<ModuleKey, "aspm">];
        return <article className={`detection-module-card ${enabled ? "enabled" : ""}`} key={module.key}>
          <div className="detection-module-heading"><span className="module-icon">{moduleIcons[module.key]}</span><div><strong>{display?.name ?? module.name}</strong><span>{display?.purpose ?? module.description}</span></div></div>
          <button className={`module-select-button ${enabled ? "selected" : ""}`} disabled={!project || savingKey === module.key || loading || moduleLoading[module.key as ExecutableModuleKey]} onClick={() => void onToggle(module)}>{enabled ? "已接入" : "接入模块"}</button>
        </article>;
      })}
    </div>

    {relationNotices.length > 0 ? <section className="relation-notices">
      <h3>模块关系提示</h3>
      {relationNotices.map((notice, index) => <div className="relation-notice" key={`${index}-${notice.text}`}><span>{notice.text}</span>{notice.modules ? <button className="secondary-action" disabled={loading} onClick={() => void onEnableRelated(notice.modules!)}>{notice.action}</button> : null}</div>)}
    </section> : null}

    <section className="panel detection-config">
      <div className="panel-header"><h2>执行配置</h2><span>只显示已接入模块所需的参数</span></div>
      {selected.length === 0 ? <div className="empty-project">请先选择需要接入的安全模块。</div> : <div className="detection-config-grid">
        {sourceEnabled ? <label><span>项目源码路径</span><input value={sourcePath} onChange={(event) => onSourcePathChange(event.target.value)} placeholder="项目源码所在目录" /></label> : null}
        {enabledModules.has("dast") ? <label><span>动态验证地址</span><input value={targetUrl} onChange={(event) => onTargetUrlChange(event.target.value)} placeholder="https://项目运行地址" /></label> : null}
        {enabledModules.has("sandbox") ? <div className="empty-project">SANDBOX 不需要在这里填写执行命令。隔离目标的镜像与启动命令在“项目资产”配置，固定验证策略由 DAST 审批后自动入队。</div> : null}
      </div>}
    </section>

    <section className="panel detection-run-panel">
      <div className="detection-run-copy"><h2>一键执行安全检测</h2><p>{scanMode === "quick" ? "快速模式使用本地规则和离线情报，并对文件数、体积和模块耗时进行有界降级。" : "深度模式启用增强 SCA 与 Semgrep，适合预先准备，不建议在未知项目现场首次运行。"}</p></div>
      <div className="scan-mode-switch" role="radiogroup" aria-label="扫描模式"><button type="button" className={scanMode === "quick" ? "active" : ""} onClick={() => onScanModeChange("quick")}><strong>快速演示</strong><span>默认 · 本地有界</span></button><button type="button" className={scanMode === "deep" ? "active" : ""} onClick={() => onScanModeChange("deep")}><strong>深度扫描</strong><span>增强工具 · 耗时不定</span></button></div>
      <button className="primary-action run-all-button" disabled={!project || loading || runBlocked || selected.length === 0} onClick={() => void onRun()}>{loading ? "检测执行中" : runBlocked ? "单模块执行中" : "一键执行"}</button>
      {executionSteps.length > 0 ? <div className="execution-progress">{executionSteps.map((step) => <div className={`execution-step ${step.status}`} key={step.module}><span>{MODULE_DISPLAY[step.module].name}</span><strong>{executionStatusLabel(step.status)}</strong><small>{step.detail}</small></div>)}</div> : null}
    </section>
  </section>;
}

type GovernanceScope = "overview" | Exclude<ModuleKey, "aspm">;

function GovernanceCenter({
  project,
  enabledModules,
  summary,
  components,
  findings,
  validations,
  evidence,
  graph,
  retestComparisons,
  scaScanHistory,
  agentScanHistory,
  agentSnapshot,
  agentScanDiff,
  agentAuditDiff,
  selectedScaScanId,
  scaScanDiff,
  dependencyGraph,
  scaToolScanEnabled,
  sandboxTemplates,
  dastStrategies,
  dastStrategyId,
  dastTargetConfirmation,
  loading,
  unifiedLoading,
  moduleLoading,
  targetUrl,
  runCommand,
  sandboxImage,
  selectedFindingId,
  selectedValidationId,
  onTargetUrlChange,
  onRunCommandChange,
  onSandboxImageChange,
  onDastStrategyChange,
  onDastTargetConfirmationChange,
  onScaToolScanChange,
  onSelectScaScan,
  onExportScaSbom,
  onExportScaReport,
  onRunSastAgentReview,
  onRunAgentAiReview,
  onSelectDastRisk,
  onSelectSandboxRisk,
  onSelectSandboxValidation,
  onRunDast,
  onCreateManualDast,
  onUpdateManualDast,
  onExportDastReport,
  onRunSandbox,
  onRunModule,
  onUpdateFinding,
}: {
  project: Project | null;
  enabledModules: Set<ModuleKey>;
  summary: AspmSummary | null;
  components: Component[];
  findings: Finding[];
  validations: DastValidation[];
  evidence: SandboxEvidence[];
  graph: EvidenceGraph | null;
  retestComparisons: Record<"sca" | "sast" | "agent", FindingRetestComparison | null>;
  scaScanHistory: ScaScanHistoryItem[];
  agentScanHistory: AgentScanHistoryItem[];
  agentSnapshot: AgentScanSnapshot | null;
  agentScanDiff: AgentScanDiff | null;
  agentAuditDiff: AgentOfflineAuditDiff | null;
  selectedScaScanId: string | null;
  scaScanDiff: ScaScanDiff | null;
  dependencyGraph: DependencyGraph | null;
  scaToolScanEnabled: boolean;
  sandboxTemplates: SandboxTemplate[];
  dastStrategies: DastStrategy[];
  dastStrategyId: string;
  dastTargetConfirmation: string;
  loading: boolean;
  unifiedLoading: boolean;
  moduleLoading: ModuleLoadingState;
  targetUrl: string;
  runCommand: string;
  sandboxImage: string;
  selectedFindingId: string;
  selectedValidationId: string;
  onTargetUrlChange: (value: string) => void;
  onRunCommandChange: (value: string) => void;
  onSandboxImageChange: (value: string) => void;
  onDastStrategyChange: (strategyId: string) => void;
  onDastTargetConfirmationChange: (value: string) => void;
  onScaToolScanChange: (enabled: boolean) => void;
  onSelectScaScan: (scanTaskId: string) => Promise<void>;
  onExportScaSbom: (format: "cyclonedx" | "spdx") => Promise<void>;
  onExportScaReport: () => Promise<void>;
  onRunSastAgentReview: () => Promise<void>;
  onRunAgentAiReview: (confirmationPhrase: string) => Promise<void>;
  onSelectDastRisk: (findingId: string) => void;
  onSelectSandboxRisk: (findingId: string) => void;
  onSelectSandboxValidation: (validationId: string) => void;
  onRunDast: () => Promise<void>;
  onCreateManualDast: (draft: ManualDastValidationDraft) => Promise<void>;
  onUpdateManualDast: (validationId: string, draft: ManualDastValidationDraft) => Promise<void>;
  onExportDastReport: () => Promise<void>;
  onRunSandbox: (plan: SandboxExecutionPlan) => Promise<void>;
  onRunModule: (moduleKey: Exclude<ModuleKey, "aspm">) => Promise<void>;
  onUpdateFinding: (findingId: string, patch: Partial<Pick<Finding, "status" | "remediation_owner" | "remediation_note" | "remediation_due_at">>) => Promise<void>;
}) {
  const scopes: GovernanceScope[] = ["overview", ...(["sca", "sast", "agent", "dast", "sandbox"] as const).filter((key) => enabledModules.has(key))];
  const [scope, setScope] = useState<GovernanceScope>("overview");
  const scopeLoading = (moduleKey: ExecutableModuleKey) => loading || unifiedLoading || moduleLoading[moduleKey];
  useEffect(() => { if (!scopes.includes(scope)) setScope("overview"); }, [enabledModules, scope]);

  if (!project) return <div className="panel empty-project">请先选择项目，再查看治理结果。</div>;

  return <section className="governance-center">
    <nav className="governance-scope" aria-label="治理查看范围">
      {scopes.map((item) => <button className={scope === item ? "active" : ""} key={item} onClick={() => setScope(item)}>{item === "overview" ? "综合总览" : MODULE_DISPLAY[item].name}</button>)}
    </nav>
    {scope === "overview" ? <GovernanceOverview summary={summary} enabledModules={enabledModules} components={components} findings={findings} validations={validations} evidence={evidence} graph={graph} onOpenDast={(findingId) => { onSelectDastRisk(findingId); setScope("dast"); }} onOpenSandbox={(findingId) => { onSelectSandboxRisk(findingId); setScope("sandbox"); }} onUpdateFinding={onUpdateFinding} /> : null}
    {scope === "sca" ? <ScaGovernanceView project={project} components={components} summary={summary} comparison={retestComparisons.sca} scanHistory={scaScanHistory} selectedScanId={selectedScaScanId} scanDiff={scaScanDiff} dependencyGraph={dependencyGraph} toolScanEnabled={scaToolScanEnabled} loading={scopeLoading("sca")} onToolScanChange={onScaToolScanChange} onSelectScan={onSelectScaScan} onExportSbom={onExportScaSbom} onExportReport={onExportScaReport} onRun={() => onRunModule("sca")} /> : null}
    {scope === "sast" ? <SastGovernanceWorkspace project={project} findings={findings.filter((item) => item.source === "SAST")} validations={validations} evidence={evidence} graph={graph} comparison={retestComparisons.sast} loading={scopeLoading("sast")} onRunReview={onRunSastAgentReview} onRun={() => onRunModule("sast")} onUpdateFinding={onUpdateFinding} /> : null}
    {scope === "agent" ? <FindingModuleGovernance project={project} moduleKey="agent" findings={findings.filter((item) => item.source === "AGENT")} validations={validations} evidence={evidence} graph={graph} comparison={retestComparisons.agent} scanHistory={agentScanHistory} agentSnapshot={agentSnapshot} agentScanDiff={agentScanDiff} agentAuditDiff={agentAuditDiff} loading={scopeLoading("agent")} onRunAgentAiReview={onRunAgentAiReview} onRun={() => onRunModule("agent")} onUpdateFinding={onUpdateFinding} /> : null}
    {scope === "dast" ? <DastGovernanceView project={project} findings={findings} validations={validations} strategies={dastStrategies} strategyId={dastStrategyId} targetUrl={targetUrl} targetConfirmation={dastTargetConfirmation} selectedFindingId={selectedFindingId} loading={scopeLoading("dast")} onTargetUrlChange={onTargetUrlChange} onTargetConfirmationChange={onDastTargetConfirmationChange} onStrategyChange={onDastStrategyChange} onSelectRisk={onSelectDastRisk} onRun={onRunDast} onCreateManual={onCreateManualDast} onUpdateManual={onUpdateManualDast} onExportReport={onExportDastReport} /> : null}
    {scope === "sandbox" ? <SandboxGovernanceView project={project} /> : null}
  </section>;
}

function SastGovernanceWorkspace({ project, findings, validations, evidence, graph, comparison, loading, onRunReview, onRun, onUpdateFinding }: { project: Project; findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; graph: EvidenceGraph | null; comparison: FindingRetestComparison | null; loading: boolean; onRunReview: () => Promise<void>; onRun: () => Promise<void>; onUpdateFinding: (findingId: string, patch: Partial<Pick<Finding, "status">>) => Promise<void> }) {
  return <section className="sast-governance-workspace">
    <FindingModuleGovernance moduleKey="sast" findings={findings} validations={validations} evidence={evidence} graph={graph} comparison={comparison} loading={loading} onRunReview={onRunReview} onRun={onRun} onUpdateFinding={onUpdateFinding} afterMetrics={<div className="sast-daily-below-metrics"><section className="panel full"><div className="panel-header"><div><h2>SAST 日常检测</h2><span>日常只需关注引擎状态、风险列表和 DeepSeek 审计</span></div></div><p>点击“重新扫描并复测”即可执行完整 SAST。下方高级管理仅用于 Git 增量、规则开发、CI/Worker、豁免和报告导出，不配置也不会影响基础扫描。</p></section><SastDailyEngineStatus project={project} /></div>} />
    <SastAiAgentsPanel project={project} onRunReview={onRunReview} />
    <details className="advanced-details governance-advanced-details sast-advanced-hub"><summary>高级管理（规则、Git、CI/Worker、豁免与报告）</summary><div className="advanced-details-body"><p>这些能力面向安全规则维护和服务器交付，普通本地扫描可以保持默认设置。</p><SastOperationsConsole project={project} /><SastExpertDelivery project={project} /><SastRuleManagement project={project} /><SastEvidenceGovernance project={project} /></div></details>
  </section>;
}

function SastDailyEngineStatus({ project }: { project: Project }) {
  const [health, setHealth] = useState<SastToolHealth | null>(null);
  const [history, setHistory] = useState<SastScanHistoryItem[]>([]);
  useEffect(() => { void load(); }, [project.id]);
  async function load() {
    const [nextHealth, nextHistory] = await Promise.all([
      request<SastToolHealth>("/sast/tool-health").catch(() => null),
      request<SastScanHistoryItem[]>(`/sast/projects/${project.id}/scan-history`).catch(() => []),
    ]);
    setHealth(nextHealth); setHistory(nextHistory);
  }
  const latest = history[0] ?? null;
  const semgrepStatus = latest?.engine_status.semgrep?.status;
  const localStatus = latest?.engine_status.local_rules?.status;
  const assurance = latest?.engine_status.assurance;
  return <section className="content-grid"><div className="panel"><div className="panel-header"><h2>当前扫描引擎</h2><button className="secondary-action" onClick={() => void load()}>刷新</button></div><div className="kv-list"><div><span>本地规则</span><strong>{toolStatusLabel(localStatus)}</strong></div><div><span>Semgrep</span><strong>{toolStatusLabel(semgrepStatus)}</strong></div><div><span>Semgrep 运行方式</span><strong>{health?.semgrep_cli.available ? `本机 CLI ${health.semgrep_cli.version ?? ""}` : health?.docker_image.available ? "本地 Docker 镜像" : "不可用，扫描将自动降级"}</strong></div></div></div><div className="panel"><div className="panel-header"><h2>最近扫描</h2><span>{latest ? formatDateTime(latest.finished_at ?? latest.created_at) : "尚未执行"}</span></div><div className="kv-list"><div><span>任务状态</span><strong>{scanStatusLabel(latest?.status)}</strong></div><div><span>结果可信度</span><strong>{scanAssuranceLabel(assurance?.status)}</strong></div><div><span>风险记录 / 已忽略</span><strong>{latest?.finding_count ?? 0} / {latest?.suppressed_count ?? 0}</strong></div></div>{assurance?.statement ? <p>{assurance.statement}</p> : null}{assurance?.limitations?.[0] ? <p>能力边界：{assurance.limitations[0]}</p> : null}{semgrepStatus === "degraded" ? <p>Semgrep 增强扫描未完整完成，但本地规则结果仍然有效。</p> : null}</div></section>;
}

function SastExpertDelivery({ project }: { project: Project }) {
  const [profile, setProfile] = useState<SastProfile | null>(null);
  const [packs, setPacks] = useState<SastSemgrepRule[]>([]);
  const [report, setReport] = useState<SastReport | null>(null);
  const [message, setMessage] = useState("");
  const [draft, setDraft] = useState({ name: "项目自定义规则包", status: "draft" as "draft" | "published", content: "rules:\n  - id: project.example.rule\n    languages: [python]\n    severity: WARNING\n    message: 请填写规则说明\n    pattern: eval(...)\n" });

  useEffect(() => { void load(); }, [project.id]);

  async function load() {
    const [nextProfile, packResult, nextReport] = await Promise.all([
      request<SastProfile>(`/sast/projects/${project.id}/profile`).catch(() => null),
      request<{ semgrep_rules: SastSemgrepRule[] }>(`/sast/projects/${project.id}/semgrep-rules`).catch(() => ({ semgrep_rules: [] })),
      request<SastReport>(`/sast/projects/${project.id}/report`).catch(() => null),
    ]);
    setProfile(nextProfile); setPacks(packResult.semgrep_rules ?? []); setReport(nextReport);
  }

  async function saveGitProfile() {
    if (!profile) return;
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/profile`, { method: "PATCH", body: JSON.stringify({ git_baseline_ref: profile.git_baseline_ref, scan_git_history_secrets: profile.scan_git_history_secrets, changed_files_only: profile.changed_files_only }) });
      setProfile(saved); setMessage("Git 基线配置已保存，将从下一次扫描开始生效。");
    } catch (error) { setMessage(`保存失败：${errorMessage(error)}`); }
  }

  async function validatePack() {
    try {
      const result = await request<{ yaml: { rule_count: number; sha256: string } }>("/sast/semgrep-rules/validate", { method: "POST", body: JSON.stringify(draft) });
      setMessage(`规则结构有效：${result.yaml.rule_count} 条规则，校验值 ${result.yaml.sha256.slice(0, 12)}。`);
    } catch (error) { setMessage(`规则校验失败：${errorMessage(error)}`); }
  }

  async function savePack() {
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/semgrep-rules`, { method: "POST", body: JSON.stringify(draft) });
      setProfile(saved); setPacks(saved.semgrep_rules ?? []); setMessage(draft.status === "draft" ? "规则包已保存为草稿；发布后才会参与扫描。" : "规则包已发布，将从下一次 Semgrep 扫描开始生效。");
    } catch (error) { setMessage(`保存失败：${errorMessage(error)}`); }
  }

  async function preflight(pack: SastSemgrepRule) {
    try {
      const result = await request<{ engine_checked: boolean; engine_status: string; detail: string }>("/sast/semgrep-rules/preflight", { method: "POST", body: JSON.stringify({ content: pack.content }) });
      setMessage(`${pack.name}：${toolStatusLabel(result.engine_status)}。${result.detail}`);
    } catch (error) { setMessage(`真实引擎预检失败：${errorMessage(error)}`); }
  }

  async function publish(pack: SastSemgrepRule) {
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/semgrep-rules/${pack.id}/publish`, { method: "POST" });
      setProfile(saved); setPacks(saved.semgrep_rules ?? []); setMessage(`${pack.name} 已发布。`);
    } catch (error) { setMessage(`发布失败：${errorMessage(error)}`); }
  }

  async function toggle(pack: SastSemgrepRule) {
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/semgrep-rules/${pack.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !pack.enabled }) });
      setProfile(saved); setPacks(saved.semgrep_rules ?? []);
    } catch (error) { setMessage(`更新失败：${errorMessage(error)}`); }
  }

  return <details className="advanced-details governance-advanced-details"><summary>Git 增量扫描与 Semgrep YAML 专家规则</summary><div className="advanced-details-body"><section className="content-grid">
    <div className="panel full"><div className="panel-header"><h2>Git 对比与历史密钥检查</h2><span>留空基线时仍会执行完整扫描</span></div><div className="filter-grid"><label>对比的 Git 版本<input value={profile?.git_baseline_ref ?? ""} placeholder="例如 origin/main 或 HEAD~1" onChange={(event) => setProfile((value) => value ? { ...value, git_baseline_ref: event.target.value } : value)} /></label><label className="inline-check"><input type="checkbox" checked={profile?.scan_git_history_secrets ?? true} onChange={(event) => setProfile((value) => value ? { ...value, scan_git_history_secrets: event.target.checked } : value)} />检查历史提交中的疑似密钥路径</label><label className="inline-check"><input type="checkbox" checked={profile?.changed_files_only ?? false} disabled={!profile?.git_baseline_ref} onChange={(event) => setProfile((value) => value ? { ...value, changed_files_only: event.target.checked } : value)} />只扫描相对基线发生变化的文件</label><button className="secondary-action" disabled={!profile} onClick={() => void saveGitProfile()}>保存 Git 配置</button><button className="secondary-action" onClick={() => void load()}>刷新统计</button></div>{message ? <div className="empty-project">{message}</div> : null}</div>
    <div className="panel"><div className="panel-header"><h2>CI 门禁结果</h2><span>{qualityGateStatusLabel(report?.quality_gate.status)}</span></div><div className="kv-list"><div><span>阻断等级</span><strong>{severityLabel(report?.quality_gate.threshold)}</strong></div><div><span>达到门槛的问题</span><strong>{report?.quality_gate.blocking_finding_count ?? 0}</strong></div><div><span>本次风险记录</span><strong>{report?.summary.finding_count ?? 0}</strong></div></div></div>
    <div className="panel"><div className="panel-header"><h2>Git 证据</h2><span>{report?.git.available ? "已读取 Git 信息" : "未读取到 Git 信息"}</span></div><div className="kv-list"><div><span>对比版本</span><strong>{report?.git.baseline_ref ?? "未设置"}</strong></div><div><span>变化文件</span><strong>{report?.git.changed_files?.length ?? 0}</strong></div><div><span>疑似历史密钥路径</span><strong>{report?.git.history_secret_count ?? report?.git.history_secret_files?.length ?? 0}</strong></div></div></div>
    <div className="panel full"><div className="panel-header"><h2>Semgrep YAML 规则包</h2><span>只有“已发布 + 已启用”的规则包才参与扫描</span></div><details className="advanced-details"><summary>新建专家规则包</summary><p>普通项目无需创建。只有熟悉 Semgrep YAML 时才使用这里。</p><div className="filter-grid"><label>规则包名称<input value={draft.name} onChange={(event) => setDraft((value) => ({ ...value, name: event.target.value }))} /></label><label>保存状态<select value={draft.status} onChange={(event) => setDraft((value) => ({ ...value, status: event.target.value as "draft" | "published" }))}><option value="draft">仅保存草稿</option><option value="published">保存并发布</option></select></label><label className="wide-field">规则 YAML<textarea value={draft.content} onChange={(event) => setDraft((value) => ({ ...value, content: event.target.value }))} rows={9} /></label><button className="secondary-action" onClick={() => void validatePack()}>校验规则</button><button className="primary-action" onClick={() => void savePack()}>{draft.status === "draft" ? "保存草稿" : "保存并发布"}</button></div></details>{packs.length ? <table><thead><tr><th>规则包</th><th>规则 ID</th><th>生命周期</th><th>操作</th></tr></thead><tbody>{packs.map((pack) => <tr key={pack.id}><td>{pack.name}<span className="cell-subtext">v{pack.version} · {pack.approved_by ? `审批：${pack.approved_by}` : "未记录审批人"}</span></td><td>{pack.rule_ids.join(", ")}</td><td>{semgrepRuleStatusLabel(pack.status)}<span className="cell-subtext">{pack.enabled ? "已启用" : "已停用"}</span></td><td><button className="secondary-action" onClick={() => void preflight(pack)}>真实引擎预检</button>{pack.status !== "published" ? <button className="secondary-action" onClick={() => void publish(pack)}>发布</button> : null}<button className="secondary-action" onClick={() => void toggle(pack)}>{pack.enabled ? "停用" : "启用"}</button></td></tr>)}</tbody></table> : <div className="empty-project">没有项目自定义 YAML 规则包；默认离线规则仍会参与扫描。</div>}</div>
    <div className="panel full"><div className="panel-header"><h2>后续验证建议</h2><span>不会自动发送请求或执行沙箱命令</span></div>{report?.validation_suggestions.length ? <ul>{report.validation_suggestions.map((item) => <li key={item.finding_id}><strong>{item.recommended_module}</strong> · {item.next_step}</li>)}</ul> : <div className="empty-project">当前没有需要跨模块验证的高风险线索。</div>}</div>
  </section></div></details>;
}

function SastAiAgentsPanel({ project, onRunReview }: { project: Project; onRunReview: () => Promise<void> }) {
  const [health, setHealth] = useState<SastAiHealth | null>(null);
  const [profile, setProfile] = useState<SastProfile | null>(null);
  const [runs, setRuns] = useState<SastAgentRun[]>([]);
  const [message, setMessage] = useState("");
  const [testing, setTesting] = useState(false);
  const [running, setRunning] = useState(false);

  useEffect(() => { void load(); }, [project.id]);

  async function load() {
    const [nextHealth, nextProfile, nextRuns] = await Promise.all([
      request<SastAiHealth>("/sast/ai-health").catch(() => null),
      request<SastProfile>(`/sast/projects/${project.id}/profile`).catch(() => null),
      request<SastAgentRun[]>(`/sast/projects/${project.id}/agent-runs`).catch(() => []),
    ]);
    setHealth(nextHealth); setProfile(nextProfile); setRuns(nextRuns);
  }

  async function save() {
    if (!profile) return;
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/profile`, { method: "PATCH", body: JSON.stringify({ ai_enabled: profile.ai_enabled, ai_auto_scan: profile.ai_auto_scan, ai_max_input_chars: profile.ai_max_input_chars, ai_confidence_threshold: profile.ai_confidence_threshold, ai_include_fix_drafts: profile.ai_include_fix_drafts }) });
      setProfile(saved); setMessage("DeepSeek 多 Agent 配置已保存。下一次 SAST 扫描将按该配置执行。");
    } catch (error) { setMessage(`保存失败：${errorMessage(error)}`); }
  }

  async function testConnection() {
    setTesting(true);
    try {
      const result = await request<{ model: string; latency_ms: number; prompt_tokens: number; completion_tokens: number }>("/sast/ai-health/test", { method: "POST" });
      setMessage(`连接成功：${result.model}，${result.latency_ms} ms，本次测试使用 ${result.prompt_tokens + result.completion_tokens} Token。`);
      await load();
    } catch (error) { setMessage(`连接测试失败：${errorMessage(error)}`); }
    finally { setTesting(false); }
  }

  async function runAgents() {
    if (!profile?.ai_enabled) { setMessage("请先启用并保存 DeepSeek 多 Agent。"); return; }
    setRunning(true);
    try {
      await onRunReview();
      const refreshedRuns = await request<SastAgentRun[]>(`/sast/projects/${project.id}/agent-runs`).catch(() => []);
      setRuns(refreshedRuns);
      const newest = refreshedRuns[0];
      setMessage(newest?.status === "completed"
        ? "DeepSeek 七角色深度审计已完成，Finding 与审计记录已刷新。"
        : `DeepSeek 审计已降级：${newest?.error ?? "请查看最近一次审计记录"}。本地 SAST 结果仍已保留。`);
    }
    catch (error) { setMessage(`深度审计失败：${errorMessage(error)}`); }
    finally { setRunning(false); }
  }

  const latest = runs[0] ?? null;
  return <details className="advanced-details governance-advanced-details"><summary>DeepSeek 真实多 Agent 深度审计</summary><div className="advanced-details-body"><section className="content-grid">
    <div className="panel full"><div className="panel-header"><h2>连接与安全边界</h2><span>{health?.configured ? "API Key 已在后端安全加载" : "尚未配置 API Key"}</span></div><div className="kv-list"><div><span>服务</span><strong>{health?.base_url ?? "https://api.deepseek.com"}</strong></div><div><span>发现 / 分析模型</span><strong>{health?.model ?? "-"}</strong></div><div><span>独立复核模型</span><strong>{health?.review_model ?? "-"}</strong></div><div><span>结构化思考模式</span><strong>{health?.thinking_enabled ? "已开启（更慢、费用更高）" : "已关闭（默认，更稳定）"}</strong></div><div><span>Key 文件</span><strong>{health?.api_key_location ?? "apps/api/.env"}</strong></div></div><p>代码上传前会脱敏密钥并移除疑似提示注入；Agent 不能执行代码、调用工具、访问扫描目标或直接修改源码。连接测试会产生一次极小的真实 API 调用。</p><div className="filter-grid"><button className="secondary-action" disabled={!health?.configured || testing} onClick={() => void testConnection()}>{testing ? "测试中" : "测试 DeepSeek 连接"}</button><button className="secondary-action" onClick={() => void load()}>刷新状态</button></div>{message ? <div className="empty-project">{message}</div> : null}</div>
    <div className="panel full"><div className="panel-header"><h2>项目级 Agent 策略</h2><span>默认关闭，防止无意消耗额度</span></div><div className="filter-grid"><label className="inline-check"><input type="checkbox" checked={profile?.ai_enabled ?? false} disabled={!profile || !health?.configured} onChange={(event) => setProfile((value) => value ? { ...value, ai_enabled: event.target.checked } : value)} />启用 DeepSeek 多 Agent</label><label className="inline-check"><input type="checkbox" checked={profile?.ai_auto_scan ?? true} disabled={!profile} onChange={(event) => setProfile((value) => value ? { ...value, ai_auto_scan: event.target.checked } : value)} />随 SAST 自动执行</label><label>最大上传字符数<input type="number" min={10000} max={200000} step={10000} value={profile?.ai_max_input_chars ?? 60000} disabled={!profile} onChange={(event) => setProfile((value) => value ? { ...value, ai_max_input_chars: Number(event.target.value) } : value)} /></label><label>正式 Finding 置信度<input type="number" min={50} max={100} value={profile?.ai_confidence_threshold ?? 80} disabled={!profile} onChange={(event) => setProfile((value) => value ? { ...value, ai_confidence_threshold: Number(event.target.value) } : value)} /></label><label className="inline-check"><input type="checkbox" checked={profile?.ai_include_fix_drafts ?? true} disabled={!profile} onChange={(event) => setProfile((value) => value ? { ...value, ai_include_fix_drafts: event.target.checked } : value)} />保存人工评审用补丁草案</label><button className="secondary-action" disabled={!profile} onClick={() => void save()}>保存 Agent 配置</button><button className="primary-action" disabled={!profile?.ai_enabled || !health?.configured || running} onClick={() => void runAgents()}>{running ? "七角色审计中" : "立即执行 AI 深度审计"}</button></div></div>
    <div className="panel full"><div className="panel-header"><h2>最近一次多 Agent 审计</h2><span>{latest ? `${formatDateTime(latest.finished_at ?? latest.started_at)} · ${latest.status}` : "尚未执行"}</span></div>{latest ? <><section className="module-summary"><Metric label="角色完成" value={`${latest.result_summary.completed_agent_count ?? latest.agent_steps.filter((step) => step.status === "completed").length} / ${latest.result_summary.expected_agent_count ?? 7}`} /><Metric label="候选漏洞" value={latest.result_summary.candidate_count ?? 0} /><Metric label="确认 Finding" value={latest.result_summary.confirmed_count ?? 0} /><Metric label="Token" value={(latest.token_usage.prompt_tokens ?? 0) + (latest.token_usage.completion_tokens ?? 0)} /></section><table><thead><tr><th>Agent</th><th>状态</th><th>模型</th><th>耗时</th><th>Token / 估算费用</th></tr></thead><tbody>{latest.agent_steps.map((step) => <tr key={`${latest.id}-${step.role}`}><td>{sastAgentRoleLabel(step.role)}</td><td>{step.status === "completed" ? "完成" : `失败：${step.error ?? "未知原因"}`}</td><td>{step.model ?? "-"}</td><td>{step.latency_ms != null ? `${step.latency_ms} ms` : "-"}</td><td>{(step.prompt_tokens ?? 0) + (step.completion_tokens ?? 0)}<span className="cell-subtext">{step.estimated_cost_usd == null ? "费用未计算" : `$${step.estimated_cost_usd.toFixed(6)}`}</span></td></tr>)}</tbody></table><div className="kv-list"><div><span>上传范围</span><strong>{latest.result_summary.context_summary?.uploaded_file_count ?? 0} 文件 / {latest.result_summary.context_summary?.uploaded_char_count ?? 0} 字符</strong></div><div><span>脱敏项</span><strong>{latest.result_summary.context_summary?.redaction_count ?? 0}</strong></div><div><span>未完成角色</span><strong>{latest.result_summary.incomplete_roles?.map(sastAgentRoleLabel).join("、") || "无"}</strong></div><div><span>Agent 分歧</span><strong>{latest.result_summary.disagreement_count ?? 0}</strong></div><div><span>执行错误</span><strong>{latest.error ?? "无"}</strong></div></div></> : <div className="empty-project">启用后执行 SAST 或点击“立即执行 AI 深度审计”，这里会显示七个 Agent 的真实调用状态、Token 和裁决统计。</div>}</div>
  </section></div></details>;
}

function SastOperationsConsole({ project }: { project: Project }) {
  const [sourcePath, setSourcePath] = useState(project.source_path ?? DEFAULT_SAST_PATH);
  const [profile, setProfile] = useState<SastProfile | null>(null);
  const [jobs, setJobs] = useState<ScanTask[]>([]);
  const [message, setMessage] = useState("");
  useEffect(() => { setSourcePath(project.source_path ?? DEFAULT_SAST_PATH); void load(); }, [project.id]);
  async function load() {
    const [nextProfile, tasks] = await Promise.all([request<SastProfile>(`/sast/projects/${project.id}/profile`).catch(() => null), request<ScanTask[]>(`/scans?project_id=${project.id}`).catch(() => [])]);
    setProfile(nextProfile); setJobs(tasks.filter((item) => item.scan_type === "sast_job"));
  }
  async function queue() {
    try { const job = await request<ScanTask>("/sast/jobs", { method: "POST", body: JSON.stringify({ project_id: project.id, source_path: sourcePath, branch: project.default_branch }) }); setJobs((items) => [job, ...items]); setMessage("SAST Job 已排队。可启动本地 Worker，或点击“本次运行”由当前 API 进程执行。"); }
    catch (error) { setMessage(`排队失败：${errorMessage(error)}`); }
  }
  async function run(job: ScanTask) {
    try { await request(`/sast/jobs/${job.id}/run`, { method: "POST" }); setMessage("SAST Job 已完成，已生成独立扫描批次和报告。"); await load(); }
    catch (error) { setMessage(`执行失败：${errorMessage(error)}`); await load(); }
  }
  async function changeJob(job: ScanTask, action: "cancel" | "retry") {
    try { await request<ScanTask>(`/scans/${job.id}/${action}`, { method: "POST" }); await load(); }
    catch (error) { setMessage(`${action} 失败：${errorMessage(error)}`); }
  }
  async function saveGate() {
    if (!profile) return;
    try { setProfile(await request<SastProfile>(`/sast/projects/${project.id}/profile`, { method: "PATCH", body: JSON.stringify({ quality_gate: profile.quality_gate }) })); setMessage("项目级 SAST 门禁已保存。"); }
    catch (error) { setMessage(`门禁保存失败：${errorMessage(error)}`); }
  }
  return <details className="advanced-details governance-advanced-details"><summary>异步任务与 CI 质量门禁（服务器部署可选）</summary><div className="advanced-details-body"><section className="content-grid"><div className="panel full"><div className="panel-header"><h2>后台扫描任务</h2><span>仅在需要排队、Worker 或失败重试时使用</span></div><div className="filter-grid"><label className="wide-field">源码路径<input value={sourcePath} onChange={(event) => setSourcePath(event.target.value)} /></label><button className="primary-action" onClick={() => void queue()} disabled={!sourcePath.trim()}>创建后台任务</button><button className="secondary-action" onClick={() => void load()}>刷新状态</button></div><p>服务器常驻 Worker：<code>python scripts\sast_worker.py --max-jobs 0 --concurrency 1</code>。本地日常扫描不需要使用这里。</p>{jobs.length ? <table><thead><tr><th>状态</th><th>阶段 / 进度</th><th>尝试次数</th><th>操作</th></tr></thead><tbody>{jobs.map((job) => <tr key={job.id}><td>{scanStatusLabel(job.status)}<span className="cell-subtext">{formatDateTime(job.created_at)}</span></td><td>{scanStageLabel(job.stage)}<span className="cell-subtext">{job.progress}% {job.error ? `· ${job.error}` : ""}</span></td><td>{job.attempt}</td><td>{job.status === "queued" ? <><button className="secondary-action" onClick={() => void run(job)}>立即执行此任务</button><button className="secondary-action" onClick={() => void changeJob(job, "cancel")}>取消</button></> : job.status === "failed" || job.status === "cancelled" ? <button className="secondary-action" onClick={() => void changeJob(job, "retry")}>重新排队</button> : "-"}</td></tr>)}</tbody></table> : <div className="empty-project">没有后台 SAST 任务；普通扫描无需创建任务。</div>}</div><div className="panel full"><div className="panel-header"><h2>CI 发布门禁</h2><span>用于决定代码流水线是否允许继续发布，不影响本地查看扫描结果</span></div><div className="filter-grid"><label>阻断等级<select value={profile?.quality_gate.threshold ?? "high"} disabled={!profile} onChange={(event) => setProfile((value) => value ? { ...value, quality_gate: { ...value.quality_gate, threshold: event.target.value as SastQualityGate["threshold"] } } : value)}>{(["critical", "high", "medium", "low", "info", "none"] as const).map((item) => <option value={item} key={item}>{severityLabel(item)}</option>)}</select></label><label>适用分支（glob）<input value={profile?.quality_gate.branch_patterns.join(",") ?? "*"} disabled={!profile} onChange={(event) => setProfile((value) => value ? { ...value, quality_gate: { ...value.quality_gate, branch_patterns: event.target.value.split(",").map((item) => item.trim()).filter(Boolean) } } : value)} /></label><label>不参与阻断的规则 ID<input value={profile?.quality_gate.excluded_rule_ids.join(",") ?? ""} disabled={!profile} onChange={(event) => setProfile((value) => value ? { ...value, quality_gate: { ...value.quality_gate, excluded_rule_ids: event.target.value.split(",").map((item) => item.trim()).filter(Boolean) } } : value)} /></label><label className="inline-check"><input type="checkbox" checked={profile?.quality_gate.enabled ?? true} onChange={(event) => setProfile((value) => value ? { ...value, quality_gate: { ...value.quality_gate, enabled: event.target.checked } } : value)} />启用 CI 门禁</label><label className="inline-check"><input type="checkbox" checked={profile?.quality_gate.block_new_only ?? false} onChange={(event) => setProfile((value) => value ? { ...value, quality_gate: { ...value.quality_gate, block_new_only: event.target.checked } } : value)} />只阻断本次新增问题</label><button className="secondary-action" disabled={!profile} onClick={() => void saveGate()}>保存门禁配置</button></div>{message ? <div className="empty-project">{message}</div> : null}</div></section></div></details>;
}

function SastSemanticDelivery({ project }: { project: Project }) {
  const [profile, setProfile] = useState<SastProfile | null>(null);
  const [packs, setPacks] = useState<SastSemgrepRule[]>([]);
  const [report, setReport] = useState<SastReport | null>(null);
  const [message, setMessage] = useState("");
  const [draft, setDraft] = useState({ name: "Project semantic rule pack", status: "draft" as "draft" | "published", content: "rules:\n  - id: project.example.dangerous-eval\n    languages: [python]\n    severity: WARNING\n    message: Review dynamic evaluation.\n    pattern: eval(...)\n" });

  useEffect(() => { void load(); }, [project.id]);

  async function load() {
    const [nextProfile, packResult, nextReport] = await Promise.all([
      request<SastProfile>(`/sast/projects/${project.id}/profile`).catch(() => null),
      request<{ semgrep_rules: SastSemgrepRule[] }>(`/sast/projects/${project.id}/semgrep-rules`).catch(() => ({ semgrep_rules: [] })),
      request<SastReport>(`/sast/projects/${project.id}/report`).catch(() => null),
    ]);
    setProfile(nextProfile); setPacks(packResult.semgrep_rules ?? []); setReport(nextReport);
  }

  async function saveGitProfile() {
    if (!profile) return;
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/profile`, { method: "PATCH", body: JSON.stringify({ git_baseline_ref: profile.git_baseline_ref, scan_git_history_secrets: profile.scan_git_history_secrets, changed_files_only: profile.changed_files_only }) });
      setProfile(saved); setMessage("Git 基线与历史密钥扫描配置已保存。");
    } catch (error) { setMessage(`保存失败：${errorMessage(error)}`); }
  }

  async function validatePack() {
    try {
      const result = await request<{ yaml: { rule_count: number; sha256: string } }>("/sast/semgrep-rules/validate", { method: "POST", body: JSON.stringify(draft) });
      setMessage(`YAML 结构有效：${result.yaml.rule_count} 条规则，校验值 ${result.yaml.sha256.slice(0, 12)}。`);
    } catch (error) { setMessage(`YAML 校验失败：${errorMessage(error)}`); }
  }

  async function savePack() {
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/semgrep-rules`, { method: "POST", body: JSON.stringify(draft) });
      setProfile(saved); setPacks(saved.semgrep_rules ?? []); setMessage(draft.status === "draft" ? "YAML 规则包已保存为草稿；须预检并发布后才会进入扫描。" : "YAML 规则包已发布；下次 Semgrep 运行会从 D 盘离线目录 materialize 后执行。");
    } catch (error) { setMessage(`保存失败：${errorMessage(error)}`); }
  }

  async function togglePack(pack: SastSemgrepRule) {
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/semgrep-rules/${pack.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !pack.enabled }) });
      setProfile(saved); setPacks(saved.semgrep_rules ?? []);
    } catch (error) { setMessage(`更新失败：${errorMessage(error)}`); }
  }

  async function refreshReport() {
    try { setReport(await request<SastReport>(`/sast/projects/${project.id}/report`)); setMessage("已刷新 SAST 趋势、Git 基线和质量门禁。 "); }
    catch (error) { setMessage(`尚无已完成扫描报告：${errorMessage(error)}`); }
  }

  return <details className="advanced-details governance-advanced-details" open><summary>SAST 语义分析、Git 基线与交付门禁</summary><div className="advanced-details-body"><section className="content-grid"><div className="panel full"><div className="panel-header"><h2>受限语义分析</h2><span>Python AST + 直接本地跨函数数据流；JS/TS 为保守本地数据流</span></div><p>覆盖 SQL、命令执行、SSRF、路径穿越和不安全反序列化的 Source → Sink → Sanitizer 检查。结果是可复核的静态线索，不等同于全程序可达性或可利用性证明。</p><div className="filter-grid"><label>Git 基线 revision<input value={profile?.git_baseline_ref ?? ""} placeholder="例如 origin/main 或 HEAD~1" onChange={(event) => setProfile((value) => value ? { ...value, git_baseline_ref: event.target.value } : value)} /></label><label className="inline-check"><input type="checkbox" checked={profile?.scan_git_history_secrets ?? true} onChange={(event) => setProfile((value) => value ? { ...value, scan_git_history_secrets: event.target.checked } : value)} />扫描 Git 历史中的密钥标识（仅保存路径）</label><label className="inline-check"><input type="checkbox" checked={profile?.changed_files_only ?? false} disabled={!profile?.git_baseline_ref} onChange={(event) => setProfile((value) => value ? { ...value, changed_files_only: event.target.checked } : value)} />仅扫描基线差异文件</label><button className="secondary-action" disabled={!profile} onClick={() => void saveGitProfile()}>保存基线配置</button><button className="secondary-action" onClick={() => void refreshReport()}>刷新报告</button></div>{message ? <div className="empty-project">{message}</div> : null}</div><div className="panel"><div className="panel-header"><h2>质量门禁</h2><span>{report?.quality_gate.status ?? "等待扫描"}</span></div><div className="kv-list"><div><span>阈值</span><strong>{report?.quality_gate.threshold ?? "high"}</strong></div><div><span>阻断 Finding</span><strong>{report?.quality_gate.blocking_finding_count ?? 0}</strong></div><div><span>本次扫描</span><strong>{report?.summary.finding_count ?? 0}</strong></div></div></div><div className="panel"><div className="panel-header"><h2>Git 证据</h2><span>{report?.git.available ? "已关联" : "等待 Git 项目扫描"}</span></div><div className="kv-list"><div><span>基线</span><strong>{report?.git.baseline_ref ?? "未设置"}</strong></div><div><span>差异文件</span><strong>{report?.git.changed_files?.length ?? 0}</strong></div><div><span>历史密钥路径</span><strong>{report?.git.history_secret_count ?? report?.git.history_secret_files?.length ?? 0}</strong></div></div></div><div className="panel full"><div className="panel-header"><h2>项目 Semgrep YAML 规则包</h2><span>草稿、真实引擎预检、发布、启停和离线 materialization 均已接入</span></div><div className="filter-grid"><label>规则包名称<input value={draft.name} onChange={(event) => setDraft((value) => ({ ...value, name: event.target.value }))} /></label><label>保存状态<select value={draft.status} onChange={(event) => setDraft((value) => ({ ...value, status: event.target.value as "draft" | "published" }))}><option value="draft">草稿（不扫描）</option><option value="published">直接发布</option></select></label><label className="wide-field">YAML<textarea value={draft.content} onChange={(event) => setDraft((value) => ({ ...value, content: event.target.value }))} rows={9} /></label><button className="secondary-action" onClick={() => void validatePack()}>校验 YAML</button><button className="primary-action" onClick={() => void savePack()}>{draft.status === "draft" ? "保存草稿" : "发布规则包"}</button></div>{packs.length ? <table><thead><tr><th>规则包</th><th>规则 ID</th><th>校验值</th><th>状态</th></tr></thead><tbody>{packs.map((pack) => <tr key={pack.id}><td>{pack.name}<span className="cell-subtext">v{pack.version}</span></td><td>{pack.rule_ids.join(", ")}</td><td>{pack.sha256.slice(0, 16)}</td><td><button className="secondary-action" onClick={() => void togglePack(pack)}>{pack.enabled ? "停用" : "启用"}</button></td></tr>)}</tbody></table> : <div className="empty-project">尚未添加项目 YAML 规则包；默认离线规则包仍会参与 Semgrep 扫描。</div>}</div><div className="panel full"><div className="panel-header"><h2>跨模块验证建议</h2><span>只生成建议，不会自动发送请求或执行沙箱命令</span></div>{report?.validation_suggestions.length ? <ul>{report.validation_suggestions.map((item) => <li key={item.finding_id}><strong>{item.recommended_module}</strong> · {item.next_step}</li>)}</ul> : <div className="empty-project">执行一次 SAST 后，高风险 Source/Sink 发现会在这里给出人工确认后的 DAST 或 SANDBOX 下一步。</div>}</div></section></div></details>;
}

function SastRuleManagement({ project }: { project: Project }) {
  const [profile, setProfile] = useState<SastProfile | null>(null);
  const [health, setHealth] = useState<SastToolHealth | null>(null);
  const [history, setHistory] = useState<SastScanHistoryItem[]>([]);
  const [diff, setDiff] = useState<SastScanDiff | null>(null);
  const [message, setMessage] = useState("");
  const [validation, setValidation] = useState<{ valid: boolean; test_sample_matched: boolean | null; message: string } | null>(null);
  const [draft, setDraft] = useState({ rule_id: "CUSTOM.PROJECT.PATTERN", title: "", severity: "medium" as Severity, category: "custom", pattern: "", file_extensions: ".py,.ts", description: "", remediation: "", test_sample: "" });

  useEffect(() => { void load(); }, [project.id]);

  async function load() {
    const [nextProfile, nextHealth, nextHistory, nextDiff] = await Promise.all([
      request<SastProfile>(`/sast/projects/${project.id}/profile`).catch(() => null),
      request<SastToolHealth>("/sast/tool-health").catch(() => null),
      request<SastScanHistoryItem[]>(`/sast/projects/${project.id}/scan-history`).catch(() => []),
      request<SastScanDiff>(`/sast/projects/${project.id}/scan-diff`).catch(() => null),
    ]);
    setProfile(nextProfile); setHealth(nextHealth); setHistory(nextHistory); setDiff(nextDiff);
  }

  async function saveProfile() {
    if (!profile) return;
    try {
      setProfile(await request<SastProfile>(`/sast/projects/${project.id}/profile`, { method: "PATCH", body: JSON.stringify(profile) }));
      setMessage("扫描配置已保存；版本将在下一次快照中可追溯。");
    } catch (error) { setMessage(`保存失败：${errorMessage(error)}`); }
  }

  function rulePayload() {
    return { ...draft, file_extensions: draft.file_extensions.split(",").map((item) => item.trim()).filter(Boolean) };
  }

  async function validateRule() {
    try {
      const result = await request<{ valid: boolean; test_sample_matched: boolean | null; message: string }>("/sast/rules/validate", { method: "POST", body: JSON.stringify(rulePayload()) });
      setValidation(result); setMessage(result.message);
    } catch (error) { setValidation(null); setMessage(`规则无效：${errorMessage(error)}`); }
  }

  async function createRule() {
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/rules`, { method: "POST", body: JSON.stringify(rulePayload()) });
      setProfile(saved); setValidation(null); setDraft({ rule_id: "CUSTOM.PROJECT.PATTERN", title: "", severity: "medium", category: "custom", pattern: "", file_extensions: ".py,.ts", description: "", remediation: "", test_sample: "" });
      setMessage("项目自定义规则已保存；下一次本地规则扫描会实际执行它。");
    } catch (error) { setMessage(`创建失败：${errorMessage(error)}`); }
  }

  async function toggleRule(rule: SastCustomRule) {
    try {
      setProfile(await request<SastProfile>(`/sast/projects/${project.id}/rules/${rule.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !rule.enabled }) }));
    } catch (error) { setMessage(`更新失败：${errorMessage(error)}`); }
  }

  async function downloadCiConfig() {
    try {
      const config = await request<Record<string, unknown>>(`/sast/projects/${project.id}/ci-config`);
      const url = URL.createObjectURL(new Blob([JSON.stringify(config, null, 2)], { type: "application/json" }));
      const link = document.createElement("a"); link.href = url; link.download = `${safeFilename(project.name)}-sast-ci-config.json`; link.click(); URL.revokeObjectURL(url);
      setMessage("CI 配置已导出；离线缓存目录仅使用 D 盘 artifacts/sast-offline。");
    } catch (error) { setMessage(`导出失败：${errorMessage(error)}`); }
  }

  return <details className="advanced-details governance-advanced-details"><summary>SAST 规则、离线 CI 与引擎治理</summary><div className="advanced-details-body"><section className="content-grid"><div className="panel full"><div className="panel-header"><h2>扫描配置与规则版本</h2><span>{message || `配置 v${profile?.profile_version ?? "-"} · 本地规则包 ${profile?.rule_pack_version ?? "-"}`}</span></div><div className="filter-grid"><label>Semgrep 规则包 / 本地配置<input value={profile?.semgrep_config ?? "builtin/offline-default.yml"} disabled={!profile} onChange={(event) => setProfile((value) => value ? { ...value, semgrep_config: event.target.value } : value)} /></label><label className="inline-check"><input type="checkbox" checked={profile?.semgrep_enabled ?? false} disabled={!profile} onChange={(event) => setProfile((value) => value ? { ...value, semgrep_enabled: event.target.checked } : value)} />启用 Semgrep</label><label className="inline-check"><input type="checkbox" checked={profile?.include_local_rules ?? false} disabled={!profile} onChange={(event) => setProfile((value) => value ? { ...value, include_local_rules: event.target.checked } : value)} />启用本地规则</label><label className="inline-check"><input type="checkbox" checked={profile?.clear_previous ?? true} disabled={!profile} onChange={(event) => setProfile((value) => value ? { ...value, clear_previous: event.target.checked } : value)} />新扫描关闭旧活动 Finding</label><button className="secondary-action" disabled={!profile} onClick={() => void saveProfile()}>保存</button><button className="secondary-action" onClick={() => void downloadCiConfig()}>导出 CI 配置</button></div></div><div className="panel"><div className="panel-header"><h2>固定版 Semgrep</h2><span>{health?.can_run_semgrep ? "可用" : "离线降级"}</span></div><div className="kv-list"><div><span>CLI</span><strong>{health?.semgrep_cli.version ?? "未检测到"}</strong></div><div><span>Docker 镜像</span><strong>{health?.docker_image.image ?? "-"}</strong></div><div><span>镜像状态</span><strong>{health?.docker_image.available ? "本地已准备" : "未找到（不会自动下载）"}</strong></div></div></div><div className="panel"><div className="panel-header"><h2>扫描差异</h2><span>{diff?.base_scan_id ? "与上一批次比较" : "等待第二次扫描"}</span></div><div className="kv-list"><div><span>新增</span><strong>{diff?.summary.added ?? 0}</strong></div><div><span>消失</span><strong>{diff?.summary.removed ?? 0}</strong></div><div><span>等级变化</span><strong>{diff?.summary.severity_changed ?? 0}</strong></div><div><span>历史批次</span><strong>{history.length}</strong></div></div></div><div className="panel full"><div className="panel-header"><h2>项目自定义规则</h2><span>正则规则会在本地 SAST 引擎中实际运行；样例仅做命中预览</span></div><div className="filter-grid"><label>规则 ID<input value={draft.rule_id} onChange={(event) => setDraft((value) => ({ ...value, rule_id: event.target.value }))} /></label><label>标题<input value={draft.title} onChange={(event) => setDraft((value) => ({ ...value, title: event.target.value }))} /></label><label>等级<select value={draft.severity} onChange={(event) => setDraft((value) => ({ ...value, severity: event.target.value as Severity }))}>{(["critical", "high", "medium", "low", "info"] as Severity[]).map((item) => <option key={item}>{item}</option>)}</select></label><label>分类<input value={draft.category} onChange={(event) => setDraft((value) => ({ ...value, category: event.target.value }))} /></label><label>文件后缀（逗号分隔）<input value={draft.file_extensions} onChange={(event) => setDraft((value) => ({ ...value, file_extensions: event.target.value }))} /></label><label>正则模式<input value={draft.pattern} onChange={(event) => setDraft((value) => ({ ...value, pattern: event.target.value }))} /></label><label>命中样例<textarea value={draft.test_sample} onChange={(event) => setDraft((value) => ({ ...value, test_sample: event.target.value }))} /></label><label>说明<input value={draft.description} onChange={(event) => setDraft((value) => ({ ...value, description: event.target.value }))} /></label><label>修复建议<input value={draft.remediation} onChange={(event) => setDraft((value) => ({ ...value, remediation: event.target.value }))} /></label><button className="secondary-action" onClick={() => void validateRule()}>校验 / 预览</button><button className="primary-action" onClick={() => void createRule()}>保存并启用</button></div>{validation ? <div className="empty-project">规则有效；样例：{validation.test_sample_matched === null ? "未提供" : validation.test_sample_matched ? "命中" : "未命中"}。</div> : null}{profile?.custom_rules.length ? <table><thead><tr><th>ID / 版本</th><th>规则</th><th>范围</th><th>状态</th></tr></thead><tbody>{profile.custom_rules.map((rule) => <tr key={rule.id}><td>{rule.rule_id}<span className="cell-subtext">v{rule.version}</span></td><td><strong>{rule.title}</strong><span className="cell-subtext">{rule.pattern}</span></td><td>{rule.file_extensions.join(", ") || "所有已扫描文件"}<span className="cell-subtext">{rule.severity} · {rule.category}</span></td><td><button className="secondary-action" onClick={() => void toggleRule(rule)}>{rule.enabled ? "停用" : "启用"}</button></td></tr>)}</tbody></table> : <div className="empty-project">尚未创建项目自定义规则。</div>}</div></section></div></details>;
}

function SastEvidenceGovernance({ project }: { project: Project }) {
  const [profile, setProfile] = useState<SastProfile | null>(null);
  const [history, setHistory] = useState<SastScanHistoryItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [message, setMessage] = useState("");
  const [suppression, setSuppression] = useState({ rule_id: "*", path_pattern: "**", reason: "", expires_at: "" });

  useEffect(() => { void load(); }, [project.id]);

  async function load() {
    const [nextProfile, nextHistory] = await Promise.all([
      request<SastProfile>(`/sast/projects/${project.id}/profile`).catch(() => null),
      request<SastScanHistoryItem[]>(`/sast/projects/${project.id}/scan-history`).catch(() => []),
    ]);
    setProfile(nextProfile);
    setHistory(nextHistory.map((item) => ({
      ...item,
      engine_status: Object.fromEntries(Object.entries(item.engine_status).map(([key, value]) => [key, { ...value, status: toolStatusLabel(value.status), detail: sastEngineDetailLabel(value.detail) }])),
    })));
    setSelectedScanId((current) => current && nextHistory.some((item) => item.scan_task_id === current) ? current : nextHistory[0]?.scan_task_id ?? "");
  }

  async function addSuppression() {
    if (!suppression.reason.trim()) { setMessage("请填写豁免理由。"); return; }
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/suppressions`, { method: "POST", body: JSON.stringify({ ...suppression, expires_at: emptyToNull(suppression.expires_at) }) });
      setProfile(saved);
      setSuppression({ rule_id: "*", path_pattern: "**", reason: "", expires_at: "" });
      setMessage("豁免已保存，将从下一次扫描开始生效并记录抑制数量。");
    } catch (error) { setMessage(`豁免保存失败：${errorMessage(error)}`); }
  }

  async function toggleSuppression(item: SastSuppression) {
    try {
      setProfile(await request<SastProfile>(`/sast/projects/${project.id}/suppressions/${item.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !item.enabled }) }));
      setMessage(item.enabled ? "豁免已停用。" : "豁免已启用。");
    } catch (error) { setMessage(`更新失败：${errorMessage(error)}`); }
  }

  async function downloadReport(format: "json" | "html" | "sarif") {
    if (!selectedScanId) return;
    const endpoint = format === "sarif" ? "sarif" : format === "html" ? "report.html" : "report";
    try {
      const response = await fetch(`${API_BASE}/sast/projects/${project.id}/${endpoint}?scan_task_id=${selectedScanId}`);
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${safeFilename(project.name)}-${selectedScanId.slice(0, 8)}-sast-report.${format}`;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`${format.toUpperCase()} 报告已导出。`);
    } catch (error) { setMessage(`报告导出失败：${errorMessage(error)}`); }
  }

  const selected = history.find((item) => item.scan_task_id === selectedScanId) ?? null;
  return <details className="advanced-details governance-advanced-details"><summary>SAST 豁免、报告与扫描证据</summary><div className="advanced-details-body"><section className="content-grid">
    <div className="panel full"><div className="panel-header"><h2>规则 / 路径豁免</h2><span>{message || "豁免仅影响后续扫描，历史原始批次保持不变"}</span></div><div className="filter-grid"><label>规则 ID 或 *<input value={suppression.rule_id} onChange={(event) => setSuppression((value) => ({ ...value, rule_id: event.target.value }))} /></label><label>相对路径 glob<input value={suppression.path_pattern} onChange={(event) => setSuppression((value) => ({ ...value, path_pattern: event.target.value }))} /></label><label>失效日期（可选）<input type="date" value={suppression.expires_at} onChange={(event) => setSuppression((value) => ({ ...value, expires_at: event.target.value }))} /></label><label>豁免理由<input value={suppression.reason} onChange={(event) => setSuppression((value) => ({ ...value, reason: event.target.value }))} placeholder="例如：测试夹具中的固定假数据" /></label><button className="primary-action" onClick={() => void addSuppression()}>新增豁免</button></div>{profile?.suppressions.length ? <table><thead><tr><th>规则</th><th>路径</th><th>理由</th><th>有效期</th><th>操作</th></tr></thead><tbody>{profile.suppressions.map((item) => <tr key={item.id}><td>{item.rule_id}</td><td>{item.path_pattern}</td><td>{item.reason}</td><td>{item.expires_at ? formatDateTime(item.expires_at) : "永久"}</td><td><button className="secondary-action" onClick={() => void toggleSuppression(item)}>{item.enabled ? "停用" : "启用"}</button></td></tr>)}</tbody></table> : <div className="empty-project">暂无项目级豁免。</div>}</div>
    <div className="panel full"><div className="panel-header"><h2>扫描历史与报告</h2><span>{history.length} 个已完成批次</span></div><div className="filter-grid"><label>报告批次<select value={selectedScanId} onChange={(event) => setSelectedScanId(event.target.value)}><option value="">请选择批次</option>{history.map((item) => <option key={item.scan_task_id} value={item.scan_task_id}>{formatDateTime(item.finished_at ?? item.created_at)} · {item.scan_task_id.slice(0, 8)}</option>)}</select></label><button className="secondary-action" disabled={!selectedScanId} onClick={() => void downloadReport("json")}>导出 JSON</button><button className="secondary-action" disabled={!selectedScanId} onClick={() => void downloadReport("html")}>导出 HTML</button><button className="secondary-action" disabled={!selectedScanId} onClick={() => void downloadReport("sarif")}>导出 SARIF</button><button className="secondary-action" onClick={() => void load()}>刷新历史</button></div>{selected ? <div className="kv-list"><div><span>完成时间</span><strong>{formatDateTime(selected.finished_at ?? selected.created_at)}</strong></div><div><span>Finding / 已抑制</span><strong>{selected.finding_count} / {selected.suppressed_count}</strong></div><div><span>Semgrep</span><strong>{selected.engine_status.semgrep?.status ?? "旧批次未记录"}</strong></div><div><span>Semgrep 说明</span><strong>{selected.engine_status.semgrep?.detail ?? selected.engine_status.semgrep?.config ?? "-"}</strong></div><div><span>本地规则</span><strong>{selected.engine_status.local_rules?.status ?? "旧批次未记录"}</strong></div><div><span>配置版本</span><strong>v{selected.profile.profile_version ?? "-"}</strong></div></div> : <div className="empty-project">执行一次 SAST 后，可按批次查看引擎状态并下载三种报告。</div>}</div>
  </section></div></details>;
}

function GovernanceOverview({ summary, enabledModules, components, findings, validations, evidence, graph, onOpenDast, onOpenSandbox, onUpdateFinding }: { summary: AspmSummary | null; enabledModules: Set<ModuleKey>; components: Component[]; findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; graph: EvidenceGraph | null; onOpenDast: (findingId: string) => void; onOpenSandbox: (findingId: string) => void; onUpdateFinding: (findingId: string, patch: Partial<Pick<Finding, "status">>) => Promise<void> }) {
  const fixedStatuses = new Set<FindingStatus>(["fixed", "closed", "false_positive", "accepted_risk"]);
  const validationFindingIds = new Set(validations.map((item) => item.finding_id).filter(Boolean));
  const validationById = new Map(validations.map((item) => [item.id, item]));
  const evidenceFindingIds = new Set<string>();
  evidence.forEach((item) => {
    if (item.finding_id) evidenceFindingIds.add(item.finding_id);
    if (item.validation_id) {
      const validation = validationById.get(item.validation_id);
      if (validation?.finding_id) evidenceFindingIds.add(validation.finding_id);
    }
  });
  const dynamicallyProvenIds = new Set([...validationFindingIds, ...evidenceFindingIds]);
  const activeFindings = findings.filter((item) => !fixedStatuses.has(item.status));
  const awaitingValidation = activeFindings.filter((item) => !validationFindingIds.has(item.id) && !evidenceFindingIds.has(item.id)).length;
  const dynamicallyValidated = activeFindings.filter((item) => validationFindingIds.has(item.id)).length;
  const runtimeProven = activeFindings.filter((item) => evidenceFindingIds.has(item.id)).length;
  const fixingCount = findings.filter((item) => item.status === "fixing" || item.status === "retest").length;
  const fixedCount = findings.filter((item) => item.status === "fixed" || item.status === "closed").length;
  const priorityFindings = [...activeFindings].sort((a, b) => {
    const aStage = evidenceFindingIds.has(a.id) ? 2 : validationFindingIds.has(a.id) ? 1 : 0;
    const bStage = evidenceFindingIds.has(b.id) ? 2 : validationFindingIds.has(b.id) ? 1 : 0;
    return bStage - aStage || severityRank(b.severity) - severityRank(a.severity);
  }).slice(0, 3);
  const moduleCards = (["sca", "sast", "agent", "dast", "sandbox"] as const).filter((key) => enabledModules.has(key));

  return <div className="governance-view governance-closed-loop">
    <section className="governance-hero panel">
      <div><span className="section-kicker">ASPM 项目安全治理</span><h2>从发现风险到动态证明，再到整改复测</h2><p>总览不只是汇总结果，而是回答每个问题现在走到了哪一步、证据是否充分、下一步由谁处理。</p></div>
      <div className="governance-score"><span>项目风险分</span><strong>{summary?.risk_score ?? 0}</strong><small>分数越高，当前风险越集中</small></div>
    </section>

    <SecurityLifecycle findings={findings.length} awaiting={awaitingValidation} validated={dynamicallyValidated} evidenced={runtimeProven} fixing={fixingCount} fixed={fixedCount} />

    <section className="panel evidence-chain-panel">
      <div className="panel-header"><div><h2>漏洞证据闭环</h2><span>静态发现 → 动态验证 → 运行时取证 → 整改复测</span></div><strong>{dynamicallyProvenIds.size} 条风险已有动态证据</strong></div>
      {priorityFindings.length === 0 ? <div className="empty-project">当前没有待治理风险。重新执行模块后，新发现会进入这里。</div> : <div className="risk-chain-list">{priorityFindings.map((finding) => <RiskEvidenceChainCard key={finding.id} finding={finding} validations={validations} evidence={evidence} graph={graph} canRunDast={enabledModules.has("dast")} canRunSandbox={enabledModules.has("sandbox")} onOpenDast={onOpenDast} onOpenSandbox={onOpenSandbox} onUpdateFinding={onUpdateFinding} />)}</div>}
    </section>

    <section className="governance-two-column">
      <div className="panel">
        <div className="panel-header"><h2>跨模块攻击链</h2><span>{summary?.attack_chains.length ?? 0} 条可信链路</span></div>
        <AttackChainSummary chains={summary?.attack_chains ?? []} />
      </div>
      <div className="panel">
        <div className="panel-header"><h2>已接入模块</h2><span>{moduleCards.length} 个检测与验证模块</span></div>
        <div className="module-result-overview">{moduleCards.map((moduleKey) => <div key={moduleKey}><strong>{MODULE_DISPLAY[moduleKey].name}</strong><span>{moduleOverviewText(moduleKey, components, findings, validations, evidence)}</span></div>)}</div>
      </div>
    </section>

    <section className="knowledge-preview panel">
      <div><BookOpen size={22} /><div><h2>安全知识正在从项目结果中沉淀</h2><p>规则命中、误报结论、动态验证证据和修复经验会形成后续扫描可复用的项目安全上下文。</p></div></div>
      <div className="knowledge-preview-stats"><span><strong>{uniqueValues(findings.map((item) => item.rule_id)).length}</strong> 条规则经验</span><span><strong>{validations.length}</strong> 次动态验证</span><span><strong>{evidence.length}</strong> 份运行证据</span></div>
    </section>
    <details className="advanced-details governance-advanced-details"><summary>查看完整治理闭环、全部攻击链与项目级证据图谱</summary><div className="advanced-details-body"><AspmView summary={summary} findings={findings} validations={validations} evidence={evidence} onUpdateFinding={onUpdateFinding} /><EvidenceGraphPanel graph={graph} /></div></details>
  </div>;
}

function SecurityLifecycle({ findings, awaiting, validated, evidenced, fixing, fixed }: { findings: number; awaiting: number; validated: number; evidenced: number; fixing: number; fixed: number }) {
  const stages = [
    ["多源发现", findings, "SAST / SCA / AGENT"],
    ["等待验证", awaiting, "需要动态证明"],
    ["DAST 验证", validated, "业务运行态结论"],
    ["SANDBOX 取证", evidenced, "隔离运行证据"],
    ["整改 / 复测", fixing, "修复进行中"],
    ["已闭环", fixed, "修复后未再发现"],
  ] as const;
  return <section className="security-lifecycle panel">
    <div className="panel-header"><h2>风险处理流程</h2><span>点击上方模块页可查看各阶段完整结果</span></div>
    <div className="lifecycle-track">{stages.map(([label, value, hint], index) => <React.Fragment key={label}><div className="lifecycle-stage"><span>{index + 1}</span><strong>{value}</strong><b>{label}</b><small>{hint}</small></div>{index < stages.length - 1 ? <ArrowRight className="lifecycle-arrow" size={18} /> : null}</React.Fragment>)}</div>
  </section>;
}

function RiskEvidenceChainCard({ finding, validations, evidence, graph, canRunDast, canRunSandbox, onOpenDast, onOpenSandbox, onUpdateFinding }: { finding: Finding; validations: DastValidation[]; evidence: SandboxEvidence[]; graph: EvidenceGraph | null; canRunDast: boolean; canRunSandbox: boolean; onOpenDast: (findingId: string) => void; onOpenSandbox: (findingId: string) => void; onUpdateFinding: (findingId: string, patch: Partial<Pick<Finding, "status">>) => Promise<void> }) {
  const relatedValidations = validations.filter((item) => item.finding_id === finding.id || (finding.component_id && item.component_id === finding.component_id));
  const validationIds = new Set(relatedValidations.map((item) => item.id));
  const relatedEvidence = evidence.filter((item) => item.finding_id === finding.id || (finding.component_id && item.component_id === finding.component_id) || Boolean(item.validation_id && validationIds.has(item.validation_id)));
  const [evidencePage, setEvidencePage] = useState(1);
  const relatedRecords = [...relatedValidations.map((item) => ({ kind: "validation" as const, item })), ...relatedEvidence.map((item) => ({ kind: "evidence" as const, item }))];
  const evidencePagination = paginate(relatedRecords, evidencePage);
  useEffect(() => { setEvidencePage(1); }, [finding.id, relatedRecords.length]);
  const graphNodes = findingEvidenceNodes(finding.id, graph);
  const conclusion = relatedEvidence.length ? "已有运行时证据" : relatedValidations.length ? "已完成动态验证" : "等待动态验证";
  return <article className="risk-chain-card">
    <div className="risk-chain-heading"><div><span className={`severity ${finding.severity}`}>{severityLabel(finding.severity)}</span><strong>{finding.title}</strong><small>{finding.source} · {finding.file_path ?? "项目级风险"}</small></div><div><span className={`chain-conclusion ${relatedEvidence.length ? "proven" : relatedValidations.length ? "validated" : "waiting"}`}>{conclusion}</span><select value={normalizeFindingStatus(finding.status)} onChange={(event) => void onUpdateFinding(finding.id, { status: event.target.value as FindingStatus })}>{FINDING_WORKFLOW_STATUSES.map((status) => <option key={status} value={status}>{statusLabel(status)}</option>)}</select></div></div>
    <div className="chain-timeline">
      <ChainStep module={finding.source} title="发现风险" detail={finding.evidence ?? finding.rule_id} state="done" />
      <ArrowRight size={16} />
      <ChainStep module="DAST" title={relatedValidations.length ? dastVerdictLabel(relatedValidations[0].verdict) : "等待验证"} detail={relatedValidations[0]?.evidence_summary ?? "需要在运行系统中确认是否可触发"} state={relatedValidations.length ? "done" : "waiting"} />
      <ArrowRight size={16} />
      <ChainStep module="SANDBOX" title={relatedEvidence.length ? "已取得运行证据" : "等待取证"} detail={relatedEvidence[0]?.evidence_summary ?? "必要时在隔离环境中观察行为"} state={relatedEvidence.length ? "done" : "waiting"} />
      <ArrowRight size={16} />
      <ChainStep module="治理" title={statusLabel(normalizeFindingStatus(finding.status))} detail={finding.remediation_note ?? finding.ai_review?.remediation ?? "分配负责人并记录整改结论"} state={finding.status === "fixed" || finding.status === "closed" ? "done" : "waiting"} />
    </div>
    {relatedRecords.length > 0 ? <details className="chain-evidence-details"><summary>展开完整验证与取证详情</summary><div>{evidencePagination.items.map((record) => record.kind === "validation" ? <section key={record.item.id}><strong>DAST · {dastVerdictLabel(record.item.verdict)}</strong><dl><div><dt>验证目标 / 策略</dt><dd>{record.item.target_url}<br />{record.item.strategy_name ?? "旧记录：未保存策略"}</dd></div><div><dt>检查范围与边界</dt><dd>{record.item.scope_summary ?? "未记录"}<br />{record.item.limitations ?? "未记录"}</dd></div><div><dt>请求 / 响应</dt><dd>{record.item.request_summary ?? "未记录"}<br />{record.item.response_summary ?? "未记录"}</dd></div><div><dt>复现与修复</dt><dd>{record.item.reproduction_steps ?? "未记录"}<br />{record.item.remediation_hint ?? "未记录"}</dd></div></dl></section> : <section key={record.item.id}><strong>SANDBOX · 隔离运行记录</strong><dl><div><dt>命令 / 策略</dt><dd>{record.item.run_command}<br />{record.item.strategy_name ?? "旧记录：隔离执行"}</dd></div><div><dt>取证目的与边界</dt><dd>{record.item.purpose ?? "未记录"}<br />{record.item.limitations ?? "未记录"}</dd></div><div><dt>隔离策略</dt><dd>网络：{record.item.network_policy}；文件：{record.item.filesystem_policy}</dd></div><div><dt>观察结论</dt><dd>{record.item.evidence_summary ?? "未记录"}</dd></div><div><dt>账本</dt><dd>文件 {record.item.observed_files.length} 条；网络 {record.item.observed_network.length} 条；进程 {record.item.observed_processes.length} 条；工具调用 {record.item.observed_tool_calls.length} 条</dd></div></dl></section>)}<Pagination page={evidencePagination.page} pageCount={evidencePagination.pageCount} total={relatedRecords.length} onPageChange={setEvidencePage} /></div></details> : null}
    <div className="risk-chain-footer"><div className="risk-chain-meta"><span>显式关系节点：{graphNodes.length}</span><span>DAST 记录：{relatedValidations.length}</span><span>SANDBOX 证据：{relatedEvidence.length}</span></div><div className="risk-chain-actions">{relatedValidations.length === 0 ? <button className="secondary-action" disabled={!canRunDast} onClick={() => onOpenDast(finding.id)}>{canRunDast ? "发起 DAST 验证" : "DAST 未接入"}</button> : relatedEvidence.length === 0 ? <button className="secondary-action" disabled={!canRunSandbox} onClick={() => onOpenSandbox(finding.id)}>{canRunSandbox ? "进入 SANDBOX 取证" : "SANDBOX 未接入"}</button> : <button className="secondary-action" onClick={() => onOpenSandbox(finding.id)}>查看关联证据</button>}</div></div>
  </article>;
}

function ChainStep({ module, title, detail, state }: { module: string; title: string; detail: string; state: "done" | "waiting" }) {
  return <div className={`chain-step ${state}`}><span>{module}</span><strong>{title}</strong><small title={detail}>{truncateText(detail, 70)}</small></div>;
}

function AttackChainSummary({ chains }: { chains: AttackChain[] }) {
  const [page, setPage] = useState(1);
  if (chains.length === 0) return <div className="empty-project">暂未形成可信攻击链。只有风险与 DAST 或 SANDBOX 存在显式关系后才会生成。</div>;
  const pagination = paginate(chains, page);
  return <div className="attack-chain-list">{pagination.items.map((chain) => <details key={chain.id}><summary><span className={`severity ${chain.severity}`}>{severityLabel(chain.severity)}</span><strong>{chain.name}</strong><small>{chain.modules.join(" → ")} · 可信度 {chain.confidence}%</small></summary><ol>{chain.steps.map((step) => <li key={`${chain.id}-${step.node_id ?? step.title}`}><b>{step.module}</b><span>{step.title}</span><small>{step.evidence ?? "无证据摘要"}</small></li>)}</ol><p>{chain.recommended_action}</p></details>)}<Pagination page={pagination.page} pageCount={pagination.pageCount} total={chains.length} onPageChange={setPage} /></div>;
}

function KnowledgeHubView({ project, findings, validations, evidence, summary }: { project: Project | null; findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; summary: AspmSummary | null }) {
  if (!project) return <div className="panel empty-project">请先选择项目，再查看该项目沉淀的安全知识。</div>;
  const projectId = project.id;
  const [activeTab, setActiveTab] = useState<"overview" | "candidates" | "enterprise" | "library" | "effects">("overview");
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [dastLibrary, setDastLibrary] = useState<{ total: number; builtin: Record<string, unknown>[]; learned: Record<string, unknown>[] } | null>(null);
  const [knowledgeWorkspace, setKnowledgeWorkspace] = useState<KnowledgeWorkspace | null>(null);
  const [knowledgeLoading, setKnowledgeLoading] = useState(false);
  const [knowledgeMessage, setKnowledgeMessage] = useState("");
  const [knowledgeBusyId, setKnowledgeBusyId] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState("");
  const [candidatePage, setCandidatePage] = useState(1);

  const rules = uniqueValues(findings.map((item) => item.rule_id));
  const categories = uniqueValues(findings.map((item) => item.ai_review?.category ?? "未分类"));
  const falsePositiveCount = findings.filter((item) => item.status === "false_positive").length;
  const fixedCount = findings.filter((item) => item.status === "fixed" || item.status === "closed").length;
  const confirmedCount = findings.filter((item) => ["confirmed", "fixing", "retest", "fixed", "closed"].includes(item.status)).length;
  const linkedValidationCount = validations.filter((item) => item.finding_id || item.component_id).length;
  const linkedEvidenceCount = evidence.filter((item) => item.finding_id || item.component_id || item.validation_id).length;
  const validatedFindingIds = new Set(validations.flatMap((item) => item.finding_id ? [item.finding_id] : []));
  const validationIds = new Set(validations.map((item) => item.id));
  const evidenceBackedFindingIds = new Set(evidence.flatMap((item) => item.finding_id ? [item.finding_id] : []));
  evidence.forEach((item) => {
    if (!item.validation_id || !validationIds.has(item.validation_id)) return;
    const linked = validations.find((validation) => validation.id === item.validation_id);
    if (linked?.finding_id) evidenceBackedFindingIds.add(linked.finding_id);
  });

  const knowledgeCandidates = findings.map((finding) => {
    const findingValidations = validations.filter((item) => item.finding_id === finding.id);
    const findingValidationIds = new Set(findingValidations.map((item) => item.id));
    const findingEvidence = evidence.filter((item) => item.finding_id === finding.id || Boolean(item.validation_id && findingValidationIds.has(item.validation_id)));
    const type = finding.status === "false_positive" ? "误报经验" : finding.status === "fixed" || finding.status === "closed" ? "修复方案" : findingValidations.length ? "验证剧本" : "漏洞模式";
    const state = finding.status === "false_positive" ? "待审核" : finding.status === "fixed" || finding.status === "closed" ? "可沉淀" : findingEvidence.length ? "证据就绪" : findingValidations.length ? "验证中" : "待验证";
    const tone = state === "可沉淀" || state === "证据就绪" ? "ready" : state === "待审核" ? "review" : "collecting";
    return { finding, type, state, tone, validationCount: findingValidations.length, evidenceCount: findingEvidence.length };
  }).sort((left, right) => severityRank(right.finding.severity) - severityRank(left.finding.severity));
  const candidatePagination = paginate(knowledgeCandidates, candidatePage, 8);
  const reusableCandidateCount = knowledgeCandidates.filter((item) => item.tone === "ready").length;
  const entryByFinding = new Map((knowledgeWorkspace?.entries ?? []).map((entry) => [entry.source_finding_id, entry]));
  const publishedProjectEntries = (knowledgeWorkspace?.entries ?? []).filter((entry) => entry.status === "published");
  const recommendationCount = knowledgeWorkspace?.recommendations.length ?? 0;
  const dynamicCoverage = findings.length ? Math.round((validatedFindingIds.size / findings.length) * 100) : 0;
  const evidenceCoverage = findings.length ? Math.round((evidenceBackedFindingIds.size / findings.length) * 100) : 0;
  const governanceCoverage = findings.length ? Math.round(((fixedCount + falsePositiveCount) / findings.length) * 100) : 0;
  const ruleStats = rules.map((rule) => ({ rule, count: findings.filter((item) => item.rule_id === rule).length, categories: uniqueValues(findings.filter((item) => item.rule_id === rule).map((item) => item.ai_review?.category ?? "未分类")) })).sort((a, b) => b.count - a.count);
  const tabs = [
    ["overview", "知识总览", "组织事实与闭环"],
    ["candidates", "知识候选", (knowledgeWorkspace?.status_counts.pending_review ?? 0) + " 条待审核"],
    ["enterprise", "企业知识", recommendationCount + " 条跨项目推荐"],
    ["library", "规则与 Skill", rules.length + " 条项目规则"],
    ["effects", "效果追踪", "观察复用与治理"],
  ] as const;
  const lifecycle = [
    ["01", "业务上下文", project.name, "仓库、源码、运行地址与责任人限定知识适用范围"],
    ["02", "多源发现", findings.length + " 条", "SCA、SAST 与 AGENT 结果形成事实入口"],
    ["03", "动态证明", linkedValidationCount + " 条", "DAST 目标、策略、裁决与复现过程"],
    ["04", "证据固化", linkedEvidenceCount + " 份", "SANDBOX 隔离策略和固定探针证据"],
    ["05", "治理沉淀", fixedCount + falsePositiveCount + " 条", "修复、关闭与误报结论进入候选"],
  ] as const;

  useEffect(() => { setCandidatePage(1); }, [activeTab, findings.length]);
  useEffect(() => {
    let cancelled = false;
    setDastLibrary(null);
    void request<{ total: number; builtin: Record<string, unknown>[]; learned: Record<string, unknown>[] }>(("/dast/projects/" + projectId + "/strategy-library"))
      .then((value) => { if (!cancelled) setDastLibrary(value); })
      .catch(() => { if (!cancelled) setDastLibrary(null); });
    return () => { cancelled = true; };
  }, [projectId]);

  useEffect(() => {
    let cancelled = false;
    setReport(null);
    setReportError("");
    setCandidatePage(1);
    setKnowledgeWorkspace(null);
    setKnowledgeMessage("");
    setKnowledgeLoading(true);
    void request<KnowledgeWorkspace>("/knowledge/projects/" + projectId + "/workspace")
      .then((value) => { if (!cancelled) setKnowledgeWorkspace(value); })
      .catch((error) => { if (!cancelled) setKnowledgeMessage("知识工作区加载失败：" + errorMessage(error)); })
      .finally(() => { if (!cancelled) setKnowledgeLoading(false); });
    return () => { cancelled = true; };
  }, [projectId]);

  async function refreshKnowledgeWorkspace(message = "") {
    const value = await request<KnowledgeWorkspace>("/knowledge/projects/" + projectId + "/workspace");
    setKnowledgeWorkspace(value);
    setKnowledgeMessage(message);
  }

  async function submitKnowledgeCandidate(finding: Finding) {
    setKnowledgeBusyId(finding.id);
    setKnowledgeMessage("");
    try {
      await request<KnowledgeEntry>("/knowledge/projects/" + projectId + "/candidates/" + finding.id, {
        method: "POST",
        body: JSON.stringify({ submitted_by: "security-operator" }),
      });
      await refreshKnowledgeWorkspace("候选已提交审核，来源 Finding 和证据引用已固化。");
    } catch (error) {
      setKnowledgeMessage("提交失败：" + errorMessage(error));
    } finally {
      setKnowledgeBusyId(null);
    }
  }

  async function reviewKnowledgeEntry(entry: KnowledgeEntry, decision: "publish" | "reject") {
    setKnowledgeBusyId(entry.id);
    setKnowledgeMessage("");
    try {
      await request<KnowledgeEntry>("/knowledge/entries/" + entry.id + "/review", {
        method: "POST",
        body: JSON.stringify({ decision, reviewer: "security-reviewer", note: decision === "publish" ? "证据与适用范围复核通过" : "退回补充证据或适用范围" }),
      });
      await refreshKnowledgeWorkspace(decision === "publish" ? "知识已发布到企业库，并可向同租户其他项目推荐。" : "候选已退回，可补充证据后重新提交。");
    } catch (error) {
      setKnowledgeMessage("审核失败：" + errorMessage(error));
    } finally {
      setKnowledgeBusyId(null);
    }
  }

  async function rollbackKnowledgeEntry(entry: KnowledgeEntry) {
    setKnowledgeBusyId(entry.id);
    setKnowledgeMessage("");
    try {
      const versions = await request<Array<{ version: number; change_action: string }>>("/knowledge/entries/" + entry.id + "/versions");
      const target = versions.find((item) => item.version < entry.version);
      if (!target) throw new Error("没有可回滚的历史版本");
      await request<KnowledgeEntry>("/knowledge/entries/" + entry.id + "/rollback", {
        method: "POST",
        body: JSON.stringify({ target_version: target.version, reviewer: "security-reviewer", note: "从知识中枢回滚到上一版本" }),
      });
      await refreshKnowledgeWorkspace("已恢复历史内容并生成新的知识版本，历史记录未被覆盖。");
    } catch (error) {
      setKnowledgeMessage("回滚失败：" + errorMessage(error));
    } finally {
      setKnowledgeBusyId(null);
    }
  }

  async function generateReportPreview() {
    setReportLoading(true);
    setReportError("");
    try {
      setReport(await request<SecurityReport>("/aspm/projects/" + projectId + "/report"));
    } catch (error) {
      console.error(error);
      setReportError("报告生成失败：" + errorMessage(error));
    } finally {
      setReportLoading(false);
    }
  }

  return <section className="knowledge-command-center">
    <section className="knowledge-command-hero">
      <div className="knowledge-command-copy">
        <span className="knowledge-command-kicker"><BookOpen size={15} /> SECURITY KNOWLEDGE CORE</span>
        <h2>把项目事实组织成可复用、可追溯的安全知识</h2>
        <p>项目事实先在当前项目形成候选，经过证据门槛与人工审核后发布到租户级企业知识库；其他项目只有命中相同规则或风险分类时才会收到推荐。</p>
        <div className="knowledge-command-facts"><span><ShieldCheck size={15} />当前项目：{project.name}</span><span><GitBranch size={15} />默认分支：{project.default_branch}</span><span><Lock size={15} />候选项目隔离 · 发布后租户共享</span></div>
      </div>
        <div className="knowledge-orbit" aria-label="安全知识中枢数据来源">
        <span className="orbit-node orbit-code"><Bug size={16} />规则</span>
        <span className="orbit-node orbit-supply"><Boxes size={16} />供应链</span>
        <span className="orbit-node orbit-runtime"><FlaskConical size={16} />证据</span>
        <span className="orbit-node orbit-agent"><Network size={16} />Agent</span>
        <div className="orbit-core"><BookOpen size={28} /><strong>{knowledgeWorkspace?.enterprise_published_count ?? 0}</strong><small>已发布知识</small></div>
      </div>
    </section>

    {knowledgeLoading ? <div className="knowledge-notice">正在加载 {project.name} 的知识工作区…</div> : null}
    {knowledgeMessage ? <div className="knowledge-notice active">{knowledgeMessage}</div> : null}

    <nav className="knowledge-tabs" aria-label="安全知识中枢工作区">
      {tabs.map(([key, label, detail]) => <button className={activeTab === key ? "active" : ""} key={key} onClick={() => setActiveTab(key)}><span>{label}</span><small>{detail}</small></button>)}
    </nav>

    {activeTab === "overview" ? <>
      <section className="knowledge-lifecycle">
        <div className="knowledge-section-heading"><div><span>知识形成链路</span><h3>上下文更专 → 多源发现 → 动态证明 → 知识组织</h3></div><strong>所有数字来自当前项目</strong></div>
        <div className="knowledge-lifecycle-track">{lifecycle.map(([index, label, value, description], position) => <React.Fragment key={label}><article><i>{index}</i><span>{label}</span><strong>{value}</strong><p>{description}</p></article>{position < lifecycle.length - 1 ? <ArrowRight size={18} /> : null}</React.Fragment>)}</div>
      </section>

      <section className="knowledge-domain-grid">
        <article className="knowledge-domain-card indigo"><div><Bug size={21} /><span>漏洞与规则知识</span></div><strong>{confirmedCount}</strong><p>已确认、修复中或已关闭的风险，可继续形成漏洞模式与审计规则候选。</p><small>{rules.length} 条规则 · {categories.length} 类风险</small></article>
        <article className="knowledge-domain-card cyan"><div><Activity size={21} /><span>验证剧本</span></div><strong>{dastLibrary?.total ?? 0}</strong><p>保存可审计的验证范围、固定步骤、证据要求与三色裁决条件。</p><small>{dastLibrary?.learned.length ?? 0} 个项目策略经验</small></article>
        <article className="knowledge-domain-card emerald"><div><ShieldCheck size={21} /><span>修复与误报经验</span></div><strong>{fixedCount + falsePositiveCount}</strong><p>治理结论只有绑定原始 Finding 与复测证据后，才能成为后续可复用上下文。</p><small>{fixedCount} 条修复 · {falsePositiveCount} 条误报</small></article>
        <article className="knowledge-domain-card amber"><div><FlaskConical size={21} /><span>运行时事实</span></div><strong>{linkedEvidenceCount}</strong><p>固定探针、隔离策略和运行账本作为知识依据，不将命令成功等同于漏洞成立。</p><small>{linkedValidationCount} 次关联验证</small></article>
      </section>

      <section className="knowledge-overview-grid">
        <article className="knowledge-governance-card">
          <div className="knowledge-section-heading"><div><span>知识治理</span><h3>从事实到发布必须经过四道门</h3></div><ShieldCheck size={26} /></div>
          <div className="knowledge-guardrails">
            <div><i>1</i><span><strong>证据绑定</strong><small>必须关联 Finding、验证、证据或复测记录</small></span></div>
            <div><i>2</i><span><strong>适用范围</strong><small>明确项目、语言、框架、漏洞类型和前置条件</small></span></div>
            <div><i>3</i><span><strong>人工审核</strong><small>AI 只能生成候选，不能自行发布或修改规则</small></span></div>
            <div><i>4</i><span><strong>版本回滚</strong><small>每次应用记录知识版本、命中和最终结论</small></span></div>
          </div>
        </article>
        <article className="knowledge-ready-card">
          <div className="knowledge-section-heading"><div><span>当前准备度</span><h3>{reusableCandidateCount} 条候选具备进一步沉淀条件</h3></div><strong>{knowledgeCandidates.length ? Math.round((reusableCandidateCount / knowledgeCandidates.length) * 100) : 0}%</strong></div>
          <div className="knowledge-ready-meter"><i style={{ width: (knowledgeCandidates.length ? Math.round((reusableCandidateCount / knowledgeCandidates.length) * 100) : 0) + "%" }} /></div>
          <p>“具备条件”仅表示已有动态或运行证据，不代表已经通过知识审核或发布。</p>
          <button className="secondary-action" onClick={() => setActiveTab("candidates")}>查看知识候选 <ArrowRight size={15} /></button>
        </article>
      </section>
    </> : null}

    {activeTab === "candidates" ? <section className="knowledge-workspace">
      <div className="knowledge-section-heading"><div><span>知识候选池</span><h3>提交后进入人工审核，证据不足的候选无法发布</h3></div><strong>{knowledgeCandidates.length} 条项目候选</strong></div>
      <div className="knowledge-candidate-grid">{candidatePagination.items.length ? candidatePagination.items.map(({ finding, type, state, tone, validationCount, evidenceCount }) => {
        const entry = entryByFinding.get(finding.id);
        const persistedTone = entry?.status === "published" ? "ready" : entry?.status === "pending_review" ? "review" : entry?.status === "rejected" ? "collecting" : tone;
        const persistedState = entry?.status === "published" ? `已发布 v${entry.version}` : entry?.status === "pending_review" ? "待人工审核" : entry?.status === "rejected" ? "已退回" : state;
        return <article className="knowledge-candidate-card" key={finding.id}>
          <div className="knowledge-candidate-top"><span className={"knowledge-type " + persistedTone}>{type}</span><span className={"severity " + finding.severity}>{severityLabel(finding.severity)}</span></div>
          <h4>{finding.title}</h4>
          <p>{truncateText(finding.ai_review?.description ?? finding.evidence ?? "尚未形成完整风险说明", 150)}</p>
          <dl><div><dt>来源</dt><dd>{finding.source} · {finding.rule_id}</dd></div><div><dt>证据</dt><dd>{validationCount} 次验证 · {evidenceCount} 份运行证据</dd></div><div><dt>范围</dt><dd>{finding.file_path ?? "项目级知识"}</dd></div>{entry ? <div><dt>版本</dt><dd>v{entry.version} · 提交人 {entry.submitted_by}</dd></div> : null}</dl>
          <footer><span className={"knowledge-state " + persistedTone}>{persistedState}</span><div className="knowledge-candidate-actions">
            {!entry || entry.status === "rejected" ? <button className="secondary-action" disabled={knowledgeBusyId === finding.id} onClick={() => void submitKnowledgeCandidate(finding)}>{knowledgeBusyId === finding.id ? "提交中…" : entry ? "补充后重提" : "提交审核"}</button> : null}
            {entry?.status === "pending_review" ? <><button className="primary-action" title={entry.publish_ready ? "证据门槛已满足" : "需先补充 DAST、SANDBOX 或治理结论"} disabled={!entry.publish_ready || knowledgeBusyId === entry.id} onClick={() => void reviewKnowledgeEntry(entry, "publish")}>审核发布</button><button className="secondary-action" disabled={knowledgeBusyId === entry.id} onClick={() => void reviewKnowledgeEntry(entry, "reject")}>退回</button></> : null}
            {entry?.status === "published" ? <button className="secondary-action" disabled={knowledgeBusyId === entry.id || entry.version <= 1} onClick={() => void rollbackKnowledgeEntry(entry)}>回滚上一版</button> : null}
          </div></footer>
        </article>;
      }) : <div className="knowledge-empty">执行扫描并完成复核后，符合条件的项目经验会出现在这里。</div>}</div>
      <Pagination page={candidatePagination.page} pageCount={candidatePagination.pageCount} total={knowledgeCandidates.length} onPageChange={setCandidatePage} />
    </section> : null}

    {activeTab === "enterprise" ? <section className="knowledge-enterprise-workspace">
      <section className="knowledge-enterprise-summary">
        <div><span>企业知识库</span><strong>{knowledgeWorkspace?.enterprise_published_count ?? 0}</strong><small>同一租户内已审核发布</small></div>
        <div><span>本项目贡献</span><strong>{publishedProjectEntries.length}</strong><small>来源可追溯到当前项目</small></div>
        <div><span>跨项目推荐</span><strong>{recommendationCount}</strong><small>仅规则或风险分类匹配</small></div>
      </section>
      <section className="knowledge-enterprise-panel">
        <div className="knowledge-section-heading"><div><span>当前项目已发布</span><h3>经人工审核、可被其他项目复用的知识</h3></div><strong>{publishedProjectEntries.length} 条</strong></div>
        <div className="knowledge-enterprise-grid">{publishedProjectEntries.length ? publishedProjectEntries.map((entry) => <KnowledgeEntryCard key={entry.id} entry={entry} />) : <div className="knowledge-empty">当前项目尚未发布企业知识。先在“知识候选”中提交并完成审核。</div>}</div>
      </section>
      <section className="knowledge-enterprise-panel">
        <div className="knowledge-section-heading"><div><span>来自其他项目的推荐</span><h3>复用经验，但不自动修改当前项目规则</h3></div><strong>{recommendationCount} 条</strong></div>
        <div className="knowledge-enterprise-grid">{knowledgeWorkspace?.recommendations.length ? knowledgeWorkspace.recommendations.map((item) => <article className="knowledge-recommendation-card" key={item.entry.id}><div><span>{item.entry.source_project_name}</span><strong>{item.score}% 匹配</strong></div><h4>{item.entry.title}</h4><p>{truncateText(item.entry.summary, 180)}</p><small>{item.reasons.join(" · ")} · 命中 {item.matched_finding_ids.length} 条当前 Finding</small><footer><span>{item.entry.source_module} · {item.entry.rule_id}</span><b>v{item.entry.version}</b></footer></article>) : <div className="knowledge-empty">暂时没有与当前项目规则或风险分类匹配的已发布知识。</div>}</div>
      </section>
    </section> : null}

    {activeTab === "library" ? <section className="knowledge-library-workspace">
      <section className="knowledge-library-panel">
        <div className="knowledge-section-heading"><div><span>规则资产</span><h3>当前项目已出现的检测规则与风险分类</h3></div><strong>{rules.length} 条</strong></div>
        <div className="knowledge-rule-list">{ruleStats.slice(0, 12).map((item) => <article key={item.rule}><div><Bug size={16} /><span><strong>{item.rule}</strong><small>{item.categories.join("、")}</small></span></div><b>{item.count} 次命中</b></article>)}{ruleStats.length === 0 ? <div className="knowledge-empty">当前项目还没有规则命中。</div> : null}</div>
      </section>
      <section className="knowledge-library-panel">
        <div className="knowledge-section-heading"><div><span>验证策略库</span><h3>内置剧本与当前项目策略经验</h3></div><strong>{dastLibrary?.total ?? 0} 个</strong></div>
        <div className="knowledge-strategy-list">{dastLibrary?.total ? [...dastLibrary.builtin, ...dastLibrary.learned].slice(0, 12).map((item) => <article key={String(item.id)}><div><Activity size={16} /><span><strong>{String(item.name)}</strong><small>{truncateText(String(item.description ?? item.scope_summary ?? "未记录策略范围"), 90)}</small></span></div><b>{item.source === "deepseek_local" ? "项目经验" : "内置模板"}</b></article>) : <div className="knowledge-empty">当前没有可用的 DAST 策略。</div>}</div>
      </section>
      <section className="knowledge-consumer-map">
        <div className="knowledge-section-heading"><div><span>模块消费关系</span><h3>知识发布后应通过统一版本进入六模块</h3></div><GitBranch size={24} /></div>
        <div>{[["SAST", "漏洞模式、误报经验、项目规则"], ["SCA", "组件影响、VEX、修复版本经验"], ["AGENT", "权限策略、危险配置模式"], ["DAST", "验证剧本、证据条件、裁决门槛"], ["SANDBOX", "固定探针合同、隔离策略"], ["ASPM", "审核、版本、效果与废弃治理"]].map(([module, knowledge]) => <article key={module}><b>{module}</b><ArrowRight size={15} /><span>{knowledge}</span></article>)}</div>
      </section>
    </section> : null}

    {activeTab === "effects" ? <section className="knowledge-effects-workspace">
      <div className="knowledge-section-heading"><div><span>效果与闭环</span><h3>先观察证据覆盖和治理进展，再建设精确率与召回率基准</h3></div><strong>项目级实时视图</strong></div>
      <section className="knowledge-effect-grid">
        {[["动态验证覆盖", dynamicCoverage, validatedFindingIds.size + " / " + findings.length, "已关联 DAST 的 Finding"], ["运行证据覆盖", evidenceCoverage, evidenceBackedFindingIds.size + " / " + findings.length, "已关联 SANDBOX 证据的 Finding"], ["治理沉淀覆盖", governanceCoverage, fixedCount + falsePositiveCount + " / " + findings.length, "已修复、关闭或误报"], ["可信攻击链", summary?.attack_chains.length ?? 0, String(summary?.attack_chains.length ?? 0), "只统计显式关系"]].map(([label, value, fraction, description], index) => <article key={String(label)}><span>{label}</span><strong>{index < 3 ? value + "%" : value}</strong><div><i style={{ width: (index < 3 ? Number(value) : Math.min(Number(value) * 20, 100)) + "%" }} /></div><small>{fraction} · {description}</small></article>)}
      </section>
      <section className="knowledge-feedback-grid">
        <article><div><SlidersHorizontal size={21} /><span><strong>当前可以观测</strong><small>项目级事实与知识治理</small></span></div><ul><li>{findings.length} 条 Finding 的治理状态</li><li>{validations.length} 次动态验证与裁决</li><li>{knowledgeWorkspace?.status_counts.published ?? 0} 条当前项目已发布知识</li><li>{recommendationCount} 条跨项目知识推荐</li></ul></article>
        <article><div><Lock size={21} /><span><strong>尚未建立基线</strong><small>不填造指标</small></span></div><ul><li>SAST / AGENT 精确率与召回率</li><li>DAST 重复运行裁决一致率</li><li>推荐知识被采纳后的风险降低效果</li><li>自动规则优化收益</li></ul></article>
      </section>
    </section> : null}

    <section className="knowledge-report-bar">
      <div><span>治理交付</span><h3>把当前知识、证据关系与能力边界汇总为项目安全报告</h3><p>报告只读取当前项目已保存事实，不会自动发布知识或修改检测规则。</p></div>
      <div><button className="primary-action" disabled={reportLoading} onClick={() => void generateReportPreview()}>{reportLoading ? "正在生成…" : report ? "刷新报告" : "生成报告预览"}</button><button className="secondary-action" disabled={!report} onClick={() => report && downloadSecurityReport(report, "json")}>导出 JSON</button><button className="secondary-action" disabled={!report} onClick={() => report && downloadSecurityReport(report, "html")}>导出 HTML</button></div>
      {reportError ? <div className="report-error">{reportError}</div> : null}
    </section>
    {report ? <SecurityReportPreview report={report} /> : null}
    <section className="knowledge-boundary"><strong>当前能力边界</strong><span>候选提交、证据门槛、人工审核、版本历史、回滚和同租户跨项目推荐已经持久化；当前操作人仍是显式演示身份，生产 IAM、推荐采纳反馈和自动修改规则仍未启用。</span></section>
  </section>;
}

function KnowledgeEntryCard({ entry }: { entry: KnowledgeEntry }) {
  return <article className="knowledge-enterprise-card"><div><span>{knowledgeTypeLabel(entry.knowledge_type)}</span><b>v{entry.version}</b></div><h4>{entry.title}</h4><p>{truncateText(entry.summary, 180)}</p><dl><div><dt>来源</dt><dd>{entry.source_project_name} · {entry.source_module}</dd></div><div><dt>规则</dt><dd>{entry.rule_id}</dd></div><div><dt>审核</dt><dd>{entry.reviewer ?? "未记录"} · {formatDateTime(entry.published_at)}</dd></div></dl><footer>{entry.tags.slice(0, 3).map((tag) => <span key={tag}>{tag}</span>)}</footer></article>;
}

function SecurityReportPreview({ report }: { report: SecurityReport }) {
  const retestRows: ReportRow[] = Object.values(report.retest_comparisons).flatMap((comparison) => comparison.items.map((item) => ({ id: `${comparison.source}-${item.identity}`, title: item.title, subtitle: `${comparison.source} · ${retestResultLabel(item.result)}`, summary: `${item.file_path ?? "未记录文件位置"} · 原位置 ${item.previous_line_start ?? "-"} → 当前 ${item.current_line_start ?? "-"}`, details: [["复测结果", retestResultLabel(item.result)], ["原等级 / 当前等级", `${severityLabel(item.previous_severity)} / ${severityLabel(item.current_severity)}`], ["风险标识", item.identity]] })));
  const relationRows: ReportRow[] = report.evidence_graph.edges.filter((item) => item.relation_type !== "contains").map((item) => ({ id: item.id, title: `${item.source} → ${item.target}`, subtitle: relationTypeLabel(item.relation_type), summary: item.basis, details: [["可信度", `${item.confidence}%`], ["记录时间", formatDateTime(item.created_at)], ["关系类型", relationTypeLabel(item.relation_type)]] }));
  const dependencyRows: ReportRow[] = report.dependency_graph.edges.map((item, index) => ({ id: `${item.source}-${item.target}-${index}`, title: `${item.source} → ${item.target}`, subtitle: dependencyRelationshipSourceLabel(item.quality), summary: "SCA 依赖关系", details: [["关系来源", dependencyRelationshipSourceLabel(item.quality)], ["原始标记", item.quality]] }));
  return <section className="report-preview">
    <section className="panel"><div className="panel-header"><div><span className="section-kicker">报告预览</span><h2>{report.project.name}：完整项目安全交付</h2></div><span>所有多条结果每页 10 条</span></div><section className="module-summary inline-summary"><Metric label="风险分" value={report.summary.risk_score} /><Metric label="当前风险" value={report.findings.length} /><Metric label="动态验证" value={report.validations.length} /><Metric label="运行证据" value={report.sandbox_evidence.length} /><Metric label="可信攻击链" value={report.summary.attack_chains.length} /></section><div className="report-meta"><span>接入模块：{report.summary.enabled_modules.map((item) => item.toUpperCase()).join("、") || "仅 ASPM"}</span><span>扫描任务：{report.summary.scan_task_count}</span><span>报告时间：{formatDateTime(report.generated_at)}</span></div></section>
    <ReportDataSection title="SCA：组件与供应链结果" emptyText="尚未记录组件扫描结果。" rows={report.components.map((item) => ({ id: item.id, title: `${item.name} ${item.version ?? "版本未知"}`, subtitle: `${item.ecosystem} · ${dependencyTypeLabel(item.dependency_type)}`, summary: `${riskStatusLabel(item.risk_status)} · ${severityLabel(item.severity)} · 漏洞 ${(item.vulnerability_ids ?? []).join(", ") || "无"}`, details: [["来源文件", item.source_file], ["包管理器", item.package_manager ?? "未记录"], ["许可证 / 策略", `${item.license ?? "未记录"} / ${licensePolicyLabel(item.license_risk)}`], ["风险来源", sourceLabel(item.risk_source)], ["风险摘要", item.risk_summary ?? "未记录"], ["修复建议", item.remediation ?? "未记录"]] }))} />
    <ReportDataSection title="SCA：依赖关系来源" emptyText="尚未形成依赖关系。" rows={dependencyRows} />
    <ReportDataSection title="统一风险：SCA、SAST 与 AGENT" emptyText="尚未执行检测，暂无风险结果。" rows={report.findings.map((item) => ({ id: item.id, title: item.title, subtitle: `${item.source} · ${item.rule_id} · ${severityLabel(item.severity)}`, summary: `${item.file_path ?? "未记录位置"}${item.line_start ? `:${item.line_start}` : ""} · ${statusLabel(normalizeFindingStatus(item.status))}`, details: [["原始证据", item.evidence ?? "未记录"], ["分类 / 复核结论", `${item.ai_review?.category ?? "未分类"} / ${item.ai_review?.review_verdict ?? "未记录"}`], ["修复建议", item.remediation_note ?? item.ai_review?.remediation ?? "未记录"], ["负责人 / 截止时间", `${item.remediation_owner ?? "未分配"} / ${formatDateTime(item.remediation_due_at)}`], ["AI 复核摘要", item.ai_review?.summary ?? "尚未复核"]] }))} />
    <ReportDataSection title="DAST：动态验证记录" emptyText="尚未记录动态验证。" rows={report.validations.map((item) => ({ id: item.id, title: dastVerdictLabel(item.verdict), subtitle: `${item.target_url} · ${item.strategy_name ?? item.strategy_id}`, summary: item.evidence_summary ?? "未记录验证摘要", details: [["关联方式 / 可信度", `${item.link_source} / ${item.link_confidence}%`], ["验证范围", item.scope_summary ?? "未记录"], ["能力边界", item.limitations ?? "未记录"], ["请求 / 响应", `${item.request_summary ?? "未记录"} / ${item.response_summary ?? "未记录"}`], ["复现 / 修复", `${item.reproduction_steps ?? "未记录"} / ${item.remediation_hint ?? "未记录"}`]] }))} />
    <ReportDataSection title="SANDBOX：隔离运行与取证记录" emptyText="尚未记录隔离运行证据。" rows={report.sandbox_evidence.map((item) => ({ id: item.id, title: item.strategy_name ?? "隔离运行记录", subtitle: item.run_command, summary: item.evidence_summary ?? "未记录运行结论", details: [["取证目的", item.purpose ?? "未记录"], ["隔离策略", `网络：${item.network_policy}；文件：${item.filesystem_policy}`], ["能力边界", item.limitations ?? "未记录"], ["关联方式 / 可信度", `${item.link_source} / ${item.link_confidence}%`], ["行为账本", `文件 ${item.observed_files.length}；网络 ${item.observed_network.length}；进程 ${item.observed_processes.length}；工具调用 ${item.observed_tool_calls.length}`]] }))} />
    <section className="panel"><div className="panel-header"><h2>可信攻击链</h2><span>仅由显式关联的记录形成</span></div><AttackChainSummary chains={report.summary.attack_chains} /></section>
    <ReportDataSection title="证据图谱：跨模块可信关系" emptyText="尚未形成显式的跨模块关系。" rows={relationRows} />
    <ReportDataSection title="修复复测：与上一批扫描对比" emptyText={Object.values(report.retest_comparisons).some((item) => item.has_comparison) ? "已完成复测，本次没有发现需要逐条展示的变化。" : "至少完成两次同类扫描后，才会产生逐条复测结果。"} rows={retestRows} />
    <section className="panel report-boundaries"><div className="panel-header"><h2>报告能力边界</h2><span>避免将演示能力误读为生产结论</span></div>{Object.entries(report.capability_boundaries).map(([module, items]) => <details key={module} open><summary>{module}</summary><ul>{items.map((item) => <li key={item}>{item}</li>)}</ul></details>)}</section>
  </section>;
}

function ReportDataSection({ title, emptyText, rows }: { title: string; emptyText: string; rows: ReportRow[] }) {
  const [page, setPage] = useState(1);
  const pagination = paginate(rows, page);
  useEffect(() => { setPage(1); }, [rows.length]);
  return <section className="panel report-data-section"><div className="panel-header"><h2>{title}</h2><span>完整结果 · 每页 10 条</span></div>{rows.length === 0 ? <div className="empty-project">{emptyText}</div> : <><table className="concise-table"><thead><tr><th>条目</th><th>结论 / 摘要</th><th>完整字段</th></tr></thead><tbody>{pagination.items.map((item) => <tr key={item.id}><td><strong>{item.title}</strong><span className="cell-subtext">{item.subtitle}</span></td><td>{item.summary}</td><td><details className="report-row-details"><summary>查看完整记录</summary><dl>{item.details.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl></details></td></tr>)}</tbody></table><Pagination page={pagination.page} pageCount={pagination.pageCount} total={rows.length} onPageChange={setPage} /></>}</section>;
}

function ScaGovernanceView({ project, components, summary, comparison, scanHistory, selectedScanId, scanDiff, dependencyGraph, toolScanEnabled, loading, onToolScanChange, onSelectScan, onExportSbom, onExportReport, onRun }: { project: Project | null; components: Component[]; summary: AspmSummary | null; comparison: FindingRetestComparison | null; scanHistory: ScaScanHistoryItem[]; selectedScanId: string | null; scanDiff: ScaScanDiff | null; dependencyGraph: DependencyGraph | null; toolScanEnabled: boolean; loading: boolean; onToolScanChange: (enabled: boolean) => void; onSelectScan: (scanTaskId: string) => Promise<void>; onExportSbom: (format: "cyclonedx" | "spdx") => Promise<void>; onExportReport: () => Promise<void>; onRun: () => Promise<void> }) {
  const [filters, setFilters] = useState({ keyword: "", ecosystem: "all", severity: "all", risk: "all", dependency: "all" });
  const [page, setPage] = useState(1);
  const risky = components.filter(isRiskyScaComponent);
  const high = risky.filter((item) => item.severity === "critical" || item.severity === "high");
  const filtered = components.filter((item) => {
    const keyword = filters.keyword.trim().toLowerCase();
    return (!keyword || `${item.name} ${item.version ?? ""} ${(item.vulnerability_ids ?? []).join(" ")}`.toLowerCase().includes(keyword))
      && (filters.ecosystem === "all" || item.ecosystem === filters.ecosystem)
      && (filters.severity === "all" || (item.severity ?? "none") === filters.severity)
      && (filters.risk === "all" || (item.risk_status ?? "not_checked") === filters.risk)
      && (filters.dependency === "all" || item.dependency_type === filters.dependency);
  });
  const pagination = paginate(filtered, page);
  useEffect(() => { setPage(1); }, [filters.keyword, filters.ecosystem, filters.severity, filters.risk, filters.dependency]);
  return <ModuleGovernanceShell moduleKey="sca" lastStatus={summary?.sca_governance.latest_scan_status ?? null} metrics={[["当前组件数", components.length], ["风险组件数", risky.length], ["严重 / 高危组件", high.length], ["建议升级组件", risky.filter((item) => item.remediation).length]]} action={risky.length ? "优先升级高危组件，并确认升级是否影响直接和传递依赖。" : "当前未发现高风险组件，建议定期重新扫描依赖。"} loading={loading} onRun={onRun}>
    <ModuleFilterBar><input value={filters.keyword} onChange={(event) => setFilters({ ...filters, keyword: event.target.value })} placeholder="搜索组件、版本或漏洞标识" /><SimpleFilter value={filters.ecosystem} label="全部生态" options={uniqueValues(components.map((item) => item.ecosystem))} onChange={(value) => setFilters({ ...filters, ecosystem: value })} /><SimpleFilter value={filters.severity} label="全部等级" options={uniqueValues(components.map((item) => item.severity ?? "none"))} format={severityLabel} onChange={(value) => setFilters({ ...filters, severity: value })} /><SimpleFilter value={filters.risk} label="全部风险状态" options={uniqueValues(components.map((item) => item.risk_status ?? "not_checked"))} format={riskStatusLabel} onChange={(value) => setFilters({ ...filters, risk: value })} /><SimpleFilter value={filters.dependency} label="全部依赖类型" options={uniqueValues(components.map((item) => item.dependency_type))} format={dependencyTypeLabel} onChange={(value) => setFilters({ ...filters, dependency: value })} /></ModuleFilterBar>
    <table className="concise-table"><thead><tr><th>组件</th><th>风险状态</th><th>漏洞标识</th><th>建议动作</th></tr></thead><tbody>{pagination.items.length === 0 ? <tr><td colSpan={4} className="empty-cell">没有符合筛选条件的组件。</td></tr> : pagination.items.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><span className="cell-subtext">{item.version ?? "版本未知"} · {item.ecosystem} · {dependencyTypeLabel(item.dependency_type)}</span></td><td>{riskStatusLabel(item.risk_status)}<span className="cell-subtext">{severityLabel(item.severity)}</span></td><td>{item.vulnerability_ids?.join(", ") || "无已知漏洞标识"}</td><td>{item.remediation ?? (isRiskyScaComponent(item) ? "确认可用安全版本后升级" : "暂不需要处理")}</td></tr>)}</tbody></table>
    <Pagination page={pagination.page} pageCount={pagination.pageCount} total={filtered.length} onPageChange={setPage} />
    <section className="advanced-inline-action"><div><strong>扫描报告</strong><span>扫描完成后可导出当前项目的 SCA 风险、组件和修复建议，无需配置 Docker 或离线情报。</span></div><div className="advanced-actions"><button className="secondary-action" disabled={loading || !project || components.length === 0} onClick={() => void onExportReport()}>导出 SCA 报告</button></div></section>
    <RetestComparisonPanel comparison={comparison} />
    <ScaAdvancedDetails project={project} components={components} scanHistory={scanHistory} selectedScanId={selectedScanId} scanDiff={scanDiff} dependencyGraph={dependencyGraph} toolScanEnabled={toolScanEnabled} loading={loading} onToolScanChange={onToolScanChange} onSelectScan={onSelectScan} onExportSbom={onExportSbom} />
  </ModuleGovernanceShell>;
}

function ScaAdvancedDetails({ project, components, scanHistory, selectedScanId, scanDiff, dependencyGraph, toolScanEnabled, loading, onToolScanChange, onSelectScan, onExportSbom }: { project: Project | null; components: Component[]; scanHistory: ScaScanHistoryItem[]; selectedScanId: string | null; scanDiff: ScaScanDiff | null; dependencyGraph: DependencyGraph | null; toolScanEnabled: boolean; loading: boolean; onToolScanChange: (enabled: boolean) => void; onSelectScan: (scanTaskId: string) => Promise<void>; onExportSbom: (format: "cyclonedx" | "spdx") => Promise<void> }) {
  const [toolHealth, setToolHealth] = useState<ScaToolHealth | null>(null);
  const [toolHealthLoading, setToolHealthLoading] = useState(false);
  async function refreshToolHealth() {
    setToolHealthLoading(true);
    try { setToolHealth(await request<ScaToolHealth>("/sca/tool-health")); } catch { setToolHealth(null); } finally { setToolHealthLoading(false); }
  }
  return <details className="advanced-details"><summary>高级设置（可选）：离线扫描、依赖分析与 CI 发布检查</summary><div className="advanced-details-body">
    <details className="advanced-details"><summary>Docker 增强扫描与 SBOM 导出（可选）</summary><div className="advanced-details-body"><section className="advanced-inline-action"><div><strong>外部扫描工具</strong><span>仅在需要更完整的软件物料清单（SBOM）或已准备 Docker 时启用；未启用不影响基础 SCA 扫描。</span></div><div className="advanced-actions"><label className="inline-check"><input type="checkbox" checked={toolScanEnabled} disabled={loading} onChange={(event) => onToolScanChange(event.target.checked)} />使用 Docker 增强扫描</label><button className="secondary-action" disabled={loading || !project || components.length === 0} onClick={() => void onExportSbom("cyclonedx")}>导出 CycloneDX</button><button className="secondary-action" disabled={loading || !project || components.length === 0} onClick={() => void onExportSbom("spdx")}>导出 SPDX</button></div></section><ScaToolHealthPanel health={toolHealth} loading={toolHealthLoading} onRefresh={refreshToolHealth} /></div></details>
    <details className="advanced-details"><summary>离线漏洞数据与扫描依据（可选）</summary><div className="advanced-details-body"><OsvMirrorPanel /><ScaIntelligencePanel /><ScaEvidencePanel project={project} selectedScanId={selectedScanId} /></div></details>
    <details className="advanced-details"><summary>风险例外、适用性与扫描规则（可选）</summary><div className="advanced-details-body"><ScaExceptionPanel project={project} components={components} /><ScaVexPanel project={project} components={components} /><ScaPolicyPanel /><ScaPolicyOverridePanel project={project} /></div></details>
    <details className="advanced-details"><summary>扫描历史与依赖关系分析（可选）</summary><div className="advanced-details-body"><section className="panel"><div className="panel-header"><h3>与上一批次的变化</h3><span>{scanDiff?.has_comparison ? "已生成对比" : "需要至少两次扫描"}</span></div><ScaScanDiffView diff={scanDiff} /></section><section className="panel"><div className="panel-header"><h3>扫描历史</h3><span>{scanHistory.length} 个批次</span></div><ScaScanHistoryTable history={scanHistory} selectedScanId={selectedScanId} loading={loading} onSelect={onSelectScan} /></section><section className="panel"><div className="panel-header"><h3>依赖关系与升级建议</h3><span>{dependencyGraph?.summary.node_count ?? 0} 个节点</span></div><DependencyGraphView graph={dependencyGraph} /><ImpactPathTable paths={dependencyGraph?.impact_paths ?? []} nodes={dependencyGraph?.nodes ?? []} /><UpgradeLeverTable levers={dependencyGraph?.upgrade_levers ?? []} /></section></div></details>
  </div></details>;
}

function ScaExceptionPanel({ project, components }: { project: Project | null; components: Component[] }) {
  const [items, setItems] = useState<ScaException[]>([]);
  const [selectedKey, setSelectedKey] = useState("");
  const [reason, setReason] = useState("");
  const [requester, setRequester] = useState("");
  const [requesterRole, setRequesterRole] = useState("developer");
  const [approver, setApprover] = useState("");
  const [approverRole, setApproverRole] = useState("security");
  const [expiresAt, setExpiresAt] = useState("");
  const [page, setPage] = useState(1);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const riskyComponents = components.filter((item) => isRiskyScaComponent(item) && item.risk_status !== "accepted-risk");
  const componentKey = (item: Component) => `${item.ecosystem}\u0000${item.name}\u0000${item.version ?? ""}`;
  const selected = riskyComponents.find((item) => componentKey(item) === selectedKey);
  const refresh = async () => {
    if (!project) return;
    try { setError(""); setItems(await request<ScaException[]>(`/sca/projects/${project.id}/exceptions`)); }
    catch (requestError) { setError(`例外记录加载失败：${errorMessage(requestError)}`); }
  };
  const update = async (item: ScaException, status: "approved" | "rejected" | "revoked") => {
    setSaving(true);
    try { setError(""); await request(`/sca/exceptions/${item.id}`, { method: "PATCH", body: JSON.stringify({ status, approver: approver.trim() || null, approver_role: approverRole }) }); await refresh(); }
    catch (requestError) { setError(`例外状态更新失败：${errorMessage(requestError)}`); }
    finally { setSaving(false); }
  };
  const submit = async () => {
    if (!project || !selected || !reason.trim()) return;
    setSaving(true);
    try {
      setError("");
      await request(`/sca/projects/${project.id}/exceptions`, { method: "POST", body: JSON.stringify({ ecosystem: selected.ecosystem, package_name: selected.name, package_version: selected.version, exception_type: "risk_acceptance", reason: reason.trim(), requester: requester.trim() || null, requester_role: requesterRole, expires_at: expiresAt || null }) });
      setSelectedKey(""); setReason(""); setRequester(""); setExpiresAt(""); await refresh();
    } catch (requestError) { setError(`例外申请提交失败：${errorMessage(requestError)}`); }
    finally { setSaving(false); }
  };
  useEffect(() => { void refresh(); }, [project?.id]);
  useEffect(() => { setPage(1); }, [items.length]);
  if (!project) return null;
  const pagination = paginate(items, page);
  return <section className="panel full"><div className="panel-header"><div><h3>风险例外审批</h3><span>仅用于有明确业务理由且限定范围的临时接受风险</span></div><button className="secondary-action" disabled={saving} onClick={() => void refresh()}>刷新</button></div><p>批准且未过期的例外会在下一次 SCA 扫描中标记为“已接受风险”，但原始漏洞证据、扫描历史和门禁审计仍会保留。当前角色字段用于流程与审计，尚不能替代独立 IAM 身份认证。</p><div className="filter-grid"><select value={selectedKey} onChange={(event) => setSelectedKey(event.target.value)}><option value="">选择一个当前风险组件</option>{riskyComponents.map((item) => <option key={item.id} value={componentKey(item)}>{item.name} {item.version ?? "版本未知"} · {item.ecosystem} · {severityLabel(item.severity)}</option>)}</select><input placeholder="接受风险的业务原因（必填）" value={reason} onChange={(event) => setReason(event.target.value)} /><input placeholder="申请人（可选）" value={requester} onChange={(event) => setRequester(event.target.value)} /><select value={requesterRole} onChange={(event) => setRequesterRole(event.target.value)}><option value="developer">开发</option><option value="release_manager">发布负责人</option><option value="security">安全</option><option value="legal">法务</option></select><label><span>失效日期（可选）</span><input type="date" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label><button className="secondary-action" disabled={saving || !selected || !reason.trim()} onClick={() => void submit()}>{saving ? "处理中" : "提交例外申请"}</button></div><div className="filter-grid"><input placeholder="审批人（审批/撤销时填写）" value={approver} onChange={(event) => setApprover(event.target.value)} /><select value={approverRole} onChange={(event) => setApproverRole(event.target.value)}><option value="security">安全</option><option value="legal">法务</option><option value="admin">管理员</option></select></div>{riskyComponents.length === 0 ? <div className="empty-project">当前扫描没有可申请例外的风险组件。</div> : null}{error ? <div className="report-error">{error}</div> : null}<table className="compact-table"><thead><tr><th>组件与范围</th><th>业务理由</th><th>状态 / 到期</th><th>审批操作</th></tr></thead><tbody>{items.length ? pagination.items.map((item) => <tr key={item.id}><td><strong>{item.package_name}</strong><span className="cell-subtext">{item.ecosystem} · {item.package_version ?? "全部版本"}</span></td><td>{item.reason}<span className="cell-subtext">申请人：{item.requester ?? "未填写"} · {item.requester_role ?? "未声明角色"}</span></td><td>{scaExceptionStatusLabel(item.status)}<span className="cell-subtext">{item.expires_at ? `到期：${formatDateTime(item.expires_at)}` : "未设置到期日"}</span></td><td>{item.status === "pending" ? <><button className="secondary-action" disabled={saving} onClick={() => void update(item, "approved")}>批准</button><button className="secondary-action" disabled={saving} onClick={() => void update(item, "rejected")}>拒绝</button></> : item.status === "approved" ? <><span className="cell-subtext">{item.approver ?? "已批准"} · {item.approver_role ?? "-"}</span><button className="secondary-action" disabled={saving} onClick={() => void update(item, "revoked")}>撤销</button></> : item.approver ?? "-"}<details><summary>审计记录</summary>{(item.approval_history ?? []).map((event, index) => <span className="cell-subtext" key={index}>{textValue(event.status)} · {textValue(event.role)} · {formatDateTime(typeof event.at === "string" ? event.at : null)}</span>)}</details></td></tr>) : <tr><td colSpan={4} className="empty-cell">暂无例外申请。</td></tr>}</tbody></table><Pagination page={pagination.page} pageCount={pagination.pageCount} total={items.length} onPageChange={setPage} /></section>;
}

function ScaPolicyPanel() {
  const [policies, setPolicies] = useState<ScaPolicies | null>(null);
  const [error, setError] = useState("");
  const [rulePage, setRulePage] = useState(1);
  const [licensePage, setLicensePage] = useState(1);
  const refresh = async () => {
    try { setError(""); setPolicies(await request<ScaPolicies>("/sca/policies")); }
    catch (requestError) { setError(`本地策略加载失败：${errorMessage(requestError)}`); }
  };
  useEffect(() => { void refresh(); }, []);
  const rules = policies?.vulnerability_rules ?? [];
  const licenses = policies?.license_policies ?? [];
  const rulePagination = paginate(rules, rulePage);
  const licensePagination = paginate(licenses, licensePage);
  useEffect(() => { setRulePage(1); }, [rules.length]);
  useEffect(() => { setLicensePage(1); }, [licenses.length]);
  return <section className="panel full"><div className="panel-header"><div><h3>本地 SCA 策略</h3><span>当前扫描使用的漏洞规则与许可证处置要求</span></div><button className="secondary-action" onClick={() => void refresh()}>刷新</button></div><p>这里展示当前生效的本地策略，便于审计扫描依据；策略文件由平台管理员随代码版本维护，页面不会伪装成实时联网情报。</p>{error ? <div className="report-error">{error}</div> : null}<h4>漏洞匹配规则 · {rules.length} 条</h4><table className="compact-table"><thead><tr><th>漏洞标识</th><th>生态 / 组件</th><th>等级</th><th>状态</th></tr></thead><tbody>{rules.length ? rulePagination.items.map((item) => <tr key={item.id}><td>{item.id}</td><td>{item.ecosystem} · {item.package}</td><td>{severityLabel(item.severity)}</td><td>{item.enabled ? "已启用" : "未启用"}</td></tr>) : <tr><td colSpan={4} className="empty-cell">暂无本地漏洞规则。</td></tr>}</tbody></table><Pagination page={rulePagination.page} pageCount={rulePagination.pageCount} total={rules.length} onPageChange={setRulePage} /><h4>许可证策略 · {licenses.length} 条</h4><table className="compact-table"><thead><tr><th>策略</th><th>识别关键词</th><th>是否需审批</th></tr></thead><tbody>{licenses.length ? licensePagination.items.map((item) => <tr key={item.id}><td>{item.policy}</td><td>{item.keywords.join("、") || "-"}</td><td>{item.approval_required ? "需要审批" : "不需要审批"}</td></tr>) : <tr><td colSpan={3} className="empty-cell">暂无许可证策略。</td></tr>}</tbody></table><Pagination page={licensePagination.page} pageCount={licensePagination.pageCount} total={licenses.length} onPageChange={setLicensePage} /></section>;
}

function ScaEvidencePanel({ project, selectedScanId }: { project: Project | null; selectedScanId: string | null }) {
  const [evidence, setEvidence] = useState<ScaEvidence | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const refresh = async () => {
    if (!project) return;
    setLoading(true);
    try {
      setError("");
      const suffix = selectedScanId ? `?scan_task_id=${selectedScanId}` : "";
      setEvidence(await request<ScaEvidence>(`/sca/projects/${project.id}/evidence${suffix}`));
    } catch (requestError) {
      setEvidence(null);
      setError(`SCA 证据加载失败：${errorMessage(requestError)}`);
    } finally { setLoading(false); }
  };
  useEffect(() => { void refresh(); }, [project?.id, selectedScanId]);
  if (!project) return null;
  const artifacts = objectValue(evidence?.artifact_hashes);
  const files = listValue(artifacts.files);
  const packages = listValue(artifacts.packages);
  const mirror = objectValue(evidence?.osv_mirror);
  const snapshot = objectValue(evidence?.policy_snapshot);
  const sources = Object.entries(evidence?.native_dependency_sources ?? {});
  return <section className="panel full"><div className="panel-header"><div><h3>扫描依据与发布检查</h3><span>仅供需要 CI 发布检查或核对扫描来源时查看</span></div><button className="secondary-action" disabled={loading} onClick={() => void refresh()}>刷新</button></div>{error ? <div className="report-error">{error}</div> : null}{!evidence ? <div className="empty-project">完成一次 SCA 扫描后可查看扫描依据、离线数据使用情况和发布检查结论。</div> : <div className="content-grid"><div className="panel"><div className="panel-header"><h4>发布检查（仅 CI 使用）</h4><span className={`risk-badge ${evidence.gate.decision === "block" ? "exploitable" : "not_exploitable"}`}>{evidence.gate.decision === "block" ? "阻断" : "通过"}</span></div><p>{evidence.gate.reason}</p><div className="kv-list"><div><span>会阻止发布的组件</span><strong>{evidence.gate.blocked_component_count}</strong></div><div><span>已接受风险</span><strong>{evidence.gate.accepted_risk_count}</strong></div><div><span>CI 返回码（仅流水线）</span><strong>{evidence.gate.exit_code}</strong></div></div><details><summary>CI 调用说明</summary><p>{evidence.gate.ci_usage}</p></details></div><div className="panel"><div className="panel-header"><h4>扫描文件校验（高级）</h4><span>{scaDataStatusLabel(artifacts.status)}</span></div><div className="kv-list"><div><span>依赖清单</span><strong>{files.length}</strong></div><div><span>本地包证据</span><strong>{packages.length}</strong></div><div><span>算法</span><strong>{textValue(artifacts.algorithm)}</strong></div></div><p>仅对本地实际可访问的清单、安装记录、包描述或 Maven JAR 计算 SHA-256；缺失包文件不会被伪造。</p></div><div className="panel"><div className="panel-header"><h4>离线漏洞库（可选）</h4><span>{scaDataStatusLabel(mirror.status)}</span></div><div className="kv-list"><div><span>记录数</span><strong>{textValue(mirror.entry_count)}</strong></div><div><span>更新时间</span><strong>{formatDateTime(typeof mirror.updated_at === "string" ? mirror.updated_at : null)}</strong></div></div><p>{textValue(mirror.detail) === "-" ? "未导入离线漏洞库时，基础 SCA 扫描仍可正常执行。" : textValue(mirror.detail)}</p></div><div className="panel"><div className="panel-header"><h4>本次扫描使用的规则</h4><span>当前批次</span></div><div className="kv-list"><div><span>漏洞规则</span><strong>{textValue(snapshot.enabled_vulnerability_rule_count)}</strong></div><div><span>许可证策略</span><strong>{textValue(snapshot.enabled_license_policy_count)}</strong></div><div><span>项目特殊规则</span><strong>{textValue(snapshot.override_count)}</strong></div></div></div><div className="panel full"><div className="panel-header"><h4>依赖关系的来源（仅供核对）</h4><span>扫描快照</span></div><table className="compact-table"><thead><tr><th>生态</th><th>来源</th><th>状态</th><th>关系数</th><th>说明</th></tr></thead><tbody>{sources.length ? sources.map(([ecosystem, item]) => <tr key={ecosystem}><td>{ecosystem}</td><td>{item.manifest} · {item.tool}</td><td>{nativeDependencyStatusLabel(item.status)}</td><td>{item.edge_count}</td><td>{item.detail}</td></tr>) : <tr><td colSpan={5} className="empty-cell">当前扫描未记录原生依赖来源。</td></tr>}</tbody></table></div></div>}</section>;
}

function OsvMirrorPanel() {
  const [status, setStatus] = useState<Record<string, unknown> | null>(null);
  const [source, setSource] = useState("manual-import");
  const [rawEntries, setRawEntries] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const refresh = async () => {
    try { setError(""); setStatus(await request<Record<string, unknown>>("/sca/osv-mirror/status")); }
    catch (requestError) { setStatus(null); setError(`OSV 镜像状态加载失败：${errorMessage(requestError)}`); }
  };
  const importMirror = async () => {
    try {
      const entries = JSON.parse(rawEntries);
      if (!Array.isArray(entries)) throw new Error("请输入 JSON 数组 entries");
      setSaving(true); setError("");
      setStatus(await request<Record<string, unknown>>("/sca/osv-mirror/import", { method: "POST", body: JSON.stringify({ entries, source: source.trim() || "manual-import" }) }));
      setRawEntries("");
    } catch (requestError) { setError(`OSV 镜像导入失败：${errorMessage(requestError)}`); }
    finally { setSaving(false); }
  };
  useEffect(() => { void refresh(); }, []);
  return <section className="panel full"><div className="panel-header"><div><h3>离线漏洞库（可选）</h3><span>仅在无法联网、且已有本地漏洞数据时配置；不配置也能使用基础扫描。</span></div><button className="secondary-action" disabled={saving} onClick={() => void refresh()}>刷新状态</button></div><div className="kv-list"><div><span>状态</span><strong>{scaDataStatusLabel(status?.status)}</strong></div><div><span>记录数</span><strong>{textValue(status?.entry_count)}</strong></div><div><span>保存位置</span><strong>{textValue(status?.path)}</strong></div></div><p>{textValue(status?.detail)}</p><details><summary>导入本地漏洞库 JSON</summary><p>输入 JSON 数组；每条记录需包含 ecosystem、package、version 或 affected，以及 vulnerabilities。导入文件仅写入被 Git 忽略的离线资源目录。</p><div className="filter-grid"><input value={source} onChange={(event) => setSource(event.target.value)} placeholder="情报来源标识" /><textarea value={rawEntries} onChange={(event) => setRawEntries(event.target.value)} placeholder='[{"ecosystem":"pypi","package":"example","version":"1.0.0","vulnerabilities":[{"id":"CVE-...","severity":"high","summary":"..."}]}]' /><button className="secondary-action" disabled={saving || !rawEntries.trim()} onClick={() => void importMirror()}>{saving ? "导入中" : "导入漏洞库"}</button></div></details>{error ? <div className="report-error">{error}</div> : null}</section>;
}

function ScaIntelligencePanel() {
  const [status, setStatus] = useState<Record<string, unknown> | null>(null);
  const [source, setSource] = useState("manual-cvss-epss-kev");
  const [rawEntries, setRawEntries] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const refresh = async () => {
    try { setError(""); setStatus(await request<Record<string, unknown>>("/sca/intelligence/status")); }
    catch (requestError) { setStatus(null); setError(`漏洞情报状态加载失败：${errorMessage(requestError)}`); }
  };
  const importEntries = async () => {
    try {
      const entries = JSON.parse(rawEntries);
      if (!Array.isArray(entries)) throw new Error("请输入 JSON 数组 entries");
      setSaving(true); setError("");
      setStatus(await request<Record<string, unknown>>("/sca/intelligence/import", { method: "POST", body: JSON.stringify({ entries, source: source.trim() || "manual-import" }) }));
      setRawEntries("");
    } catch (requestError) { setError(`漏洞情报导入失败：${errorMessage(requestError)}`); }
    finally { setSaving(false); }
  };
  useEffect(() => { void refresh(); }, []);
  return <section className="panel full"><div className="panel-header"><div><h3>补充风险数据（可选）</h3><span>用于补充风险分、已被利用标记和修复版本；未导入时不会伪造这些信息。</span></div><button className="secondary-action" disabled={saving} onClick={() => void refresh()}>刷新状态</button></div><div className="kv-list"><div><span>状态</span><strong>{scaDataStatusLabel(status?.status)}</strong></div><div><span>通告数</span><strong>{textValue(status?.advisory_count)}</strong></div><div><span>更新时间</span><strong>{formatDateTime(typeof status?.updated_at === "string" ? status.updated_at : null)}</strong></div></div><details><summary>导入补充风险数据 JSON</summary><p>每项使用 <code>id</code> 或 <code>cve</code>，可选 <code>cvss</code>（0–10）、<code>epss</code>（0–1）、<code>kev</code>、<code>known_exploited</code>、<code>fixed_version</code>。</p><div className="filter-grid"><input value={source} onChange={(event) => setSource(event.target.value)} placeholder="情报来源标识" /><textarea value={rawEntries} onChange={(event) => setRawEntries(event.target.value)} placeholder='[{"cve":"CVE-2026-0001","cvss":9.8,"epss":0.91,"kev":true,"fixed_version":"2.0.1"}]' /><button className="secondary-action" disabled={saving || !rawEntries.trim()} onClick={() => void importEntries()}>{saving ? "导入中" : "导入数据"}</button></div></details>{error ? <div className="report-error">{error}</div> : null}</section>;
}

function ScaVexPanel({ project, components }: { project: Project | null; components: Component[] }) {
  const [items, setItems] = useState<ScaVex[]>([]);
  const [selectedKey, setSelectedKey] = useState("");
  const [vulnerabilityId, setVulnerabilityId] = useState("");
  const [status, setStatus] = useState<ScaVex["status"]>("not_affected");
  const [justification, setJustification] = useState("");
  const [actor, setActor] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const componentKey = (item: Component) => `${item.ecosystem}\u0000${item.name}\u0000${item.version ?? ""}`;
  const selected = components.find((item) => componentKey(item) === selectedKey);
  const refresh = async () => {
    if (!project) return;
    try { setError(""); setItems(await request<ScaVex[]>(`/sca/projects/${project.id}/vex`)); }
    catch (requestError) { setError(`VEX 记录加载失败：${errorMessage(requestError)}`); }
  };
  const submit = async () => {
    if (!project || !selected || !vulnerabilityId.trim()) return;
    setSaving(true);
    try {
      setError("");
      await request(`/sca/projects/${project.id}/vex`, { method: "POST", body: JSON.stringify({ ecosystem: selected.ecosystem, package_name: selected.name, package_version: selected.version, vulnerability_id: vulnerabilityId.trim(), status, justification: justification.trim() || null, actor: actor.trim() || null }) });
      setSelectedKey(""); setVulnerabilityId(""); setJustification(""); await refresh();
    } catch (requestError) { setError(`VEX 结论保存失败：${errorMessage(requestError)}`); }
    finally { setSaving(false); }
  };
  useEffect(() => { void refresh(); }, [project?.id]);
  if (!project) return null;
  return <section className="panel full"><div className="panel-header"><div><h3>VEX 适用性结论</h3><span>对特定组件漏洞记录“未受影响、已修复、受影响或调查中”，不删除原始漏洞证据</span></div><button className="secondary-action" disabled={saving} onClick={() => void refresh()}>刷新</button></div><div className="filter-grid"><select value={selectedKey} onChange={(event) => { setSelectedKey(event.target.value); const component = components.find((item) => componentKey(item) === event.target.value); setVulnerabilityId(component?.vulnerability_ids?.[0] ?? ""); }}><option value="">选择组件</option>{components.filter((item) => item.vulnerability_ids?.length).map((item) => <option key={item.id} value={componentKey(item)}>{item.name} · {item.version ?? "-"} · {item.vulnerability_ids?.join(", ")}</option>)}</select><input value={vulnerabilityId} onChange={(event) => setVulnerabilityId(event.target.value)} placeholder="漏洞 ID，例如 CVE-2026-0001" /><select value={status} onChange={(event) => setStatus(event.target.value as ScaVex["status"])}><option value="not_affected">未受影响</option><option value="fixed">已修复</option><option value="affected">受影响</option><option value="under_investigation">调查中</option></select><input value={actor} onChange={(event) => setActor(event.target.value)} placeholder="结论提交人" /><textarea value={justification} onChange={(event) => setJustification(event.target.value)} placeholder="适用性依据、缓解措施或修复说明" /><button className="secondary-action" disabled={saving || !selected || !vulnerabilityId.trim()} onClick={() => void submit()}>{saving ? "保存中" : "保存 VEX 结论"}</button></div>{error ? <div className="report-error">{error}</div> : null}<table className="compact-table"><thead><tr><th>组件 / 漏洞</th><th>结论</th><th>依据</th><th>有效期</th></tr></thead><tbody>{items.length ? items.slice(0, 20).map((item) => <tr key={item.id}><td><strong>{item.package_name}</strong><span className="cell-subtext">{item.ecosystem} · {item.package_version ?? "全部版本"} · {item.vulnerability_id}</span></td><td>{vexStatusLabel(item.status)}<span className="cell-subtext">{item.actor ?? "未填写提交人"}</span></td><td>{item.justification ?? item.action_statement ?? item.evidence ?? "-"}</td><td>{item.expires_at ? formatDateTime(item.expires_at) : "未设置"}</td></tr>) : <tr><td colSpan={4} className="empty-cell">暂无 VEX 结论。</td></tr>}</tbody></table></section>;
}

function ScaPolicyOverridePanel({ project }: { project: Project | null }) {
  const [policies, setPolicies] = useState<ScaPolicies | null>(null);
  const [audit, setAudit] = useState<ScaPolicyAudit[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [scope, setScope] = useState<"project" | "platform">("project");
  const [policyKind, setPolicyKind] = useState<"vulnerability" | "license" | "gate">("vulnerability");
  const [policyId, setPolicyId] = useState("");
  const [policyConfig, setPolicyConfig] = useState("");
  const refresh = async () => {
    if (!project) return;
    try {
      setError("");
      const [policyData, auditData] = await Promise.all([
        request<ScaPolicies>(`/sca/policies?project_id=${project.id}`),
        request<ScaPolicyAudit[]>(`/sca/projects/${project.id}/policy-audit`),
      ]);
      setPolicies(policyData); setAudit(auditData);
    } catch (requestError) { setError(`策略治理数据加载失败：${errorMessage(requestError)}`); }
  };
  const toggle = async (policyKind: "vulnerability" | "license" | "gate", policyId: string, enabled: boolean) => {
    if (!project) return;
    setSaving(true);
    try {
      setError("");
      await request("/sca/policies/overrides", { method: "POST", body: JSON.stringify({ project_id: project.id, policy_kind: policyKind, policy_id: policyId, enabled, actor: "platform-admin", change_note: `通过治理页${enabled ? "启用" : "停用"}策略` }) });
      await refresh();
    } catch (requestError) { setError(`策略更新失败：${errorMessage(requestError)}`); }
    finally { setSaving(false); }
  };
  const saveCustomPolicy = async () => {
    if (!policyId.trim() || !policyConfig.trim()) return;
    setSaving(true);
    try {
      const config = JSON.parse(policyConfig);
      if (!config || typeof config !== "object" || Array.isArray(config)) throw new Error("策略配置必须是 JSON 对象");
      setError("");
      await request("/sca/policies/overrides", { method: "POST", body: JSON.stringify({ project_id: scope === "project" ? project?.id : null, policy_kind: policyKind, policy_id: policyId.trim(), enabled: true, config, actor: "platform-admin", change_note: "通过治理页新增或覆盖策略" }) });
      setPolicyId(""); setPolicyConfig(""); await refresh();
    } catch (requestError) { setError(`策略保存失败：${errorMessage(requestError)}`); }
    finally { setSaving(false); }
  };
  useEffect(() => { void refresh(); }, [project?.id]);
  if (!project) return null;
  const rows = [
    ...(policies?.vulnerability_rules ?? []).map((item) => ({ kind: "vulnerability" as const, id: item.id, title: item.id, detail: `${item.ecosystem} · ${item.package} · ${item.affected ?? "-"}`, enabled: item.enabled, source: item.source ?? "packaged" })),
    ...(policies?.license_policies ?? []).map((item) => ({ kind: "license" as const, id: item.id, title: item.id, detail: `${item.policy} · ${item.keywords.join("、") || "无关键词"}`, enabled: item.enabled !== false, source: item.source ?? "packaged" })),
    ...(policies?.gate_policy ? [{ kind: "gate" as const, id: "default", title: "CI 门禁策略", detail: `等级：${policies.gate_policy.block_severities.join("、") || "不按等级阻断"}；风险分 ≥ ${policies.gate_policy.min_risk_score}；KEV：${policies.gate_policy.block_kev ? "阻断" : "不阻断"}`, enabled: policies.gate_policy.enabled, source: policies.gate_policy.source ?? "packaged" }] : []),
  ];
  return <section className="panel full"><div className="panel-header"><div><h3>项目级策略覆盖与审计</h3><span>覆盖不改写随代码发布的基线规则，并在后续扫描快照中留痕</span></div><button className="secondary-action" disabled={saving} onClick={() => void refresh()}>刷新</button></div>{error ? <div className="report-error">{error}</div> : null}<table className="compact-table"><thead><tr><th>策略</th><th>范围</th><th>来源</th><th>状态</th><th>操作</th></tr></thead><tbody>{rows.length ? rows.map((item) => <tr key={`${item.kind}-${item.id}`}><td><strong>{item.title}</strong><span className="cell-subtext">{item.detail}</span></td><td>当前项目</td><td>{item.source}</td><td>{item.enabled ? "已启用" : "已停用"}</td><td><button className="secondary-action" disabled={saving} onClick={() => void toggle(item.kind, item.id, !item.enabled)}>{item.enabled ? "停用" : "启用"}</button></td></tr>) : <tr><td colSpan={5} className="empty-cell">暂无可管理策略。</td></tr>}</tbody></table><details className="advanced-details"><summary>新增或覆盖策略</summary><p>漏洞策略 JSON 需包含 ecosystem、package、affected、severity、summary、fixed_version；许可证策略需包含 keywords、policy、summary、remediation；门禁策略的 ID 固定为 default，可配置 block_severities、block_license_policies、min_risk_score、block_kev、max_scan_age_hours。选择“平台级”会应用于所有本地项目。</p><div className="filter-grid"><select value={scope} onChange={(event) => setScope(event.target.value as "project" | "platform")}><option value="project">当前项目</option><option value="platform">平台级</option></select><select value={policyKind} onChange={(event) => setPolicyKind(event.target.value as "vulnerability" | "license" | "gate")}><option value="vulnerability">漏洞规则</option><option value="license">许可证策略</option><option value="gate">CI 门禁策略</option></select><input value={policyId} onChange={(event) => setPolicyId(event.target.value)} placeholder={policyKind === "gate" ? "固定为 default" : "策略 ID，例如 CUSTOM-CVE-2026-001"} /><textarea value={policyConfig} onChange={(event) => setPolicyConfig(event.target.value)} placeholder={policyKind === "gate" ? '{"block_severities":["critical","high"],"min_risk_score":80,"block_kev":true,"max_scan_age_hours":168}' : '{"ecosystem":"npm","package":"example","affected":"<2.0.0","severity":"high","summary":"...","fixed_version":"2.0.0"}'} /><button className="secondary-action" disabled={saving || !policyId.trim() || !policyConfig.trim()} onClick={() => void saveCustomPolicy()}>保存策略</button></div></details><details className="advanced-details"><summary>策略审计记录（最近 {audit.length} 条）</summary>{audit.length ? <table className="compact-table"><thead><tr><th>时间</th><th>事件</th><th>操作人</th><th>详情</th></tr></thead><tbody>{audit.slice(0, 10).map((item) => <tr key={item.id}><td>{formatDateTime(item.created_at)}</td><td>{item.event_type}</td><td>{item.actor ?? "-"}</td><td>{Object.entries(item.details).map(([key, value]) => <span className="cell-subtext" key={key}>{key}: {textValue(value)}</span>)}</td></tr>)}</tbody></table> : <div className="empty-project">暂无项目级策略变更记录。</div>}</details></section>;
}

function ImpactPathTable({ paths, nodes }: { paths: NonNullable<DependencyGraph["impact_paths"]>; nodes: DependencyGraphNode[] }) {
  const [page, setPage] = useState(1);
  const labels = new Map(nodes.map((node) => [node.id, node.label]));
  const pagination = paginate(paths, page);
  useEffect(() => { setPage(1); }, [paths.length]);
  return <section className="impact-paths"><div className="panel-header"><h4>风险影响路径</h4><span>从风险组件向上追溯到项目</span></div>{paths.length === 0 ? <div className="empty-project">暂无可追溯的风险依赖路径。</div> : <><table className="compact-table"><thead><tr><th>风险组件</th><th>等级 / 状态</th><th>影响路径</th></tr></thead><tbody>{pagination.items.map((item) => <tr key={`${item.component}-${item.risk_status}`}><td>{item.component}</td><td>{severityLabel(item.severity)}<span className="cell-subtext">{riskStatusLabel(item.risk_status)}</span></td><td>{item.paths.length ? <details><summary>查看 {item.paths.length} 条路径</summary>{item.paths.map((path, index) => <span className="cell-subtext" key={`${item.component}-${index}`}>{path.map((id) => labels.get(id) ?? id).join(" → ")}</span>)}</details> : "未找到从项目到该组件的依赖关系"}</td></tr>)}</tbody></table><Pagination page={pagination.page} pageCount={pagination.pageCount} total={paths.length} onPageChange={setPage} /></>}</section>;
}

function AgentGovernanceConsole({ project, snapshot }: { project: Project; snapshot: AgentScanSnapshot | null }) {
  const [workspace, setWorkspace] = useState<"policy" | "exceptions" | "delivery">("policy");
  const [profile, setProfile] = useState<AgentProfile | null>(null);
  const [gate, setGate] = useState<AgentQualityGate | null>(snapshot?.quality_gate ?? null);
  const [message, setMessage] = useState("");
  const [actor, setActor] = useState("local-operator");
  const [decisionNote, setDecisionNote] = useState("");
  const [allowlist, setAllowlist] = useState<AgentAllowlistItem>({ path_pattern: "*", subject_pattern: "*", capability: "*", scope_pattern: "*", reason: "" });
  const [exception, setException] = useState({ kind: "finding" as "finding" | "permission", disposition: "accept_risk" as "suppress" | "accept_risk", rule_id: "*", path_pattern: "*", subject_pattern: "*", capability: "*", scope_pattern: "*", reason: "", expires_at: "" });

  useEffect(() => { void load(); }, [project.id, snapshot?.scan_task_id]);

  async function load() {
    const [nextProfile, nextGate] = await Promise.all([
      request<AgentProfile>(`/agent/projects/${project.id}/profile`).catch(() => null),
      request<AgentQualityGate>(`/agent/projects/${project.id}/gate`).catch(() => snapshot?.quality_gate ?? null),
    ]);
    setProfile(nextProfile); setGate(nextGate);
  }

  async function saveProfile(nextProfile = profile) {
    if (!nextProfile) return;
    try {
      const payload = { actor, disabled_rule_ids: nextProfile.disabled_rule_ids, excluded_paths: nextProfile.excluded_paths, permission_allowlist: nextProfile.permission_allowlist, required_approval_capabilities: nextProfile.required_approval_capabilities, target_runtime_execution_enabled: nextProfile.target_runtime_execution_enabled, quality_gate: nextProfile.quality_gate };
      setProfile(await request<AgentProfile>(`/agent/projects/${project.id}/profile`, { method: "PATCH", body: JSON.stringify(payload) }));
      setMessage("治理策略已保存；扫描规则从下一次扫描生效，真实目标执行开关立即生效但仍需独立确认。");
    } catch (error) { setMessage(`策略保存失败：${errorMessage(error)}`); }
  }

  function addAllowlist() {
    if (!profile || !allowlist.reason.trim()) { setMessage("新增 Allowlist 必须填写治理理由。"); return; }
    const next = { ...profile, permission_allowlist: [...profile.permission_allowlist, allowlist] };
    setProfile(next);
    setAllowlist({ path_pattern: "*", subject_pattern: "*", capability: "*", scope_pattern: "*", reason: "" });
    void saveProfile(next);
  }

  async function createException() {
    if (!exception.reason.trim()) { setMessage("例外申请必须填写理由。"); return; }
    try {
      await request(`/agent/projects/${project.id}/exceptions`, { method: "POST", body: JSON.stringify({ ...exception, actor, expires_at: exception.expires_at ? new Date(`${exception.expires_at}T23:59:59Z`).toISOString() : null }) });
      setException({ kind: "finding", disposition: "accept_risk", rule_id: "*", path_pattern: "*", subject_pattern: "*", capability: "*", scope_pattern: "*", reason: "", expires_at: "" });
      setMessage("例外申请已创建，批准前不会改变扫描结果。"); await load();
    } catch (error) { setMessage(`例外申请失败：${errorMessage(error)}`); }
  }

  async function decideException(id: string, status: "approved" | "rejected" | "revoked") {
    if (!decisionNote.trim()) { setMessage("审批或撤销前请填写审批说明。"); return; }
    try {
      await request(`/agent/projects/${project.id}/exceptions/${id}`, { method: "PATCH", body: JSON.stringify({ status, approval_note: decisionNote, actor }) });
      setDecisionNote(""); setMessage(`例外已${status === "approved" ? "批准" : status === "rejected" ? "拒绝" : "撤销"}；变更从下一次扫描开始反映。`); await load();
    } catch (error) { setMessage(`例外审批失败：${errorMessage(error)}`); }
  }

  async function downloadAgentArtifact(kind: "json" | "html" | "sarif" | "ci") {
    const endpoint = kind === "json" ? "report" : kind === "html" ? "report.html" : kind === "sarif" ? "sarif" : "ci-config";
    try {
      const response = await fetch(`${API_BASE}/agent/projects/${project.id}/${endpoint}`);
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = document.createElement("a");
      link.href = url; link.download = `${safeFilename(project.name)}-agent-${kind === "ci" ? "ci-config.json" : `report.${kind}`}`; link.click(); URL.revokeObjectURL(url);
      setMessage(`${kind === "ci" ? "离线 CI 配置" : kind.toUpperCase() + " 报告"}已导出。`);
    } catch (error) { setMessage(`导出失败：${errorMessage(error)}`); }
  }

  if (!profile) return <section className="retest-panel"><div className="panel-header"><h3>AGENT 治理与交付</h3><span>正在加载策略</span></div><p>该区域只管理本地静态扫描策略，不会连接或执行 Agent、MCP Server、插件或工具。</p></section>;
  const policy = profile.quality_gate;
  return <section className="agent-governance-console"><div className="agent-governance-summary"><div><span>当前治理配置</span><strong>v{profile.profile_version}</strong><small>规则 {profile.rule_version}</small></div><div><span>质量门禁</span><strong>{gate?.decision === "block" ? "阻断" : gate?.decision === "pass" ? "通过" : "等待扫描"}</strong><small>{agentUiText(gate?.reasons?.[0] ?? "修改后需重新扫描裁决")}</small></div><div><span>项目例外</span><strong>{profile.exceptions.length}</strong><small>{profile.exceptions.filter((item) => item.status === "pending").length} 条待审批</small></div><div><span>权限 Allowlist</span><strong>{profile.permission_allowlist.length}</strong><small>仅影响治理裁决</small></div></div><nav className="agent-governance-nav" aria-label="策略与交付工作区"><button type="button" className={workspace === "policy" ? "active" : ""} onClick={() => setWorkspace("policy")}>扫描与门禁</button><button type="button" className={workspace === "exceptions" ? "active" : ""} onClick={() => setWorkspace("exceptions")}>例外与边界</button><button type="button" className={workspace === "delivery" ? "active" : ""} onClick={() => setWorkspace("delivery")}>报告与审计</button></nav><section className="content-grid agent-governance-panels">
    {workspace === "policy" ? <>
    <div className="panel full"><div className="panel-header"><h2>项目扫描策略</h2><span>{message || "保存后从下一次扫描生效"}</span></div><p>历史扫描与原始 Finding 不会被重写。操作人用于本项目策略审计，不等同于平台身份认证。</p><div className="filter-grid agent-form-grid"><label>操作人<input value={actor} onChange={(event) => setActor(event.target.value)} /></label><label>停用规则 ID（每行一个）<textarea rows={4} value={profile.disabled_rule_ids.join("\n")} onChange={(event) => setProfile({ ...profile, disabled_rule_ids: splitLines(event.target.value) })} /></label><label>排除路径 glob（每行一个）<textarea rows={4} value={profile.excluded_paths.join("\n")} onChange={(event) => setProfile({ ...profile, excluded_paths: splitLines(event.target.value) })} placeholder="例如 fixtures/**" /></label><label>强制审批能力（每行一个）<textarea rows={4} value={profile.required_approval_capabilities.join("\n")} onChange={(event) => setProfile({ ...profile, required_approval_capabilities: splitLines(event.target.value) })} /></label><label className="inline-check agent-full-row"><input type="checkbox" checked={profile.target_runtime_execution_enabled} onChange={(event) => setProfile({ ...profile, target_runtime_execution_enabled: event.target.checked })} />允许本项目显示真实目标执行入口；仍需精确 staging、固定镜像和二次确认</label><div className="agent-form-actions"><button className="primary-action" onClick={() => void saveProfile()}>保存项目策略</button></div></div></div>
    <div className="panel full">
      <div className="panel-header"><h2>质量门禁</h2><span className={`severity ${gate?.decision === "block" ? "high" : "info"}`}>{gate?.decision === "block" ? "阻断" : gate?.decision === "pass" ? "通过" : "等待扫描"}</span></div>
      <div className="filter-grid agent-form-grid agent-gate-form">
        <label>Finding 阈值<select value={policy.threshold} onChange={(event) => setProfile({ ...profile, quality_gate: { ...policy, threshold: event.target.value as AgentGatePolicy["threshold"] } })}>{["critical", "high", "medium", "low", "info", "none"].map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
        <label>最大阻断 Finding 数<input type="number" min={0} value={policy.max_blocking_findings} onChange={(event) => setProfile({ ...profile, quality_gate: { ...policy, max_blocking_findings: Math.max(0, Number(event.target.value)) } })} /></label>
        <label>情报最大年龄（天）<input type="number" min={1} max={3650} value={policy.max_intelligence_age_days} onChange={(event) => setProfile({ ...profile, quality_gate: { ...policy, max_intelligence_age_days: Math.max(1, Number(event.target.value)) } })} /></label>
        <label>最低信任分（显式启用后生效）<input type="number" min={0} max={100} value={policy.minimum_trust_score} onChange={(event) => setProfile({ ...profile, quality_gate: { ...policy, minimum_trust_score: Math.max(0, Math.min(100, Number(event.target.value))) } })} /></label>
        <details className="agent-policy-conditions"><summary>高级门禁条件（22 项）</summary><div className="agent-policy-switches">{([['enabled', '启用门禁'], ['block_new_only', '只阻断新增 Finding'], ['block_wildcard_permissions', '阻断通配权限'], ['block_parse_failures', '阻断结构化解析失败'], ['block_skipped_files', '阻断跳过文件'], ['block_generic_config_validation', '阻断仅通用解析的配置'], ['block_unvalidated_schema_references', '阻断声明但未校验的 Schema'], ['block_permission_expansion', '阻断权限扩大'], ['require_approval_for_high_risk', '高风险权限必须声明审批'], ['block_unpinned_sources', '阻断未锁定依赖'], ['block_insecure_sources', '阻断不安全来源'], ['block_unknown_sources', '阻断来源未知'], ['block_partial_integrity', '阻断不完整哈希证据'], ['block_integrity_changes', '阻断完整性变化'], ['block_source_changes', '阻断来源变化'], ['block_known_vulnerabilities', '阻断已命中漏洞'], ['block_malicious_packages', '阻断恶意包情报命中'], ['block_package_confusion', '阻断包名混淆信号'], ['block_intelligence_gaps', '阻断情报未覆盖或版本未解析'], ['block_stale_intelligence', '阻断已配置但过期的本地情报'], ['block_high_risk_dataflow_paths', '阻断高风险 Prompt→工具→资源路径'], ['block_low_trust_score', '阻断低于最低信任分的扫描']] as Array<[keyof AgentGatePolicy, string]>).map(([key, label]) => <label className="inline-check" key={key}><input type="checkbox" checked={Boolean(policy[key])} onChange={(event) => setProfile({ ...profile, quality_gate: { ...policy, [key]: event.target.checked } })} />{label}</label>)}</div></details>
        <div className="agent-form-actions"><button className="primary-action" onClick={() => void saveProfile()}>保存门禁</button></div>
      </div>
      <div className="kv-list"><div><span>阻断 Finding</span><strong>{gate?.blocking_finding_count ?? 0}</strong></div><div><span>阻断权限</span><strong>{gate?.blocking_permission_count ?? 0}</strong></div><div><span>阻断来源资产</span><strong>{gate?.blocking_asset_count ?? 0}</strong></div><div><span>阻断配置覆盖</span><strong>{gate?.blocking_coverage_count ?? 0}</strong></div><div><span>阻断情报命中</span><strong>{gate?.blocking_intelligence_count ?? 0}</strong></div><div><span>阻断数据流路径</span><strong>{gate?.blocking_dataflow_count ?? 0}</strong></div></div>
      {gate?.reasons?.length ? <ul>{gate.reasons.map((reason) => <li key={reason}>{agentUiText(reason)}</li>)}</ul> : <p>最近扫描没有门禁阻断原因；修改策略后需重新扫描才能重新裁决。</p>}
    </div>
    </> : null}
    {workspace === "exceptions" ? <>
    <div className="panel full"><div className="panel-header"><h2>权限 Allowlist</h2><span>{profile.permission_allowlist.length} 条项目级边界</span></div><div className="filter-grid agent-form-grid"><label>资产路径 glob<input value={allowlist.path_pattern} onChange={(event) => setAllowlist({ ...allowlist, path_pattern: event.target.value })} /></label><label>主体 glob<input value={allowlist.subject_pattern} onChange={(event) => setAllowlist({ ...allowlist, subject_pattern: event.target.value })} /></label><label>能力<input value={allowlist.capability} onChange={(event) => setAllowlist({ ...allowlist, capability: event.target.value })} /></label><label>范围 glob<input value={allowlist.scope_pattern} onChange={(event) => setAllowlist({ ...allowlist, scope_pattern: event.target.value })} /></label><label className="agent-full-row">治理理由<input value={allowlist.reason} onChange={(event) => setAllowlist({ ...allowlist, reason: event.target.value })} /></label><div className="agent-form-actions"><button className="primary-action" onClick={addAllowlist}>新增并保存</button></div></div>{profile.permission_allowlist.length ? <table className="compact-table"><thead><tr><th>资产 / 主体</th><th>能力 / 范围</th><th>理由</th><th>操作</th></tr></thead><tbody>{profile.permission_allowlist.map((item, index) => <tr key={item.id ?? index}><td>{item.path_pattern}<span className="cell-subtext">{item.subject_pattern}</span></td><td>{item.capability}<span className="cell-subtext">{item.scope_pattern}</span></td><td>{item.reason}</td><td><button className="secondary-action" onClick={() => { const next = { ...profile, permission_allowlist: profile.permission_allowlist.filter((_, itemIndex) => itemIndex !== index) }; setProfile(next); void saveProfile(next); }}>移除</button></td></tr>)}</tbody></table> : <div className="empty-project">暂无 Allowlist；新权限与高风险权限按门禁策略裁决。</div>}</div>
    <div className="panel full"><div className="panel-header"><h2>Finding / 权限例外审批</h2><span>申请与批准分离记录；批准后下一次扫描生效</span></div><div className="filter-grid agent-form-grid"><label>对象<select value={exception.kind} onChange={(event) => setException({ ...exception, kind: event.target.value as "finding" | "permission" })}><option value="finding">Finding</option><option value="permission">权限</option></select></label><label>处置<select value={exception.disposition} onChange={(event) => setException({ ...exception, disposition: event.target.value as "suppress" | "accept_risk" })}><option value="accept_risk">接受风险</option><option value="suppress">抑制 / 误报</option></select></label><label>规则 ID<input value={exception.rule_id} disabled={exception.kind !== "finding"} onChange={(event) => setException({ ...exception, rule_id: event.target.value })} /></label><label>资产路径 glob<input value={exception.path_pattern} onChange={(event) => setException({ ...exception, path_pattern: event.target.value })} /></label><label>主体 glob<input value={exception.subject_pattern} disabled={exception.kind !== "permission"} onChange={(event) => setException({ ...exception, subject_pattern: event.target.value })} /></label><label>能力<input value={exception.capability} disabled={exception.kind !== "permission"} onChange={(event) => setException({ ...exception, capability: event.target.value })} /></label><label>范围 glob<input value={exception.scope_pattern} disabled={exception.kind !== "permission"} onChange={(event) => setException({ ...exception, scope_pattern: event.target.value })} /></label><label>失效日期<input type="date" value={exception.expires_at} onChange={(event) => setException({ ...exception, expires_at: event.target.value })} /></label><label className="agent-full-row">申请理由<input value={exception.reason} onChange={(event) => setException({ ...exception, reason: event.target.value })} /></label><div className="agent-form-actions"><button className="primary-action" onClick={() => void createException()}>提交例外申请</button></div></div><label className="agent-approval-note">审批说明<input value={decisionNote} onChange={(event) => setDecisionNote(event.target.value)} placeholder="批准、拒绝或撤销前必填" /></label>{profile.exceptions.length ? <table className="compact-table"><thead><tr><th>对象 / 选择器</th><th>理由 / 有效期</th><th>状态 / 审批</th><th>操作</th></tr></thead><tbody>{profile.exceptions.map((item) => <tr key={item.id}><td>{item.kind === "finding" ? item.rule_id : item.capability}<span className="cell-subtext">{item.path_pattern}</span></td><td>{item.reason}<span className="cell-subtext">{item.expires_at ? formatDateTime(item.expires_at) : "永久"}</span></td><td>{item.status}<span className="cell-subtext">申请：{item.requester ?? "-"} · 审批：{item.approver ?? "-"}</span></td><td>{item.status === "pending" ? <><button className="secondary-action" onClick={() => void decideException(item.id, "approved")}>批准</button><button className="secondary-action" onClick={() => void decideException(item.id, "rejected")}>拒绝</button></> : item.status === "approved" ? <button className="secondary-action" onClick={() => void decideException(item.id, "revoked")}>撤销</button> : "-"}</td></tr>)}</tbody></table> : <div className="empty-project">暂无例外申请。</div>}</div>
    </> : null}
    {workspace === "delivery" ? <div className="panel full"><div className="panel-header"><h2>报告、离线 CI 与策略审计</h2><span>JSON / SARIF / HTML 均来自同一扫描快照</span></div><div className="probe-actions"><button className="secondary-action" disabled={!snapshot} onClick={() => void downloadAgentArtifact("json")}>导出 JSON</button><button className="secondary-action" disabled={!snapshot} onClick={() => void downloadAgentArtifact("sarif")}>导出 SARIF</button><button className="secondary-action" disabled={!snapshot} onClick={() => void downloadAgentArtifact("html")}>导出 HTML</button><button className="secondary-action" onClick={() => void downloadAgentArtifact("ci")}>导出离线 CI 配置</button></div><p>CI 命令只做本地静态解析；不下载资源、不联网，也不运行目标 Agent/MCP/插件。使用基线报告时可只阻断新增 Finding 和权限扩大。</p>{profile.audit_log.length ? <details><summary>最近 {profile.audit_log.length} 条策略审计</summary><table className="compact-table"><thead><tr><th>时间</th><th>事件</th><th>操作人</th><th>详情</th></tr></thead><tbody>{profile.audit_log.slice(-20).reverse().map((item) => <tr key={item.id}><td>{formatDateTime(item.at)}</td><td>{item.action}</td><td>{item.actor}</td><td>{Object.entries(item.detail ?? {}).map(([key, value]) => <span className="cell-subtext" key={key}>{key}: {textValue(value)}</span>)}</td></tr>)}</tbody></table></details> : <div className="empty-project">暂无策略变更记录。</div>}</div> : null}
  </section></section>;
}

function AgentScanCoveragePanel({ history }: { history: AgentScanHistoryItem[] }) {
  const latest = history[0];
  if (!latest) return <section className="retest-panel"><div className="panel-header"><h3>扫描覆盖</h3><span>尚无批次</span></div><p>执行一次 AGENT 扫描后，这里会显示识别到的资产类型、解析结果和规则版本。</p></section>;
  const coverage = latest.coverage;
  return <section className="retest-panel">
    <div className="panel-header"><h3>最近扫描覆盖</h3><span>{formatDateTime(latest.finished_at ?? latest.created_at)}</span></div>
    <div className="retest-summary"><Metric label="识别资产" value={coverage.discovered_asset_count} /><Metric label="解析成功" value={coverage.parsed_asset_count} /><Metric label="解析失败" value={coverage.failed_asset_count} /><Metric label="跳过文件" value={coverage.skipped_file_count} /></div>
    <p className="retest-note">规则版本：{latest.rule_version ?? "旧批次未记录"}。资产类型：{Object.entries(coverage.asset_types).length ? Object.entries(coverage.asset_types).map(([key, value]) => `${agentAssetTypeLabel(key)} ${value}`).join("、") : "未识别到受支持的 Agent 资产"}。</p>
    <div className="retest-summary"><Metric label="通用解析资产" value={coverage.generic_parser_asset_count ?? 0} /><Metric label="未验证 Schema 引用" value={coverage.schema_references_not_validated ?? 0} /></div>
    {Object.keys(coverage.adapter_coverage ?? {}).length ? <details className="advanced-details"><summary>查看配置适配与覆盖缺口</summary><p className="retest-note">“结构化”表示已应用当前内置字段与安全检查；“通用”表示只做 JSON/YAML/TOML 解析，不代表通过厂商 Schema。为避免扫描期间联网，声明的 Schema 引用不会自动下载或校验。</p><table className="compact-table"><thead><tr><th>适配器</th><th>资产 / 解析</th><th>验证级别</th><th>Schema 引用</th><th>边界</th></tr></thead><tbody>{Object.entries(coverage.adapter_coverage).map(([id, item]) => <tr key={id}><td><strong>{item.label}</strong><span className="cell-subtext">{id}</span></td><td>{item.asset_count} / {item.parsed_asset_count}<span className="cell-subtext">失败 {item.failed_asset_count}</span></td><td>{item.validation_level === "structural" ? "结构化检查" : item.validation_level === "generic" ? "通用解析" : item.validation_level === "frontmatter" ? "Frontmatter" : "文本规则"}<span className="cell-subtext">{item.status === "generic" ? "存在厂商 Schema 覆盖缺口" : item.status === "failed" ? "解析失败" : "当前适配范围"}</span></td><td>{item.schema_reference_count}<span className="cell-subtext">未验证 {item.schema_references_not_validated}</span></td><td>{item.limitation}</td></tr>)}</tbody></table></details> : <p className="retest-note">旧扫描批次没有配置适配覆盖数据；请重新执行 AGENT 扫描。</p>}
    {history.length > 1 ? <details className="advanced-details"><summary>查看最近 {Math.min(history.length, 10)} 个扫描批次</summary><table className="compact-table"><thead><tr><th>时间</th><th>状态</th><th>资产</th><th>问题</th><th>离线审计草案</th><th>规则版本</th></tr></thead><tbody>{history.slice(0, 10).map((item) => <tr key={item.scan_task_id}><td>{formatDateTime(item.finished_at ?? item.created_at)}</td><td>{scanStatusLabel(item.status)}</td><td>{item.coverage.discovered_asset_count}</td><td>{item.finding_count}</td><td>{item.audit_summary?.available ? <><strong>{item.audit_summary.review_item_count} 个候选</strong><span className="cell-subtext">模型：{item.audit_summary.external_model_invoked ? "已调用" : "未调用"} · {item.audit_summary.model_status ?? "未知"}</span></> : <span className="cell-subtext">旧批次无兼容草案</span>}</td><td>{item.rule_version ?? "旧批次未记录"}</td></tr>)}</tbody></table></details> : null}
  </section>;
}

function AgentAssetInventoryPanel({ snapshot }: { snapshot: AgentScanSnapshot | null }) {
  const [keyword, setKeyword] = useState("");
  const [assetType, setAssetType] = useState("all");
  const [page, setPage] = useState(1);
  const assets = snapshot?.assets ?? [];
  const filtered = assets.filter((asset) => {
    const haystack = `${asset.name ?? ""} ${asset.path} ${asset.publisher ?? ""} ${asset.transport ?? ""}`.toLowerCase();
    return (!keyword.trim() || haystack.includes(keyword.trim().toLowerCase())) && (assetType === "all" || asset.asset_type === assetType);
  });
  const pagination = paginate(filtered, page);
  useEffect(() => { setPage(1); }, [keyword, assetType]);
  return <section className="retest-panel">
    <div className="panel-header"><h3>Agent 资产清单</h3><span>{assets.length} 个已识别资产</span></div>
    {!snapshot ? <p>完成一次 AGENT 扫描后显示逐资产解析结果。</p> : <>
      <ModuleFilterBar><input value={keyword} onChange={(event) => setKeyword(event.target.value)} placeholder="搜索资产、路径、发布者或传输方式" /><SimpleFilter value={assetType} label="全部资产类型" options={uniqueValues(assets.map((item) => item.asset_type))} format={agentAssetTypeLabel} onChange={setAssetType} /></ModuleFilterBar>
      <table className="concise-table"><thead><tr><th>资产</th><th>类型 / 解析</th><th>声明边界</th><th>结果</th></tr></thead><tbody>{pagination.items.length === 0 ? <tr><td className="empty-cell" colSpan={4}>没有符合筛选条件的 Agent 资产。</td></tr> : pagination.items.map((asset) => <tr key={`${asset.asset_type}-${asset.path}`}><td><strong>{asset.name ?? asset.path}</strong><span className="cell-subtext">{asset.path}</span><span className="cell-subtext">{asset.version ? `版本 ${asset.version}` : "未声明版本"}{asset.publisher ? ` · ${asset.publisher}` : ""}</span></td><td><strong>{agentAssetTypeLabel(asset.asset_type)}</strong><span className="cell-subtext">{asset.parser} · {asset.status === "parsed" ? "解析成功" : "解析失败"}</span><span className="cell-subtext">{asset.transport ? `传输：${asset.transport}` : "无传输声明"}</span></td><td><details className="record-evidence"><summary>工具 {asset.declared_tools.length} · 资源 {asset.declared_resources.length} · Prompt {asset.declared_prompts.length}</summary><dl><div><dt>启动入口</dt><dd>{asset.entrypoint ?? "未声明"}</dd></div><div><dt>工具</dt><dd>{asset.declared_tools.join("、") || "未声明"}</dd></div><div><dt>资源范围</dt><dd>{asset.declared_resources.join("、") || "未声明"}</dd></div><div><dt>Prompt</dt><dd>{asset.declared_prompts.join("、") || "未声明"}</dd></div><div><dt>解析检查</dt><dd>{asset.checks.join("、") || "未记录"}</dd></div></dl></details></td><td><span className={`severity ${asset.finding_count ? "high" : "info"}`}>{asset.finding_count} 个问题</span><span className="cell-subtext">{asset.permission_count} 条权限</span>{Number(asset.metadata.permissions_truncated ?? 0) > 0 ? <span className="cell-subtext">另有 {Number(asset.metadata.permissions_truncated)} 条权限因单资产上限未保存</span> : null}{asset.detail ? <span className="cell-subtext">{asset.detail}</span> : null}</td></tr>)}</tbody></table>
      <Pagination page={pagination.page} pageCount={pagination.pageCount} total={filtered.length} onPageChange={setPage} />
      {snapshot.skipped_files.length ? <details className="advanced-details"><summary>查看跳过的 {snapshot.skipped_files.length} 个文件</summary><table className="compact-table"><thead><tr><th>文件</th><th>原因</th></tr></thead><tbody>{snapshot.skipped_files.map((item) => <tr key={`${item.path}-${item.reason}`}><td>{item.path}</td><td>{item.reason}</td></tr>)}</tbody></table></details> : null}
    </>}
  </section>;
}

function AgentProvenancePanel({ snapshot }: { snapshot: AgentScanSnapshot | null }) {
  const [page, setPage] = useState(1);
  const assets = snapshot?.assets ?? [];
  const records = assets.flatMap((asset) => asset.provenance.map((item) => ({ asset, item })));
  const pagination = paginate(records, page);
  const unpinned = records.filter(({ item }) => ["missing", "floating"].includes(item.version_status)).length;
  const unsafe = records.filter(({ item }) => item.issues.some((issue) => ["insecure-http-source", "embedded-source-credentials", "local-path-escape"].includes(issue))).length;
  const privateSources = records.filter(({ item }) => item.source_visibility === "private-declared").length;
  const privatePreflightGaps = records.filter(({ item }) => item.source_visibility === "private-declared" && item.onboarding_status !== "preflight-ready").length;
  const partial = assets.filter((asset) => asset.integrity_status === "partial").length;
  useEffect(() => { setPage(1); }, [snapshot?.scan_task_id]);
  return <section className="retest-panel">
    <div className="panel-header"><h3>来源与完整性证据</h3><span>{records.length} 条安装或来源声明</span></div>
    <div className="retest-summary"><Metric label="来源记录" value={records.length} /><Metric label="私有来源声明" value={privateSources} /><Metric label="私有源预检缺口" value={privatePreflightGaps} /><Metric label="未锁定版本" value={unpinned} /><Metric label="不安全来源" value={unsafe} /><Metric label="哈希不完整" value={partial} /></div>
    <p className="retest-note">私有源预检只解析配置中的可见性和凭据引用声明，连接状态始终表示“未尝试”；SHA-256 仅用于比较本地字节，发布者字段不构成签名、Registry 身份或发布者真实性验证。</p>
    {!snapshot ? <p>完成一次 AGENT 扫描后显示包来源、安装方式、版本锁定和本地哈希。</p> : <>
      <table className="concise-table"><thead><tr><th>资产 / 主体</th><th>包与版本</th><th>来源 / 安装</th><th>发布者状态</th><th>本地完整性</th></tr></thead><tbody>{pagination.items.length === 0 ? <tr><td colSpan={5} className="empty-cell">当前资产没有可提取的安装来源；配置文件 SHA-256 仍保存在资产快照中。</td></tr> : pagination.items.map(({ asset, item }, index) => <tr key={`${asset.path}-${item.subject}-${index}`}><td><strong>{item.subject}</strong><span className="cell-subtext">{asset.path}</span></td><td><strong>{item.package_name ?? "未声明包名"}</strong><span className="cell-subtext">{item.package_version ?? "未声明版本"} · {agentVersionStatusLabel(item.version_status)}</span>{item.issues.length ? <span className="cell-subtext">问题：{item.issues.map(agentProvenanceIssueLabel).join("、")}</span> : null}</td><td><strong>{agentSourceTypeLabel(item.source_type)}</strong><span className="cell-subtext">{item.source_ref ?? "未声明来源"}</span><span className="cell-subtext">安装：{item.installation_method}</span>{item.source_visibility === "private-declared" ? <><span className="cell-subtext">私有来源声明 · 凭据：{item.authentication_status} · 预检：{item.onboarding_status}</span><span className="cell-subtext">连接：{item.connection_status}（未发起连接）</span></> : null}</td><td>{item.publisher_claim ?? "未声明"}<span className="cell-subtext">{item.publisher_status === "claim-only" ? "仅声明，未验证" : "无发布者声明"}</span></td><td><span className={`severity ${asset.integrity_status === "partial" ? "medium" : "info"}`}>{asset.integrity_status === "recorded" ? "已记录" : "部分记录"}</span><span className="cell-subtext">{truncateText(asset.directory_sha256 ?? asset.file_sha256 ?? "无哈希", 22)}</span><span className="cell-subtext">{asset.directory_sha256 ? "目录 SHA-256" : "文件 SHA-256"}</span></td></tr>)}</tbody></table>
      <Pagination page={pagination.page} pageCount={pagination.pageCount} total={records.length} onPageChange={setPage} />
    </>}
  </section>;
}

function AgentIntelligencePanel({ snapshot }: { snapshot: AgentScanSnapshot | null }) {
  const intelligence = agentSnapshotSection<AgentIntelligence>(snapshot?.intelligence, undefined, "offline-only");
  if (!intelligence) return <section className="retest-panel"><div className="panel-header"><h3>依赖漏洞与恶意包情报</h3><span>等待扫描</span></div><p>完成一次新 AGENT 扫描后，这里会显示包坐标、本地漏洞匹配和可选恶意包情报覆盖。</p></section>;
  const summary = intelligence.summary ?? {};
  const packages = intelligence.packages ?? [];
  return <section className="retest-panel">
    <div className="panel-header"><h3>依赖漏洞与恶意包情报</h3><span>严格离线 · {packages.length} 个包坐标</span></div>
    <p className="agent-time-note">情报快照生成：{formatDateTime(intelligence.generated_at)}</p>
    <div className="retest-summary"><Metric label="本地源已覆盖" value={summary.covered_count ?? 0} /><Metric label="漏洞包" value={summary.vulnerable_package_count ?? 0} /><Metric label="恶意包命中" value={summary.malicious_match_count ?? 0} /><Metric label="包名混淆" value={summary.package_confusion_count ?? 0} /></div>
    <p className="retest-note">“本地源未命中”只表示已配置的离线规则或镜像未匹配该精确版本，不代表组件无漏洞。恶意包和受保护包名检查仅在本地情报文件已配置时有效。</p>
    <table className="compact-table"><thead><tr><th>情报源</th><th>状态</th><th>记录</th><th>更新时间 / 年龄</th></tr></thead><tbody>{Object.entries(intelligence.sources ?? {}).map(([name, source]) => <tr key={name}><td>{agentIntelligenceSourceLabel(name)}<span className="cell-subtext">{source.path}</span></td><td><span className={`severity ${source.status === "invalid" ? "high" : source.status === "available" ? "info" : "low"}`}>{source.status === "available" ? "可用" : source.status === "not_configured" ? "未配置" : "无效"}</span>{source.detail ? <span className="cell-subtext">{source.detail}</span> : null}</td><td>{source.entry_count ?? 0}{source.protected_package_count ? <span className="cell-subtext">受保护包名 {source.protected_package_count}</span> : null}</td><td>{source.updated_at ? formatDateTime(source.updated_at) : "未记录"}<span className="cell-subtext">{typeof source.age_days === "number" ? `${source.age_days} 天` : "年龄未知"}</span></td></tr>)}</tbody></table>
    <table className="concise-table"><thead><tr><th>资产 / 包坐标</th><th>版本与覆盖</th><th>漏洞</th><th>恶意包 / 混淆</th></tr></thead><tbody>{packages.length === 0 ? <tr><td className="empty-cell" colSpan={4}>当前资产没有提取到 npm 或 PyPI 包坐标；Git、容器或来源不明的记录会明确标记为暂不支持。</td></tr> : packages.map((item, index) => <tr key={`${item.asset_path}-${item.subject}-${index}`}><td><strong>{item.package_name}</strong><span className="cell-subtext">{item.ecosystem} · {item.subject}</span><span className="cell-subtext">{item.asset_path}</span>{item.purl ? <span className="cell-subtext">{item.purl}</span> : null}</td><td><span className={`severity ${item.lookup_status === "vulnerable" ? "high" : item.lookup_status === "checked_no_match" ? "info" : "low"}`}>{agentIntelligenceStatusLabel(item.lookup_status)}</span><span className="cell-subtext">{item.package_version ?? "版本未解析"} · {agentVersionStatusLabel(item.version_status)}</span><span className="cell-subtext">{item.coverage_sources.length ? item.coverage_sources.join("、") : "无适用本地覆盖源"}</span></td><td>{item.vulnerabilities.length ? item.vulnerabilities.map((match) => <span className="cell-subtext" key={`${match.source}-${match.id}`}>{match.id ?? "本地记录"} · {match.severity ?? "未知等级"} · {match.source ?? "未知来源"}</span>) : "未记录命中"}</td><td>{item.threats.map((match) => <span className="cell-subtext" key={`${match.source}-${match.id}`}>恶意包：{match.id ?? "本地记录"}</span>)}{item.confusion_signals.map((match) => <span className="cell-subtext" key={`${match.source}-${match.protected_package}`}>疑似混淆：{match.protected_package}（编辑距离 {match.distance}）</span>)}{!item.threats.length && !item.confusion_signals.length ? "未记录命中" : null}</td></tr>)}</tbody></table>
    {intelligence.limitations?.length ? <details className="advanced-details"><summary>查看能力边界</summary><ul>{intelligence.limitations.map((item) => <li key={item}>{agentUiText(item)}</li>)}</ul></details> : null}
  </section>;
}

function AgentDataflowPanel({ snapshot }: { snapshot: AgentScanSnapshot | null }) {
  const [page, setPage] = useState(1);
  const dataflow = agentSnapshotSection<AgentDataflow>(snapshot?.dataflow, "agent-dataflow/v1");
  const paths = dataflow?.paths ?? [];
  const pagination = paginate(paths, page);
  const nodes = new Map((dataflow?.nodes ?? []).map((item) => [item.id, item]));
  useEffect(() => { setPage(1); }, [snapshot?.scan_task_id]);
  if (!dataflow) return <section className="retest-panel"><div className="panel-header"><h3>Prompt → 工具 → 资源路径</h3><span>等待扫描</span></div><p>完成一次新 AGENT 扫描后，这里会显示静态数据流关系、置信度和缺失控制。</p></section>;
  const summary = dataflow.summary ?? {};
  return <section className="retest-panel">
    <div className="panel-header"><h3>Prompt → 工具 → 资源静态路径</h3><span>{paths.length} 条潜在路径 · 未执行目标 Agent</span></div>
    <div className="retest-summary"><Metric label="节点 / 边" value={`${summary.node_count ?? 0} / ${summary.edge_count ?? 0}`} /><Metric label="严重 / 高风险" value={`${summary.critical_path_count ?? 0} / ${summary.high_path_count ?? 0}`} /><Metric label="缺失控制路径" value={summary.unguarded_path_count ?? 0} /><Metric label="保守推断边" value={summary.inferred_edge_count ?? 0} /></div>
    <p className="retest-note">这是配置级静态模型，不是运行时调用记录。高置信表示配置明确声明；低置信表示同项目共存等保守推断。Allowlist 和例外只是治理决策，不会被当成真实运行时防护。</p>
    <table className="concise-table"><thead><tr><th>等级 / 置信度</th><th>路径</th><th>能力与资源</th><th>控制状态</th></tr></thead><tbody>{pagination.items.length === 0 ? <tr><td colSpan={4} className="empty-cell">当前静态声明没有形成可展示的 Prompt→工具→资源路径；这不代表运行时一定不存在数据流。</td></tr> : pagination.items.map((item) => {
      const sequence = item.node_ids.map((id) => nodes.get(id)?.label).filter(Boolean).join(" → ");
      return <tr key={item.id}><td><span className={`severity ${item.severity}`}>{severityLabel(item.severity)}</span><span className="cell-subtext">{agentDataflowConfidenceLabel(item.confidence)}</span><span className="cell-subtext">{item.source_trust === "adversarial-signal" ? "存在可疑指令信号" : "输入信任状态未知"}</span></td><td><strong>{agentUiText(item.title)}</strong><span className="cell-subtext">{sequence || item.id}</span><span className="cell-subtext">Prompt 资产：{item.asset_path}</span>{item.tool_asset_path ? <span className="cell-subtext">工具资产：{item.tool_asset_path}</span> : null}<details className="record-evidence"><summary>查看路径证据</summary><ul>{item.evidence.map((value) => <li key={value}>{agentUiText(value)}</li>)}</ul></details></td><td><strong>{agentCapabilityLabel(item.capability)}</strong><span className="cell-subtext">{item.resource_type}: {item.resource_scope}</span><span className="cell-subtext">审批声明：{agentApprovalLabel(item.approval)}</span></td><td>{item.controls.length ? item.controls.map((control, index) => <span className="cell-subtext" key={`${control.type}-${index}`}>已有：{agentDataflowControlLabel(control.type)}{control.runtime_verified === false ? "（未验证执行）" : ""}</span>) : <span className="cell-subtext">未识别到已声明控制</span>}{item.missing_controls.map((control) => <span className="cell-subtext" key={control}>缺少：{agentDataflowControlLabel(control)}</span>)}</td></tr>;
    })}</tbody></table>
    <Pagination page={pagination.page} pageCount={pagination.pageCount} total={paths.length} onPageChange={setPage} />
    {(dataflow.limitations ?? []).length ? <details className="advanced-details"><summary>查看模型边界</summary><ul>{dataflow.limitations.map((item) => <li key={item}>{agentUiText(item)}</li>)}</ul></details> : null}
  </section>;
}

function AgentOfflineAuditPanel({ snapshot }: { snapshot: AgentScanSnapshot | null }) {
  const audit = agentSnapshotSection<AgentOfflineAudit>(snapshot?.audit, "ai-security-platform.agent-offline-audit/v1");
  if (!audit) return <section className="retest-panel"><div className="panel-header"><h3>AGENT 离线审计草案</h3><span>等待新扫描</span></div><p>完成一次新版本 AGENT 扫描后，这里会显示由现有本地静态证据形成的人工复核候选项。</p></section>;
  const priorityLabel: Record<string, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" };
  const kindLabel: Record<string, string> = { finding: "静态发现", "coverage-gap": "覆盖缺口", "private-source-preflight": "私有来源预检", "static-dataflow": "静态数据流" };
  return <section className="retest-panel">
    <div className="panel-header"><h3>AGENT 离线审计草案</h3><span className="severity info">{audit.summary.review_item_count} 个待人工复核</span></div>
    <p className="agent-time-note">审计草案生成：{formatDateTime(audit.generated_at)}</p>
    <div className="retest-summary"><Metric label="审计模式" value="本地规则草案" /><Metric label="外部模型" value={audit.external_model_invoked ? "已调用" : "未调用"} /><Metric label="活跃发现" value={audit.summary.active_finding_count} /><Metric label="关联信任分" value={`${audit.summary.trust_score} / 100`} /></div>
    <p className="retest-note">该草案只编排当前静态证据的人工复核顺序，不改变 Finding 严重性、治理状态、质量门禁或信任评分；静态路径与来源声明不是运行时观测或可利用性证明。</p>
    <table className="compact-table"><thead><tr><th>优先级</th><th>类型</th><th>复核候选</th><th>证据引用</th><th>状态</th></tr></thead><tbody>{audit.items.length ? audit.items.map((item) => <tr key={item.id}><td><span className={`severity ${item.priority === "critical" || item.priority === "high" ? "high" : item.priority === "medium" ? "medium" : "info"}`}>{priorityLabel[item.priority] ?? item.priority}</span></td><td>{kindLabel[item.kind] ?? item.kind}</td><td><strong>{agentUiText(item.title)}</strong><span className="cell-subtext">{agentUiText(item.rationale)}</span></td><td>{item.evidence_refs.map((value) => <span className="cell-subtext" key={value}>{value}</span>)}</td><td>{item.review_status === "pending-human-review" ? "待人工复核" : agentUiText(item.review_status)}</td></tr>) : <tr><td colSpan={5}>当前静态证据未生成复核候选。</td></tr>}</tbody></table>
    <details className="advanced-details"><summary>查看审计边界与哈希</summary><div className="advanced-details-body"><p>模式：本地确定性静态复核；模型状态：未调用；审计 SHA-256：<code>{audit.audit_sha256}</code></p><ul>{audit.limitations.map((item) => <li key={item}>{agentUiText(item)}</li>)}</ul></div></details>
  </section>;
}

function AgentDeepSeekReviewPanel({ snapshot, loading, onRun }: { snapshot: AgentScanSnapshot | null; loading: boolean; onRun: (confirmationPhrase: string) => Promise<void> }) {
  const audit = agentSnapshotSection<AgentOfflineAudit>(snapshot?.audit, "ai-security-platform.agent-offline-audit/v1");
  const review = agentSnapshotSection<AgentAiReview>(snapshot?.ai_review, "ai-security-platform.agent-ai-review/v1");
  const legacyEnglishReview = Boolean(review && [review.summary, ...review.reviews.flatMap((item) => [item.rationale, ...item.review_questions, ...item.recommended_actions, ...item.limitations])].some(containsEnglishProse));
  const startReview = () => {
    if (!audit || !window.confirm("将向 DeepSeek 发送最多 25 个已脱敏的 AGENT 静态审计候选项；不会发送源码、Prompt、密钥、工具参数或目标数据。是否继续？")) return;
    const phrase = window.prompt("请输入 AGENT_DEEPSEEK_REVIEW 以确认本次 DeepSeek 审计：", "");
    if (phrase !== "AGENT_DEEPSEEK_REVIEW") return window.alert("确认短语不匹配，未发送任何数据。");
    void onRun(phrase);
  };
  if (!audit) return <section className="retest-panel"><div className="panel-header"><h3>AGENT DeepSeek 审计</h3><span>需要扫描</span></div><p>请先完成一次 AGENT 扫描；模型审计只会使用该扫描已经生成的离线审计草案。</p></section>;
  return <section className="retest-panel">
    <div className="panel-header"><h3>AGENT DeepSeek 审计</h3><span className={`severity ${review?.external_model_invoked ? "info" : "low"}`}>{review?.external_model_invoked ? "已生成建议" : "默认未调用"}</span></div>
    <div className="retest-summary"><Metric label="输入候选上限" value="25" /><Metric label="源码 / Prompt" value="不发送" /><Metric label="最大估算费用" value="$0.02" /><Metric label="自动扫描调用" value="关闭" /></div>
    <p className="retest-note">模型只生成待人工复核建议，不能改变 Finding、质量门禁、信任评分或代码。每次调用均需在此页面二次确认；失败时离线审计草案不会被覆盖。</p>
    {!review ? <button className="primary-action" disabled={loading} onClick={startReview}>{loading ? "审计中" : "执行 DeepSeek 审计（需二次确认）"}</button> : legacyEnglishReview ? <><div className="retest-summary"><Metric label="模型" value={review.model} /><Metric label="历史建议" value={review.reviews.length} /><Metric label="耗时" value={`${review.usage.latency_ms} ms`} /><Metric label="估算费用" value={review.usage.estimated_cost_usd === null ? "未知" : `$${review.usage.estimated_cost_usd}`} /></div><div className="agent-localization-notice"><strong>当前批次保存的是旧版英文模型建议</strong><p>为避免机器翻译改变安全语义，页面不直接展示英文原文。重新执行审计后，模型将按简体中文输出；原始历史证据仍保留在扫描快照中。</p><button className="secondary-action" disabled={loading} onClick={startReview}>{loading ? "审计中" : "重新生成中文建议"}</button></div></> : <><div className="retest-summary"><Metric label="模型" value={review.model} /><Metric label="建议数量" value={review.reviews.length} /><Metric label="耗时" value={`${review.usage.latency_ms} ms`} /><Metric label="估算费用" value={review.usage.estimated_cost_usd === null ? "未知" : `$${review.usage.estimated_cost_usd}`} /></div><p className="retest-note">{review.summary || "模型未提供摘要。"}</p><table className="compact-table"><thead><tr><th>候选 ID</th><th>建议优先级</th><th>人工复核理由</th><th>建议动作</th></tr></thead><tbody>{review.reviews.length ? review.reviews.map((item) => <tr key={item.audit_item_id}><td>{item.audit_item_id}</td><td><span className={`severity ${item.review_priority === "critical" || item.review_priority === "high" ? "high" : item.review_priority === "medium" ? "medium" : "info"}`}>{severityLabel(item.review_priority as Severity)}</span></td><td>{item.rationale}<span className="cell-subtext">{item.review_questions.join("；")}</span></td><td>{item.recommended_actions.map((action) => <span className="cell-subtext" key={action}>{action}</span>)}</td></tr>) : <tr><td colSpan={4}>模型未保留可用建议；本地草案仍可人工复核。</td></tr>}</tbody></table><details className="advanced-details"><summary>查看模型审计边界</summary><p>输入 SHA-256：<code>{review.input_sha256}</code></p><ul>{review.limitations.map((item) => <li key={item}>{agentUiText(item)}</li>)}</ul></details></>}
  </section>;
}

function AgentTrustScorePanel({ snapshot }: { snapshot: AgentScanSnapshot | null }) {
  const trust = agentSnapshotSection<AgentTrustScore>(snapshot?.trust_score, "ai-security-platform.agent-trust-score/v1");
  if (!trust) return <section className="retest-panel"><div className="panel-header"><h3>AGENT 可解释信任评分</h3><span>等待新扫描</span></div><p>完成一次新版本 AGENT 扫描后，这里会根据来源、哈希、情报、权限、数据流和运行证据给出可解释评分。</p></section>;
  const gradeLabels: Record<string, string> = { "provisional-high": "静态证据较完整", guarded: "需带控制使用", low: "低信任", untrusted: "不可信", "insufficient-evidence": "证据不足" };
  const confidenceLabels = { low: "低", medium: "中", high: "高" };
  const statusLabels: Record<string, string> = { complete: "证据完整", partial: "证据部分完整", insufficient_evidence: "证据不足", not_applicable: "不适用", missing: "证据缺失", risk_detected: "发现风险路径", preflight_only: "仅完成预检", not_run: "未运行", observed: "已观察", limited_observation: "有限运行观测" };
  const runtimeObserved = Boolean(trust.evidence_summary.target_runtime_observed);
  return <section className="retest-panel">
    <div className="panel-header"><h3>AGENT 可解释信任评分</h3><span className={`severity ${trust.score < 50 ? "high" : trust.score < 75 ? "medium" : "info"}`}>{trust.score} / 100 · {gradeLabels[trust.grade] ?? trust.grade}</span></div>
    <p className="agent-time-note">评分快照生成：{formatDateTime(snapshot?.created_at)}</p>
    <div className="retest-summary"><Metric label="当前分数" value={`${trust.score} / 100`} /><Metric label="证据完整度" value={`${trust.evidence_completeness}%`} /><Metric label="证据置信度" value={confidenceLabels[trust.confidence]} /><Metric label="目标运行证据" value={runtimeObserved ? "已观察" : "尚未观察"} /></div>
    <p className="retest-note">这是现有扫描证据的治理摘要，不是“安全认证”。接受风险不会抹掉技术扣分；误报只取消对应 Finding 的直接扣分，独立的来源、情报、权限或路径证据仍可能扣分。本地情报未命中也不等于组件安全。{runtimeObserved ? `当前评分已纳入目标运行证据，总分上限为 ${trust.score_cap}。` : `当前没有目标 Agent 运行证据，总分最高为 ${trust.score_cap}。`}</p>
    <table className="compact-table"><thead><tr><th>分项</th><th>得分</th><th>证据状态</th><th>扣分依据</th></tr></thead><tbody>{trust.dimensions.map((item) => <tr key={item.id}><td><strong>{item.label}</strong></td><td>{item.score} / {item.max_score}</td><td>{statusLabels[item.status] ?? item.status}</td><td>{item.deductions.length ? item.deductions.map((value) => <span className="cell-subtext" key={value.id}>-{value.points}：{value.detail}{value.count > 1 ? `（${value.count} 项）` : ""}</span>) : <span className="cell-subtext">本分项没有技术扣分</span>}</td></tr>)}</tbody></table>
    {trust.improvements.length ? <div><strong>优先改进建议</strong><ol>{trust.improvements.map((item) => <li key={item.id}><strong>{item.title}</strong>：{item.action}</li>)}</ol></div> : <p>当前没有生成额外改进建议。</p>}
    <details className="advanced-details"><summary>查看评分上限、限制与证据哈希</summary>{trust.score_caps.length ? <ul>{trust.score_caps.map((item) => <li key={item.id}>{agentUiText(item.detail)}</li>)}</ul> : <p>当前没有额外评分上限。</p>}<ul>{trust.limitations.map((item) => <li key={item}>{agentUiText(item)}</li>)}</ul><p>算法：{trust.algorithm_version}；证据摘要 SHA-256：{trust.trust_sha256}</p></details>
  </section>;
}

function AgentRuntimePreflightPanel({ project, snapshot }: { project: Project; snapshot: AgentScanSnapshot | null }) {
  const savedPlan = snapshot?.runtime_validation?.schema ? snapshot.runtime_validation : undefined;
  const [plan, setPlan] = useState<AgentRuntimePlan | null>(savedPlan ?? null);
  const [command, setCommand] = useState(savedPlan?.proposed_command ?? project.sandbox_command ?? "");
  const [image, setImage] = useState(savedPlan?.proposed_image ?? project.sandbox_image ?? "");
  const [timeoutSeconds, setTimeoutSeconds] = useState(savedPlan?.timeout_seconds ?? 10);
  const [confirmed, setConfirmed] = useState(false);
  const [stagingConfirmed, setStagingConfirmed] = useState(false);
  const [stagingResult, setStagingResult] = useState<AgentStagingResult | null>(null);
  const [fixtureStatus, setFixtureStatus] = useState<AgentFixtureStatus | null>(null);
  const [fixtureImage, setFixtureImage] = useState("");
  const [fixtureConfirmed, setFixtureConfirmed] = useState(false);
  const [fixtureEvidence, setFixtureEvidence] = useState<AgentFixtureEvidence | null>(null);
  const [targetStatus, setTargetStatus] = useState<AgentTargetStatus | null>(null);
  const [targetBuildId, setTargetBuildId] = useState("");
  const [targetConfirmed, setTargetConfirmed] = useState(false);
  const [targetPhrase, setTargetPhrase] = useState("");
  const [targetEvidence, setTargetEvidence] = useState<AgentTargetEvidence | null>(savedPlan?.evidence ?? null);
  const [mcpProbeStatus, setMcpProbeStatus] = useState<AgentMcpProbeStatus | null>(null);
  const [mcpProbeBuildId, setMcpProbeBuildId] = useState("");
  const [mcpProbeCandidateId, setMcpProbeCandidateId] = useState("");
  const [mcpProbePhrase, setMcpProbePhrase] = useState("");
  const [mcpProbeConfirmed, setMcpProbeConfirmed] = useState(false);
  const [mcpProbeEvidence, setMcpProbeEvidence] = useState<AgentMcpProbeEvidence | null>(null);
  const [remoteMcpProbeStatus, setRemoteMcpProbeStatus] = useState<AgentRemoteMcpProbeStatus | null>(null);
  const [remoteMcpProbeBuildId, setRemoteMcpProbeBuildId] = useState("");
  const [remoteMcpProbeCandidateId, setRemoteMcpProbeCandidateId] = useState("");
  const [remoteMcpProbePhrase, setRemoteMcpProbePhrase] = useState("");
  const [remoteMcpProbeConfirmed, setRemoteMcpProbeConfirmed] = useState(false);
  const [remoteMcpProbeEvidence, setRemoteMcpProbeEvidence] = useState<AgentRemoteMcpProbeEvidence | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => {
    setPlan(savedPlan ?? null);
    setCommand(savedPlan?.proposed_command ?? project.sandbox_command ?? "");
    setImage(savedPlan?.proposed_image ?? project.sandbox_image ?? "");
    setTimeoutSeconds(savedPlan?.timeout_seconds ?? 10);
    setConfirmed(false);
    setStagingConfirmed(false);
    setStagingResult(null);
    setFixtureConfirmed(false);
    setTargetConfirmed(false);
    setTargetPhrase("");
    setMcpProbeConfirmed(false);
    setMcpProbePhrase("");
    setRemoteMcpProbeConfirmed(false);
    setRemoteMcpProbePhrase("");
    void Promise.all([
      request<AgentFixtureStatus>(`/agent/projects/${project.id}/runtime-fixture-status`).catch(() => null),
      request<AgentFixtureEvidence[]>(`/agent/projects/${project.id}/runtime-fixture-evidence`).catch(() => []),
      request<AgentTargetStatus>(`/agent/projects/${project.id}/runtime-target-status`).catch(() => null),
      request<AgentTargetEvidence[]>(`/agent/projects/${project.id}/runtime-target-evidence`).catch(() => []),
      request<AgentMcpProbeStatus>(`/agent/projects/${project.id}/runtime-mcp-probe-status`).catch(() => null),
      request<AgentMcpProbeEvidence[]>(`/agent/projects/${project.id}/runtime-mcp-probe-evidence`).catch(() => []),
      request<AgentRemoteMcpProbeStatus>(`/agent/projects/${project.id}/runtime-remote-mcp-probe-status`).catch(() => null),
      request<AgentRemoteMcpProbeEvidence[]>(`/agent/projects/${project.id}/runtime-remote-mcp-probe-evidence`).catch(() => []),
    ]).then(([status, evidence, nextTargetStatus, targetEvidenceItems, nextProbeStatus, probeEvidenceItems, nextRemoteProbeStatus, remoteProbeEvidenceItems]) => {
      setFixtureStatus(status);
      setFixtureImage(status?.recommended_image ?? "");
      setFixtureEvidence(evidence[0] ?? null);
      setTargetStatus(nextTargetStatus);
      setTargetBuildId(nextTargetStatus?.builds[0]?.build_id ?? "");
      setTargetEvidence(savedPlan?.evidence ?? targetEvidenceItems[0] ?? null);
      setMcpProbeStatus(nextProbeStatus);
      const probeBuild = nextProbeStatus?.builds.find((item) => item.candidates.some((candidate) => candidate.eligible));
      setMcpProbeBuildId(probeBuild?.build_id ?? "");
      setMcpProbeCandidateId(probeBuild?.candidates.find((candidate) => candidate.eligible)?.candidate_id ?? "");
      setMcpProbeEvidence(probeEvidenceItems[0] ?? null);
      setRemoteMcpProbeStatus(nextRemoteProbeStatus);
      const remoteProbeBuild = nextRemoteProbeStatus?.builds.find((item) => item.candidates.some((candidate) => candidate.eligible));
      setRemoteMcpProbeBuildId(remoteProbeBuild?.build_id ?? "");
      setRemoteMcpProbeCandidateId(remoteProbeBuild?.candidates.find((candidate) => candidate.eligible)?.candidate_id ?? "");
      setRemoteMcpProbeEvidence(remoteProbeEvidenceItems[0] ?? null);
    });
  }, [snapshot?.scan_task_id, project.id]);

  async function runPreflight() {
    setLoading(true); setMessage("");
    try {
      const next = await request<AgentRuntimePlan>(`/agent/projects/${project.id}/runtime-preflight`, {
        method: "POST",
        body: JSON.stringify({ command, image, timeout_seconds: timeoutSeconds, operator_confirmed: confirmed }),
      });
      setPlan(next);
      setStagingConfirmed(false);
      setMessage("预检已刷新；没有创建工作副本、拉取镜像或运行容器。");
    } catch (error) { setMessage(`预检失败：${errorMessage(error)}`); }
    finally { setLoading(false); }
  }

  async function buildStaging() {
    if (!plan || !stagingConfirmed) return;
    setLoading(true); setMessage("");
    try {
      const result = await request<AgentStagingResult>(`/agent/projects/${project.id}/runtime-staging`, {
        method: "POST",
        body: JSON.stringify({ command, image, timeout_seconds: timeoutSeconds, plan_sha256: plan.plan_sha256, operator_confirmed: true }),
      });
      setStagingResult(result);
      setStagingConfirmed(false);
      const nextTargetStatus = await request<AgentTargetStatus>(`/agent/projects/${project.id}/runtime-target-status`).catch(() => null);
      setTargetStatus(nextTargetStatus);
      setTargetBuildId(result.staging.build_id);
      const nextProbeStatus = await request<AgentMcpProbeStatus>(`/agent/projects/${project.id}/runtime-mcp-probe-status`).catch(() => null);
      setMcpProbeStatus(nextProbeStatus);
      const probeBuild = nextProbeStatus?.builds.find((item) => item.build_id === result.staging.build_id);
      setMcpProbeBuildId(probeBuild?.build_id ?? "");
      setMcpProbeCandidateId(probeBuild?.candidates.find((candidate) => candidate.eligible)?.candidate_id ?? "");
      const nextRemoteProbeStatus = await request<AgentRemoteMcpProbeStatus>(`/agent/projects/${project.id}/runtime-remote-mcp-probe-status`).catch(() => null);
      setRemoteMcpProbeStatus(nextRemoteProbeStatus);
      const remoteProbeBuild = nextRemoteProbeStatus?.builds.find((item) => item.build_id === result.staging.build_id);
      setRemoteMcpProbeBuildId(remoteProbeBuild?.build_id ?? "");
      setRemoteMcpProbeCandidateId(remoteProbeBuild?.candidates.find((candidate) => candidate.eligible)?.candidate_id ?? "");
      setMessage("过滤副本已在 D 盘生成并完成哈希复核；没有运行 Agent、容器或工具。");
    } catch (error) { setMessage(`过滤副本生成失败：${errorMessage(error)}`); }
    finally { setLoading(false); }
  }

  async function validateHarmlessFixture() {
    if (!fixtureConfirmed || !fixtureImage) return;
    setLoading(true); setMessage("");
    try {
      const result = await request<AgentFixtureEvidence>(`/agent/projects/${project.id}/runtime-fixture-validation`, {
        method: "POST",
        body: JSON.stringify({ image: fixtureImage, timeout_seconds: Math.min(15, timeoutSeconds), operator_confirmed: true }),
      });
      setFixtureEvidence(result);
      setFixtureConfirmed(false);
      setMessage(`无害夹具策略验收完成：${result.decision === "pass" ? "全部检查通过" : "存在阻断项"}。本次没有运行任何项目 Agent。`);
    } catch (error) { setMessage(`无害夹具验收失败：${errorMessage(error)}`); }
    finally { setLoading(false); }
  }

  async function refreshTargetRuntime() {
    const next = await request<AgentTargetStatus>(`/agent/projects/${project.id}/runtime-target-status`).catch(() => null);
    setTargetStatus(next);
    if (next && !next.builds.some((item) => item.build_id === targetBuildId)) setTargetBuildId(next.builds[0]?.build_id ?? "");
    const nextProbe = await request<AgentMcpProbeStatus>(`/agent/projects/${project.id}/runtime-mcp-probe-status`).catch(() => null);
    setMcpProbeStatus(nextProbe);
    if (nextProbe && !nextProbe.builds.some((item) => item.build_id === mcpProbeBuildId)) {
      const build = nextProbe.builds.find((item) => item.candidates.some((candidate) => candidate.eligible));
      setMcpProbeBuildId(build?.build_id ?? "");
      setMcpProbeCandidateId(build?.candidates.find((candidate) => candidate.eligible)?.candidate_id ?? "");
    }
    const nextRemoteProbe = await request<AgentRemoteMcpProbeStatus>(`/agent/projects/${project.id}/runtime-remote-mcp-probe-status`).catch(() => null);
    setRemoteMcpProbeStatus(nextRemoteProbe);
    if (nextRemoteProbe && !nextRemoteProbe.builds.some((item) => item.build_id === remoteMcpProbeBuildId)) {
      const build = nextRemoteProbe.builds.find((item) => item.candidates.some((candidate) => candidate.eligible));
      setRemoteMcpProbeBuildId(build?.build_id ?? "");
      setRemoteMcpProbeCandidateId(build?.candidates.find((candidate) => candidate.eligible)?.candidate_id ?? "");
    }
  }

  async function validateMcpProbe() {
    const selectedBuild = mcpProbeStatus?.builds.find((item) => item.build_id === mcpProbeBuildId);
    const selectedCandidate = selectedBuild?.candidates.find((item) => item.candidate_id === mcpProbeCandidateId);
    if (!selectedBuild || !selectedCandidate?.eligible || !mcpProbeConfirmed || mcpProbePhrase !== mcpProbeStatus?.authorization_phrase) return;
    setLoading(true); setMessage("");
    try {
      const result = await request<AgentMcpProbeEvidence>(`/agent/projects/${project.id}/runtime-mcp-probe-validation`, {
        method: "POST",
        body: JSON.stringify({
          image: selectedBuild.image, timeout_seconds: selectedBuild.timeout_seconds,
          plan_sha256: selectedBuild.plan_sha256, staging_build_id: selectedBuild.build_id,
          staging_sha256: selectedBuild.staging_sha256, manifest_sha256: selectedBuild.manifest_sha256,
          candidate_id: selectedCandidate.candidate_id, authorization_phrase: mcpProbePhrase,
          operator_confirmed: true,
        }),
      });
      setMcpProbeEvidence(result);
      setMcpProbeConfirmed(false);
      setMcpProbePhrase("");
      setMessage("stdio MCP Server 能力探测已完成；只执行初始化和能力列表，没有调用工具或读取内容。");
    } catch (error) { setMessage(`MCP Server 能力探测失败：${errorMessage(error)}`); }
    finally { setLoading(false); }
  }

  async function validateRemoteMcpProbe() {
    const selectedBuild = remoteMcpProbeStatus?.builds.find((item) => item.build_id === remoteMcpProbeBuildId);
    const selectedCandidate = selectedBuild?.candidates.find((item) => item.candidate_id === remoteMcpProbeCandidateId);
    if (!selectedBuild || !selectedCandidate?.eligible || !remoteMcpProbeConfirmed || remoteMcpProbePhrase !== remoteMcpProbeStatus?.authorization_phrase) return;
    setLoading(true); setMessage("");
    try {
      const result = await request<AgentRemoteMcpProbeEvidence>(`/agent/projects/${project.id}/runtime-remote-mcp-probe-validation`, {
        method: "POST",
        body: JSON.stringify({
          image: selectedBuild.image, timeout_seconds: selectedBuild.timeout_seconds,
          plan_sha256: selectedBuild.plan_sha256, staging_build_id: selectedBuild.build_id,
          staging_sha256: selectedBuild.staging_sha256, manifest_sha256: selectedBuild.manifest_sha256,
          candidate_id: selectedCandidate.candidate_id, authorization_phrase: remoteMcpProbePhrase,
          operator_confirmed: true,
        }),
      });
      setRemoteMcpProbeEvidence(result);
      setRemoteMcpProbeConfirmed(false);
      setRemoteMcpProbePhrase("");
      setMessage("远程 MCP Server 能力探测已完成；未发送配置凭据，只列出公开能力名称。");
    } catch (error) { setMessage(`远程 MCP Server 能力探测失败：${errorMessage(error)}`); }
    finally { setLoading(false); }
  }

  async function validateTargetAgent() {
    const selected = targetStatus?.builds.find((item) => item.build_id === targetBuildId);
    if (!selected || !targetConfirmed || targetPhrase !== targetStatus?.authorization_phrase) return;
    setLoading(true); setMessage("");
    try {
      const result = await request<AgentTargetEvidence>(`/agent/projects/${project.id}/runtime-target-validation`, {
        method: "POST",
        body: JSON.stringify({
          command, image, timeout_seconds: timeoutSeconds,
          plan_sha256: selected.plan_sha256, staging_build_id: selected.build_id,
          staging_sha256: selected.staging_sha256, manifest_sha256: selected.manifest_sha256,
          authorization_phrase: targetPhrase, operator_confirmed: true,
        }),
      });
      setTargetEvidence(result);
      setTargetConfirmed(false);
      setTargetPhrase("");
      setMessage("指定 Agent 受控运行证据已保存；刷新项目数据后，信任评分会显示本次有限运行观测。");
    } catch (error) { setMessage(`指定 Agent 受控运行失败：${errorMessage(error)}`); }
    finally { setLoading(false); }
  }

  if (!plan) return <section className="retest-panel"><div className="panel-header"><h3>AGENT 受控运行预检</h3><span>等待 AGENT 扫描</span></div><p>先执行一次 AGENT 扫描，系统才会将高风险静态路径带入预检计划。本区域不会运行任何命令。</p></section>;
  const summary = plan.summary ?? {};
  const exactPlanConfirmed = plan.checks.some((item) => item.id === "operator-confirmation" && item.status === "pass");
  const selectedTargetBuild = targetStatus?.builds.find((item) => item.build_id === targetBuildId);
  const selectedMcpProbeBuild = mcpProbeStatus?.builds.find((item) => item.build_id === mcpProbeBuildId);
  const selectedMcpProbeCandidate = selectedMcpProbeBuild?.candidates.find((item) => item.candidate_id === mcpProbeCandidateId);
  const selectedRemoteMcpProbeBuild = remoteMcpProbeStatus?.builds.find((item) => item.build_id === remoteMcpProbeBuildId);
  const selectedRemoteMcpProbeCandidate = selectedRemoteMcpProbeBuild?.candidates.find((item) => item.candidate_id === remoteMcpProbeCandidateId);
  const mcpSummary = targetEvidence?.mcp_ledger?.summary;
  const mcpResponses = targetEvidence?.mcp_ledger?.events.filter((item) => item.event_type === "mcp_response") ?? [];
  return <section className="retest-panel">
    <div className="panel-header"><h3>AGENT 受控运行预检</h3><span className={`severity ${targetEvidence?.policy_verified ? "info" : plan.decision === "blocked" ? "high" : "info"}`}>{targetEvidence?.policy_verified ? "已有有限目标运行证据" : plan.decision === "blocked" ? "预检尚未通过" : "等待单独执行批准"}</span></div>
    <div className="retest-summary"><Metric label="通过 / 阻断检查" value={`${Number(summary.pass_count ?? 0)} / ${Number(summary.blocking_count ?? 0)}`} /><Metric label="候选高风险路径" value={Number(summary.candidate_path_count ?? 0)} /><Metric label="敏感文件名命中" value={Number(summary.sensitive_file_count ?? 0)} /><Metric label="预检自身会执行" value={plan.execution_enabled ? "是" : "否"} /></div>
    <p className="retest-note">“只执行安全预检”不会复制文件或联系 Docker。下方只有在你单独勾选确认后，才会把普通文件复制到 D 盘唯一目录并生成哈希清单；它会排除 `.env`、凭据、私钥信号、链接和版本库/构建元数据，绝不直接挂载项目源码。</p>
    <div className="filter-grid"><label>拟执行命令<input value={command} onChange={(event) => { setCommand(event.target.value); setConfirmed(false); setStagingConfirmed(false); }} placeholder="必须由操作人明确选择，不自动推断" /></label><label>本地镜像（必须固定 digest）<input value={image} onChange={(event) => { setImage(event.target.value); setConfirmed(false); setStagingConfirmed(false); }} placeholder="name@sha256:...；预检不会下载" /></label><label>超时秒数<input type="number" min={1} max={30} value={timeoutSeconds} onChange={(event) => { setTimeoutSeconds(Math.max(1, Math.min(30, Number(event.target.value)))); setConfirmed(false); setStagingConfirmed(false); }} /></label><label className="inline-check"><input type="checkbox" checked={confirmed} onChange={(event) => { setConfirmed(event.target.checked); setStagingConfirmed(false); }} />我只确认预检这组命令、镜像和目标；不授权执行</label><button className="primary-action" disabled={loading} onClick={() => void runPreflight()}>{loading ? "预检中" : "只执行安全预检"}</button></div>
    {message ? <p>{message}</p> : null}
    <div className="filter-grid"><label className="inline-check"><input type="checkbox" disabled={!exactPlanConfirmed} checked={stagingConfirmed} onChange={(event) => setStagingConfirmed(event.target.checked)} />我确认创建本计划对应的 D 盘过滤副本；不授权运行 Agent 或容器</label><button className="secondary-action" disabled={loading || !stagingConfirmed || !exactPlanConfirmed} onClick={() => void buildStaging()}>{loading ? "处理中" : "创建并校验过滤副本"}</button>{!exactPlanConfirmed ? <span>请先勾选上方目标确认并重新执行安全预检。</span> : null}</div>
    {stagingResult ? <div className="kv-list"><div><span>过滤副本状态</span><strong>{stagingResult.staging.verification.status === "verified" ? "已校验" : stagingResult.staging.verification.status}</strong><span>{stagingResult.staging.destination_path}</span></div><div><span>复制 / 排除文件</span><strong>{stagingResult.staging.summary.copied_file_count} / {stagingResult.staging.summary.excluded_count}</strong><span>{stagingResult.staging.summary.copied_bytes} 字节；未执行运行时</span></div><div><span>Staging SHA-256</span><strong>{truncateText(stagingResult.staging.staging_sha256, 20)}</strong><span>Manifest：{truncateText(stagingResult.staging.manifest_sha256, 20)}</span></div></div> : null}
    <details className="advanced-details"><summary>无害夹具容器策略验收</summary><p className="retest-note">该操作会真实启动一次仓库自带的固定无害夹具，但不会使用项目源码或运行真实 Agent。镜像必须已在本地且固定 digest，Docker 使用 `--pull=never`；容器结束后会删除，仅在 D 盘保留过滤副本和证据 JSON。</p><div className="filter-grid"><label>本地 Python digest 镜像<select value={fixtureImage} onChange={(event) => { setFixtureImage(event.target.value); setFixtureConfirmed(false); }}><option value="">{fixtureStatus?.available ? "选择本地镜像" : "没有可用的本地 digest 镜像"}</option>{(fixtureStatus?.images ?? []).map((item) => <option key={item.reference} value={item.reference}>{item.reference}（{item.size}）</option>)}</select></label><label className="inline-check"><input type="checkbox" disabled={!fixtureImage} checked={fixtureConfirmed} onChange={(event) => setFixtureConfirmed(event.target.checked)} />我确认只运行仓库无害夹具并验证固定隔离策略</label><button className="secondary-action" disabled={loading || !fixtureConfirmed || !fixtureImage} onClick={() => void validateHarmlessFixture()}>{loading ? "验收中" : "运行无害夹具策略验收"}</button></div>{fixtureStatus ? <p>{agentUiText(fixtureStatus.message)} 未执行任何下载。</p> : <p>正在检查本地镜像；不会自动下载。</p>}{fixtureEvidence ? <div className="kv-list"><div><span>最近验收</span><strong>{fixtureEvidence.decision === "pass" ? "通过" : "阻断"}</strong><span>{formatDateTime(fixtureEvidence.started_at)} · 耗时 {fixtureEvidence.elapsed_ms} ms</span></div><div><span>策略检查</span><strong>{Object.values(fixtureEvidence.policy_checks).filter(Boolean).length} / {Object.keys(fixtureEvidence.policy_checks).length}</strong><span>真实 Agent 执行：未启用</span></div><div><span>证据 SHA-256</span><strong>{truncateText(fixtureEvidence.evidence_sha256, 20)}</strong><span>{fixtureEvidence.evidence_path}</span></div></div> : null}</details>
    <div className="kv-list"><div><span>过滤工作副本</span><strong>{plan.staging.status === "not_created" ? "未创建" : plan.staging.status === "unverified_existing" ? "检测到未绑定副本" : plan.staging.status}</strong><span>{plan.staging.path}</span></div><div><span>未来容器策略</span><strong>禁网 · 只读 · drop-all</strong><span>无宿主环境变量、无宿主控制 Socket</span></div><div><span>计划 SHA-256</span><strong>{truncateText(plan.plan_sha256, 20)}</strong><span>用于未来证据关联</span></div></div>
    <table className="compact-table"><thead><tr><th>状态</th><th>检查</th><th>结果</th><th>处理建议</th></tr></thead><tbody>{plan.checks.map((item) => <tr key={item.id}><td><span className={`severity ${item.status === "block" ? "high" : item.status === "warn" ? "medium" : "info"}`}>{item.status === "pass" ? "通过" : item.status === "warn" ? "警告" : "阻断"}</span></td><td>{agentCheckLabel(item.id)}</td><td>{agentUiText(item.detail)}</td><td>{item.remediation ? agentUiText(item.remediation) : "-"}</td></tr>)}</tbody></table>
    {plan.candidate_dataflow_paths.length ? <details className="advanced-details"><summary>查看计划验证的 {plan.candidate_dataflow_paths.length} 条静态路径</summary><table className="compact-table"><thead><tr><th>风险</th><th>路径</th><th>能力 / 资源</th></tr></thead><tbody>{plan.candidate_dataflow_paths.map((item) => <tr key={item.id}><td><span className={`severity ${item.severity}`}>{severityLabel(item.severity)}</span><span className="cell-subtext">{agentDataflowConfidenceLabel(item.confidence)}</span></td><td>{agentUiText(item.title)}<span className="cell-subtext">{item.asset_path}{item.tool_asset_path ? ` → ${item.tool_asset_path}` : ""}</span></td><td>{agentCapabilityLabel(item.capability)}<span className="cell-subtext">{item.resource_type}: {item.resource_scope}</span></td></tr>)}</tbody></table></details> : null}
    <details className="advanced-details"><summary>从已验证配置自动探测 stdio MCP Server</summary>
      <p className="retest-note">平台直接读取所选 staging 中已哈希的 MCP 配置，并用固定探测客户端启动 Server，无需项目源码主动接入观察器。探测只执行 initialize、tools/list、resources/list 和 prompts/list；不会调用工具、读取资源或获取 Prompt 内容。</p>
      <div className="filter-grid"><label>已验证 staging<select value={mcpProbeBuildId} onChange={(event) => { const build = mcpProbeStatus?.builds.find((item) => item.build_id === event.target.value); setMcpProbeBuildId(event.target.value); setMcpProbeCandidateId(build?.candidates.find((item) => item.eligible)?.candidate_id ?? build?.candidates[0]?.candidate_id ?? ""); setMcpProbeConfirmed(false); setMcpProbePhrase(""); }}><option value="">选择包含 MCP 配置的副本</option>{(mcpProbeStatus?.builds ?? []).filter((item) => item.candidates.length).map((item) => <option key={item.build_id} value={item.build_id}>{item.build_id} · {item.candidates.length} 个候选</option>)}</select></label><label>stdio MCP Server<select value={mcpProbeCandidateId} onChange={(event) => { setMcpProbeCandidateId(event.target.value); setMcpProbeConfirmed(false); setMcpProbePhrase(""); }}><option value="">选择 Server</option>{(selectedMcpProbeBuild?.candidates ?? []).map((item) => <option key={item.candidate_id} value={item.candidate_id}>{item.server_name} · {item.eligible ? "可探测" : `阻断：${item.rejection_reasons.join(", ")}`}</option>)}</select></label><label>输入确认短语 <code>{mcpProbeStatus?.authorization_phrase ?? "PROBE STDIO MCP SERVER"}</code><input value={mcpProbePhrase} onChange={(event) => { setMcpProbePhrase(event.target.value); setMcpProbeConfirmed(false); }} /></label><label className="inline-check"><input type="checkbox" disabled={!selectedMcpProbeCandidate?.eligible || mcpProbePhrase !== mcpProbeStatus?.authorization_phrase || !mcpProbeStatus?.execution_enabled_by_project_policy} checked={mcpProbeConfirmed} onChange={(event) => setMcpProbeConfirmed(event.target.checked)} />我确认只探测这个精确 Server 的公开能力，不调用工具或读取内容</label><button className="secondary-action" disabled={loading || !mcpProbeConfirmed || !selectedMcpProbeCandidate?.eligible || !mcpProbeStatus?.execution_enabled_by_project_policy || mcpProbePhrase !== mcpProbeStatus?.authorization_phrase} onClick={() => void validateMcpProbe()}>{loading ? "探测中" : "运行 MCP 能力探测"}</button></div>
      {selectedMcpProbeCandidate ? <div className="kv-list"><div><span>配置 / Server</span><strong>{selectedMcpProbeCandidate.config_path} / {selectedMcpProbeCandidate.server_name}</strong><span>{selectedMcpProbeCandidate.command_preview ?? "没有可执行命令"}</span></div><div><span>安全资格</span><strong>{selectedMcpProbeCandidate.eligible ? "通过" : "不可探测"}</strong><span>{selectedMcpProbeCandidate.eligible ? "配置无环境注入、远程 URL、Shell 或危险参数" : selectedMcpProbeCandidate.rejection_reasons.join("、")}</span></div></div> : <p>当前 staging 没有可选择的 stdio MCP Server；请先创建包含受支持 MCP 配置的过滤副本。</p>}
      {mcpProbeEvidence ? <><div className="retest-summary"><Metric label="探测结果" value={agentUiText(mcpProbeEvidence.capability_probe.status)} /><Metric label="工具清单" value={mcpProbeEvidence.capability_probe.tool_names.length} /><Metric label="资源 Scheme" value={mcpProbeEvidence.capability_probe.resource_schemes.length} /><Metric label="Prompt 清单" value={mcpProbeEvidence.capability_probe.prompt_names.length} /></div><div className="kv-list"><div><span>Server 身份声明</span><strong>{mcpProbeEvidence.capability_probe.server_name || "未声明"} · {mcpProbeEvidence.capability_probe.server_version || "未声明版本"}</strong><span>协议：{mcpProbeEvidence.capability_probe.protocol_version || "未声明"}</span></div><div><span>工具</span><strong>{mcpProbeEvidence.capability_probe.tool_names.join("、") || "无"}</strong><span>仅列出名称，未调用</span></div><div><span>资源 / Prompt</span><strong>{mcpProbeEvidence.capability_probe.resource_schemes.join("、") || "无"} / {mcpProbeEvidence.capability_probe.prompt_names.join("、") || "无"}</strong><span>未读取资源或 Prompt 内容</span></div><div><span>证据 SHA-256</span><strong>{truncateText(mcpProbeEvidence.evidence_sha256, 20)}</strong><span>{mcpProbeEvidence.evidence_path}</span></div></div><p>这些名称是 Server 返回的声明；事件日志不是密码学认证通道，本次结果也不代表整个 Agent 的运行行为已经验证。</p></> : null}
    </details>
    <details className="advanced-details"><summary>从已验证配置安全探测远程 MCP（Streamable HTTP / SSE）</summary>
      <p className="retest-note">平台只接受 staging 中已哈希的 HTTPS endpoint。执行前重新解析 DNS，任何回环、内网、链路本地、保留地址或云元数据地址都会阻断；连接固定到批准的公网 IP，并禁止跨域重定向。不会使用配置里的 Header、Token、Cookie 或环境变量，也不会调用工具、读取资源或获取 Prompt 内容。</p>
      <div className="filter-grid"><label>已验证 staging<select value={remoteMcpProbeBuildId} onChange={(event) => { const build = remoteMcpProbeStatus?.builds.find((item) => item.build_id === event.target.value); setRemoteMcpProbeBuildId(event.target.value); setRemoteMcpProbeCandidateId(build?.candidates.find((item) => item.eligible)?.candidate_id ?? build?.candidates[0]?.candidate_id ?? ""); setRemoteMcpProbeConfirmed(false); setRemoteMcpProbePhrase(""); }}><option value="">选择包含远程 MCP 配置的副本</option>{(remoteMcpProbeStatus?.builds ?? []).filter((item) => item.candidates.length).map((item) => <option key={item.build_id} value={item.build_id}>{item.build_id} · {item.candidates.length} 个远程候选</option>)}</select></label><label>远程 MCP Server<select value={remoteMcpProbeCandidateId} onChange={(event) => { setRemoteMcpProbeCandidateId(event.target.value); setRemoteMcpProbeConfirmed(false); setRemoteMcpProbePhrase(""); }}><option value="">选择 Server</option>{(selectedRemoteMcpProbeBuild?.candidates ?? []).map((item) => <option key={item.candidate_id} value={item.candidate_id}>{item.server_name} · {item.eligible ? "可探测" : `阻断：${item.rejection_reasons.join(", ")}`}</option>)}</select></label><label>输入确认短语 <code>{remoteMcpProbeStatus?.authorization_phrase ?? "PROBE REMOTE MCP SERVER"}</code><input value={remoteMcpProbePhrase} onChange={(event) => { setRemoteMcpProbePhrase(event.target.value); setRemoteMcpProbeConfirmed(false); }} /></label><label className="inline-check"><input type="checkbox" disabled={!selectedRemoteMcpProbeCandidate?.eligible || remoteMcpProbePhrase !== remoteMcpProbeStatus?.authorization_phrase || !remoteMcpProbeStatus?.execution_enabled_by_project_policy} checked={remoteMcpProbeConfirmed} onChange={(event) => setRemoteMcpProbeConfirmed(event.target.checked)} />我确认仅连接这个精确公网 endpoint 并盘点公开能力；不授权发送凭据或调用能力</label><button className="secondary-action" disabled={loading || !remoteMcpProbeConfirmed || !selectedRemoteMcpProbeCandidate?.eligible || !remoteMcpProbeStatus?.execution_enabled_by_project_policy || remoteMcpProbePhrase !== remoteMcpProbeStatus?.authorization_phrase} onClick={() => void validateRemoteMcpProbe()}>{loading ? "探测中" : "运行远程 MCP 能力探测"}</button></div>
      {selectedRemoteMcpProbeCandidate ? <div className="kv-list"><div><span>配置 / Server</span><strong>{selectedRemoteMcpProbeCandidate.config_path} / {selectedRemoteMcpProbeCandidate.server_name}</strong><span>{selectedRemoteMcpProbeCandidate.endpoint_preview}</span></div><div><span>传输 / 安全资格</span><strong>{selectedRemoteMcpProbeCandidate.transport} · {selectedRemoteMcpProbeCandidate.eligible ? "通过" : "不可探测"}</strong><span>{selectedRemoteMcpProbeCandidate.eligible ? "HTTPS、标准端口、无凭据/自定义 Header；DNS 将在执行前复核" : selectedRemoteMcpProbeCandidate.rejection_reasons.join("、")}</span></div></div> : <p>当前 staging 没有可选择的远程 MCP Server；HTTP、内网地址、URL 查询参数和带认证配置会显示为不可探测。</p>}
      {remoteMcpProbeEvidence ? <><div className="retest-summary"><Metric label="探测结果" value={agentUiText(remoteMcpProbeEvidence.capability_probe.status)} /><Metric label="实际传输" value={agentUiText(remoteMcpProbeEvidence.capability_probe.transport_mode)} /><Metric label="工具清单" value={remoteMcpProbeEvidence.capability_probe.tool_names.length} /><Metric label="目标公网 IP" value={remoteMcpProbeEvidence.network_policy.approved_ips.length} /></div><div className="kv-list"><div><span>Endpoint / Server 声明</span><strong>{remoteMcpProbeEvidence.capability_probe.endpoint}</strong><span>{remoteMcpProbeEvidence.capability_probe.server_name || "未声明"} · 协议 {remoteMcpProbeEvidence.capability_probe.protocol_version || "未声明"}</span></div><div><span>批准的网络目标</span><strong>{remoteMcpProbeEvidence.network_policy.approved_ips.join("、") || "无"}</strong><span>私网与元数据地址已阻断；跨域重定向已阻断</span></div><div><span>工具</span><strong>{remoteMcpProbeEvidence.capability_probe.tool_names.join("、") || "无"}</strong><span>仅列出名称，未调用</span></div><div><span>资源 / Prompt</span><strong>{remoteMcpProbeEvidence.capability_probe.resource_schemes.join("、") || "无"} / {remoteMcpProbeEvidence.capability_probe.prompt_names.join("、") || "无"}</strong><span>未读取资源或 Prompt 内容，未发送配置凭据</span></div><div><span>证据 SHA-256</span><strong>{truncateText(remoteMcpProbeEvidence.evidence_sha256, 20)}</strong><span>{remoteMcpProbeEvidence.evidence_path}</span></div></div><p>这份证据只证明该 endpoint 在本次无凭据连接中返回了这些名称，不验证其真实实现、认证后能力或整个 Agent 的安全性。</p></> : null}
    </details>
    <details className="advanced-details"><summary>指定项目 Agent 受控运行（高风险，默认关闭）</summary>
      <p className="retest-note">这里会真实启动所选 staging 中的 Agent。服务器会重新核验扫描批次、计划、命令指纹、镜像 digest、staging/manifest 哈希和 Docker 隔离配置；使用 `--pull=never`，不会下载镜像。对于使用平台 stdio 观察器的 MCP 目标，可记录脱敏的方法调用账本及 MCP Server 子进程；逐文件访问、系统级子进程和网络尝试目的地仍未插桩。</p>
      <div className="retest-summary"><Metric label="项目执行开关" value={targetStatus?.execution_enabled_by_project_policy ? "已启用" : "默认关闭"} /><Metric label="可执行绑定副本" value={targetStatus?.builds.length ?? 0} /><Metric label="最近策略验证" value={targetEvidence?.policy_verified ? "通过" : targetEvidence ? "需关注" : "尚未运行"} /><Metric label="MCP 调用账本" value={Number(mcpSummary?.request_count ?? 0)} /></div>
      <div className="filter-grid"><label>绑定的 D 盘 staging<select value={targetBuildId} onChange={(event) => { setTargetBuildId(event.target.value); setTargetConfirmed(false); setTargetPhrase(""); }}><option value="">选择已验证副本</option>{(targetStatus?.builds ?? []).map((item) => <option key={item.build_id} value={item.build_id}>{item.build_id} · {item.file_count} 文件 · {formatDateTime(item.created_at)}</option>)}</select></label><label>固定绑定镜像<input value={selectedTargetBuild?.image ?? ""} readOnly placeholder="由 staging 清单绑定" /></label><label>输入确认短语 <code>{targetStatus?.authorization_phrase ?? "RUN ISOLATED AGENT"}</code><input value={targetPhrase} onChange={(event) => { setTargetPhrase(event.target.value); setTargetConfirmed(false); }} /></label><label className="inline-check"><input type="checkbox" disabled={!selectedTargetBuild || targetPhrase !== targetStatus?.authorization_phrase || !targetStatus?.execution_enabled_by_project_policy} checked={targetConfirmed} onChange={(event) => setTargetConfirmed(event.target.checked)} />我确认真实运行这个精确副本、命令和镜像；理解当前插桩仍有限</label><button className="secondary-action" disabled={loading || !targetConfirmed || !selectedTargetBuild || targetPhrase !== targetStatus?.authorization_phrase || !targetStatus?.execution_enabled_by_project_policy} onClick={() => void validateTargetAgent()}>{loading ? "运行中" : "运行所选真实 Agent"}</button><button className="secondary-action" disabled={loading} onClick={() => void refreshTargetRuntime()}>刷新执行状态</button></div>
      {!targetStatus?.execution_enabled_by_project_policy ? <p>项目策略仍保持默认关闭。只有在上方“项目扫描策略”明确开启并保存后，本按钮才可能使用；开启策略本身不会运行 Agent。</p> : null}
      {selectedTargetBuild && (command.trim() !== plan.proposed_command?.trim() || image.trim() !== selectedTargetBuild.image || timeoutSeconds !== selectedTargetBuild.timeout_seconds) ? <p className="report-error">当前命令、镜像或超时与所选 staging 的绑定可能不同，服务器将拒绝执行。请重新预检并创建新副本。</p> : null}
      {targetEvidence ? <><div className="kv-list"><div><span>最近目标证据</span><strong>{targetEvidence.decision === "pass" ? "策略通过" : "需要关注"}</strong><span>{formatDateTime(targetEvidence.started_at)} 至 {formatDateTime(targetEvidence.finished_at)} · 耗时 {targetEvidence.elapsed_ms} ms</span></div><div><span>退出 / 超时 / 清理</span><strong>{targetEvidence.container.exit_code ?? "无"} / {targetEvidence.container.timed_out ? "是" : "否"} / {targetEvidence.container.removed_after_run ? "已删除" : "失败"}</strong><span>工作区保持不变：{targetEvidence.staging.unchanged_after_run ? "是" : "否"}</span></div><div><span>证据 SHA-256</span><strong>{truncateText(targetEvidence.evidence_sha256, 20)}</strong><span>{targetEvidence.evidence_path}</span></div></div><details><summary>查看运行观测覆盖</summary><div className="kv-list">{Object.entries(targetEvidence.telemetry_coverage).map(([key, value]) => <div key={key}><span>{agentUiText(key)}</span><strong>{agentUiText(value)}</strong></div>)}</div><p>“未观察”不代表行为不可能发生；当前没有展示 Agent 标准输出，以降低敏感信息二次暴露风险。</p></details>{targetEvidence.mcp_ledger ? <details><summary>MCP stdio 调用账本（{Number(mcpSummary?.request_count ?? 0)} 次请求）</summary><div className="retest-summary"><Metric label="成功响应" value={Number(mcpSummary?.successful_response_count ?? 0)} /><Metric label="工具调用" value={Number(mcpSummary?.tool_call_count ?? 0)} /><Metric label="资源读取" value={Number(mcpSummary?.resource_read_count ?? 0)} /><Metric label="Prompt 获取" value={Number(mcpSummary?.prompt_get_count ?? 0)} /></div>{mcpResponses.length ? <table className="compact-table"><thead><tr><th>方法</th><th>目标</th><th>结果 / 耗时</th><th>事件哈希</th></tr></thead><tbody>{mcpResponses.map((item) => <tr key={item.event_id}><td>{item.method ?? "-"}</td><td>{item.subject_kind ?? "-"}: {item.subject ?? "-"}</td><td>{item.outcome ?? "-"} / {item.duration_ms ?? 0} ms</td><td>{truncateText(item.event_sha256, 16)}</td></tr>)}</tbody></table> : <p>本次没有收到可验证的 MCP 响应事件。</p>}<p>账本不保存 params、result 或标准输出内容。事件格式与哈希已校验，但日志通道不是密码学认证通道，恶意目标仍可能伪造同类记录。</p></details> : null}</> : null}
    </details>
    <p>{agentUiText(plan.next_action)}</p>
    <details className="advanced-details"><summary>查看运行证据边界</summary><p>当前可记录主进程、工作区前后完整性、适配 stdio 观察器的 MCP 方法调用与 MCP Server 子进程，以及单个远程 MCP endpoint 的受控能力清单和实际公网目标。逐文件访问、系统级子进程、整个 Agent 的透明网络目的地和认证后远程能力仍未插桩；每条静态路径继续区分“已观察”与“未插桩”，不会把“未观察”写成“不可利用”。</p><p>证据脱敏：{plan.evidence_template.redaction.applied ? "启用" : "未启用"}；保存密钥值：{plan.evidence_template.redaction.secret_values_stored ? "是" : "否"}。</p></details>
  </section>;
}

function AgentPermissionMatrixPanel({ snapshot }: { snapshot: AgentScanSnapshot | null }) {
  const [filters, setFilters] = useState({ keyword: "", capability: "all", risk: "all", approval: "all" });
  const [page, setPage] = useState(1);
  const permissions = snapshot?.permissions ?? [];
  const filtered = permissions.filter((permission) => {
    const keyword = filters.keyword.trim().toLowerCase();
    const haystack = `${permission.asset_path} ${permission.subject} ${permission.capability} ${permission.scope} ${permission.source}`.toLowerCase();
    return (!keyword || haystack.includes(keyword))
      && (filters.capability === "all" || permission.capability === filters.capability)
      && (filters.risk === "all" || permission.risk_level === filters.risk)
      && (filters.approval === "all" || permission.approval === filters.approval);
  });
  const pagination = paginate(filtered, page);
  const unknownApproval = permissions.filter((item) => item.approval === "unknown").length;
  const elevated = permissions.filter((item) => ["critical", "high"].includes(item.risk_level)).length;
  useEffect(() => { setPage(1); }, [filters.keyword, filters.capability, filters.risk, filters.approval]);
  return <section className="retest-panel">
    <div className="panel-header"><h3>能力与权限矩阵</h3><span>{permissions.length} 条声明边界</span></div>
    <div className="retest-summary"><Metric label="权限总数" value={permissions.length} /><Metric label="严重 / 高风险" value={elevated} /><Metric label="审批未知" value={unknownApproval} /><Metric label="涉及资产" value={new Set(permissions.map((item) => item.asset_path)).size} /></div>
    <p className="retest-note">矩阵来自静态配置声明，表示潜在权限边界；没有真实连接或执行对应 Agent、MCP Server、插件与工具。</p>
    <ModuleFilterBar><input value={filters.keyword} onChange={(event) => setFilters({ ...filters, keyword: event.target.value })} placeholder="搜索主体、能力、资源范围或配置路径" /><SimpleFilter value={filters.capability} label="全部能力" options={uniqueValues(permissions.map((item) => item.capability))} format={agentCapabilityLabel} onChange={(value) => setFilters({ ...filters, capability: value })} /><SimpleFilter value={filters.risk} label="全部风险" options={["critical", "high", "medium", "low", "info"]} format={severityLabel} onChange={(value) => setFilters({ ...filters, risk: value })} /><SimpleFilter value={filters.approval} label="全部审批状态" options={["required", "not-required", "unknown"]} format={agentApprovalLabel} onChange={(value) => setFilters({ ...filters, approval: value })} /></ModuleFilterBar>
    <table className="concise-table"><thead><tr><th>资产 / 主体</th><th>能力</th><th>资源范围</th><th>审批 / 风险</th></tr></thead><tbody>{pagination.items.length === 0 ? <tr><td className="empty-cell" colSpan={4}>当前资产没有可展示的权限声明。</td></tr> : pagination.items.map((permission) => <tr key={`${permission.asset_path}-${permission.subject}-${permission.source}-${permission.capability}-${permission.scope}`}><td><strong>{permission.subject}</strong><span className="cell-subtext">{permission.asset_path}</span><span className="cell-subtext">配置：{permission.source}</span></td><td><strong>{agentCapabilityLabel(permission.capability)}</strong><span className="cell-subtext">{agentAccessLabel(permission.access)}</span></td><td><strong>{permission.scope}</strong><span className="cell-subtext">{permission.resource_type}</span></td><td><span className={`severity ${permission.risk_level}`}>{severityLabel(permission.risk_level as Severity)}</span><span className="cell-subtext">{agentApprovalLabel(permission.approval)}</span></td></tr>)}</tbody></table>
    <Pagination page={pagination.page} pageCount={pagination.pageCount} total={filtered.length} onPageChange={setPage} />
  </section>;
}

function AgentSemanticDiffPanel({ diff }: { diff: AgentScanDiff | null }) {
  if (!diff?.has_comparison) return <section className="retest-panel"><div className="panel-header"><h3>资产、来源与权限变更</h3><span>等待第二次扫描</span></div><p>至少完成两个 AGENT 扫描批次后，系统才会显示资产、来源、SHA-256 和权限边界变化。</p></section>;
  const changes = diff.summary;
  return <section className="retest-panel">
    <div className="panel-header"><h3>最近资产与权限语义差异</h3><span>{diff.base_scan_id?.slice(0, 8)} → {diff.target_scan_id.slice(0, 8)}</span></div>
    <div className="retest-summary"><Metric label="新增 / 移除资产" value={`${changes.assets_added} / ${changes.assets_removed}`} /><Metric label="来源变化" value={changes.source_changes} /><Metric label="完整性变化" value={changes.integrity_changes} /><Metric label="权限扩大 / 收缩 / 变化" value={`${changes.permissions_added} / ${changes.permissions_removed} / ${changes.permissions_changed}`} /></div>
    {diff.assets.length ? <details className="advanced-details"><summary>查看 {diff.assets.length} 条资产变化</summary><table className="compact-table"><thead><tr><th>变化</th><th>资产</th><th>变化字段</th></tr></thead><tbody>{diff.assets.map((item) => <tr key={item.identity}><td>{item.change_type === "added" ? "新增" : item.change_type === "removed" ? "移除" : "配置变化"}</td><td>{item.path}<span className="cell-subtext">{agentAssetTypeLabel(item.asset_type)}</span></td><td>{item.changes.map((field) => AGENT_DIFF_FIELD_LABELS[field] ?? field).join("、")}</td></tr>)}</tbody></table></details> : null}
    {diff.permissions.length ? <details className="advanced-details"><summary>查看 {diff.permissions.length} 条权限变化</summary><table className="compact-table"><thead><tr><th>方向</th><th>主体 / 能力</th><th>资源范围</th><th>审批</th></tr></thead><tbody>{diff.permissions.map((item) => <tr key={item.identity}><td><span className={`severity ${item.direction === "expanded" ? "high" : item.direction === "reduced" ? "low" : "info"}`}>{item.direction === "expanded" ? "权限扩大" : item.direction === "reduced" ? "权限收缩" : "边界变化"}</span></td><td>{item.permission.subject}<span className="cell-subtext">{agentCapabilityLabel(item.permission.capability)} · {agentAccessLabel(item.permission.access)}</span></td><td>{item.permission.scope}<span className="cell-subtext">{item.permission.asset_path}</span></td><td>{agentApprovalLabel(item.permission.approval)}</td></tr>)}</tbody></table></details> : null}
    {!diff.assets.length && !diff.permissions.length ? <p>最近两个批次的资产和权限边界没有变化。</p> : null}
  </section>;
}

function AgentOfflineAuditHistoryPanel({ diff }: { diff: AgentOfflineAuditDiff | null }) {
  if (!diff) return <section className="retest-panel"><div className="panel-header"><h3>离线审计草案批次对比</h3><span>等待扫描</span></div><p>完成一次包含离线审计草案的 AGENT 扫描后，这里会显示与上一兼容批次的候选项对比。</p></section>;
  if (!diff.has_comparison) return <section className="retest-panel"><div className="panel-header"><h3>离线审计草案批次对比</h3><span>暂不可比较</span></div><p>{diff.comparison_status === "base-audit-not-available" ? "上一扫描批次没有兼容的离线审计草案，因此当前候选不会被标记为新增。" : "当前扫描批次没有兼容的离线审计草案，因此未生成候选项对比。"}</p><details className="advanced-details"><summary>查看能力边界</summary><ul>{diff.limitations.map((item) => <li key={item}>{agentUiText(item)}</li>)}</ul></details></section>;
  const resultLabel: Record<string, string> = { new: "新增候选", "still-pending": "持续待人工复核", "not-current-candidate": "当前未再生成候选" };
  const kindLabel: Record<string, string> = { finding: "静态发现", "coverage-gap": "覆盖缺口", "private-source-preflight": "私有来源预检", "static-dataflow": "静态数据流" };
  return <section className="retest-panel">
    <div className="panel-header"><h3>离线审计草案批次对比</h3><span>{diff.base_scan_id?.slice(0, 8)} → {diff.target_scan_id.slice(0, 8)}</span></div>
    <div className="retest-summary"><Metric label="新增候选" value={diff.summary.new_count} /><Metric label="持续待人工复核" value={diff.summary.still_pending_count} /><Metric label="当前未再生成候选" value={diff.summary.not_current_candidate_count} /><Metric label="外部模型" value="未调用" /></div>
    <p className="retest-note">“当前未再生成候选”仅表示最新静态证据未产生同一候选项，不表示风险已修复、系统安全、运行时行为不存在或不可利用；候选内容或证据引用变化会显示为新增与旧候选不再出现，必须人工判读。</p>
    <details className="advanced-details"><summary>查看 {diff.items.length} 条候选项对比</summary><table className="compact-table"><thead><tr><th>对比状态</th><th>优先级 / 类型</th><th>候选项</th><th>证据引用</th></tr></thead><tbody>{diff.items.map((item) => <tr key={`${item.result}-${item.id}`}><td><span className={`severity ${item.result === "new" ? "high" : item.result === "still-pending" ? "medium" : "info"}`}>{resultLabel[item.result] ?? item.result}</span></td><td><span className={`severity ${item.priority === "critical" || item.priority === "high" ? "high" : item.priority === "medium" ? "medium" : "info"}`}>{item.priority}</span><span className="cell-subtext">{kindLabel[item.kind] ?? item.kind}</span></td><td>{item.title}</td><td>{item.evidence_refs.map((value) => <span className="cell-subtext" key={value}>{value}</span>)}</td></tr>)}</tbody></table></details>
    <details className="advanced-details"><summary>查看能力边界</summary><ul>{diff.limitations.map((item) => <li key={item}>{agentUiText(item)}</li>)}</ul></details>
  </section>;
}

type AgentWorkspaceTab = "overview" | "risks" | "assets" | "validation" | "governance";
type AgentAssetWorkspaceTab = "coverage" | "inventory" | "paths";

function AgentWorkspaceNavigation({ active, onChange }: { active: AgentWorkspaceTab; onChange: (value: AgentWorkspaceTab) => void }) {
  const items: Array<[AgentWorkspaceTab, string, string]> = [
    ["overview", "概览", "态势与下一步"],
    ["risks", "风险", "发现与复测"],
    ["assets", "资产与边界", "覆盖、权限与路径"],
    ["validation", "动态验证", "预检与受控探测"],
    ["governance", "策略与交付", "门禁、例外与报告"],
  ];
  return <nav className="agent-workspace-tabs" aria-label="AGENT 工作区">{items.map(([key, label, description]) => <button type="button" className={active === key ? "active" : ""} aria-current={active === key ? "page" : undefined} onClick={() => onChange(key)} key={key}><strong>{label}</strong><span>{description}</span></button>)}</nav>;
}

function AgentAssetWorkspaceNavigation({ active, onChange }: { active: AgentAssetWorkspaceTab; onChange: (value: AgentAssetWorkspaceTab) => void }) {
  return <div className="agent-segmented-tabs" role="tablist" aria-label="AGENT 资产视图">
    <button type="button" role="tab" aria-selected={active === "coverage"} className={active === "coverage" ? "active" : ""} onClick={() => onChange("coverage")}>扫描覆盖</button>
    <button type="button" role="tab" aria-selected={active === "inventory"} className={active === "inventory" ? "active" : ""} onClick={() => onChange("inventory")}>资产与权限</button>
    <button type="button" role="tab" aria-selected={active === "paths"} className={active === "paths" ? "active" : ""} onClick={() => onChange("paths")}>风险路径</button>
  </div>;
}

function AgentOverviewWorkspace({ findings, history, snapshot, onOpenTab }: { findings: Finding[]; history: AgentScanHistoryItem[]; snapshot: AgentScanSnapshot | null; onOpenTab: (value: AgentWorkspaceTab) => void }) {
  const latest = history[0];
  const trust = snapshot?.trust_score;
  const gate = snapshot?.quality_gate;
  const paths = snapshot?.dataflow?.paths ?? [];
  const priorityFindings = [...findings].sort((left, right) => severityRank(right.severity) - severityRank(left.severity)).slice(0, 5);
  const assetTypes = latest?.coverage.asset_types ?? {};
  const instructionAssets = Object.entries(assetTypes).filter(([key]) => ["instruction", "instructions", "prompt", "skill"].some((item) => key.toLowerCase().includes(item))).reduce((sum, [, value]) => sum + value, 0);
  const protocolAssets = Object.entries(assetTypes).filter(([key]) => ["mcp", "tool"].some((item) => key.toLowerCase().includes(item))).reduce((sum, [, value]) => sum + value, 0);
  const pluginAssets = Object.entries(assetTypes).filter(([key]) => ["plugin", "extension"].some((item) => key.toLowerCase().includes(item))).reduce((sum, [, value]) => sum + value, 0);
  const highPaths = paths.filter((item) => item.severity === "critical" || item.severity === "high").length;
  const runtimeObserved = Boolean(snapshot?.runtime_validation?.evidence?.policy_verified);
  const nextAction = trust?.improvements?.[0]?.action ?? (priorityFindings.length ? "优先复核高风险 Finding，并确认权限与资源范围是否符合项目用途。" : "当前没有风险 Finding；请确认扫描覆盖和适配边界后再形成结论。");
  return <section className="agent-overview-workspace">
    <div className="agent-overview-grid">
      <article className="agent-trust-hero"><div className="agent-trust-score"><strong>{trust?.score ?? "-"}</strong><span>/ {trust?.score_cap ?? 100}</span></div><div><span>可解释信任评分</span><h3>{trust ? agentTrustGradeLabel(trust.grade) : "等待新扫描"}</h3><p>{trust ? `证据完整度 ${trust.evidence_completeness}% · ${agentConfidenceLabel(trust.confidence)}置信度` : "完成扫描后，根据来源、权限、路径和运行证据形成评分。"}</p></div><button type="button" className="secondary-action" onClick={() => onOpenTab("assets")}>查看评分依据</button></article>
      <article className={`agent-gate-card ${gate?.decision === "block" ? "blocked" : "ready"}`}><span>质量门禁</span><strong>{gate?.decision === "block" ? "当前阻断" : gate?.decision === "pass" ? "当前通过" : "等待裁决"}</strong><p>{agentUiText(gate?.reasons?.[0] ?? "门禁结论来自最近一次扫描快照。")}</p><button type="button" onClick={() => onOpenTab("governance")}>查看策略</button></article>
    </div>
    <section className="agent-section-card"><div className="agent-section-heading"><div><span>扫描覆盖</span><h3>PPT 三类检查面，一眼确认覆盖情况</h3></div><button type="button" className="text-action" onClick={() => onOpenTab("assets")}>查看全部资产</button></div><div className="agent-coverage-cards"><article><i>01</i><span>指令与 Prompt</span><strong>{instructionAssets}</strong><small>指令文件、Prompt、Skill</small></article><article><i>02</i><span>MCP 与工具</span><strong>{protocolAssets}</strong><small>工具协议、能力与资源声明</small></article><article><i>03</i><span>插件与来源</span><strong>{pluginAssets}</strong><small>插件扩展、安装来源与完整性</small></article><article className={runtimeObserved ? "observed" : "conditional"}><i>04</i><span>运行证据</span><strong>{runtimeObserved ? "已观察" : "有条件"}</strong><small>{runtimeObserved ? "存在有限目标运行证据" : "需要独立预检与明确确认"}</small></article></div></section>
    <div className="agent-overview-columns">
      <section className="agent-section-card"><div className="agent-section-heading"><div><span>优先风险</span><h3>先处理最影响当前项目的事项</h3></div><button type="button" className="text-action" onClick={() => onOpenTab("risks")}>全部 {findings.length} 条</button></div>{priorityFindings.length ? <div className="agent-priority-list">{priorityFindings.map((finding) => <button type="button" onClick={() => onOpenTab("risks")} key={finding.id}><span className={`severity ${finding.severity}`}>{severityLabel(finding.severity)}</span><div><strong>{agentUiText(findingTitle(finding))}</strong><small>{finding.file_path ?? "项目级问题"} · {agentCategoryLabel(finding.ai_review?.category ?? "unknown")}</small></div><ArrowRight size={16} /></button>)}</div> : <div className="agent-empty-state">当前批次没有风险 Finding。请继续确认资产覆盖和未验证边界。</div>}</section>
      <aside className="agent-next-action"><span>建议下一步</span><h3>{highPaths ? `先处理 ${highPaths} 条高风险静态路径` : priorityFindings.length ? "完成风险人工复核" : "确认覆盖边界"}</h3><p>{nextAction}</p><div><button type="button" className="primary-action" onClick={() => onOpenTab(highPaths ? "assets" : priorityFindings.length ? "risks" : "assets")}>开始处理</button><button type="button" className="secondary-action" onClick={() => onOpenTab("validation")}>动态验证</button></div><small>静态路径不是运行时事实；证据不足时保持未验证。</small></aside>
    </div>
  </section>;
}

function FindingModuleGovernance({ project, moduleKey, findings, validations, evidence, graph, comparison, scanHistory = [], agentSnapshot = null, agentScanDiff = null, agentAuditDiff = null, loading, onRunReview, onRunAgentAiReview, onRun, onUpdateFinding, afterMetrics }: { project?: Project; moduleKey: "sast" | "agent"; findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; graph: EvidenceGraph | null; comparison: FindingRetestComparison | null; scanHistory?: AgentScanHistoryItem[]; agentSnapshot?: AgentScanSnapshot | null; agentScanDiff?: AgentScanDiff | null; agentAuditDiff?: AgentOfflineAuditDiff | null; loading: boolean; onRunReview?: () => Promise<void>; onRunAgentAiReview?: (confirmationPhrase: string) => Promise<void>; onRun: () => Promise<void>; onUpdateFinding: (findingId: string, patch: Partial<Pick<Finding, "status">>) => Promise<void>; afterMetrics?: React.ReactNode }) {
  const [filters, setFilters] = useState({ keyword: "", severity: "all", status: "all", category: "all" });
  const [page, setPage] = useState(1);
  const [agentTab, setAgentTab] = useState<AgentWorkspaceTab>("overview");
  const [agentAssetTab, setAgentAssetTab] = useState<AgentAssetWorkspaceTab>("coverage");
  const high = findings.filter((item) => item.severity === "critical" || item.severity === "high").length;
  const open = findings.filter((item) => ["open", "pending", "confirmed"].includes(item.status)).length;
  const latestAgentScan = moduleKey === "agent" ? scanHistory[0] : null;
  const reviewed = findings.filter((item) => moduleKey === "agent" ? item.ai_review?.review_status === "reviewed" : Boolean(item.ai_review)).length;
  const pendingReview = moduleKey === "agent" ? findings.length - reviewed : reviewed;
  const filtered = findings.filter((item) => {
    const keyword = filters.keyword.trim().toLowerCase();
    const category = item.ai_review?.category ?? "unknown";
    return (!keyword || `${item.title} ${item.file_path ?? ""} ${item.rule_id} ${item.evidence ?? ""}`.toLowerCase().includes(keyword))
      && (filters.severity === "all" || item.severity === filters.severity)
      && (filters.status === "all" || normalizeFindingStatus(item.status) === filters.status)
      && (filters.category === "all" || category === filters.category);
  });
  const pagination = paginate(filtered, page);
  useEffect(() => { setPage(1); }, [filters.keyword, filters.severity, filters.status, filters.category]);
  useEffect(() => { if (moduleKey === "agent") { setAgentTab("overview"); setAgentAssetTab("coverage"); } }, [moduleKey, project?.id]);
  const commonAdvanced = <details className="advanced-details"><summary>查看高级分析与复核信息</summary><div className="advanced-details-body"><div className="advanced-summary-grid"><div><span>风险分类</span><KeyValue data={countBy(findings.map((item) => ({ category: item.ai_review?.category ?? "unknown" })), "category")} formatKey={moduleKey === "agent" ? agentCategoryLabel : (value) => value} /></div><div><span>严重等级</span><KeyValue data={countBy(findings, "severity")} formatKey={severityLabel} /></div></div>{moduleKey === "sast" ? <section className="advanced-inline-action"><div><strong>SAST Agent 复核</strong><span>启用 DeepSeek 后执行真实七角色审计；未启用时使用本地规则化复核。修复内容始终只保存为人工评审草案，不会直接修改源码。</span></div><button className="secondary-action" disabled={loading || findings.length === 0} onClick={() => void onRunReview?.()}>{loading ? "复核中" : "执行 Agent 复核"}</button></section> : <section className="advanced-inline-action"><div><strong>AGENT DeepSeek 审计边界</strong><span>模型只接收受限脱敏静态证据，不能修改风险结论或替代人工审查。指定目标运行仍须满足项目开关、精确绑定和二次确认。</span></div></section>}</div></details>;
  if (moduleKey === "sast") return <ModuleGovernanceShell moduleKey={moduleKey} lastStatus={findings.length ? "completed" : null} metrics={[["问题总数", findings.length], ["严重 / 高危", high], ["待处理", open], ["已复核", reviewed]]} action={high ? `优先处理 ${high} 个严重或高危问题，确认影响后分配整改负责人。` : findings.length ? "逐项确认中低风险问题，记录误报或修复结论。" : "当前没有检测结果，请先在安全检测中执行该模块。"} loading={loading} onRun={onRun} afterMetrics={afterMetrics}><ModuleFilterBar><input value={filters.keyword} onChange={(event) => setFilters({ ...filters, keyword: event.target.value })} placeholder="搜索风险、文件或规则" /><SimpleFilter value={filters.severity} label="全部等级" options={["critical", "high", "medium", "low", "info"]} format={severityLabel} onChange={(value) => setFilters({ ...filters, severity: value })} /><SimpleFilter value={filters.status} label="全部处理状态" options={FINDING_WORKFLOW_STATUSES} format={(value) => statusLabel(value as FindingStatus)} onChange={(value) => setFilters({ ...filters, status: value })} /><SimpleFilter value={filters.category} label="全部风险分类" options={uniqueValues(findings.map((item) => item.ai_review?.category ?? "unknown"))} onChange={(value) => setFilters({ ...filters, category: value })} /></ModuleFilterBar><ConciseFindingTable findings={pagination.items} validations={validations} evidence={evidence} graph={graph} onUpdateFinding={onUpdateFinding} /><Pagination page={pagination.page} pageCount={pagination.pageCount} total={filtered.length} onPageChange={setPage} /><RetestComparisonPanel comparison={comparison} />{commonAdvanced}</ModuleGovernanceShell>;
  return <ModuleGovernanceShell moduleKey="agent" lastStatus={latestAgentScan?.status ?? null} metrics={[["已识别资产", latestAgentScan?.coverage.discovered_asset_count ?? 0], ["问题总数", findings.length], ["严重 / 高危", high], ["待人工复核", pendingReview]]} action={high ? `优先处理 ${high} 个严重或高危问题，确认影响后分配整改负责人。` : findings.length ? "逐项确认中低风险问题，记录误报或修复结论。" : latestAgentScan?.status === "completed" ? "本批次已完成；请查看覆盖情况确认扫描边界。" : "当前没有检测结果，请先执行 AGENT 扫描。"} loading={loading} onRun={onRun} afterMetrics={afterMetrics}>
    <div className="agent-workspace"><AgentWorkspaceNavigation active={agentTab} onChange={setAgentTab} />
      {agentTab === "overview" ? <AgentOverviewWorkspace findings={findings} history={scanHistory} snapshot={agentSnapshot} onOpenTab={setAgentTab} /> : null}
      {agentTab === "risks" ? <section className="agent-tab-panel"><div className="agent-tab-heading"><div><span>风险与复测</span><h3>从规则命中走到人工处置结论</h3></div><small>分类筛选和原始证据按需展开</small></div><ModuleFilterBar><input value={filters.keyword} onChange={(event) => setFilters({ ...filters, keyword: event.target.value })} placeholder="搜索风险、文件或规则" /><SimpleFilter value={filters.severity} label="全部等级" options={["critical", "high", "medium", "low", "info"]} format={severityLabel} onChange={(value) => setFilters({ ...filters, severity: value })} /><SimpleFilter value={filters.status} label="全部处理状态" options={FINDING_WORKFLOW_STATUSES} format={(value) => statusLabel(value as FindingStatus)} onChange={(value) => setFilters({ ...filters, status: value })} /><details className="agent-more-filter"><summary>更多筛选</summary><SimpleFilter value={filters.category} label="全部风险分类" options={uniqueValues(findings.map((item) => item.ai_review?.category ?? "unknown"))} format={agentCategoryLabel} onChange={(value) => setFilters({ ...filters, category: value })} /></details></ModuleFilterBar><ConciseFindingTable findings={pagination.items} validations={validations} evidence={evidence} graph={graph} onUpdateFinding={onUpdateFinding} /><Pagination page={pagination.page} pageCount={pagination.pageCount} total={filtered.length} onPageChange={setPage} /><RetestComparisonPanel comparison={comparison} /><AgentOfflineAuditPanel snapshot={agentSnapshot} />{onRunAgentAiReview ? <AgentDeepSeekReviewPanel snapshot={agentSnapshot} loading={loading} onRun={onRunAgentAiReview} /> : null}<AgentOfflineAuditHistoryPanel diff={agentAuditDiff} /></section> : null}
      {agentTab === "assets" ? <section className="agent-tab-panel"><div className="agent-tab-heading"><div><span>资产与安全边界</span><h3>按检查面查看覆盖、声明权限和潜在路径</h3></div><small>静态声明不等同于运行时事实</small></div><AgentAssetWorkspaceNavigation active={agentAssetTab} onChange={setAgentAssetTab} />{agentAssetTab === "coverage" ? <><AgentScanCoveragePanel history={scanHistory} /><AgentTrustScorePanel snapshot={agentSnapshot} /><AgentProvenancePanel snapshot={agentSnapshot} /><AgentIntelligencePanel snapshot={agentSnapshot} /></> : null}{agentAssetTab === "inventory" ? <><AgentAssetInventoryPanel snapshot={agentSnapshot} /><AgentPermissionMatrixPanel snapshot={agentSnapshot} /></> : null}{agentAssetTab === "paths" ? <><AgentDataflowPanel snapshot={agentSnapshot} /><AgentSemanticDiffPanel diff={agentScanDiff} /></> : null}</section> : null}
      {agentTab === "validation" ? <section className="agent-tab-panel agent-validation-workspace"><div className="agent-tab-heading"><div><span>动态验证</span><h3>预检 → 过滤副本 → 能力探测 → 隔离运行</h3></div><small>每一步都需要独立确认</small></div>{project ? <AgentRuntimePreflightPanel project={project} snapshot={agentSnapshot} /> : <div className="agent-empty-state">请先选择项目。</div>}</section> : null}
      {agentTab === "governance" ? <section className="agent-tab-panel agent-governance-workspace"><div className="agent-tab-heading"><div><span>策略与交付</span><h3>门禁、例外和报告集中管理</h3></div><small>策略修改从下一次扫描生效</small></div>{project ? <AgentGovernanceConsole project={project} snapshot={agentSnapshot} /> : <div className="agent-empty-state">请先选择项目。</div>}</section> : null}
    </div>
  </ModuleGovernanceShell>;
}

type DastGovernanceProps = { project: Project; findings: Finding[]; validations: DastValidation[]; strategies: DastStrategy[]; strategyId: string; targetUrl: string; targetConfirmation: string; selectedFindingId: string; loading: boolean; onTargetUrlChange: (value: string) => void; onTargetConfirmationChange: (value: string) => void; onStrategyChange: (strategyId: string) => void; onSelectRisk: (findingId: string) => void; onRun: () => Promise<void>; onCreateManual: (draft: ManualDastValidationDraft) => Promise<void>; onUpdateManual: (validationId: string, draft: ManualDastValidationDraft) => Promise<void>; onExportReport: () => Promise<void> };

function DastGovernanceView({ project, loading: parentLoading, onExportReport }: DastGovernanceProps) {
  const workspaceProjectIdRef = React.useRef(project.id);
  workspaceProjectIdRef.current = project.id;
  const [candidates, setCandidates] = useState<DastBusinessCandidate[]>([]);
  const [flows, setFlows] = useState<DastBusinessFlow[]>([]);
  const [runs, setRuns] = useState<DastBusinessRun[]>([]);
  const [snapshots, setSnapshots] = useState<DastBusinessSnapshot[]>([]);
  const [report, setReport] = useState<DastReport | null>(null);
  const [discovery, setDiscovery] = useState<DastDiscovery | null>(null);
  const [preflight, setPreflight] = useState<DastPreflight | null>(null);
  const [aiHealth, setAiHealth] = useState<{ configured: boolean; status: string; model?: string } | null>(null);
  const [strategyLibrary, setStrategyLibrary] = useState<{ total: number; builtin: Record<string, unknown>[]; learned: Record<string, unknown>[] } | null>(null);
  const [runtimeTargets, setRuntimeTargets] = useState<SandboxTarget[]>([]);
  const [candidateId, setCandidateId] = useState("");
  const [flowId, setFlowId] = useState("");
  const [runId, setRunId] = useState("");
  const [approval, setApproval] = useState({ reference: "", approved_by: "" });
  const [operator, setOperator] = useState("dast-operator");
  const [strategyJson, setStrategyJson] = useState("");
  const [busy, setBusy] = useState(false);
  const [activeAction, setActiveAction] = useState("");
  const [executionFeedback, setExecutionFeedback] = useState<{ tone: "success" | "error"; text: string } | null>(null);
  const [message, setMessage] = useState("");
  const [queueFilters, setQueueFilters] = useState({ keyword: "", validation: "all", verdict: "all" });
  const [verdictPanelFilter, setVerdictPanelFilter] = useState("all");
  const [evidenceDrawerOpen, setEvidenceDrawerOpen] = useState(false);
  const executionConsoleRef = React.useRef<HTMLElement | null>(null);
  const sandboxRuntime = runtimeTargets.find((item) => item.status === "running")?.runtime_url ?? "";
  const target = project.api_base_url || project.runtime_url || sandboxRuntime;
  const selectedCandidate = candidates.find((item) => item.id === candidateId) ?? candidates.find((item) => item.readiness === "ready") ?? candidates[0];
  const selectedFlow = flows.find((item) => item.id === flowId) ?? flows.find((item) => item.finding_id === selectedCandidate?.id) ?? (!selectedCandidate ? flows[0] : undefined);
  const selectedRun = runs.find((item) => item.id === runId) ?? runs[0];
  const stateSnapshots = snapshots.filter((item) => item.step_kind === "state_transition").sort((a, b) => Number(a.detail.sequence ?? 0) - Number(b.detail.sequence ?? 0));
  const requestSnapshots = snapshots.filter((item) => item.step_kind === "http_request" || item.step_kind === "login");
  const sandboxEvidenceSnapshots = snapshots.filter((item) => item.step_kind === "sandbox_evidence");
  const selectedEvidenceComplete = selectedRun?.status === "completed" && Boolean(selectedRun.verdict) && sandboxEvidenceSnapshots.some((item) => Boolean(item.detail.complete) && Boolean(item.detail.request_id));
  const triColor = report?.summary.tri_color ?? { total: 0, exploitable: 0, uncertain: 0, not_exploitable: 0 };
  const verifiedCandidates = candidates.filter((item) => item.validation_status === "verified" && item.latest_verdict);
  const visibleVerdictResults = verifiedCandidates
    .filter((item) => verdictPanelFilter === "all" || item.latest_verdict === verdictPanelFilter)
    .sort((left, right) => apiDateTime(right.latest_verified_at ?? "").getTime() - apiDateTime(left.latest_verified_at ?? "").getTime());
  const filteredCandidates = candidates.filter((item) => {
    const keyword = queueFilters.keyword.trim().toLowerCase();
    const searchable = [item.title, item.rule_id, item.vulnerability_type, item.file_path, item.recommended_strategy_name].filter(Boolean).join(" ").toLowerCase();
    return (!keyword || searchable.includes(keyword))
      && (queueFilters.validation === "all" || item.validation_status === queueFilters.validation)
      && (queueFilters.verdict === "all" || item.latest_verdict === queueFilters.verdict);
  });
  const readyCount = candidates.filter((item) => item.readiness === "ready").length;
  const blockedCount = candidates.filter((item) => item.readiness !== "ready").length;
  const identityContextCount = candidates.filter((item) => item.missing.some((value) => value.includes("身份") || value.includes("凭据"))).length;
  const mappingPendingCount = candidates.filter((item) => item.missing.some((value) => value.includes("参数"))).length;
  const templateNames = uniqueValues(candidates.map((item) => item.recommended_strategy_name));
  const linkedSelectedFlow = flows.find((flow) => flow.finding_id === selectedCandidate?.id);
  const selectedMappingItems = selectedCandidate?.missing.filter((item) => item.includes("参数")) ?? [];
  const selectedBlockingItems = selectedCandidate?.missing.filter((item) => !item.includes("参数")) ?? [];

  async function load(nextFlowId?: string, nextRunId?: string, resetSelection = false) {
    const loadingProjectId = project.id;
    try {
      const [nextCandidates, nextFlows, nextReport, nextHealth, nextLibrary, latestDiscovery, nextTargets] = await Promise.all([
        request<DastBusinessCandidate[]>(`/dast/projects/${project.id}/business-candidates`),
        request<DastBusinessFlow[]>(`/dast/projects/${project.id}/business-flows`),
        request<DastReport>(`/dast/projects/${project.id}/report`),
        request<{ configured: boolean; status: string; model?: string }>("/dast/business-draft-health"),
        request<{ total: number; builtin: Record<string, unknown>[]; learned: Record<string, unknown>[] }>(`/dast/projects/${project.id}/strategy-library`),
        request<DastDiscovery | null>(`/dast/projects/${project.id}/discoveries/latest`),
        request<SandboxTarget[]>(`/sandbox/projects/${project.id}/targets`).catch(() => [] as SandboxTarget[]),
      ]);
      if (workspaceProjectIdRef.current !== loadingProjectId) return;
      setCandidates(nextCandidates); setFlows(nextFlows); setReport(nextReport); setAiHealth(nextHealth); setStrategyLibrary(nextLibrary); setDiscovery(latestDiscovery); setRuntimeTargets(nextTargets);
      const preservedCandidate = !resetSelection && nextCandidates.some((item) => item.id === candidateId) ? candidateId : "";
      const activeCandidate = preservedCandidate || nextCandidates.find((item) => item.readiness === "ready")?.id || nextCandidates[0]?.id || "";
      if (activeCandidate) setCandidateId(activeCandidate);
      const activeFlow = nextFlowId || nextFlows.find((item) => item.finding_id === activeCandidate)?.id || "";
      if (activeFlow) {
        setFlowId(activeFlow);
        const [nextRuns, nextPreflight] = await Promise.all([request<DastBusinessRun[]>(`/dast/business-flows/${activeFlow}/runs`), request<DastPreflight>(`/dast/business-flows/${activeFlow}/preflight`)]);
        if (workspaceProjectIdRef.current !== loadingProjectId) return;
        setRuns(nextRuns); setPreflight(nextPreflight);
        const activeRun = nextRunId || (!resetSelection && runId) || nextRuns[0]?.id || "";
        if (activeRun) { const nextSnapshots = await request<DastBusinessSnapshot[]>(`/dast/business-runs/${activeRun}/snapshots`); if (workspaceProjectIdRef.current !== loadingProjectId) return; setRunId(activeRun); setSnapshots(nextSnapshots); }
        else { setRunId(""); setSnapshots([]); }
      } else { setRuns([]); setSnapshots([]); setPreflight(null); }
    } catch (error) { if (workspaceProjectIdRef.current === loadingProjectId) setMessage(`DAST 工作台加载失败：${errorMessage(error)}`); }
  }
  useEffect(() => {
    setCandidates([]); setFlows([]); setRuns([]); setSnapshots([]); setReport(null); setDiscovery(null); setPreflight(null); setRuntimeTargets([]);
    setCandidateId(""); setFlowId(""); setRunId(""); setMessage(""); setActiveAction(""); setExecutionFeedback(null);
    setQueueFilters({ keyword: "", validation: "all", verdict: "all" }); setVerdictPanelFilter("all"); setEvidenceDrawerOpen(false);
    void load(undefined, undefined, true);
  }, [project.id]);
  useEffect(() => { if (selectedFlow) setStrategyJson(JSON.stringify(selectedFlow.steps, null, 2)); }, [selectedFlow?.id]);
  useEffect(() => {
    if (!evidenceDrawerOpen) return;
    const previousOverflow = document.body.style.overflow;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") setEvidenceDrawerOpen(false); };
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", closeOnEscape);
    return () => { document.body.style.overflow = previousOverflow; window.removeEventListener("keydown", closeOnEscape); };
  }, [evidenceDrawerOpen]);

  function beginAction(action: string, statusMessage: string) {
    setActiveAction(action);
    setMessage(statusMessage);
    setBusy(true);
  }
  function finishAction() {
    setBusy(false);
    setActiveAction("");
  }
  function revealExecutionConsole() {
    window.requestAnimationFrame(() => executionConsoleRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }

  async function materialize() {
    if (!selectedCandidate) return setMessage("请先选择一条 SAST / AGENT 漏洞。");
    const existingFlow = flows.find((flow) => flow.finding_id === selectedCandidate.id);
    if (selectedCandidate.target_status !== "configured") return setMessage("当前还没有可访问的运行目标：已上线项目请在项目资产配置运行地址；只有源码的项目请先到 SANDBOX 启动项目隔离实例，启动成功后返回这里同步。");
    if (selectedCandidate.missing.some((item) => item.includes("参数"))) return setMessage("系统尚未唯一定位运行时输入点。请先“同步运行资产”；系统会自动重新映射，不需要在此手工填写。");
    beginAction(existingFlow ? "open-strategy" : "materialize", existingFlow ? "正在校验已生成策略是否仍与当前源码路由和运行资产一致…" : "正在把上游漏洞转换为 DAST 策略，并校验目标、参数和证据要求…");
    try {
      const flow = await request<DastBusinessFlow>(`/dast/business-candidates/${selectedCandidate.id}/materialize`, { method: "POST" });
      await load(flow.id); setFlowId(flow.id); setMessage(existingFlow ? "已校验并打开与当前源码及运行资产一致的策略。" : "已把上游漏洞自动转换为 DAST 策略草案；无需重复填写目标、方法、参数和证据标准。"); revealExecutionConsole();
    } catch (error) { await load(undefined, undefined, false); setMessage(`${existingFlow ? "策略校验或打开" : "策略生成"}失败：${errorMessage(error)}`); } finally { finishAction(); }
  }
  async function saveStrategy() {
    if (!selectedFlow) return;
    try {
      const steps = JSON.parse(strategyJson) as Record<string, unknown>[];
      beginAction("save-strategy", "正在保存策略修改并重新执行安全校验…"); await request(`/dast/business-flows/${selectedFlow.id}`, { method: "PATCH", body: JSON.stringify({ steps }) });
      await load(selectedFlow.id); setMessage("策略修改已保存；已审批策略若发生变化会自动退回草稿。");
    } catch (error) { setMessage(error instanceof SyntaxError ? "策略 JSON 格式不正确。" : `策略保存失败：${errorMessage(error)}`); } finally { finishAction(); }
  }
  async function generateAiStrategy() {
    if (!selectedCandidate) return setMessage("请先选择一条 SAST / AGENT 漏洞。");
    if (!aiHealth?.configured) return setMessage("DeepSeek 当前未配置；可继续使用本地策略模板，或由管理员配置 DeepSeek 后再生成草案。");
    if (!target) return setMessage("DeepSeek 生成运行时策略需要一个可访问目标。已上线项目请配置运行地址；只有源码的项目请先在 SANDBOX 启动隔离实例。");
    beginAction("ai-strategy", "DeepSeek 正在分析漏洞上下文并生成待审批策略草案…");
    try {
      const result = await request<{ draft: { name: string; flow_mode: "api" | "browser" | "hybrid"; roles: Record<string, unknown>[]; steps: Record<string, unknown>[]; sufficiency_criteria: Record<string, unknown>; safety_notes: string[]; missing_information: string[] }; model: string }>(`/dast/business-candidates/${selectedCandidate.id}/ai-draft`, { method: "POST", body: JSON.stringify({ business_description: `${selectedCandidate.title}。${selectedCandidate.evidence ?? ""}`, target_description: selectedCandidate.attack_surface.urls.join("、") || target, confirmation_phrase: `DAST_DEEPSEEK_DRAFT:${selectedCandidate.id}` }) });
      const allowedPaths = selectedCandidate.attack_surface.urls.map((url) => { try { return new URL(url).pathname || "/"; } catch { return "/"; } });
      const flow = await request<DastBusinessFlow>("/dast/business-flows", { method: "POST", body: JSON.stringify({ project_id: project.id, finding_id: selectedCandidate.id, name: result.draft.name, target_url: selectedCandidate.attack_surface.urls[0] || target, flow_mode: result.draft.flow_mode, strategy_source: "ai_draft", authorized_scope: `仅限项目已配置同源目标 ${target}；禁止业务副作用。`, allowed_paths: uniqueValues(allowedPaths), roles: result.draft.roles, steps: result.draft.steps, sufficiency_criteria: { ...result.draft.sufficiency_criteria, safety_notes: result.draft.safety_notes, missing_information: result.draft.missing_information }, requester: "deepseek-dast-adapter" }) });
      await load(flow.id); setFlowId(flow.id); setMessage(`DeepSeek ${result.model} 已生成待审批策略，并作为本地知识中枢中的项目策略经验保存。`);
    } catch (error) { setMessage(`DeepSeek 策略生成失败：${errorMessage(error)}`); } finally { finishAction(); }
  }
  async function approve() {
    if (!selectedFlow || !approval.reference.trim() || !approval.approved_by.trim()) return setMessage("连接目标前必须填写真实审批依据和审批人；漏洞信息本身不需要重复填写。");
    beginAction("approve", "正在锁定策略范围并记录审批信息…");
    try { await request(`/dast/business-flows/${selectedFlow.id}`, { method: "PATCH", body: JSON.stringify({ status: "approved", approval_reference: approval.reference, approved_by: approval.approved_by }) }); await load(selectedFlow.id); setMessage("策略范围已锁定并记录审批。"); }
    catch (error) { setMessage(`审批失败：${errorMessage(error)}`); } finally { finishAction(); }
  }
  async function execute(mode: "dry_run" | "api_execution") {
    if (!selectedFlow) return;
    setExecutionFeedback(null);
    beginAction(mode, mode === "dry_run" ? "正在进行策略预执行：只校验步骤、角色、路径和安全边界，不连接目标…" : "DAST HTTP 执行中：正在按已审批策略发送有界请求、分析差分并归档证据…");
    try {
      const run = await request<DastBusinessRun>(`/dast/business-flows/${selectedFlow.id}/runs`, { method: "POST", body: JSON.stringify({ operator, execution_mode: mode, target_confirmation: mode === "api_execution" ? `DAST_BUSINESS_FLOW:${selectedFlow.id}:${selectedFlow.target_url}` : null }) });
      await load(selectedFlow.id, run.id);
      const completed = !["blocked", "failed", "canceled"].includes(run.status);
      const resultMessage = mode === "dry_run"
        ? `预执行已结束：${run.verdict_reason ?? "未连接目标，校验结果已归档。"}`
        : `DAST HTTP 执行已结束（${run.status.toUpperCase()}）：${run.verdict_reason ?? "请求、证据和状态已归档。"}`;
      setExecutionFeedback({ tone: completed ? "success" : "error", text: resultMessage });
      setMessage(resultMessage);
    } catch (error) {
      const resultMessage = `执行失败：${errorMessage(error)}`;
      setExecutionFeedback({ tone: "error", text: resultMessage });
      setMessage(resultMessage);
    } finally { finishAction(); }
  }
  async function handoffSandbox() {
    if (!selectedFlow) return;
    setExecutionFeedback(null);
    beginAction("sandbox-handoff", "正在生成 SANDBOX 隔离执行合同并加入验证队列…");
    try {
      const result = await request<{ run: DastBusinessRun; preflight: DastPreflight; handoff: { required_capabilities: string[] } }>(`/dast/business-flows/${selectedFlow.id}/sandbox-runs`, { method: "POST", body: JSON.stringify({ operator }) });
      await load(selectedFlow.id, result.run.id); const resultMessage = `已生成 SANDBOX 隔离执行任务，等待能力 ${result.handoff.required_capabilities.join(" / ")} 接管并回传证据。`; setExecutionFeedback({ tone: "success", text: resultMessage }); setMessage(resultMessage);
    } catch (error) { const resultMessage = `SANDBOX 任务创建失败：${errorMessage(error)}`; setExecutionFeedback({ tone: "error", text: resultMessage }); setMessage(resultMessage); } finally { finishAction(); }
  }
  async function discover() {
    if (!target) return setMessage("当前没有可同步的运行目标。已上线项目请在项目资产配置 runtime_url/api_base_url；只有源码的项目不需要虚构 URL，请先在 SANDBOX 启动隔离实例，DAST 会自动使用其临时地址。");
    beginAction("discover", "正在同步运行资产：抓取授权范围内的 URL、表单、API 和参数…");
    try { const result = await request<DastDiscovery>(`/dast/projects/${project.id}/discover`, { method: "POST", body: JSON.stringify({ target_url: target, target_confirmation: `DAST_DISCOVERY:${target}`, max_pages: 12 }) }); setDiscovery(result); setMessage(`资产发现完成：${result.urls.length} 个 URL、${result.forms.length} 个表单、${result.parameters.length} 个参数。`); }
    catch (error) { setMessage(`资产发现未完成：${errorMessage(error)}`); } finally { finishAction(); }
  }
  async function selectFlow(nextId: string, preferredRunId = "") {
    setFlowId(nextId); setRunId(""); setSnapshots([]);
    if (!nextId) { setPreflight(null); return setRuns([]); }
    try { const [nextRuns, nextPreflight] = await Promise.all([request<DastBusinessRun[]>(`/dast/business-flows/${nextId}/runs`), request<DastPreflight>(`/dast/business-flows/${nextId}/preflight`)]); setRuns(nextRuns); setPreflight(nextPreflight); const nextRun = nextRuns.find((item) => item.id === preferredRunId) ?? nextRuns[0]; if (nextRun) { setRunId(nextRun.id); setSnapshots(await request<DastBusinessSnapshot[]>(`/dast/business-runs/${nextRun.id}/snapshots`)); } } catch (error) { setMessage(`运行记录加载失败：${errorMessage(error)}`); }
  }
  async function selectRun(nextId: string) { setRunId(nextId); setSnapshots(nextId ? await request<DastBusinessSnapshot[]>(`/dast/business-runs/${nextId}/snapshots`) : []); }
  async function openVerdictResult(item: DastBusinessCandidate) {
    setCandidateId(item.id);
    const linkedFlowId = item.latest_flow_id ?? flows.find((flow) => flow.finding_id === item.id)?.id ?? "";
    if (!linkedFlowId) return setMessage("该裁决的历史策略已归档，结果仍保留在专项报告中。");
    await selectFlow(linkedFlowId, item.latest_run_id ?? "");
  }

  return <ModuleGovernanceShell moduleKey="dast" lastStatus={runs.length ? "completed" : candidates.length ? "waiting" : null} metrics={[["待验证场景", candidates.length], ["可直接生成", readyCount], ["待运行上下文", blockedCount], ["已执行任务", report?.summary.business_run_count ?? 0]]} action={blockedCount ? `${blockedCount} 个场景尚待运行上下文，其中 ${identityContextCount} 个需要统一测试身份配置；这不是要求逐条补录漏洞信息。` : candidates.length ? "上游风险已自动归一化，可直接生成策略并预执行。" : "请先运行 SAST 或 AGENT，新的 Finding 会自动进入此工作台。"} loading={parentLoading || busy} hideRunButton onRun={() => execute("dry_run")}>
    <section className="dast-verdict-panel dast-verdict-overview">
      <div className="panel-header"><div><h3>三色裁决</h3><p>结果来自已完成且证据完整的 SANDBOX 任务；点击颜色筛选，点击结果查看任务与证据。</p></div><span>{Math.max(0, candidates.length - verifiedCandidates.length)} 条未验证</span></div>
      <div className="dast-verdict-metrics">
        {(["exploitable", "uncertain", "not_exploitable"] as const).map((verdict) => <button type="button" key={verdict} className={verdict} aria-pressed={verdictPanelFilter === verdict} onClick={() => setVerdictPanelFilter(verdictPanelFilter === verdict ? "all" : verdict)}><b>{triColor[verdict]}</b>{dastVerdictLabel(verdict)}<small>{verdict === "exploitable" ? "明确触发且造成实际影响" : verdict === "uncertain" ? "存在异常但证据尚不充分" : "多组验证未触发且确认防护有效"}</small></button>)}
      </div>
      <div className="dast-verdict-results-heading"><strong>{verdictPanelFilter === "all" ? "全部已验证结果" : dastVerdictLabel(verdictPanelFilter)}</strong><span>{visibleVerdictResults.length} 条</span>{verdictPanelFilter !== "all" ? <button type="button" onClick={() => setVerdictPanelFilter("all")}>查看全部</button> : null}</div>
      <div className="dast-verdict-results">{visibleVerdictResults.length === 0 ? <div className="workbench-empty">当前筛选下暂无已形成三色裁决的漏洞。</div> : visibleVerdictResults.map((item) => <button type="button" key={item.id} className={selectedCandidate?.id === item.id ? "active" : ""} onClick={() => void openVerdictResult(item)}><span className={`dast-result-verdict ${item.latest_verdict}`}>{dastVerdictLabel(item.latest_verdict ?? "")}</span><strong>{item.title}</strong><small>{item.recommended_strategy_name} · {formatDateTime(item.latest_verified_at)}</small><ArrowRight size={16} /></button>)}</div>
      {selectedCandidate?.latest_verdict ? <div className={`dast-current-verdict ${selectedCandidate.latest_verdict}`}><div><strong>{dastVerdictLabel(selectedCandidate.latest_verdict)} · {selectedCandidate.title}</strong><p>{selectedCandidate.latest_verdict_reason || "已形成证据门控裁决。"}</p><small>Task {selectedCandidate.latest_run_id} · 已持久化 {formatDateTime(selectedCandidate.latest_verified_at)}</small></div><button className="secondary-action" type="button" onClick={() => { void openVerdictResult(selectedCandidate).then(() => setEvidenceDrawerOpen(true)); }}>查看任务与证据</button></div> : null}
    </section>
    <section className="dast-auto-hero">
      <div><span>DAST VERIFICATION ORCHESTRATOR</span><h3>从静态风险到动态证据，一条自动化链路完成</h3><p>SAST / AGENT Finding 自动映射目标、方法、参数和策略；同漏洞类型、同路径和同方法的重复代码命中会合并为一个动态场景，纯静态风险留在上游模块，不会为了凑数进入 DAST。</p></div>
      <div className="dast-pipeline">{["自动接入", "资产发现", "策略生成", "动态执行", "证据分析", "三色报告"].map((item, index) => <React.Fragment key={item}><b><i>{index + 1}</i>{item}</b>{index < 5 ? <ArrowRight size={16} /> : null}</React.Fragment>)}</div>
    </section>
    {message ? <div className="dast-message">{message}</div> : null}
    <section className="dast-overview-grid">
      <article className="dast-overview-card"><span>目标与资产</span><strong>{target || "未配置运行目标"}</strong><p>{sandboxRuntime ? `当前使用 SANDBOX 临时运行目标。${discovery ? `已识别 ${discovery.urls.length} URL、${discovery.forms.length} 表单、${discovery.api_urls.length} API、${discovery.parameters.length} 参数。` : "可直接同步运行资产。"}` : discovery ? `${discovery.urls.length} URL · ${discovery.forms.length} 表单 · ${discovery.api_urls.length} API · ${discovery.parameters.length} 参数` : "同源、GET 限定、自动去重，最多抓取 12 个页面。"}</p><button className="secondary-action" disabled={busy} onClick={() => void discover()}>{activeAction === "discover" ? <><LoaderCircle className="sandbox-spin" size={16} />正在同步…</> : discovery ? "重新同步资产" : "同步运行资产"}</button></article>
      <article className="dast-overview-card"><span>会话管理</span><strong>Cookie Jar + 环境变量凭据</strong><p>每个业务角色使用独立 Cookie 会话；Token / OAuth 测试凭据仅允许通过后端 env: 引用，不回显到页面或日志。</p><em>{selectedCandidate?.preconditions.required_roles.length ? `需要：${selectedCandidate.preconditions.required_roles.join(" / ")}` : "当前策略可使用匿名会话"}</em></article>
      <article className="dast-overview-card"><span>策略智能</span><strong>{strategyLibrary?.total ?? templateNames.length} 个本地策略 · {strategyLibrary?.learned.length ?? 0} 个 AI 经验</strong><p>{aiHealth?.configured ? `DeepSeek ${aiHealth.model ?? ""} 已就绪：无匹配模板时可生成待审批草案并沉淀为本地流程模板。` : "DeepSeek 未配置；当前使用可审计的本地模板，不影响自动归一化。"}</p><em>{aiHealth?.configured ? "AI 只生成草案，不绕过审批" : "本地模板模式"}</em></article>
    </section>
    <section className="dast-auto-layout">
      <div className="dast-candidate-panel">
        <div className="panel-header"><div><h3>漏洞验证队列</h3><p>SAST / AGENT 输出已转换为 DAST 格式</p></div><span>{verifiedCandidates.length} 已验证 · {candidates.length - verifiedCandidates.length} 未完成</span></div>
        <div className="dast-queue-filters"><input value={queueFilters.keyword} onChange={(event) => setQueueFilters({ ...queueFilters, keyword: event.target.value })} placeholder="搜索漏洞、规则或策略" /><select aria-label="按验证状态筛选" value={queueFilters.validation} onChange={(event) => setQueueFilters({ ...queueFilters, validation: event.target.value })}><option value="all">全部验证状态</option><option value="verified">已验证</option><option value="unverified">未验证</option><option value="verifying">验证中</option><option value="failed">验证失败</option></select><select aria-label="按三色裁决筛选" value={queueFilters.verdict} onChange={(event) => setQueueFilters({ ...queueFilters, verdict: event.target.value })}><option value="all">全部三色裁决</option><option value="exploitable">可利用</option><option value="uncertain">不确定</option><option value="not_exploitable">不可利用</option></select></div>
        <div className="dast-candidate-list">{candidates.length === 0 ? <div className="workbench-empty">暂无可验证线索。执行 SAST 或 AGENT 后会自动出现在这里。</div> : filteredCandidates.length === 0 ? <div className="workbench-empty">没有符合当前筛选条件的漏洞。</div> : [...filteredCandidates].sort((left, right) => Number(right.readiness === "ready") - Number(left.readiness === "ready")).map((item) => <button key={item.id} className={selectedCandidate?.id === item.id ? "active" : ""} onClick={() => { setCandidateId(item.id); const linkedFlowId = item.latest_flow_id ?? flows.find((flow) => flow.finding_id === item.id)?.id ?? ""; void selectFlow(linkedFlowId, item.latest_run_id ?? ""); }}><span><i className={`dast-ready-dot ${item.readiness}`} />{item.source} · {severityLabel(item.severity)}<b className={`dast-validation-badge ${item.validation_status}`}>{validationStatusLabel(item.validation_status)}</b></span><strong>{item.title}</strong><small>{item.latest_verdict ? `${dastVerdictLabel(item.latest_verdict)} · ${item.recommended_strategy_name}` : item.recommended_strategy_name}</small><em>{item.validation_status === "verified" ? `已验证 ${item.validation_count} 次 · ${formatDateTime(item.latest_verified_at)}` : item.validation_status === "verifying" ? `任务 ${item.latest_run_status ?? "运行中"}` : item.validation_status === "failed" ? `最近任务 ${item.latest_run_status ?? "失败"}` : item.readiness === "ready" ? "尚未验证 · 已自动补全" : item.readiness === "blocked" ? "尚未验证 · 等待目标配置" : item.missing.some((value) => value.includes("参数")) ? "尚未验证 · 等待系统自动定位输入点" : item.missing.some((value) => value.includes("身份") || value.includes("凭据")) ? "尚未验证 · 等待项目统一测试身份" : `尚未验证 · 还缺 ${item.missing.length} 项运行上下文`}</em></button>)}</div>
      </div>
      <div className="dast-candidate-detail">
        {selectedCandidate ? <>
          <div className="dast-detail-title"><div><span className={`severity ${selectedCandidate.severity}`}>{severityLabel(selectedCandidate.severity)}</span><b>{selectedCandidate.vulnerability_type}</b></div><h3>{selectedCandidate.title}</h3><p>{selectedCandidate.source} · {selectedCandidate.rule_id} · {selectedCandidate.file_path ?? "项目级风险"}</p></div>
          <div className="dast-detail-grid"><div><span>系统已自动补全</span><p>{selectedCandidate.auto_filled.join("、") || "等待识别"}</p></div><div><span>目标 / 接口</span><p>{selectedCandidate.attack_surface.urls.join("、") || "未识别"}</p></div><div><span>方法 / 注入点</span><p>{selectedCandidate.attack_surface.methods.join(" / ")} · {selectedCandidate.attack_surface.injection_points?.map((item) => `${item.location}:${item.name}`).join("、") || selectedCandidate.attack_surface.parameters.join("、") || "无显式参数"}</p></div><div><span>证据要求</span><p>{selectedCandidate.evidence_requirements.join("、")}</p></div></div>
          {selectedBlockingItems.length ? <div className="dast-blockers"><strong>执行所需运行上下文（不是漏洞信息补录）</strong>{selectedBlockingItems.map((item) => <span key={item}><b>{item}</b><small>{item.includes("运行地址") || item.includes("API 地址") ? "不是在此处手工填写。已上线项目在“项目资产”配置；只有源码时到 SANDBOX 启动临时目标。" : item.includes("身份") || item.includes("凭据") ? "由管理员为项目统一配置一次测试身份，队列内同类场景自动复用；页面不会要求逐条填写或暴露明文 Cookie、Token、密码。" : "系统会尽量从项目配置、上游证据和资产发现结果中补全。"}</small></span>)}</div> : null}
          {selectedMappingItems.length ? <div className="dast-mapping-notice"><strong>系统正在自动定位运行时输入点</strong><span>当前 SAST 证据还不能唯一确定“哪个 URL 的哪个参数”。系统会继续结合源码数据流和“同步运行资产”结果自动匹配；这不是要求您填写。定位前不会生成空参数攻击请求。</span></div> : !selectedBlockingItems.length ? <div className="dast-ready-banner"><Check size={16} />运行时验证所需字段已由系统补全</div> : null}
          <div className="dast-strategy-match"><span>匹配策略</span><strong>{selectedCandidate.recommended_strategy_name}</strong><p>{selectedCandidate.strategy_description}</p><code>{selectedCandidate.recommended_strategy_id}</code>{selectedCandidate.required_capabilities.length ? <small>隔离执行能力：{selectedCandidate.required_capabilities.join(" / ")}</small> : <small>可由 DAST 有界 HTTP 执行器完成</small>}</div>
          <div className="dast-generate-actions"><button className="primary-action" disabled={busy || (!linkedSelectedFlow && (selectedMappingItems.length > 0 || selectedCandidate.strategy_match === "ai_required"))} onClick={() => void materialize()}>{activeAction === "materialize" ? <><LoaderCircle className="sandbox-spin" size={16} />正在生成策略…</> : activeAction === "open-strategy" ? <><LoaderCircle className="sandbox-spin" size={16} />正在打开…</> : linkedSelectedFlow ? "打开已生成策略" : selectedMappingItems.length ? "等待自动定位输入点" : selectedCandidate.strategy_match === "builtin" ? "自动生成 DAST 策略" : "等待新策略模板"}</button>{aiHealth?.configured && selectedCandidate.strategy_match === "ai_required" ? <button className="secondary-action" disabled={busy} onClick={() => void generateAiStrategy()}>{activeAction === "ai-strategy" ? <><LoaderCircle className="sandbox-spin" size={16} />DeepSeek 生成中…</> : "DeepSeek 生成待审批模板"}</button> : null}</div>
        </> : <div className="workbench-empty">选择一条漏洞查看自动识别结果。</div>}
      </div>
    </section>
    <section className="dast-execution-console" ref={executionConsoleRef}>
      <div className="panel-header"><div><h3>策略与动态执行器</h3><p>策略 ID、任务 ID、请求 ID 全程关联；任何策略修改都会撤销原审批。</p></div><select value={selectedFlow?.id ?? ""} onChange={(event) => void selectFlow(event.target.value)}><option value="">尚未生成策略</option>{flows.map((flow) => <option key={flow.id} value={flow.id}>{flow.status === "approved" ? "已审批" : "草稿"} · {flow.name}</option>)}</select></div>
      {selectedFlow ? <div className="dast-console-grid">
        <div className="dast-strategy-editor"><div className="dast-id-line"><span>STRATEGY ID</span><code>{selectedFlow.id}</code></div><div className="dast-flow-meta"><span>{selectedFlow.flow_mode.toUpperCase()}</span><span>{selectedFlow.strategy_source}</span><span>{selectedFlow.allowed_paths.length} 条授权路径</span><span>{selectedFlow.roles.length} 个隔离会话</span></div><details><summary>人工修改策略步骤（可选）</summary><textarea rows={14} value={strategyJson} onChange={(event) => setStrategyJson(event.target.value)} /><button className="secondary-action" disabled={busy} onClick={() => void saveStrategy()}>{activeAction === "save-strategy" ? <><LoaderCircle className="sandbox-spin" size={16} />正在保存…</> : "保存策略修改"}</button></details></div>
        <div className="dast-run-controls"><h4>执行前控制</h4><label>审批依据<input value={approval.reference} onChange={(event) => setApproval({ ...approval, reference: event.target.value })} placeholder="真实授权工单 / 书面审批编号" /></label><label>审批人<input value={approval.approved_by} onChange={(event) => setApproval({ ...approval, approved_by: event.target.value })} /></label><button className="secondary-action" disabled={busy || selectedFlow.status === "approved"} onClick={() => void approve()}>{activeAction === "approve" ? <><LoaderCircle className="sandbox-spin" size={16} />正在记录审批…</> : selectedFlow.status === "approved" ? "范围已审批" : "审批并锁定范围"}</button><label>操作人<input value={operator} onChange={(event) => setOperator(event.target.value)} /></label><div className="dast-run-buttons"><button className="secondary-action" disabled={busy} onClick={() => void execute("dry_run")}>{activeAction === "dry_run" ? <><LoaderCircle className="sandbox-spin" size={17} />正在预执行…</> : "预执行（不联网）"}</button><button className="primary-action" disabled={busy || !preflight?.can_execute_local} onClick={() => void execute("api_execution")}>{activeAction === "api_execution" ? <><LoaderCircle className="sandbox-spin" size={17} />DAST HTTP 执行中…</> : "DAST HTTP 执行"}</button>{preflight?.can_handoff_sandbox ? <button className="primary-action" disabled={busy} onClick={() => void handoffSandbox()}>{activeAction === "sandbox-handoff" ? <><LoaderCircle className="sandbox-spin" size={17} />正在移交…</> : "交给 SANDBOX 隔离执行"}</button> : null}</div>{["dry_run", "api_execution", "sandbox-handoff"].includes(activeAction) ? <div className="dast-execution-progress"><LoaderCircle className="sandbox-spin" size={19} /><div><strong>{activeAction === "api_execution" ? "DAST 正在执行已审批 HTTP 策略" : activeAction === "dry_run" ? "正在进行不联网预执行" : "正在创建 SANDBOX 隔离任务"}</strong><span>{activeAction === "api_execution" ? "请求、响应、耗时和状态变化完成后会自动归档到下方任务记录。" : "操作完成后会自动刷新执行前检查、任务和证据。"}</span></div></div> : executionFeedback ? <div className={`dast-execution-result ${executionFeedback.tone}`} role="status">{executionFeedback.text}</div> : null}</div>
      </div> : <div className="workbench-empty">从左侧漏洞队列生成策略后，执行器会在这里就绪。</div>}
    </section>
    {selectedFlow ? <section className="dast-preflight-panel"><div className="panel-header"><div><h3>执行前检查</h3><p>运行目标、审批范围、会话、路径和执行后端必须分别满足。</p></div><span className={`dast-preflight-status ${preflight?.status ?? "blocked"}`}>{preflight?.status === "ready" ? "可由 DAST 执行" : preflight?.status === "waiting_sandbox" ? "等待 SANDBOX" : "存在阻塞"}</span></div><div className="dast-preflight-grid">{preflight?.checks.map((item) => <div key={item.code} className={item.status}><b>{item.label}</b><span>{item.detail}</span>{item.remediation ? <small>{item.remediation}</small> : null}</div>)}</div>{preflight?.required_capabilities.length ? <p className="dast-capability-contract">SANDBOX 合同能力：{preflight.required_capabilities.join(" / ")}。DAST 只下发已审批策略并接收事实证据，三色裁决仍由 DAST 完成。</p> : null}</section> : null}
    <section className="dast-state-panel"><div className="panel-header"><div><h3>过程状态机</h3><p>成功路径与 BLOCKED / FAILED / CANCELED 等终止分支分别记录</p></div>{runs.length ? <select value={selectedRun?.id ?? ""} onChange={(event) => void selectRun(event.target.value)}>{runs.map((run) => <option key={run.id} value={run.id}>{run.status} · {formatDateTime(run.created_at)}</option>)}</select> : null}</div>{selectedRun ? <><div className="dast-id-line"><span>TASK ID</span><code>{selectedRun.id}</code></div><div className="dast-state-track">{stateSnapshots.map((log) => { const state = String(log.detail.state ?? log.step_id); return <div className="complete" key={log.id}><i><Check size={13} /></i><b>{state}</b><small>{String(log.response_summary ?? "已记录")}</small></div>; })}</div></> : <div className="workbench-empty">运行策略后显示完整状态轨迹。</div>}</section>
    <section className="dast-evidence-panel dast-evidence-summary">
      <div className="panel-header"><div><h3>证据归档</h3><p>主页面仅显示当前任务的证据完整性；原始事实和诊断日志按需查看。</p></div><div className="dast-evidence-actions"><button className="primary-action" disabled={!selectedRun && !discovery} onClick={() => setEvidenceDrawerOpen(true)}>查看证据详情</button><button className="secondary-action" disabled={busy} onClick={() => void onExportReport()}>导出专项报告</button></div></div>
      <div className="dast-evidence-summary-grid">
        <article><span>当前任务</span><strong>{selectedRun?.id ?? "尚未选择任务"}</strong><small>{selectedRun ? `${selectedRun.execution_mode} · ${selectedRun.status}` : "选择已执行任务后查看"}</small></article>
        <article><span>证据状态</span><strong>{selectedEvidenceComplete ? "完整并已裁决" : requestSnapshots.length + sandboxEvidenceSnapshots.length ? "已采集，尚未满足裁决门槛" : "尚无运行证据"}</strong><small>Dry Run 和等待任务不计为已验证</small></article>
        <article><span>HTTP 交换</span><strong>{requestSnapshots.length} 条</strong><small>脱敏请求、响应与时延</small></article>
        <article><span>SANDBOX 事实</span><strong>{sandboxEvidenceSnapshots.length} 条</strong><small>差分、截图、HAR、Console、OAST 等</small></article>
      </div>
    </section>
    {evidenceDrawerOpen ? <div className="dast-evidence-drawer-backdrop" role="presentation" onMouseDown={() => setEvidenceDrawerOpen(false)}>
      <aside className="dast-evidence-drawer" role="dialog" aria-modal="true" aria-labelledby="dast-evidence-drawer-title" onMouseDown={(event) => event.stopPropagation()}>
        <div className="dast-evidence-drawer-header"><div><span>DAST EVIDENCE</span><h3 id="dast-evidence-drawer-title">证据详情与执行日志</h3><p>{selectedCandidate?.title ?? "项目运行证据"} · Task {selectedRun?.id ?? "未选择"}</p></div><button type="button" aria-label="关闭证据详情" onClick={() => setEvidenceDrawerOpen(false)}>×</button></div>
        <div className="dast-evidence-drawer-body">
          <div className="dast-evidence-coverage">{[["原始请求 / 响应", requestSnapshots.length ? "已脱敏归档" : "等待执行"], ["截图 / 录屏", sandboxEvidenceSnapshots.some((item) => ["browser", "screenshot", "video", "har"].includes(String(item.detail.evidence_type))) ? "已归档" : "等待隔离浏览器"], ["DNS / HTTP 外带", sandboxEvidenceSnapshots.some((item) => item.detail.evidence_type === "oast_callback") ? "已归档" : "等待 OAST 回调"], ["时间延迟", requestSnapshots.length || sandboxEvidenceSnapshots.some((item) => item.detail.evidence_type === "timing") ? "已记录" : "等待执行"], ["环境信息", discovery || sandboxEvidenceSnapshots.some((item) => item.detail.evidence_type === "environment") ? "已识别" : "等待资产同步"]].map(([name, status]) => <span key={name}><b>{name}</b><small>{status}</small></span>)}</div>
          <details className="dast-evidence-guide"><summary>这些证据分别代表什么？</summary><div><p><b>原始请求 / 响应</b><span>实际执行时保存的脱敏 HTTP 交换，用于证明输入、响应和状态差异。</span></p><p><b>截图 / HAR / Console</b><span>隔离浏览器的页面截图、网络归档和控制台日志；每条都保存状态及内容哈希。</span></p><p><b>DNS / HTTP 外带</b><span>OAST 回调，用于证明 SSRF、XXE 或命令执行产生了目标外的网络行为。</span></p><p><b>时间延迟 / 环境信息</b><span>多次时延样本与沙箱运行时元数据，用于时延型验证和结果复核。</span></p></div></details>
          <section className="dast-drawer-evidence-section"><div><h4>当前任务 HTTP 证据</h4><span>{requestSnapshots.length} 条</span></div>{requestSnapshots.length ? <div className="dast-request-log">{requestSnapshots.map((item) => <details key={item.id}><summary><code>{String(item.detail.request_id ?? item.id)}</code><span>{item.step_id} · {item.status}</span><b>{item.evidence_hash.slice(0, 12)}…</b></summary><dl><div><dt>Task ID</dt><dd>{String(item.detail.task_id ?? item.run_id)}</dd></div><div><dt>Strategy ID</dt><dd>{String(item.detail.strategy_id ?? item.flow_id)}</dd></div><div><dt>请求</dt><dd>{item.request_summary ?? "未发起"}</dd></div><div><dt>响应</dt><dd>{item.response_summary ?? "未记录"}</dd></div><div><dt>脱敏原始报文与时延</dt><dd><pre className="code-preview">{JSON.stringify(item.detail.exchange ?? {}, null, 2)}</pre></dd></div></dl></details>)}</div> : <div className="workbench-empty">暂无 HTTP 请求证据。Dry Run 和等待 SANDBOX 的任务不会伪造网络证据。</div>}</section>
          <section className="dast-drawer-evidence-section"><div><h4>SANDBOX 事实证据</h4><span>{sandboxEvidenceSnapshots.length} 条</span></div>{sandboxEvidenceSnapshots.length ? <div className="dast-discovery-log dast-sandbox-fact-list">{sandboxEvidenceSnapshots.map((item) => <p key={item.id}><code>{String(item.detail.evidence_id ?? item.id)}</code><span>{String(item.detail.evidence_type ?? "runtime_trace")}</span><b>{item.status} · {item.evidence_hash.slice(0, 12)}…</b></p>)}</div> : <div className="workbench-empty">当前任务没有 SANDBOX 事实证据。</div>}</section>
          {discovery?.request_logs.length ? <details className="dast-discovery-log dast-advanced-log"><summary>高级诊断：资产发现请求日志 · Task {discovery.task_id}</summary><p className="dast-log-explanation">这些同源只读 GET 仅用于发现 URL、表单和 API，不属于漏洞裁决证据。</p>{discovery.request_logs.map((item) => <p key={item.request_id}><code>{item.request_id}</code><span>{item.method} {item.url}</span><b>HTTP {item.status_code ?? item.status} · {item.duration_ms} ms</b></p>)}</details> : null}
        </div>
      </aside>
    </div> : null}
  </ModuleGovernanceShell>;
}

// Kept intentionally for rollback/reference while the automated DAST workbench is validated.
// The component is no longer rendered; none of its data-entry workflows have been deleted.
function LegacyDastGovernanceView({ project, findings, validations, strategies, strategyId, targetUrl, targetConfirmation, selectedFindingId, loading, onTargetUrlChange, onTargetConfirmationChange, onStrategyChange, onSelectRisk, onRun, onCreateManual, onUpdateManual, onExportReport }: DastGovernanceProps) {
  const [filters, setFilters] = useState({ keyword: "", verdict: "all", linked: "all" });
  const [page, setPage] = useState(1);
  const [entryMode, setEntryMode] = useState<"baseline" | "manual">("baseline");
  const [manualDraft, setManualDraft] = useState<ManualDastValidationDraft>({ target_url: targetUrl, verdict: "uncertain", evidence_summary: "", reproduction_steps: "", response_summary: "", remediation_hint: "" });
  const [reviewValidationId, setReviewValidationId] = useState("");
  const findingMap = new Map(findings.map((item) => [item.id, item]));
  const selectedFinding = findingMap.get(selectedFindingId);
  const selectedStrategy = strategies.find((item) => item.id === strategyId) ?? strategies[0];
  const attention = validations.filter((item) => item.verdict === "baseline_attention" || item.verdict === "exploitable").length;
  const uncertain = validations.filter((item) => item.verdict === "uncertain").length;
  const linked = validations.filter((item) => item.finding_id || item.component_id).length;
  const filtered = validations.filter((item) => {
    const isLinked = Boolean(item.finding_id || item.component_id);
    return (!filters.keyword.trim() || item.target_url.toLowerCase().includes(filters.keyword.trim().toLowerCase()))
      && (filters.verdict === "all" || item.verdict === filters.verdict)
      && (filters.linked === "all" || (filters.linked === "linked") === isLinked);
  });
  const pagination = paginate(filtered, page);
  const manualRecords = validations.filter((item) => item.validation_mode === "manual_validation");
  const reviewRecord = manualRecords.find((item) => item.id === reviewValidationId);
  const manualReady = Boolean(selectedFindingId && selectedStrategy && manualDraft.target_url.trim() && manualDraft.evidence_summary.trim() && manualDraft.reproduction_steps.trim());
  useEffect(() => { setPage(1); }, [filters.keyword, filters.verdict, filters.linked]);
  return <ModuleGovernanceShell moduleKey="dast" lastStatus={validations.length ? "completed" : null} metrics={[["观察记录", validations.length], ["需复核信号", attention], ["未完成观察", uncertain], ["已关联风险", linked]]} action={attention ? `有 ${attention} 条基础观察带有需复核信号；它们不是漏洞利用证明，应按策略补充业务验证。` : uncertain ? `有 ${uncertain} 项基础观察未完成，需要补充网络、登录态、业务参数或专用验证策略。` : "基础观察未发现异常；这不代表上游漏洞已经排除，也不等于不可利用。"} loading={loading} hideRunButton onRun={onRun}>
    <section className="validation-workbench">
      <div className="workbench-heading"><span>动态证明</span><h3>选择一条已发现风险，在运行系统中验证它是否能被触发</h3><p>只有从具体风险发起的验证才会进入证据链；当前自动能力属于 Web 基础验证，业务漏洞应补充对应测试策略。</p></div>
        <div className="module-filter-bar"><button className={entryMode === "baseline" ? "primary-action" : "secondary-action"} onClick={() => setEntryMode("baseline")}>自动基础观察</button><button className={entryMode === "manual" ? "primary-action" : "secondary-action"} onClick={() => setEntryMode("manual")}>人工验证记录</button></div>
        <div className="validation-form">
          <label><span>① 待验证风险</span><select value={selectedFindingId} onChange={(event) => onSelectRisk(event.target.value)}><option value="">请选择 SAST / SCA / AGENT 风险</option>{findings.map((finding) => <option value={finding.id} key={finding.id}>{finding.source} · {severityLabel(finding.severity)} · {finding.title}</option>)}</select></label>
          <ArrowRight size={18} />
          <label><span>② 验证策略</span><select value={strategyId} onChange={(event) => onStrategyChange(event.target.value)} disabled={!selectedFinding || strategies.length === 0}><option value="">请选择策略</option>{strategies.map((strategy) => <option value={strategy.id} key={strategy.id}>{strategy.name}</option>)}</select></label>
          {entryMode === "baseline" ? <><label><span>③ 已配置项目同源目标</span><input value={targetUrl} onChange={(event) => onTargetUrlChange(event.target.value)} placeholder="https://项目运行地址/具体接口" /></label><label><span>④ 精确连接确认</span><input value={targetConfirmation} onChange={(event) => onTargetConfirmationChange(event.target.value)} placeholder={`DAST_WEB_BASELINE:${targetUrl}`} /></label><ArrowRight size={18} /><button className="primary-action" disabled={loading || !selectedFindingId || !targetUrl.trim() || targetConfirmation !== `DAST_WEB_BASELINE:${targetUrl}` || !selectedStrategy} onClick={() => void onRun()}>{loading ? "观察中" : "⑤ 执行基础观察"}</button></> : <><label><span>③ 验证目标（仅记录）</span><input value={manualDraft.target_url} onChange={(event) => setManualDraft({ ...manualDraft, target_url: event.target.value })} placeholder="https://已验证的目标或接口" /></label><label><span>④ 人工裁决</span><select value={manualDraft.verdict} onChange={(event) => setManualDraft({ ...manualDraft, verdict: event.target.value as ManualDastValidationDraft["verdict"] })}><option value="exploitable">可利用（需复现证据）</option><option value="uncertain">不确定</option><option value="not_exploitable">限定范围内未复现</option></select></label><button className="primary-action" disabled={loading || !manualReady} onClick={() => void onCreateManual(manualDraft)}>{loading ? "保存中" : "⑤ 保存人工验证"}</button></>}
        </div>
        {entryMode === "baseline" ? <p className="retest-note">该操作只会对已配置项目运行地址或 API 地址的同源 URL 发送一次无认证 GET；不跟随重定向、不读取正文、不发送 payload。输入精确确认短语后才会连接目标。</p> : <div className="verification-strategy-card"><label><span>必填：观察证据摘要</span><textarea value={manualDraft.evidence_summary} onChange={(event) => setManualDraft({ ...manualDraft, evidence_summary: event.target.value })} placeholder="说明实际观察到的响应、日志或人工复核证据；不要将未观察行为写成不存在。" /></label><label><span>必填：复现步骤与范围</span><textarea value={manualDraft.reproduction_steps} onChange={(event) => setManualDraft({ ...manualDraft, reproduction_steps: event.target.value })} placeholder="记录环境、身份、输入、步骤和实际结果。限定范围内未复现不等于不可利用。" /></label><label><span>可选：响应摘要</span><textarea value={manualDraft.response_summary} onChange={(event) => setManualDraft({ ...manualDraft, response_summary: event.target.value })} placeholder="仅记录允许保留的摘要。" /></label><label><span>可选：修复提示</span><textarea value={manualDraft.remediation_hint} onChange={(event) => setManualDraft({ ...manualDraft, remediation_hint: event.target.value })} placeholder="人工建议，不自动修改代码。" /></label><p>保存人工记录不会发起网络请求、执行 payload 或修改目标；结论仅适用于所记录的范围与证据。</p></div>}
        {selectedStrategy ? <section className="verification-strategy-card"><div><span>本次会检查</span><strong>{selectedStrategy.name}</strong><p>{selectedStrategy.description}</p><ul>{selectedStrategy.check_items.map((item) => <li key={item}>{item}</li>)}</ul></div><div><span>明确不检查</span><p>{selectedStrategy.scope_summary}</p><ul>{selectedStrategy.limitations.map((item) => <li key={item}>{item}</li>)}</ul></div></section> : <div className="workbench-empty">先选择风险，系统才会给出适合该风险的安全验证策略。</div>}
      {selectedFinding ? <div className="selected-risk-context"><span className={`severity ${selectedFinding.severity}`}>{severityLabel(selectedFinding.severity)}</span><div><strong>{selectedFinding.title}</strong><small>{selectedFinding.source} · {selectedFinding.file_path ?? "项目级风险"} · {selectedFinding.rule_id}</small></div><b>本次结果将回写到这条风险的证据链</b></div> : <div className="workbench-empty">请先选择风险。没有上游风险的 URL 检查只属于 Web 基础检查，不计入漏洞证据闭环。</div>}
    </section>
    <ModuleFilterBar><input value={filters.keyword} onChange={(event) => setFilters({ ...filters, keyword: event.target.value })} placeholder="搜索验证地址" /><SimpleFilter value={filters.verdict} label="全部观察 / 裁决" options={["baseline_attention", "baseline_clear", "exploitable", "uncertain", "not_exploitable"]} format={dastVerdictLabel} onChange={(value) => setFilters({ ...filters, verdict: value })} /><SimpleFilter value={filters.linked} label="全部关联状态" options={["linked", "unlinked"]} format={(value) => value === "linked" ? "已关联风险" : "独立验证"} onChange={(value) => setFilters({ ...filters, linked: value })} /></ModuleFilterBar>
    <table className="concise-table"><thead><tr><th>关联的原始风险</th><th>验证目标 / 策略</th><th>观察 / 裁决</th><th>验证证据</th></tr></thead><tbody>{pagination.items.length === 0 ? <tr><td colSpan={4} className="empty-cell">没有符合筛选条件的动态验证记录。</td></tr> : pagination.items.map((item) => { const linkedFinding = item.finding_id ? findingMap.get(item.finding_id) : null; return <tr key={item.id}><td>{linkedFinding ? <><strong>{linkedFinding.title}</strong><span className="cell-subtext">{linkedFinding.source} · {severityLabel(linkedFinding.severity)}</span></> : <><strong>独立 Web 基础检查</strong><span className="cell-subtext">不计入漏洞证据链</span></>}</td><td><strong>{item.target_url}</strong><span className="cell-subtext">{item.strategy_name ?? "旧记录：未保存策略"}</span><span className="cell-subtext">{formatDateTime(item.created_at)}</span></td><td><span className={`verdict-badge ${item.verdict}`}>{dastVerdictLabel(item.verdict)}</span><span className="cell-subtext">{item.validation_mode === "manual_validation" ? "人工验证记录" : "自动基础观察"} · 关联可信度 {item.link_confidence}%</span></td><td><details className="record-evidence"><summary>{truncateText(item.evidence_summary ?? "查看验证过程", 80)}</summary><dl><div><dt>策略范围</dt><dd>{item.scope_summary ?? "旧记录未保存检查范围"}</dd></div><div><dt>能力边界</dt><dd>{item.limitations ?? "旧记录未保存能力边界"}</dd></div><div><dt>请求</dt><dd>{item.request_summary ?? "未记录"}</dd></div><div><dt>响应</dt><dd>{item.response_summary ?? "未记录"}</dd></div><div><dt>复现过程</dt><dd>{item.reproduction_steps ?? "未记录"}</dd></div><div><dt>修复提示</dt><dd>{item.remediation_hint ?? "未记录"}</dd></div></dl></details></td></tr>; })}</tbody></table>
    <Pagination page={pagination.page} pageCount={pagination.pageCount} total={filtered.length} onPageChange={setPage} />
    <section className="verification-strategy-card">
      <div><span>本地交付</span><strong>DAST 专项报告与人工复核</strong><p>报告仅汇总已保存记录；导出和编辑均不会连接目标。自动基础观察为原始只读记录，不能在此改写为人工结论。</p></div>
      <div className="filter-grid"><button className="secondary-action" disabled={loading} onClick={() => void onExportReport()}>导出 DAST JSON 报告</button><label>选择人工记录复核<select value={reviewValidationId} onChange={(event) => setReviewValidationId(event.target.value)}><option value="">请选择人工验证记录</option>{manualRecords.map((item) => <option key={item.id} value={item.id}>{dastVerdictLabel(item.verdict)} · {item.target_url} · {formatDateTime(item.created_at)}</option>)}</select></label></div>
      {reviewRecord ? <ManualDastReviewEditor key={reviewRecord.id} validation={reviewRecord} loading={loading} onSave={onUpdateManual} /> : <p>{manualRecords.length ? "选择一条人工记录后可编辑其目标、裁决、证据与复现步骤。" : "暂无人工验证记录；自动基础观察保持只读。"}</p>}
    </section>
    <DastVerificationLedger project={project} findings={findings} validations={validations} strategies={strategies} />
    <DastBusinessFlowWorkspace project={project} />
  </ModuleGovernanceShell>;
}

function ManualDastReviewEditor({ validation, loading, onSave }: { validation: DastValidation; loading: boolean; onSave: (validationId: string, draft: ManualDastValidationDraft) => Promise<void> }) {
  const [draft, setDraft] = useState<ManualDastValidationDraft>({ target_url: validation.target_url, verdict: validation.verdict as ManualDastValidationDraft["verdict"], evidence_summary: validation.evidence_summary ?? "", reproduction_steps: validation.reproduction_steps ?? "", response_summary: validation.response_summary ?? "", remediation_hint: validation.remediation_hint ?? "" });
  const ready = Boolean(draft.target_url.trim() && draft.evidence_summary.trim() && draft.reproduction_steps.trim());
  return <div className="verification-strategy-card"><label><span>验证目标（仅更新记录）</span><input value={draft.target_url} onChange={(event) => setDraft({ ...draft, target_url: event.target.value })} /></label><label><span>人工裁决</span><select value={draft.verdict} onChange={(event) => setDraft({ ...draft, verdict: event.target.value as ManualDastValidationDraft["verdict"] })}><option value="exploitable">可利用（需复现证据）</option><option value="uncertain">不确定</option><option value="not_exploitable">限定范围内未复现</option></select></label><label><span>必填：观察证据摘要</span><textarea value={draft.evidence_summary} onChange={(event) => setDraft({ ...draft, evidence_summary: event.target.value })} /></label><label><span>必填：复现步骤与范围</span><textarea value={draft.reproduction_steps} onChange={(event) => setDraft({ ...draft, reproduction_steps: event.target.value })} /></label><label><span>可选：响应摘要</span><textarea value={draft.response_summary} onChange={(event) => setDraft({ ...draft, response_summary: event.target.value })} /></label><label><span>可选：修复提示</span><textarea value={draft.remediation_hint} onChange={(event) => setDraft({ ...draft, remediation_hint: event.target.value })} /></label><p>复核只更新本地人工记录；请仅写入实际观察到的内容，限定范围内未复现不等于不可利用。</p><button className="primary-action" disabled={loading || !ready} onClick={() => void onSave(validation.id, draft)}>{loading ? "保存中" : "保存人工复核"}</button></div>;
}

function DastVerificationLedger({ project, findings, validations, strategies }: { project: Project; findings: Finding[]; validations: DastValidation[]; strategies: DastStrategy[] }) {
  const [report, setReport] = useState<DastReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [planDraft, setPlanDraft] = useState({ title: "", target_url: "", authorized_scope: "", allowed_paths: "", allowed_methods: "GET", finding_id: "", strategy_id: "web-baseline", limitations: "", requester: "" });
  const [selectedPlanId, setSelectedPlanId] = useState("");
  const [selectedRunId, setSelectedRunId] = useState("");
  const [approval, setApproval] = useState({ reference: "", approved_by: "" });
  const [runDraft, setRunDraft] = useState({ operator: "", purpose: "" });
  const [evidenceDraft, setEvidenceDraft] = useState({ evidence_type: "manual_observation", content_summary: "", source_reference: "", collected_by: "" });
  const [validationId, setValidationId] = useState("");
  const load = async () => {
    setLoading(true);
    try { setReport(await request<DastReport>(`/dast/projects/${project.id}/report`)); setMessage(""); }
    catch (error) { setMessage(`台账加载失败：${errorMessage(error)}`); }
    finally { setLoading(false); }
  };
  useEffect(() => { void load(); }, [project.id]);
  const plans = report?.verification_plans ?? [];
  const runs = report?.verification_runs ?? [];
  const evidence = report?.evidence_index ?? [];
  const selectedPlan = plans.find((item) => item.id === selectedPlanId);
  const selectedRun = runs.find((item) => item.id === selectedRunId);
  async function createPlan() {
    if (!planDraft.title.trim() || !planDraft.target_url.trim() || !planDraft.authorized_scope.trim() || !planDraft.requester.trim()) return setMessage("请填写计划标题、目标、授权范围和申请人。");
    setLoading(true);
    try {
      await request("/dast/plans", { method: "POST", body: JSON.stringify({ project_id: project.id, title: planDraft.title, target_url: planDraft.target_url, authorized_scope: planDraft.authorized_scope, allowed_paths: splitLines(planDraft.allowed_paths), allowed_methods: planDraft.allowed_methods.split(",").map((item) => item.trim()).filter(Boolean), finding_id: emptyToNull(planDraft.finding_id), strategy_id: planDraft.strategy_id, limitations: emptyToNull(planDraft.limitations), requester: planDraft.requester }) });
      setPlanDraft({ ...planDraft, title: "", authorized_scope: "", allowed_paths: "", limitations: "" });
      await load(); setMessage("DAST 验证计划已保存为草稿；尚未获得审批，也未连接目标。");
    } catch (error) { setMessage(`计划保存失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }
  async function approvePlan() {
    if (!selectedPlan || !approval.reference.trim() || !approval.approved_by.trim()) return setMessage("请选择计划并填写审批依据与审批人。");
    setLoading(true);
    try { await request(`/dast/plans/${selectedPlan.id}`, { method: "PATCH", body: JSON.stringify({ approval_status: "approved", approval_reference: approval.reference, approved_by: approval.approved_by }) }); await load(); setMessage("审批记录已保存；本版本创建的仍是仅文档台账，不会连接目标。"); }
    catch (error) { setMessage(`审批记录保存失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }
  async function createRun() {
    if (!selectedPlan || !runDraft.operator.trim()) return setMessage("请选择已审批计划并填写记录人。");
    setLoading(true);
    try { await request(`/dast/plans/${selectedPlan.id}/runs`, { method: "POST", body: JSON.stringify(runDraft) }); await load(); setMessage("已创建仅文档 DAST 运行台账；平台没有发起请求或执行测试。"); }
    catch (error) { setMessage(`运行台账创建失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }
  async function addEvidence() {
    if (!selectedRun || !evidenceDraft.content_summary.trim()) return setMessage("请选择运行台账并填写实际观察摘要。");
    setLoading(true);
    try { await request(`/dast/runs/${selectedRun.id}/evidence`, { method: "POST", body: JSON.stringify(evidenceDraft) }); setEvidenceDraft({ ...evidenceDraft, content_summary: "", source_reference: "" }); await load(); setMessage("证据摘要已脱敏并写入哈希索引；请勿输入密钥或完整敏感正文。"); }
    catch (error) { setMessage(`证据保存失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }
  async function markReviewed() {
    if (!selectedRun || !validationId) return setMessage("请选择运行台账和一条人工 DAST 三态裁决。");
    setLoading(true);
    try { await request(`/dast/runs/${selectedRun.id}`, { method: "PATCH", body: JSON.stringify({ validation_id: validationId, status: "reviewed" }) }); await load(); setMessage("运行台账已关联人工裁决并标为已复核；结论仍只适用于记录范围与证据。"); }
    catch (error) { setMessage(`复核关联失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }
  return <details className="advanced-details governance-advanced-details" open><summary>PPT 验收：DAST 验证计划、证据台账与回溯</summary><div className="advanced-details-body">
    <p>本阶段只建立可审计的本地工作流。运行模式固定为“仅文档记录”，不会连接目标、爬取页面、登录、发送 payload 或执行漏洞测试。</p>
    <section className="verification-strategy-card"><div><span>① 验证计划</span><strong>授权范围与策略</strong><p>计划默认是草稿。审批记录仅保存你填写的依据和人员，不替代真实身份认证或外部授权。</p></div><div className="filter-grid"><label>计划标题<input value={planDraft.title} onChange={(event) => setPlanDraft({ ...planDraft, title: event.target.value })} /></label><label>目标（仅记录）<input value={planDraft.target_url} onChange={(event) => setPlanDraft({ ...planDraft, target_url: event.target.value })} placeholder="https://已获授权的测试环境" /></label><label>关联 Finding<select value={planDraft.finding_id} onChange={(event) => setPlanDraft({ ...planDraft, finding_id: event.target.value })}><option value="">不关联 Finding</option>{findings.map((item) => <option key={item.id} value={item.id}>{item.source} · {item.title}</option>)}</select></label><label>验证策略<select value={planDraft.strategy_id} onChange={(event) => setPlanDraft({ ...planDraft, strategy_id: event.target.value })}>{strategies.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label>授权范围<textarea value={planDraft.authorized_scope} onChange={(event) => setPlanDraft({ ...planDraft, authorized_scope: event.target.value })} placeholder="环境、允许测试窗口、数据边界和禁止项" /></label><label>允许路径（每行一条）<textarea value={planDraft.allowed_paths} onChange={(event) => setPlanDraft({ ...planDraft, allowed_paths: event.target.value })} /></label><label>允许 HTTP 方法（逗号分隔）<input value={planDraft.allowed_methods} onChange={(event) => setPlanDraft({ ...planDraft, allowed_methods: event.target.value })} /></label><label>限制<textarea value={planDraft.limitations} onChange={(event) => setPlanDraft({ ...planDraft, limitations: event.target.value })} /></label><label>申请人<input value={planDraft.requester} onChange={(event) => setPlanDraft({ ...planDraft, requester: event.target.value })} /></label><button className="primary-action" disabled={loading} onClick={() => void createPlan()}>保存草稿计划</button></div></section>
    <section className="verification-strategy-card"><div><span>② 审批与台账</span><strong>{plans.length} 个计划 · {runs.length} 条运行记录 · {evidence.length} 项证据</strong><p>只有标为已审批的计划才能创建台账；创建台账不代表已执行 Web 测试。</p></div><div className="filter-grid"><label>选择计划<select value={selectedPlanId} onChange={(event) => { setSelectedPlanId(event.target.value); setSelectedRunId(""); }}><option value="">请选择计划</option>{plans.map((item) => <option key={item.id} value={item.id}>{item.approval_status === "approved" ? "已审批" : item.approval_status} · {item.title}</option>)}</select></label>{selectedPlan ? <><label>审批依据<input value={approval.reference} onChange={(event) => setApproval({ ...approval, reference: event.target.value })} placeholder="工单号、书面授权编号等" /></label><label>审批人<input value={approval.approved_by} onChange={(event) => setApproval({ ...approval, approved_by: event.target.value })} /></label><button className="secondary-action" disabled={loading || selectedPlan.approval_status === "approved"} onClick={() => void approvePlan()}>记录审批</button><label>台账记录人<input value={runDraft.operator} onChange={(event) => setRunDraft({ ...runDraft, operator: event.target.value })} /></label><label>台账目的<input value={runDraft.purpose} onChange={(event) => setRunDraft({ ...runDraft, purpose: event.target.value })} /></label><button className="secondary-action" disabled={loading || selectedPlan.approval_status !== "approved"} onClick={() => void createRun()}>创建仅文档台账</button></> : null}</div></section>
    <section className="verification-strategy-card"><div><span>③ 证据与人工结论</span><strong>脱敏摘要、哈希、时间线</strong><p>系统对常见 Authorization、Token、Password、Secret 字段脱敏后计算哈希；该能力不是原始响应、截图或完整执行日志归档。</p></div><div className="filter-grid"><label>选择运行台账<select value={selectedRunId} onChange={(event) => setSelectedRunId(event.target.value)}><option value="">请选择运行台账</option>{runs.filter((item) => !selectedPlanId || item.plan_id === selectedPlanId).map((item) => <option key={item.id} value={item.id}>{item.status} · {item.operator} · {formatDateTime(item.created_at)}</option>)}</select></label>{selectedRun ? <><label>证据类型<input value={evidenceDraft.evidence_type} onChange={(event) => setEvidenceDraft({ ...evidenceDraft, evidence_type: event.target.value })} /></label><label>实际观察摘要<textarea value={evidenceDraft.content_summary} onChange={(event) => setEvidenceDraft({ ...evidenceDraft, content_summary: event.target.value })} placeholder="仅写入允许保留且实际观察到的摘要" /></label><label>来源引用（可选）<input value={evidenceDraft.source_reference} onChange={(event) => setEvidenceDraft({ ...evidenceDraft, source_reference: event.target.value })} /></label><label>采集人（可选）<input value={evidenceDraft.collected_by} onChange={(event) => setEvidenceDraft({ ...evidenceDraft, collected_by: event.target.value })} /></label><button className="secondary-action" disabled={loading} onClick={() => void addEvidence()}>保存脱敏证据</button><label>关联人工三态裁决<select value={validationId} onChange={(event) => setValidationId(event.target.value)}><option value="">请选择人工验证记录</option>{validations.filter((item) => item.validation_mode === "manual_validation").map((item) => <option key={item.id} value={item.id}>{dastVerdictLabel(item.verdict)} · {item.target_url}</option>)}</select></label><button className="primary-action" disabled={loading || selectedRun.status === "reviewed"} onClick={() => void markReviewed()}>关联结论并复核</button></> : null}</div>{selectedRun ? <div className="empty-project">当前台账证据：{evidence.filter((item) => item.run_id === selectedRun.id).map((item) => <p key={item.id}>{item.evidence_type} · 哈希 {item.content_hash.slice(0, 12)}… · {formatDateTime(item.created_at)}</p>)}</div> : null}</section>
    {message ? <div className="empty-project">{message}</div> : null}
  </div></details>;
}

function DastBusinessFlowWorkspace({ project }: { project: Project }) {
  const [candidates, setCandidates] = useState<DastBusinessCandidate[]>([]);
  const [flows, setFlows] = useState<DastBusinessFlow[]>([]);
  const [runs, setRuns] = useState<DastBusinessRun[]>([]);
  const [snapshots, setSnapshots] = useState<DastBusinessSnapshot[]>([]);
  const [candidateId, setCandidateId] = useState("");
  const [flowId, setFlowId] = useState("");
  const [runId, setRunId] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [draft, setDraft] = useState({ name: "", target_url: "", flow_mode: "hybrid", authorized_scope: "", allowed_paths: "", requester: "", roles: '[{"alias":"user_a","credential_ref":"env:DAST_FLOW_USER_A","description":"测试身份 A"}]', steps: '[{"id":"step-1","kind":"http_request","role":"user_a","method":"GET","url":""}]', criteria: '{"required_assertions":[]}' });
  const [approval, setApproval] = useState({ reference: "", approved_by: "" });
  const [runDraft, setRunDraft] = useState({ operator: "", execution_mode: "dry_run", confirmation: "" });
  const [verdict, setVerdict] = useState({ value: "uncertain", reason: "" });
  const [aiDraft, setAiDraft] = useState({ business: "", target: "", confirmation: "" });
  const [aiHealth, setAiHealth] = useState<{ configured: boolean; status: string; model?: string; data_boundary?: string } | null>(null);
  const [showAdvancedEditor, setShowAdvancedEditor] = useState(false);
  const [simpleFlow, setSimpleFlow] = useState({ userA: "用户 A", userAEnv: "DAST_FLOW_USER_A", userB: "用户 B", userBEnv: "DAST_FLOW_USER_B", protectedPath: "", proofMarker: "", expectedOutcome: "blocked" });
  const selectedFlow = flows.find((item) => item.id === flowId);
  const selectedRun = runs.find((item) => item.id === runId);
  const selectedCandidate = candidates.find((item) => item.id === candidateId);
  const load = async () => {
    setLoading(true);
    try {
      const [nextCandidates, nextFlows, health] = await Promise.all([
        request<DastBusinessCandidate[]>(`/dast/projects/${project.id}/business-candidates`),
        request<DastBusinessFlow[]>(`/dast/projects/${project.id}/business-flows`),
        request<{ configured: boolean; status: string; model?: string; data_boundary?: string }>("/dast/business-draft-health"),
      ]);
      setCandidates(nextCandidates); setFlows(nextFlows); setAiHealth(health); setMessage("");
    } catch (error) { setMessage(`业务验证数据加载失败：${errorMessage(error)}`); } finally { setLoading(false); }
  };
  const loadRuns = async (nextFlowId: string) => { if (!nextFlowId) { setRuns([]); return; } try { setRuns(await request<DastBusinessRun[]>(`/dast/business-flows/${nextFlowId}/runs`)); } catch (error) { setMessage(`运行记录加载失败：${errorMessage(error)}`); } };
  const loadSnapshots = async (nextRunId: string) => { if (!nextRunId) { setSnapshots([]); return; } try { setSnapshots(await request<DastBusinessSnapshot[]>(`/dast/business-runs/${nextRunId}/snapshots`)); } catch (error) { setMessage(`步骤快照加载失败：${errorMessage(error)}`); } };
  useEffect(() => { void load(); }, [project.id]);
  async function createFlow() {
    try {
      const roles = JSON.parse(draft.roles) as Record<string, unknown>[];
      const steps = JSON.parse(draft.steps) as Record<string, unknown>[];
      const criteria = JSON.parse(draft.criteria) as Record<string, unknown>;
      if (!draft.name.trim() || !draft.target_url.trim() || !draft.authorized_scope.trim() || !draft.requester.trim()) return setMessage("请填写流程名称、目标、授权范围和申请人。");
      setLoading(true);
      await request("/dast/business-flows", { method: "POST", body: JSON.stringify({ project_id: project.id, finding_id: candidateId || null, name: draft.name, target_url: draft.target_url, flow_mode: draft.flow_mode, strategy_source: "manual", authorized_scope: draft.authorized_scope, allowed_paths: splitLines(draft.allowed_paths), roles, steps, sufficiency_criteria: criteria, requester: draft.requester }) });
      await load(); setMessage("业务流程草案已保存；尚未审批、未连接任何目标。");
    } catch (error) { setMessage(`流程草案格式或保存失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }
  function absoluteTarget(path: string) {
    if (/^https?:\/\//i.test(path.trim())) return path.trim();
    return `${draft.target_url.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
  }
  async function createSimpleFlow() {
    if (!draft.name.trim() || !draft.target_url.trim() || !draft.authorized_scope.trim() || !draft.requester.trim() || !simpleFlow.protectedPath.trim()) return setMessage("请先填写流程名称、目标地址、授权范围、申请人和受保护资源路径。");
    if (simpleFlow.expectedOutcome === "exposed" && !simpleFlow.proofMarker.trim()) return setMessage("选择“用户 B 能读取用户 A 的数据”时，必须填写用于证明归属的脱敏响应标记。");
    const roleA = "user_a";
    const roleB = "user_b";
    const bStatuses = simpleFlow.expectedOutcome === "blocked" ? [401, 403, 404] : [200];
    const bVerdict = simpleFlow.expectedOutcome === "blocked" ? "not_exploitable" : simpleFlow.expectedOutcome === "exposed" ? "exploitable" : undefined;
    const bAssertion: Record<string, unknown> = { id: "check-user-b", kind: "assert", role: roleB, status_in: bStatuses };
    if (simpleFlow.proofMarker.trim()) bAssertion.body_contains = simpleFlow.proofMarker.trim();
    if (bVerdict) bAssertion.verdict_on_pass = bVerdict;
    const resourceUrl = absoluteTarget(simpleFlow.protectedPath);
    const roles = [
      { alias: roleA, credential_ref: `env:${simpleFlow.userAEnv.trim()}`, description: simpleFlow.userA.trim() || "用户 A" },
      { alias: roleB, credential_ref: `env:${simpleFlow.userBEnv.trim()}`, description: simpleFlow.userB.trim() || "用户 B" },
    ];
    const steps = [
      { id: "read-as-user-a", kind: "http_request", role: roleA, method: "GET", url: resourceUrl, headers: { Authorization: "Bearer {{credential.token}}" } },
      { id: "check-user-a", kind: "assert", role: roleA, status_in: [200] },
      { id: "switch-to-user-b", kind: "switch_identity", role: roleB },
      { id: "read-as-user-b", kind: "http_request", role: roleB, method: "GET", url: resourceUrl, headers: { Authorization: "Bearer {{credential.token}}" } },
      bAssertion,
    ];
    try {
      setLoading(true);
      await request("/dast/business-flows", { method: "POST", body: JSON.stringify({ project_id: project.id, finding_id: candidateId || null, name: draft.name, target_url: draft.target_url, flow_mode: "api", strategy_source: "manual", authorized_scope: draft.authorized_scope, allowed_paths: splitLines(draft.allowed_paths), roles, steps, sufficiency_criteria: { scenario: "read_only_authorization_check", expected_outcome: simpleFlow.expectedOutcome, required_assertions: ["check-user-a", "check-user-b"] }, requester: draft.requester }) });
      await load(); setMessage("只读权限验证草案已保存；尚未审批，未连接任何目标。");
    } catch (error) { setMessage(`草案保存失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }
  async function approveFlow() {
    if (!selectedFlow || !approval.reference.trim() || !approval.approved_by.trim()) return setMessage("请选择流程并填写审批依据与审批人。");
    setLoading(true); try { await request(`/dast/business-flows/${selectedFlow.id}`, { method: "PATCH", body: JSON.stringify({ status: "approved", approval_reference: approval.reference, approved_by: approval.approved_by }) }); await load(); setMessage("流程审批已记录。实际连接仍须在执行时输入精确确认短语。"); } catch (error) { setMessage(`审批保存失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }
  async function execute() {
    if (!selectedFlow || !runDraft.operator.trim()) return setMessage("请选择流程并填写操作人。");
    setLoading(true); try { const created = await request<DastBusinessRun>(`/dast/business-flows/${selectedFlow.id}/runs`, { method: "POST", body: JSON.stringify({ operator: runDraft.operator, execution_mode: runDraft.execution_mode, target_confirmation: runDraft.confirmation || null }) }); await loadRuns(selectedFlow.id); setRunId(created.id); await loadSnapshots(created.id); setMessage(created.execution_mode === "dry_run" ? "Dry Run 已完成，未连接目标。" : "API 业务验证已完成；请查看每步快照和裁决依据。"); } catch (error) { setMessage(`流程运行失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }
  async function saveVerdict() {
    if (!selectedRun || !verdict.reason.trim()) return setMessage("请选择运行记录并填写裁决理由。");
    setLoading(true); try { await request(`/dast/business-runs/${selectedRun.id}/verdict`, { method: "PATCH", body: JSON.stringify({ verdict: verdict.value, reason: verdict.reason }) }); await loadRuns(selectedRun.flow_id); setMessage("三色裁决已保存；结论只适用于已记录的环境、身份、步骤和证据。"); } catch (error) { setMessage(`裁决保存失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }
  async function generateAiDraft() {
    if (!selectedCandidate || !aiDraft.business.trim() || !aiDraft.target.trim() || !aiDraft.confirmation.trim()) return setMessage("请选择候选，并填写业务说明、目标说明和精确确认短语。");
    setLoading(true); try { const result = await request<{ draft: { name: string; flow_mode: string; roles: Record<string, unknown>[]; steps: Record<string, unknown>[]; sufficiency_criteria: Record<string, unknown>; safety_notes: string[]; missing_information: string[] }; model: string }>(`/dast/business-candidates/${selectedCandidate.id}/ai-draft`, { method: "POST", body: JSON.stringify({ business_description: aiDraft.business, target_description: aiDraft.target, confirmation_phrase: aiDraft.confirmation }) }); setDraft({ ...draft, name: result.draft.name, flow_mode: result.draft.flow_mode, roles: JSON.stringify(result.draft.roles, null, 2), steps: JSON.stringify(result.draft.steps, null, 2), criteria: JSON.stringify(result.draft.sufficiency_criteria, null, 2) }); setMessage(`DeepSeek 已生成待审批草案（${result.model}）；请补全缺失信息后保存。`); } catch (error) { setMessage(`DeepSeek 草案生成失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }
  return <details className="advanced-details governance-advanced-details dast-business-workspace" open><summary>业务流程验证</summary><div className="advanced-details-body">
    <section className="dast-business-intro"><div><span>从风险线索到可复查结论</span><h3>创建一次业务安全验证</h3><p>依次选择风险、描述只读验证流程、审批并运行。系统不会自动连接目标，且不会执行删除、付款、发信、上传或修改真实数据的操作。</p></div><ol><li>选择风险线索</li><li>填写验证方案</li><li>审批并运行</li><li>查看证据与结论</li></ol></section>
    <section className="dast-business-step"><div className="dast-step-heading"><span>第 1 步</span><div><h3>选择要验证的风险</h3><p>可不关联静态风险；关联后，报告会保留来源关系。</p></div></div><label className="dast-field full-width">风险线索<select value={candidateId} onChange={(event) => setCandidateId(event.target.value)}><option value="">不关联静态风险</option>{candidates.map((item) => <option key={item.id} value={item.id}>{item.source} · {severityLabel(item.severity)} · {item.title}</option>)}</select></label>{selectedCandidate ? <div className="dast-info-strip"><strong>{selectedCandidate.vulnerability_type}</strong><span>还需要人工补充：{selectedCandidate.missing.join("、") || "无"}</span></div> : <div className="dast-info-strip">当前有 {candidates.length} 条可关联的 SCA / SAST / AGENT 风险线索。</div>}</section>
    <section className="dast-business-step"><div className="dast-step-heading"><span>第 2 步</span><div><h3>填写只读权限验证方案</h3><p>适用于“用户 B 能否读取用户 A 的受保护数据”这类业务越权验证。凭据只保存在后端环境变量中，此页面不填写密码或 Token。</p></div></div><div className="dast-form-grid"><label className="dast-field">流程名称<input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="例如：订单详情只读权限验证" /></label><label className="dast-field">已授权测试环境地址<input value={draft.target_url} onChange={(event) => setDraft({ ...draft, target_url: event.target.value })} placeholder="https://test.example.com" /></label><label className="dast-field full-width">授权范围<textarea rows={3} value={draft.authorized_scope} onChange={(event) => setDraft({ ...draft, authorized_scope: event.target.value })} placeholder="写明环境、测试窗口、允许的测试身份、数据边界和禁止操作。" /></label><label className="dast-field">允许访问的路径（每行一条）<textarea rows={3} value={draft.allowed_paths} onChange={(event) => setDraft({ ...draft, allowed_paths: event.target.value })} placeholder="/api/orders" /></label><label className="dast-field">申请人<input value={draft.requester} onChange={(event) => setDraft({ ...draft, requester: event.target.value })} placeholder="填写本次验证申请人" /></label></div><div className="dast-role-grid"><section><h4>测试身份 A：资源所属者</h4><label className="dast-field">显示名称<input value={simpleFlow.userA} onChange={(event) => setSimpleFlow({ ...simpleFlow, userA: event.target.value })} /></label><label className="dast-field">后端凭据变量名<input value={simpleFlow.userAEnv} onChange={(event) => setSimpleFlow({ ...simpleFlow, userAEnv: event.target.value })} placeholder="DAST_FLOW_USER_A" /></label></section><section><h4>测试身份 B：另一普通用户</h4><label className="dast-field">显示名称<input value={simpleFlow.userB} onChange={(event) => setSimpleFlow({ ...simpleFlow, userB: event.target.value })} /></label><label className="dast-field">后端凭据变量名<input value={simpleFlow.userBEnv} onChange={(event) => setSimpleFlow({ ...simpleFlow, userBEnv: event.target.value })} placeholder="DAST_FLOW_USER_B" /></label></section></div><div className="dast-form-grid"><label className="dast-field full-width">受保护资源地址或路径<input value={simpleFlow.protectedPath} onChange={(event) => setSimpleFlow({ ...simpleFlow, protectedPath: event.target.value })} placeholder="例如：/api/orders/已准备好的测试订单编号" /></label><label className="dast-field">预期结果<select value={simpleFlow.expectedOutcome} onChange={(event) => setSimpleFlow({ ...simpleFlow, expectedOutcome: event.target.value })}><option value="blocked">用户 B 应被拒绝访问</option><option value="exposed">用户 B 错误地读取到用户 A 的数据</option><option value="uncertain">只记录步骤，不自动裁决</option></select></label><label className="dast-field">用于证明数据归属的脱敏响应标记（可选）<input value={simpleFlow.proofMarker} onChange={(event) => setSimpleFlow({ ...simpleFlow, proofMarker: event.target.value })} placeholder="例如：已脱敏订单号或固定测试标识" /></label></div><div className="dast-action-row"><p>将依次以身份 A 和身份 B 对同一资源发起只读 GET 请求，再依据上述预期产生草案。保存不会连接目标。</p><button className="primary-action" disabled={loading} onClick={() => void createSimpleFlow()}>保存验证方案</button></div></section>
    <details className="dast-advanced-editor" open={showAdvancedEditor} onToggle={(event) => setShowAdvancedEditor(event.currentTarget.open)}><summary>高级配置：自定义 API 步骤或登录方式</summary><p>仅在常用的只读权限验证无法满足需求时使用。此处的内容供技术人员编辑，保存时同样不会连接目标。</p><div className="dast-form-grid"><label className="dast-field">流程类型<select value={draft.flow_mode} onChange={(event) => setDraft({ ...draft, flow_mode: event.target.value })}><option value="api">API</option><option value="browser">页面（当前不可执行）</option><option value="hybrid">页面 + API（当前仅 API 可执行）</option></select></label><div className="dast-field"></div><label className="dast-field full-width">测试身份配置（JSON）<textarea rows={7} value={draft.roles} onChange={(event) => setDraft({ ...draft, roles: event.target.value })} /></label><label className="dast-field full-width">验证步骤（JSON）<textarea rows={10} value={draft.steps} onChange={(event) => setDraft({ ...draft, steps: event.target.value })} /></label><label className="dast-field full-width">裁决标准（JSON）<textarea rows={5} value={draft.criteria} onChange={(event) => setDraft({ ...draft, criteria: event.target.value })} /></label></div><button className="secondary-action" disabled={loading} onClick={() => void createFlow()}>保存高级验证方案</button></details>
    <section className="dast-business-step"><div className="dast-step-heading"><span>可选</span><div><h3>让 DeepSeek 帮我起草方案</h3><p>{aiHealth?.configured ? "仅发送已脱敏的业务和接口说明；它只生成待审批草案，不会执行测试。" : "新 DAST DeepSeek Key 尚未生效或 API 服务尚未重启。"}</p></div></div><div className="dast-form-grid"><label className="dast-field">业务说明<textarea rows={3} value={aiDraft.business} onChange={(event) => setAiDraft({ ...aiDraft, business: event.target.value })} placeholder="例如：用户下单后只能查看自己的订单。" /></label><label className="dast-field">目标或 API 说明<textarea rows={3} value={aiDraft.target} onChange={(event) => setAiDraft({ ...aiDraft, target: event.target.value })} placeholder="只填写脱敏的域名、路径或接口说明。" /></label><label className="dast-field full-width">调用确认<input value={aiDraft.confirmation} onChange={(event) => setAiDraft({ ...aiDraft, confirmation: event.target.value })} placeholder={selectedCandidate ? `DAST_DEEPSEEK_DRAFT:${selectedCandidate.id}` : "先在第 1 步选择风险线索"} /></label></div><button className="secondary-action" disabled={loading || !aiHealth?.configured || !selectedCandidate} onClick={() => void generateAiDraft()}>生成待审批方案</button></section>
    <section className="dast-business-step"><div className="dast-step-heading"><span>第 3 步</span><div><h3>审批并运行</h3><p>Dry Run 只检查方案格式，永不连接目标。实际 API 验证必须先审批，并在运行时再次精确确认目标。</p></div></div><label className="dast-field full-width">选择已保存的验证方案<select value={flowId} onChange={(event) => { setFlowId(event.target.value); setRunId(""); void loadRuns(event.target.value); }}><option value="">请选择方案</option>{flows.map((item) => <option key={item.id} value={item.id}>{item.status === "approved" ? "已审批" : "草案"} · {item.name}</option>)}</select></label>{selectedFlow ? <div className="dast-form-grid"><label className="dast-field">审批依据<input value={approval.reference} onChange={(event) => setApproval({ ...approval, reference: event.target.value })} placeholder="例如：工单号或书面授权编号" /></label><label className="dast-field">审批人<input value={approval.approved_by} onChange={(event) => setApproval({ ...approval, approved_by: event.target.value })} /></label><div className="dast-action-row"><p>保存审批记录后，仍需在下一步单独确认才会连接目标。</p><button className="secondary-action" disabled={loading || selectedFlow.status === "approved"} onClick={() => void approveFlow()}>记录审批</button></div><label className="dast-field">操作人<input value={runDraft.operator} onChange={(event) => setRunDraft({ ...runDraft, operator: event.target.value })} /></label><label className="dast-field">运行方式<select value={runDraft.execution_mode} onChange={(event) => setRunDraft({ ...runDraft, execution_mode: event.target.value })}><option value="dry_run">检查方案（不连接目标）</option><option value="api_execution">执行已审批 API 方案（连接目标）</option></select></label>{runDraft.execution_mode === "api_execution" ? <label className="dast-field full-width">目标连接确认<input value={runDraft.confirmation} onChange={(event) => setRunDraft({ ...runDraft, confirmation: event.target.value })} placeholder={`DAST_BUSINESS_FLOW:${selectedFlow.id}:${selectedFlow.target_url}`} /></label> : null}<div className="dast-action-row"><p>{runDraft.execution_mode === "dry_run" ? "此操作不会发出任何网络请求。" : "该操作将连接上方已审批的目标；只会执行方案中允许的安全方法。"}</p><button className="primary-action" disabled={loading || (runDraft.execution_mode === "api_execution" && selectedFlow.status !== "approved")} onClick={() => void execute()}>{runDraft.execution_mode === "dry_run" ? "检查方案" : "执行已审批方案"}</button></div></div> : <div className="dast-info-strip">先保存一个验证方案，才能审批或运行。</div>}</section>
    <section className="dast-business-step"><div className="dast-step-heading"><span>第 4 步</span><div><h3>查看证据并给出结论</h3><p>结论仅适用于已记录的环境、身份、步骤和证据。一次请求失败不能直接得出“不可利用”。</p></div></div>{runs.length ? <><label className="dast-field full-width">选择运行记录<select value={runId} onChange={(event) => { setRunId(event.target.value); void loadSnapshots(event.target.value); }}><option value="">请选择运行记录</option>{runs.map((item) => <option key={item.id} value={item.id}>{item.execution_mode === "dry_run" ? "方案检查" : "API 验证"} · {item.status} · {item.verdict ? dastVerdictLabel(item.verdict) : "尚未裁决"}</option>)}</select></label>{selectedRun ? <div className="dast-form-grid"><label className="dast-field">最终结论<select value={verdict.value} onChange={(event) => setVerdict({ ...verdict, value: event.target.value })}><option value="exploitable">可利用：已有充分的无害证据</option><option value="not_exploitable">不可利用：已充分验证受到保护</option><option value="uncertain">不确定：证据不足或流程未完成</option></select></label><label className="dast-field">结论依据<textarea rows={3} value={verdict.reason} onChange={(event) => setVerdict({ ...verdict, reason: event.target.value })} placeholder="说明已完成的步骤、实际观察和证据位置。" /></label><div className="dast-action-row"><p>保存的是人工复核结论，不会再次连接目标。</p><button className="secondary-action" disabled={loading} onClick={() => void saveVerdict()}>保存结论</button></div></div> : null}</> : <div className="dast-info-strip">尚无运行记录。完成第 3 步后，脱敏快照会显示在这里。</div>}{snapshots.length ? <div className="evidence-record-stack">{snapshots.map((item) => <details key={item.id} className="record-evidence"><summary>{item.step_id} · {item.step_kind} · {item.status} · 证据 {item.evidence_hash.slice(0, 12)}…</summary><dl><div><dt>使用的测试身份</dt><dd>{item.role_alias ?? "无"}</dd></div><div><dt>请求摘要</dt><dd>{item.request_summary ?? "未发起请求"}</dd></div><div><dt>响应或结果</dt><dd>{item.response_summary ?? "未记录"}</dd></div><div><dt>步骤详情</dt><dd><pre className="code-preview">{JSON.stringify(item.detail, null, 2)}</pre></dd></div></dl></details>)}</div> : null}</section>
    {message ? <div className="dast-message">{message}</div> : null}
  </div></details>;
}

function SandboxGovernanceView({ project }: { project: Project }) {
  const [health, setHealth] = useState<SandboxCapabilityHealth | null>(null);
  const [templates, setTemplates] = useState<SandboxTemplate[]>([]);
  const [launchPlan, setLaunchPlan] = useState<SandboxLaunchPlan | null>(null);
  const [targets, setTargets] = useState<SandboxTarget[]>([]);
  const [tasks, setTasks] = useState<SandboxTask[]>([]);
  const [events, setEvents] = useState<SandboxTaskEvent[]>([]);
  const [selectedTaskId, setSelectedTaskId] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const selectedTask = tasks.find((item) => item.id === selectedTaskId) ?? tasks[0];
  const runningTargets = targets.filter((item) => item.status === "running");
  const activeTargets = targets.filter((item) => item.status !== "stopped");
  const stoppedTargetCount = targets.length - activeTargets.length;
  const suggestedStart = templates.find((item) => item.command_type === "start");
  const plannedStart = launchPlan?.recommended;
  const effectiveSandboxImage = project.sandbox_image || plannedStart?.image || suggestedStart?.image || "";
  const effectiveSandboxCommand = project.sandbox_command || plannedStart?.command || suggestedStart?.command || "";
  const dockerTargetReady = Boolean(project.source_path && ((project.sandbox_image && project.sandbox_command) || plannedStart || suggestedStart));

  async function reload() {
    const [nextHealth, nextTargets, nextTasks, nextTemplates] = await Promise.all([
      request<SandboxCapabilityHealth>("/sandbox/capabilities"),
      request<SandboxTarget[]>(`/sandbox/projects/${project.id}/targets`),
      request<SandboxTask[]>(`/sandbox/projects/${project.id}/tasks`),
      request<SandboxTemplate[]>(`/sandbox/projects/${project.id}/templates`),
    ]);
    const activeTaskId = nextTasks.some((item) => item.id === selectedTaskId) ? selectedTaskId : nextTasks[0]?.id ?? "";
    const nextEvents = activeTaskId ? await request<SandboxTaskEvent[]>(`/sandbox/tasks/${activeTaskId}/events`) : [];
    setHealth(nextHealth);
    setTargets(nextTargets);
    setTasks(nextTasks);
    setTemplates(nextTemplates);
    setSelectedTaskId(activeTaskId);
    setEvents(nextEvents);
    return { targetCount: nextTargets.length, taskCount: nextTasks.length, eventCount: nextEvents.length };
  }

  async function refreshWorkspace() {
    if (busy) return;
    setBusy("refresh");
    setMessage("正在重新检查执行能力、目标健康状态、任务队列和状态日志…");
    try {
      const refreshableTargets = targets.filter((target) => target.status !== "stopped");
      const healthResults = await Promise.allSettled(
        refreshableTargets.map((target) => request(`/sandbox/targets/${target.id}/health`, { method: "POST" })),
      );
      const failedHealthChecks = healthResults.filter((item) => item.status === "rejected").length;
      const summary = await reload();
      const refreshedAt = new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date());
      setMessage(`刷新完成（${refreshedAt}）：${summary.targetCount} 个目标、${summary.taskCount} 个任务、当前任务 ${summary.eventCount} 条状态日志${failedHealthChecks ? `；${failedHealthChecks} 个目标健康检查失败` : ""}。`);
    } catch (error) {
      setMessage(`工作台刷新失败：${errorMessage(error)}`);
    } finally {
      setBusy("");
    }
  }

  useEffect(() => {
    let active = true;
    setTargets([]); setTasks([]); setTemplates([]); setLaunchPlan(null); setEvents([]); setSelectedTaskId(""); setAuthorized(false); setMessage("");
    Promise.all([
      request<SandboxCapabilityHealth>("/sandbox/capabilities"),
      request<SandboxTarget[]>(`/sandbox/projects/${project.id}/targets`),
      request<SandboxTask[]>(`/sandbox/projects/${project.id}/tasks`),
      request<SandboxTemplate[]>(`/sandbox/projects/${project.id}/templates`),
      request<SandboxLaunchPlan>(`/sandbox/projects/${project.id}/launch-plan?use_ai=true`),
    ]).then(([nextHealth, nextTargets, nextTasks, nextTemplates, nextLaunchPlan]) => {
      if (!active) return;
      setHealth(nextHealth); setTargets(nextTargets); setTasks(nextTasks); setTemplates(nextTemplates); setLaunchPlan(nextLaunchPlan); setSelectedTaskId(nextTasks[0]?.id ?? "");
    }).catch((error) => { if (active) setMessage(`工作台加载失败：${errorMessage(error)}`); });
    return () => { active = false; };
  }, [project.id]);

  useEffect(() => {
    if (!selectedTask?.id) { setEvents([]); return; }
    let active = true;
    request<SandboxTaskEvent[]>(`/sandbox/tasks/${selectedTask.id}/events`).then((items) => { if (active) setEvents(items); }).catch((error) => { if (active) setMessage(`状态日志加载失败：${errorMessage(error)}`); });
    return () => { active = false; };
  }, [selectedTask?.id, selectedTask?.updated_at]);

  async function createTarget(mode: "external" | "docker") {
    setBusy(`target-${mode}`);
    setMessage(mode === "docker" ? `正在启动项目隔离实例：检查或拉取白名单镜像、在临时构建网络准备依赖、切换到隔离网络并等待 HTTP 健康检查。首次启动可能需要数分钟，请不要重复点击。` : "正在注册目标并执行可达性检查…");
    try {
      const created = await request<SandboxTarget>(`/sandbox/projects/${project.id}/targets`, { method: "POST", body: JSON.stringify({ mode, operator: "web-operator", operator_confirmed: authorized, browser_session_id: mode === "docker" ? SANDBOX_BROWSER_SESSION_ID : null, image: mode === "docker" ? effectiveSandboxImage : null, command: mode === "docker" ? effectiveSandboxCommand : null, container_port: mode === "docker" ? plannedStart?.container_port ?? suggestedStart?.container_port ?? null : null, health_path: mode === "docker" ? plannedStart?.health_path ?? "/" : "/" }) });
      if (mode === "docker") registerSandboxUnloadProject(project.id);
      await reload();
      setMessage(mode === "docker" ? created.status === "running" ? "项目专属隔离实例已启动；返回 DAST 刷新后会自动使用这个临时地址。" : `隔离实例已创建，但健康检查状态为“${sandboxStatusLabel(created.status)}”。请查看目标卡片的健康信息；依赖、数据库或启动环境未就绪时，DAST 不会使用该地址。` : created.status === "running" ? "已上线目标已注册并完成可达性检查。" : "目标已登记，但当前不可达；DAST 不会把它当作可运行目标。"
      );
    } catch (error) { setMessage(`目标创建失败：${errorMessage(error)}`); }
    finally { setBusy(""); }
  }

  async function refreshTarget(target: SandboxTarget) {
    setBusy(`health-${target.id}`); setMessage("");
    try { await request(`/sandbox/targets/${target.id}/health`, { method: "POST" }); await reload(); }
    catch (error) { setMessage(`健康检查失败：${errorMessage(error)}`); }
    finally { setBusy(""); }
  }

  async function bootstrapIdentity(target: SandboxTarget) {
    setBusy(`identity-${target.id}`);
    setMessage("正在识别注册/登录流程并创建一次性测试身份；凭据不会显示在页面或写入日志…");
    try {
      const updated = await request<SandboxTarget>(`/sandbox/targets/${target.id}/identities/bootstrap`, { method: "POST" });
      await reload();
      const identity = updated.health_detail?.identity as { status?: string; role_count?: number; detail?: string } | undefined;
      setMessage(identity?.status === "ready" ? `测试身份已就绪：${identity.role_count ?? 0} 个业务角色可由 DAST 自动复用。` : `自动身份初始化未完成：${identity?.detail ?? "项目需要登录适配器或管理员密钥引用。"}`);
    } catch (error) { setMessage(`测试身份初始化失败：${errorMessage(error)}`); }
    finally { setBusy(""); }
  }

  async function stopRuntime(target: SandboxTarget) {
    setBusy(`stop-${target.id}`); setMessage("");
    try { await request(`/sandbox/targets/${target.id}/stop`, { method: "POST" }); await reload(); setMessage("目标实例已停止；Docker 容器与专属网络已移除，任务和证据记录仍保留。"); }
    catch (error) { setMessage(`停止失败：${errorMessage(error)}`); }
    finally { setBusy(""); }
  }

  async function executeSelected() {
    if (!selectedTask) return;
    setBusy(`execute-${selectedTask.id}`); setMessage("");
    try {
      const target = runningTargets[0];
      const updated = await request<SandboxTask>(`/sandbox/tasks/${selectedTask.id}/execute`, { method: "POST", body: JSON.stringify({ operator: "web-operator", target_instance_id: target?.id ?? null }) });
      await reload();
      setSelectedTaskId(updated.id);
      setMessage(updated.status === "completed" ? "隔离执行完成，事实证据已回传 DAST 并完成三色裁决。" : `任务已进入 ${sandboxStatusLabel(updated.status)}。`);
    } catch (error) { setMessage(`执行失败：${errorMessage(error)}`); }
    finally { setBusy(""); }
  }

  async function cancelSelected() {
    if (!selectedTask) return;
    setBusy(`cancel-${selectedTask.id}`); setMessage("");
    try { await request(`/sandbox/tasks/${selectedTask.id}/cancel`, { method: "POST", body: JSON.stringify({ operator: "web-operator", reason: "操作员在 SANDBOX 工作台取消" }) }); await reload(); setMessage("任务已取消并同步回 DAST。" ); }
    catch (error) { setMessage(`取消失败：${errorMessage(error)}`); }
    finally { setBusy(""); }
  }

  const capabilityEntries = Object.entries(health?.capabilities ?? {});
  return <section className="sandbox-workbench">
    <section className="module-governance-heading sandbox-workbench-heading"><div className="module-icon">{moduleIcons.sandbox}</div><div><h2>{MODULE_DISPLAY.sandbox.name}</h2><p>{MODULE_DISPLAY.sandbox.purpose}</p></div><button className="secondary-action" disabled={Boolean(busy)} onClick={() => void refreshWorkspace()}>{busy === "refresh" ? "刷新中…" : "刷新工作台"}</button></section>
    {message ? <div className="panel full sandbox-message">{message}</div> : null}

    <section className="panel full"><div className="panel-header"><div><h2>1. 执行能力预检</h2><span>{health?.docker.detail ?? "正在检查执行环境"}</span></div><span className={`sandbox-state ${health?.status ?? "checking"}`}>{health?.status === "ready" ? "基础执行器就绪" : "存在阻塞项"}</span></div>
      <div className="sandbox-capability-grid">{capabilityEntries.map(([key, item]) => <article key={key} className={`sandbox-capability ${item.status}`}><div><strong>{sandboxCapabilityLabel(key)}</strong><span>{sandboxStatusLabel(item.status)}</span></div><p>{item.detail}</p></article>)}</div>
    </section>

    <section className="panel full"><div className="panel-header"><div><h2>2. 项目测试目标</h2><span>已上线地址可直接注册；只有源码时由 SANDBOX 生成临时 URL，不需要手工编写地址</span></div></div>
      <label className="sandbox-authorization"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span>我确认这些目标属于当前项目，且本次动态测试已获授权。</span></label>
      <div className="sandbox-target-actions"><button className="primary-action" disabled={!authorized || !Boolean(project.runtime_url || project.api_base_url) || Boolean(busy)} onClick={() => void createTarget("external")}>{busy === "target-external" ? <><LoaderCircle className="sandbox-spin" size={17} />正在检查目标…</> : "注册已上线目标"}</button><button className="secondary-action" disabled={!authorized || !dockerTargetReady || Boolean(busy)} onClick={() => void createTarget("docker")}>{busy === "target-docker" ? <><LoaderCircle className="sandbox-spin" size={17} />正在启动隔离实例…</> : "启动项目隔离实例"}</button></div>
      {busy === "target-docker" ? <div className="sandbox-start-progress"><LoaderCircle className="sandbox-spin" size={20} /><div><strong>隔离实例正在启动</strong><span>正在完成镜像校验/拉取 → 依赖准备 → 候选试运行 → 端口绑定 → HTTP 健康检查；首次启动可能需要几分钟</span></div></div> : null}
      {!project.runtime_url && !project.api_base_url ? effectiveSandboxImage && effectiveSandboxCommand ? <div className="dast-info-strip">{project.sandbox_image && project.sandbox_command ? "项目已保存运行方案" : plannedStart?.source === "deepseek_validated" ? "DeepSeek 候选已通过本地安全校验" : "已从源码确定启动方案"}：<strong>{effectiveSandboxImage}</strong> · <code>{effectiveSandboxCommand}</code> · 端口 {plannedStart?.container_port ?? suggestedStart?.container_port ?? 8000}。{launchPlan?.orchestration?.support_services.length ? ` 将同时编排：${launchPlan.orchestration.support_services.map((item) => `${item.kind}(${item.image})`).join("、")}；依赖不暴露宿主端口。` : " 当前为单服务运行方案。"}{launchPlan?.ai.status === "completed" ? ` DeepSeek（${launchPlan.ai.model ?? "configured"}）已参与依赖与入口分析。` : ` DeepSeek 状态：${launchPlan?.ai.rationale ?? launchPlan?.ai.status ?? "分析中"}。`} 启动时会按锁文件准备依赖；缺失的官方白名单镜像可自动拉取，成功方案会保存到当前项目。</div> : <div className="empty-project">{launchPlan?.message ?? "只有源码但尚未识别出可运行入口。"} DeepSeek 会尝试从 README、Dockerfile、CI 和框架配置补充候选；仍无法通过安全校验时才需要专用运行适配器。</div> : null}
      <div className="sandbox-target-list">{activeTargets.length === 0 ? <div className="empty-project">还没有可用目标实例。创建后系统会自动进行健康检查。</div> : activeTargets.map((target) => { const identity = target.health_detail?.identity as { status?: string; role_count?: number; detail?: string } | undefined; const services = Array.isArray(target.policy?.support_services) ? target.policy.support_services as Record<string, unknown>[] : []; return <article key={target.id} className="sandbox-target-card"><div><span className={`sandbox-state ${target.status}`}>{sandboxStatusLabel(target.status)}</span><strong>{target.mode === "docker" ? "项目专属 Docker 实例" : "已上线项目地址"}</strong><code>{target.runtime_url}</code><small>{String(target.health_detail?.status_code ?? "-")} · {String(target.health_detail?.latency_ms ?? "-")} ms · {formatDateTime(target.updated_at)}</small>{services.length ? <small>依赖服务：{services.map((item) => `${String(item.kind)} ${String(item.status)}`).join("、")}</small> : null}{target.health_detail?.error ? <small>诊断：{String(target.health_detail.error)} · {String(target.health_detail.remediation ?? "请核对监听地址、端口和健康路径")}</small> : null}<small>测试身份：{identity?.status === "ready" ? `已自动准备 ${identity.role_count ?? 0} 个角色` : identity?.detail ?? "等待初始化"}</small></div><div className="sandbox-row-actions"><button className="secondary-action" disabled={Boolean(busy)} onClick={() => void refreshTarget(target)}>检查</button>{target.mode === "docker" && identity?.status !== "ready" ? <button className="secondary-action" disabled={Boolean(busy)} onClick={() => void bootstrapIdentity(target)}>{busy === `identity-${target.id}` ? "初始化中…" : "重试测试身份"}</button> : null}<button className="secondary-action danger" disabled={Boolean(busy)} onClick={() => void stopRuntime(target)}>停止</button></div></article>; })}</div>
      {stoppedTargetCount ? <p className="retest-note">已保留 {stoppedTargetCount} 条停止记录用于审计，默认不在演示工作区展示。</p> : null}
    </section>

    <section className="sandbox-task-layout"><section className="panel"><div className="panel-header"><div><h2>3. DAST 自动验证队列</h2><span>仅接收 DAST 已批准的隔离合同</span></div><span>{tasks.length} 个任务</span></div><div className="sandbox-task-list">{tasks.length === 0 ? <div className="empty-project">暂无任务。在 DAST 中批准策略并提交隔离执行后会自动出现在这里。</div> : tasks.map((task) => <button key={task.id} className={`sandbox-task-item ${selectedTask?.id === task.id ? "active" : ""}`} onClick={() => setSelectedTaskId(task.id)}><span className={`sandbox-state ${task.status}`}>{sandboxStatusLabel(task.status)}</span><strong>{String((task.contract as { target?: { url?: string } }).target?.url ?? task.strategy_id)}</strong><small>{task.required_capabilities.map(sandboxCapabilityLabel).join("、") || "基础 HTTP"} · {formatDateTime(task.created_at)}</small></button>)}</div></section>
      <section className="panel sandbox-task-detail"><div className="panel-header"><div><h2>4. 执行与证据回传</h2><span>{selectedTask ? `任务 ${selectedTask.id}` : "请选择任务"}</span></div></div>{!selectedTask ? <div className="empty-project">当前没有可执行任务。</div> : <>
        <dl className="sandbox-contract-summary"><div><dt>来源 / 策略</dt><dd>{selectedTask.source_module} / {selectedTask.strategy_id}</dd></div><div><dt>目标实例</dt><dd>{selectedTask.target_instance_id ?? "执行时自动选择健康实例"}</dd></div><div><dt>所需能力</dt><dd>{selectedTask.required_capabilities.map(sandboxCapabilityLabel).join("、") || "基础 HTTP"}</dd></div><div><dt>结果</dt><dd>{selectedTask.result_summary ?? selectedTask.error ?? "等待执行"}</dd></div></dl>
        <div className="sandbox-target-actions"><button className="primary-action" disabled={Boolean(busy) || !["queued", "blocked"].includes(selectedTask.status) || runningTargets.length === 0} onClick={() => void executeSelected()}>{busy.startsWith("execute-") ? "隔离执行中…" : "执行固定验证策略"}</button><button className="secondary-action" disabled={Boolean(busy) || !["queued", "blocked"].includes(selectedTask.status)} onClick={() => void cancelSelected()}>取消任务</button></div>
        {runningTargets.length === 0 ? <div className="empty-project">没有健康目标实例，暂不能执行；任务与策略不会丢失。</div> : null}
        <details className="record-evidence" open><summary>状态机日志（{events.length}）</summary><ol className="sandbox-event-list">{events.map((event) => <li key={event.id}><b>{event.state}</b><span>{sandboxStatusLabel(event.status)}</span><p>{String(event.detail.message ?? "状态已记录")}</p><small>{formatDateTime(event.created_at)}</small></li>)}</ol></details>
        <details className="record-evidence" open><summary>事实证据（{selectedTask.evidence.length}）</summary><div className="sandbox-evidence-list">{selectedTask.evidence.length === 0 ? <p>尚未产生证据。</p> : selectedTask.evidence.map((item, index) => <article key={String(item.evidence_id ?? index)}><strong>{String(item.type ?? "runtime_trace")} · {item.confirmed ? "已确认触发" : "已记录"}</strong><p>{String(item.facts ?? "")}</p><small>request_id: {String(item.request_id ?? "-")} · sha256: {String(item.artifact_sha256 ?? "-")}</small></article>)}</div></details>
      </>}</section>
    </section>
  </section>;
}

function sandboxCapabilityLabel(value: string): string { return ({ isolated_http: "隔离 HTTP", timing_probe: "时延差分", oast: "外带回调", browser: "浏览器取证", agent_runtime: "Agent 运行时" } as Record<string, string>)[value] ?? value; }
function sandboxStatusLabel(value: string): string { return ({ ready: "就绪", blocked: "阻塞", waiting_adapter: "待接入", queued: "待执行", running: "执行中", analyzing: "分析中", completed: "已完成", failed: "失败", cancelled: "已取消", unhealthy: "不可达", stopped: "已停止", starting: "启动中", pending: "等待中", reported: "已回传" } as Record<string, string>)[value] ?? value; }

// 旧的手工命令/证据关联界面暂时保留，默认入口已切换到闭环工作台。
function LegacySandboxGovernanceView({ findings, validations, evidence, graph, templates, runCommand, sandboxImage, selectedFindingId, selectedValidationId, loading, onRunCommandChange, onSandboxImageChange, onSelectRisk, onSelectValidation, onRun }: { findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; graph: EvidenceGraph | null; templates: SandboxTemplate[]; runCommand: string; sandboxImage: string; selectedFindingId: string; selectedValidationId: string; loading: boolean; onRunCommandChange: (value: string) => void; onSandboxImageChange: (value: string) => void; onSelectRisk: (findingId: string) => void; onSelectValidation: (validationId: string) => void; onRun: (plan: SandboxExecutionPlan) => Promise<void> }) {
  const [filters, setFilters] = useState({ keyword: "", linked: "all", result: "all", runtime: "all" });
  const [page, setPage] = useState(1);
  const [templatePage, setTemplatePage] = useState(1);
  const findingMap = new Map(findings.map((item) => [item.id, item]));
  const validationMap = new Map(validations.map((item) => [item.id, item]));
  const selectedFinding = findingMap.get(selectedFindingId);
  const selectedValidation = validationMap.get(selectedValidationId);
  const executionPlan = sandboxExecutionPlan(selectedFinding, selectedValidation);
  const linked = evidence.filter((item) => item.finding_id || item.component_id || item.validation_id).length;
  const completed = evidence.filter((item) => item.observed_processes.some((process) => textValue(process.exit_code) !== "-")).length;
  const filtered = evidence.filter((item) => {
    const process = item.observed_processes[0] ?? {};
    const exitCode = textValue(process.exit_code);
    const isLinked = Boolean(item.finding_id || item.component_id || item.validation_id);
    const executionResult = exitCode === "0" ? "success" : exitCode === "-" ? "unknown" : "failed";
    return (!filters.keyword.trim() || item.run_command.toLowerCase().includes(filters.keyword.trim().toLowerCase()))
      && (filters.linked === "all" || (filters.linked === "linked") === isLinked)
      && (filters.result === "all" || filters.result === executionResult)
      && (filters.runtime === "all" || (item.runtime_profile ?? "unknown") === filters.runtime);
  });
  const pagination = paginate(filtered, page);
  const templatePagination = paginate(templates, templatePage);
  useEffect(() => { setPage(1); }, [filters.keyword, filters.linked, filters.result, filters.runtime]);
  return <ModuleGovernanceShell moduleKey="sandbox" lastStatus={evidence.length ? "completed" : null} metrics={[["运行证据", evidence.length], ["执行完成", completed], ["进入证据链", linked], ["隔离策略", "禁网 / 只读"]]} action={linked ? "结合上游风险和 DAST 裁决复核运行行为，判断证据是否足以支持最终风险结论。" : "请先选择一条风险或 DAST 验证，独立命令执行不能证明漏洞成立。"} loading={loading} hideRunButton onRun={() => onRun(executionPlan)}>
    <section className="validation-workbench sandbox-workbench">
      <div className="workbench-heading"><span>运行时取证</span><h3>围绕具体风险或 DAST 结果，在隔离环境中观察真实行为</h3><p>沙箱负责记录进程、文件、网络策略和工具调用；“命令执行成功”不等于“漏洞成立”，必须结合上游对象解释。</p></div>
      <div className="sandbox-source-grid">
        <label><span>① 上游 DAST 验证（优先）</span><select value={selectedValidationId} onChange={(event) => onSelectValidation(event.target.value)}><option value="">不从 DAST 结果进入</option>{validations.filter((item) => item.finding_id || item.component_id).map((item) => <option key={item.id} value={item.id}>{dastVerdictLabel(item.verdict)} · {item.target_url}</option>)}</select></label>
        <label><span>或直接选择风险</span><select value={selectedFindingId} onChange={(event) => onSelectRisk(event.target.value)}><option value="">请选择风险</option>{findings.map((finding) => <option value={finding.id} key={finding.id}>{finding.source} · {severityLabel(finding.severity)} · {finding.title}</option>)}</select></label>
      </div>
      {templates.length ? <div className="sandbox-template-picker"><span>可选：使用安全命令模板</span><select defaultValue="" onChange={(event) => { const template = templates.find((item) => item.name === event.target.value); if (template) { onRunCommandChange(template.command); onSandboxImageChange(template.image); } }}><option value="">手动填写命令和镜像</option>{templatePagination.items.map((template) => <option key={template.name} value={template.name}>{template.name} · {template.description}</option>)}</select><small>模板只会填入命令和隔离镜像；仍需先选择要验证的风险或 DAST 记录。</small><Pagination page={templatePagination.page} pageCount={templatePagination.pageCount} total={templates.length} onPageChange={setTemplatePage} /></div> : null}
      <section className="verification-strategy-card sandbox-plan-card"><div><span>本次取证目的</span><strong>{executionPlan.strategyName}</strong><p>{executionPlan.purpose}</p></div><div><span>不能证明的事项</span><p>{executionPlan.limitations}</p></div></section>
      <div className="validation-form sandbox-command-form">
        <label><span>② 验证命令</span><input value={runCommand} onChange={(event) => onRunCommandChange(event.target.value)} placeholder="例如：python verify_sql_injection.py" /></label>
        <label><span>隔离镜像</span><input value={sandboxImage} onChange={(event) => onSandboxImageChange(event.target.value)} placeholder="python:3.12-slim" /></label>
        <button className="primary-action" disabled={loading || (!selectedFindingId && !selectedValidationId) || !runCommand.trim()} onClick={() => void onRun(executionPlan)}>{loading ? "取证中" : "③ 执行隔离取证"}</button>
      </div>
      {selectedFinding || selectedValidation ? <div className="selected-risk-context"><span className={`severity ${selectedFinding?.severity ?? "info"}`}>{selectedFinding ? severityLabel(selectedFinding.severity) : "动态验证"}</span><div><strong>{selectedFinding?.title ?? selectedValidation?.target_url}</strong><small>{selectedValidation ? `DAST：${dastVerdictLabel(selectedValidation.verdict)} · ${selectedValidation.target_url}` : `${selectedFinding?.source} · ${selectedFinding?.file_path ?? "项目级风险"}`}</small></div><b>运行记录将沿用上游关系进入同一条证据链</b></div> : <div className="workbench-empty">请选择上游风险或已关联的 DAST 验证，再执行沙箱取证。</div>}
    </section>
    <ModuleFilterBar><input value={filters.keyword} onChange={(event) => setFilters({ ...filters, keyword: event.target.value })} placeholder="搜索运行命令" /><SimpleFilter value={filters.linked} label="全部关联状态" options={["linked", "unlinked"]} format={(value) => value === "linked" ? "已关联风险" : "独立运行"} onChange={(value) => setFilters({ ...filters, linked: value })} /><SimpleFilter value={filters.result} label="全部执行结果" options={["success", "failed", "unknown"]} format={(value) => value === "success" ? "执行成功" : value === "failed" ? "执行失败" : "结果未知"} onChange={(value) => setFilters({ ...filters, result: value })} /><SimpleFilter value={filters.runtime} label="全部运行环境" options={uniqueValues(evidence.map((item) => item.runtime_profile ?? "unknown"))} onChange={(value) => setFilters({ ...filters, runtime: value })} /></ModuleFilterBar>
    <table className="concise-table"><thead><tr><th>上游风险 / 验证</th><th>隔离执行</th><th>观察结论</th><th>运行时账本</th></tr></thead><tbody>{pagination.items.length === 0 ? <tr><td colSpan={4} className="empty-cell">没有符合筛选条件的沙箱证据。</td></tr> : pagination.items.map((item) => { const process = item.observed_processes[0] ?? {}; const validation = item.validation_id ? validationMap.get(item.validation_id) : null; const finding = item.finding_id ? findingMap.get(item.finding_id) : validation?.finding_id ? findingMap.get(validation.finding_id) : null; return <tr key={item.id}><td>{finding ? <><strong>{finding.title}</strong><span className="cell-subtext">{finding.source} · {severityLabel(finding.severity)}</span></> : validation ? <><strong>{validation.target_url}</strong><span className="cell-subtext">DAST · {dastVerdictLabel(validation.verdict)}</span></> : <><strong>独立命令运行</strong><span className="cell-subtext">不计入漏洞证据链</span></>}</td><td><strong>{item.run_command}</strong><span className="cell-subtext">{item.strategy_name ?? "旧记录：隔离执行"}</span><span className="cell-subtext">{item.runtime_profile ?? "默认环境"} · 退出码 {textValue(process.exit_code)}</span><span className="cell-subtext">{formatDateTime(item.created_at)}</span></td><td>{item.evidence_summary ?? "未记录证据摘要"}</td><td><details className="record-evidence"><summary>查看取证目的、能力边界与账本</summary><dl><div><dt>取证目的</dt><dd>{item.purpose ?? "旧记录未保存取证目的"}</dd></div><div><dt>能力边界</dt><dd>{item.limitations ?? "旧记录未保存能力边界"}</dd></div><div><dt>文件</dt><dd>{item.observed_files.length} 条事件</dd></div><div><dt>网络</dt><dd>{item.observed_network.length} 条事件 · {item.network_policy}</dd></div><div><dt>进程</dt><dd>{item.observed_processes.length} 条事件</dd></div><div><dt>工具调用</dt><dd>{item.observed_tool_calls.length} 条事件</dd></div></dl></details></td></tr>; })}</tbody></table>
    <Pagination page={pagination.page} pageCount={pagination.pageCount} total={filtered.length} onPageChange={setPage} />
    <details className="advanced-evidence"><summary>查看项目级原始证据关系</summary><EvidenceGraphPanel graph={graph} /></details>
  </ModuleGovernanceShell>;
}

function ModuleGovernanceShell({ moduleKey, lastStatus, metrics, action, loading, runDisabled = false, runLabel, hideRunButton = false, onRun, children, afterMetrics }: { moduleKey: Exclude<ModuleKey, "aspm">; lastStatus: string | null; metrics: Array<[string, string | number]>; action: string; loading: boolean; runDisabled?: boolean; runLabel?: string; hideRunButton?: boolean; onRun: () => Promise<void>; children: React.ReactNode; afterMetrics?: React.ReactNode }) {
  return <div className="governance-view module-governance-view">
    <section className="module-governance-heading"><div className="module-icon">{moduleIcons[moduleKey]}</div><div><h2>{MODULE_DISPLAY[moduleKey].name}</h2><p>{MODULE_DISPLAY[moduleKey].purpose}</p></div><div className="module-run-actions"><span>{lastStatus ? scanStatusLabel(lastStatus) : "尚未执行"}</span>{hideRunButton ? null : <button className="primary-action" disabled={loading || runDisabled} onClick={() => void onRun()}>{loading ? "执行中" : runLabel ?? (moduleKey === "dast" || moduleKey === "sandbox" ? "再次执行" : moduleKey === "agent" ? "重新扫描并对比" : "重新扫描并复测")}</button>}</div></section>
    <section className="governance-metrics">{metrics.map(([label, value]) => <Metric key={label} label={label} value={value} />)}</section>
    {afterMetrics}
    <section className="panel"><div className="panel-header"><h2>主要结果</h2><span>完整结果 · 每页 10 条</span></div>{children}</section>
    <section className="next-action-panel"><strong>建议动作</strong><span>{action}</span></section>
  </div>;
}

function sandboxExecutionPlan(finding?: Finding, validation?: DastValidation): SandboxExecutionPlan {
  if (validation) return {
    strategyName: "DAST 结果后的隔离取证",
    purpose: `围绕 DAST 的“${dastVerdictLabel(validation.verdict)}”结果，在禁网、只读容器中执行选定命令，补充执行结果和隔离策略证据。`,
    limitations: "该过程不会重放 HTTP 请求或攻击 payload；命令执行成功不等于上游漏洞已经成立。当前也不采集真实网络连接、文件访问或完整进程树。",
  };
  if (finding) return {
    strategyName: "上游风险的隔离运行检查",
    purpose: `围绕“${finding.title}”执行受控命令，确认项目在隔离环境中的基础运行结果，并为后续人工复核保留上下文。`,
    limitations: "该过程不直接触发或利用该风险；执行结果只能作为运行环境佐证，不能证明业务漏洞、权限绕过或组件漏洞实际可利用。",
  };
  return {
    strategyName: "隔离受控执行",
    purpose: "在禁网、只读容器中执行选定命令，记录执行摘要和隔离策略。",
    limitations: "独立命令运行不计入漏洞证据链，也不能证明漏洞成立。",
  };
}

function ConciseFindingTable({ findings, validations, evidence, graph, onUpdateFinding }: { findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; graph?: EvidenceGraph | null; onUpdateFinding: (findingId: string, patch: Partial<Pick<Finding, "status">>) => Promise<void> }) {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  return <div className="concise-finding-table-wrap"><table className="concise-table"><thead><tr><th>风险问题</th><th>等级</th><th>位置</th><th>处理状态</th><th>验证证据</th></tr></thead><tbody>{findings.length === 0 ? <tr><td colSpan={5} className="empty-cell">当前没有需要展示的风险问题。</td></tr> : findings.map((finding) => { const rawTitle = findingTitle(finding); const rawDescription = finding.ai_review?.description ?? finding.evidence ?? "暂无影响说明"; const displayTitle = finding.source === "AGENT" ? agentUiText(rawTitle) : rawTitle; const description = finding.source === "AGENT" ? agentUiText(rawDescription) : rawDescription; const evidenceNodes = findingEvidenceNodes(finding.id, graph); const validationCount = validations.filter((item) => item.finding_id === finding.id).length; const evidenceCount = evidence.filter((item) => item.finding_id === finding.id || Boolean(item.validation_id && validations.some((validation) => validation.id === item.validation_id && validation.finding_id === finding.id))).length; return <tr key={finding.id}><td><strong title={displayTitle}>{truncateText(displayTitle, 100)}</strong><span className="cell-subtext" title={description}>{truncateText(description, 140)}</span></td><td><span className={`severity ${finding.severity}`}>{severityLabel(finding.severity)}</span></td><td>{finding.file_path ?? "项目级问题"}<span className="cell-subtext">{finding.line_start ? `第 ${finding.line_start} 行` : finding.source}</span></td><td><select value={normalizeFindingStatus(finding.status)} onChange={(event) => void onUpdateFinding(finding.id, { status: event.target.value as FindingStatus })}>{FINDING_WORKFLOW_STATUSES.map((status) => <option key={status} value={status}>{statusLabel(status)}</option>)}</select></td><td><button className="secondary-action" onClick={() => setSelectedFinding(finding)}>{validationCount || evidenceCount ? `查看证据（${validationCount + evidenceCount}）` : evidenceNodes.length ? `查看关系（${evidenceNodes.length}）` : "尚未验证"}</button></td></tr>; })}</tbody></table>{selectedFinding ? <FindingEvidenceDetail finding={selectedFinding} validations={validations} evidence={evidence} graph={graph ?? null} onClose={() => setSelectedFinding(null)} /> : null}</div>;
}

function ModuleFilterBar({ children }: { children: React.ReactNode }) {
  return <div className="module-filter-bar">{children}</div>;
}

function SimpleFilter({ value, label, options, format = (item) => item, onChange }: { value: string; label: string; options: string[]; format?: (value: string) => string; onChange: (value: string) => void }) {
  return <select value={value} onChange={(event) => onChange(event.target.value)}><option value="all">{label}</option>{options.map((option) => <option value={option} key={option}>{format(option)}</option>)}</select>;
}

function Pagination({ page, pageCount, total, onPageChange }: { page: number; pageCount: number; total: number; onPageChange: (page: number) => void }) {
  return <div className="result-pagination"><span>共 {total} 条，每页 10 条</span><div><button disabled={page <= 1} onClick={() => onPageChange(page - 1)}>上一页</button><strong>第 {page} / {pageCount} 页</strong><button disabled={page >= pageCount} onClick={() => onPageChange(page + 1)}>下一页</button></div></div>;
}

function RetestComparisonPanel({ comparison }: { comparison: FindingRetestComparison | null }) {
  const [resultFilter, setResultFilter] = useState("all");
  const [page, setPage] = useState(1);
  const sourceLabel = comparison?.source === "SAST" ? "SAST" : comparison?.source === "AGENT" ? "AGENT" : comparison?.source === "SCA" ? "SCA" : "当前模块";
  const sourceNote = comparison?.source === "SCA"
    ? "这里统计的是 SCA 风险记录，不是组件数量；一个组件可能对应多个漏洞、许可证或版本风险，因此风险记录数可能大于组件数。"
    : comparison?.source === "SAST"
      ? "这里仅比较最近两次 SAST 扫描的代码漏洞记录，不包含 SCA 组件或依赖风险。"
      : comparison?.source === "AGENT"
        ? "这里仅比较最近两次 AGENT 扫描的 Agent 配置、能力边界与数据流风险，不包含 SCA 组件风险。"
        : "这里仅比较当前模块最近两次扫描的风险记录。";
  if (!comparison?.has_comparison) return <section className="retest-panel"><div className="panel-header"><h3>{sourceLabel} 扫描批次对比</h3><span>等待第二次扫描</span></div><p>再次扫描后，系统会比较最近两个批次，显示风险记录仍存在、消失、新增或变化；首次扫描不会被表述为已经完成复测。</p></section>;
  const filtered = comparison.items.filter((item) => resultFilter === "all" || item.result === resultFilter);
  const pagination = paginate(filtered, page);
  const currentBatchCount = comparison.still_present_count + comparison.new_count + comparison.changed_count;
  const previousBatchCount = comparison.still_present_count + comparison.resolved_count + comparison.changed_count;
  return <section className="retest-panel">
    <div className="panel-header"><h3>最近两个 {sourceLabel} 扫描批次对比</h3><span>{formatDateTime(comparison.previous_scan_at)} → {formatDateTime(comparison.current_scan_at)}</span></div>
    <div className="retest-summary"><Metric label="仍然存在的风险记录" value={comparison.still_present_count} /><Metric label="已消失的风险记录" value={comparison.resolved_count} /><Metric label="新增风险记录" value={comparison.new_count} /><Metric label="内容发生变化" value={comparison.changed_count} /></div>
    <p className="retest-note">{sourceNote} 当前批次共 {currentBatchCount} 条（仍存在 + 新增 + 变化），上一批次共 {previousBatchCount} 条（仍存在 + 已消失 + 变化）；四张卡展示的是两个批次的变化分类，不能直接相加后与当前问题总数比较。“已消失”表示本次未再次发现；“仍然存在”表示需要继续整改。</p>
    <details className="retest-details">
      <summary>查看全部风险记录复测明细（{comparison.items.length} 条）</summary>
      <div className="module-filter-bar"><SimpleFilter value={resultFilter} label="全部复测结果" options={["still_present", "resolved", "new", "changed"]} format={retestResultLabel} onChange={(value) => { setResultFilter(value); setPage(1); }} /></div>
      <table className="concise-table"><thead><tr><th>风险记录</th><th>复测结论</th><th>位置变化</th><th>等级变化</th></tr></thead><tbody>{pagination.items.length === 0 ? <tr><td colSpan={4} className="empty-cell">没有符合筛选条件的复测结果。</td></tr> : pagination.items.map((item) => <tr key={item.identity}><td><strong>{comparison.source === "AGENT" ? agentUiText(item.title) : item.title}</strong><span className="cell-subtext">{item.file_path ?? "项目级问题"}</span></td><td><span className={`retest-badge ${item.result}`}>{retestResultLabel(item.result)}</span></td><td>{item.previous_line_start ?? "-"} → {item.current_line_start ?? "-"}</td><td>{severityLabel(item.previous_severity)} → {severityLabel(item.current_severity)}</td></tr>)}</tbody></table>
      <Pagination page={pagination.page} pageCount={pagination.pageCount} total={filtered.length} onPageChange={setPage} />
    </details>
  </section>;
}

function FindingEvidenceDetail({ finding, validations, evidence, graph, onClose }: { finding: Finding; validations: DastValidation[]; evidence: SandboxEvidence[]; graph: EvidenceGraph | null; onClose: () => void }) {
  const [recordPage, setRecordPage] = useState(1);
  const [fixDraft, setFixDraft] = useState<SastFixDraft | null>(null);
  const [fixDraftMessage, setFixDraftMessage] = useState("");
  const [fixDraftLoading, setFixDraftLoading] = useState(false);
  const nodes = findingEvidenceNodes(finding.id, graph);
  const relatedValidations = validations.filter((item) => item.finding_id === finding.id);
  const validationIds = new Set(relatedValidations.map((item) => item.id));
  const relatedEvidence = evidence.filter((item) => item.finding_id === finding.id || Boolean(item.validation_id && validationIds.has(item.validation_id)));
  const relatedRecords = [...relatedValidations.map((item) => ({ kind: "validation" as const, item })), ...relatedEvidence.map((item) => ({ kind: "evidence" as const, item }))];
  const recordPagination = paginate(relatedRecords, recordPage);
  useEffect(() => { setRecordPage(1); setFixDraft(null); setFixDraftMessage(""); }, [finding.id, relatedRecords.length]);
  const hasValidation = relatedValidations.length > 0 || nodes.some((node) => node.kind === "validation");
  const hasRuntimeEvidence = relatedEvidence.length > 0 || nodes.some((node) => node.kind === "evidence");
  const conclusion = hasValidation && hasRuntimeEvidence ? "已形成完整证据链" : hasRuntimeEvidence ? "已有运行证据" : hasValidation ? "已完成动态验证" : "仅发现，尚未验证";
  async function loadFixDraft() {
    setFixDraftLoading(true);
    try {
      setFixDraft(await request<SastFixDraft>(`/sast/findings/${finding.id}/fix-draft`));
      setFixDraftMessage("");
    } catch (error) { setFixDraftMessage(`无法生成草案：${errorMessage(error)}`); }
    finally { setFixDraftLoading(false); }
  }
  return <section className="finding-evidence-detail">
    <div className="panel-header"><div><h3>风险证据链</h3><span>{finding.source === "AGENT" ? agentUiText(finding.title) : finding.title}</span></div><button className="secondary-action" onClick={onClose}>关闭</button></div>
    <div className="evidence-conclusion"><strong>{conclusion}</strong><span>{nodes.length ? "以下内容来自已保存的显式关联，不代表自动确认漏洞成立。" : "当前问题还没有关联 DAST 或 SANDBOX 证据。"}</span></div>
      {finding.source === "SAST" && ["critical", "high"].includes(finding.severity) ? <details className="record-evidence"><summary>人工评审修复草案（不会修改源码）</summary><p>草案仅供开发人员参考，不会写入文件、创建提交、创建 PR 或自动执行回归。</p><button className="secondary-action" disabled={fixDraftLoading} onClick={() => void loadFixDraft()}>{fixDraftLoading ? "正在生成" : fixDraft ? "重新生成草案" : "生成修复草案"}</button>{fixDraftMessage ? <div className="empty-project">{fixDraftMessage}</div> : null}{fixDraft ? <dl><div><dt>建议修改</dt><dd>{fixDraft.recommended_change}</dd></div><div><dt>补丁草案</dt><dd><pre className="code-preview">{fixDraft.patch}</pre></dd></div><div><dt>限制</dt><dd>{fixDraft.limitations.join("；") || "无额外说明"}</dd></div><div><dt>回归入口</dt><dd>{fixDraft.regression_scan.endpoint}（必填：{fixDraft.regression_scan.required_fields.join("、")}）</dd></div></dl> : null}</details> : null}
      {finding.ai_review?.ai_provider ? <details className="record-evidence" open><summary>DeepSeek 多 Agent 复核：{finding.ai_review.review_verdict ?? "等待人工确认"} · 置信度 {finding.ai_review.ai_confidence ?? 0}%</summary><dl><div><dt>证据摘要</dt><dd>{finding.ai_review.evidence_summary ?? finding.ai_review.summary}</dd></div><div><dt>Agent 流程</dt><dd>{(finding.ai_review.agent_pipeline ?? []).map(sastAgentRoleLabel).join(" → ")}</dd></div><div><dt>修复建议</dt><dd>{finding.ai_review.fix_draft?.recommended_change ?? finding.ai_review.fix_strategy ?? finding.ai_review.remediation}</dd></div><div><dt>补丁草案</dt><dd>{finding.ai_review.fix_draft?.patch ? <pre className="code-preview">{finding.ai_review.fix_draft.patch}</pre> : "未保存补丁草案"}</dd></div></dl></details> : null}
      <ol className="evidence-timeline">
      <li><b>{finding.source}</b><div><strong>发现风险</strong><span>{finding.file_path ?? "项目级问题"} · {severityLabel(finding.severity)}</span></div></li>
        {nodes.map((node) => <li key={node.id}><b>{node.module}</b><div><strong>{evidenceNodeStage(node)}</strong><span>{node.module === "AGENT" ? agentUiText(node.label) : node.label}</span><small>{node.module === "AGENT" ? agentUiText(node.detail ?? "未记录证据摘要") : node.detail ?? "未记录证据摘要"} · {formatDateTime(node.created_at)}</small></div></li>)}
      </ol>
      {relatedRecords.length > 0 ? <div className="evidence-record-stack">{recordPagination.items.map((record) => record.kind === "validation" ? <details key={record.item.id} open><summary>DAST：{dastVerdictLabel(record.item.verdict)} · {record.item.target_url}</summary><dl><div><dt>验证策略</dt><dd>{record.item.strategy_name ?? "旧记录：未保存策略"}</dd></div><div><dt>检查范围与边界</dt><dd>{record.item.scope_summary ?? "未记录"}<br />{record.item.limitations ?? "未记录"}</dd></div><div><dt>请求</dt><dd>{record.item.request_summary ?? "未记录"}</dd></div><div><dt>响应</dt><dd>{record.item.response_summary ?? "未记录"}</dd></div><div><dt>复现过程</dt><dd>{record.item.reproduction_steps ?? "未记录"}</dd></div><div><dt>修复提示</dt><dd>{record.item.remediation_hint ?? "未记录"}</dd></div></dl></details> : <details key={record.item.id} open><summary>SANDBOX：{record.item.run_command}</summary><dl><div><dt>取证策略与目的</dt><dd>{record.item.strategy_name ?? "旧记录：隔离执行"}<br />{record.item.purpose ?? "未记录"}</dd></div><div><dt>能力边界</dt><dd>{record.item.limitations ?? "未记录"}</dd></div><div><dt>隔离策略</dt><dd>网络：{record.item.network_policy}；文件：{record.item.filesystem_policy}</dd></div><div><dt>观察结论</dt><dd>{record.item.evidence_summary ?? "未记录"}</dd></div><div><dt>行为账本</dt><dd>文件 {record.item.observed_files.length} 条；网络 {record.item.observed_network.length} 条；进程 {record.item.observed_processes.length} 条；工具调用 {record.item.observed_tool_calls.length} 条</dd></div></dl></details>)}<Pagination page={recordPagination.page} pageCount={recordPagination.pageCount} total={relatedRecords.length} onPageChange={setRecordPage} /></div> : null}
    </section>;
}

function findingEvidenceNodes(findingId: string, graph?: EvidenceGraph | null): EvidenceGraphNode[] {
  if (!graph) return [];
  const findingNodeId = `finding:${findingId}`;
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  const relationEdges = graph.edges.filter((edge) => edge.relation_type !== "contains");
  const visited = new Set<string>([findingNodeId]);
  relationEdges.filter((edge) => edge.target === findingNodeId && edge.relation_type === "reported_by").forEach((edge) => visited.add(edge.source));
  let changed = true;
  while (changed) {
    changed = false;
    for (const edge of relationEdges) {
      if (visited.has(edge.source) && !visited.has(edge.target)) {
        visited.add(edge.target);
        changed = true;
      }
    }
  }
  return [...visited]
    .filter((id) => id !== findingNodeId)
    .map((id) => nodes.get(id))
    .filter((node): node is EvidenceGraphNode => Boolean(node))
    .sort((a, b) => String(a.created_at ?? "").localeCompare(String(b.created_at ?? "")));
}

function ModulesView({ modules, project, enabledModules, selectedModules, savingKey, onToggle }: { modules: SecurityModule[]; project: Project | null; enabledModules: Set<ModuleKey>; selectedModules: SecurityModule[]; savingKey: ModuleKey | null; onToggle: (module: SecurityModule) => Promise<void> }) { return <><section className="module-summary"><Metric label="已选择模块" value={`${selectedModules.length} / ${modules.length}`} /><Metric label="当前项目" value={project?.name ?? "本地预览"} /><Metric label="动态验证依赖" value={enabledModules.has("dast") ? "SAST 联动" : "未接入"} /><Metric label="治理底座" value="ASPM 内置" /></section><section className="module-layout"><div className="module-grid">{modules.map((module) => { const enabled = enabledModules.has(module.key); return <article className={`module-card ${enabled ? "enabled" : ""}`} key={module.key}><div className="module-card-top"><div className="module-icon">{moduleIcons[module.key]}</div><div><span className="module-code">{module.code}</span><h2>{module.name}</h2></div><button aria-label={`${enabled ? "停用" : "启用"} ${module.code}`} className={`toggle ${enabled ? "on" : ""}`} disabled={savingKey === module.key} onClick={() => void onToggle(module)}><span /></button></div><p className="module-subtitle">{module.subtitle}</p><p className="module-description">{module.description}</p><div className="capability-list">{module.capabilities.map((capability) => <span key={capability.title} title={capability.description}><Check size={14} />{capability.title}</span>)}</div>{module.dependencies.length ? <div className="dependency-note"><Lock size={14} />启用时会自动接入依赖模块：{module.dependencies.join(", ").toUpperCase()}</div> : null}</article>; })}</div><aside className="selection-panel"><div className="panel-header"><h2>接入预览</h2><span>Project: {project?.name ?? "本地预览"}</span></div><ol className="selected-list">{selectedModules.map((module) => <li key={module.key}><b>{module.code}</b><span>{module.name}</span></li>)}<li className="builtin-module"><b>ASPM</b><span>平台内置治理底座</span></li></ol><div className="execution-flow"><h3>推荐执行顺序</h3><p>SCA -&gt; SAST -&gt; AGENT -&gt; DAST -&gt; SANDBOX，结果自动进入 ASPM 治理总览。</p></div></aside></section></>; }

function TaskCenter(props: { project: Project | null; assetProbe: ProjectAssetProbe | null; enabledModules: Set<ModuleKey>; sourcePath: string; sastPath: string; agentPath: string; targetUrl: string; runCommand: string; loading: boolean; onSourcePathChange: (value: string) => void; onSastPathChange: (value: string) => void; onAgentPathChange: (value: string) => void; onTargetUrlChange: (value: string) => void; onRunCommandChange: (value: string) => void; onScan: (kind: "sca" | "sast" | "agent") => Promise<void>; onRecommended: () => Promise<void>; onDast: () => Promise<void>; onSandbox: () => Promise<void> }) { const recommended = props.assetProbe?.recommended_tasks ?? []; const runnable = recommended.filter((kind) => props.enabledModules.has(kind)); const hasTask = OPTIONAL_MODULES.some((moduleKey) => props.enabledModules.has(moduleKey)); return <section className="task-stack"><div className="panel asset-probe"><div className="panel-header"><h2>源码自动识别</h2><span>{props.assetProbe?.message ?? "未探测"}</span></div><div className="probe-summary"><Metric label="依赖清单" value={props.assetProbe?.sca_files.length ?? 0} /><Metric label="源码文件" value={props.assetProbe?.source_files.length ?? 0} /><Metric label="Agent 配置" value={props.assetProbe?.agent_files.length ?? 0} /><Metric label="可执行推荐" value={runnable.length} /></div><div className="probe-actions"><div><strong>{props.project?.source_path ?? "未配置本地源码路径"}</strong><span>{runnable.length ? `可执行推荐：${runnable.map((item) => item.toUpperCase()).join(" + ")}` : "推荐任务会同时受源码识别和模块启用状态影响"}</span></div><button className="primary-action" disabled={props.loading || runnable.length === 0} onClick={() => void props.onRecommended()}>执行推荐任务</button></div></div>{hasTask ? <section className="task-grid">{props.enabledModules.has("sca") && <TaskCard title="SCA 组件清单" desc="解析依赖文件并写入 components。" value={props.sourcePath} onChange={props.onSourcePathChange} button="执行 SCA" disabled={props.loading} onClick={() => props.onScan("sca")} />}{props.enabledModules.has("sast") && <TaskCard title="SAST 基础扫描" desc="扫描硬编码密钥、命令执行、SQL 拼接等模式。" value={props.sastPath} onChange={props.onSastPathChange} button="执行 SAST" disabled={props.loading} onClick={() => props.onScan("sast")} />}{props.enabledModules.has("agent") && <TaskCard title="AGENT 配置扫描" desc="扫描 Agent/MCP/插件配置中的危险权限。" value={props.agentPath} onChange={props.onAgentPathChange} button="执行 AGENT" disabled={props.loading} onClick={() => props.onScan("agent")} />}{props.enabledModules.has("dast") && <TaskCard title="DAST 验证记录" desc="创建一条人工动态验证裁决。" value={props.targetUrl} onChange={props.onTargetUrlChange} button="记录 DAST" disabled={props.loading} onClick={props.onDast} />}{props.enabledModules.has("sandbox") && <TaskCard title="SANDBOX 受控执行" desc="执行受控命令并采集进程输出、耗时和策略证据。" value={props.runCommand} onChange={props.onRunCommandChange} button="执行 SANDBOX" disabled={props.loading} onClick={props.onSandbox} />}</section> : <div className="panel empty-project">当前项目未启用可执行模块。请先到模块接入启用 SCA、SAST、AGENT、DAST 或 SANDBOX。</div>}</section>; }
function TaskCard({ title, desc, value, button, disabled, onChange, onClick }: { title: string; desc: string; value: string; button: string; disabled: boolean; onChange: (value: string) => void; onClick: () => void }) { return <div className="panel task-card"><h2>{title}</h2><p>{desc}</p><div className="path-control"><input value={value} onChange={(event) => onChange(event.target.value)} /><button className="primary-action" disabled={disabled} onClick={onClick}>{button}</button></div></div>; }

function EvidenceLinkSelector({
  title,
  findings,
  components,
  validations,
  suggestions,
  selectedFindingId,
  selectedComponentId,
  selectedValidationId,
  onFindingChange,
  onComponentChange,
  onValidationChange,
  onSuggestionApply,
}: {
  title: string;
  findings: Finding[];
  components: Component[];
  validations: DastValidation[];
  suggestions: LinkSuggestion[];
  selectedFindingId: string;
  selectedComponentId: string;
  selectedValidationId: string;
  onFindingChange: (value: string) => void;
  onComponentChange: (value: string) => void;
  onValidationChange: (value: string) => void;
  onSuggestionApply: (suggestion: LinkSuggestion) => void;
}) {
  return (
    <section className="panel full evidence-link-selector">
      <div className="panel-header">
        <h2>{title}</h2>
        <span>系统给出候选与理由；高置信度会预选，执行前仍可调整</span>
      </div>
      <div className="link-suggestion-list">
        {suggestions.length === 0 ? <div className="empty-project">暂无可靠候选。当前记录可以保持未关联，或手动选择。</div> : suggestions.map((suggestion, index) => {
          const selected = suggestion.validation_id
            ? suggestion.validation_id === selectedValidationId
            : Boolean(suggestion.finding_id && suggestion.finding_id === selectedFindingId);
          return <article className={`link-suggestion ${selected ? "selected" : ""}`} key={`${suggestion.validation_id ?? suggestion.finding_id ?? index}`}>
            <div><strong>{index === 0 ? "首选 · " : ""}{suggestion.label}</strong><span>{suggestion.reasons.join("；")}</span></div>
            <div className="suggestion-score"><b className={suggestion.confidence_level}>{suggestion.confidence}%</b><span>{confidenceLevelLabel(suggestion.confidence_level)}</span><button className="secondary-action" onClick={() => onSuggestionApply(suggestion)}>{selected ? "已采用" : "采用建议"}</button></div>
          </article>;
        })}
      </div>
      <div className="evidence-link-grid">
        <label>
          Finding
          <select value={selectedFindingId} onChange={(event) => onFindingChange(event.target.value)}>
            <option value="">不关联 Finding</option>
            {findings.map((finding) => <option key={finding.id} value={finding.id}>{finding.source} · {finding.severity} · {finding.title}</option>)}
          </select>
        </label>
        <label>
          SCA 组件
          <select value={selectedComponentId} onChange={(event) => onComponentChange(event.target.value)}>
            <option value="">不关联组件</option>
            {components.map((component) => <option key={component.id} value={component.id}>{component.ecosystem} · {component.name} {component.version ?? ""}</option>)}
          </select>
        </label>
        {validations.length > 0 ? (
          <label>
            DAST 验证
            <select value={selectedValidationId} onChange={(event) => onValidationChange(event.target.value)}>
              <option value="">不关联 DAST 验证</option>
              {validations.map((validation) => <option key={validation.id} value={validation.id}>{validation.verdict} · {validation.target_url}</option>)}
            </select>
          </label>
        ) : null}
      </div>
    </section>
  );
}

function AgentView({ project, findings, categorySummary, sourcePath, loading, onSourcePathChange, onRunScan }: { project: Project | null; findings: Finding[]; categorySummary: Record<string, number>; sourcePath: string; loading: boolean; onSourcePathChange: (value: string) => void; onRunScan: () => Promise<void> }) {
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const severitySummary = countBy(findings, "severity");
  const pageCount = Math.max(1, Math.ceil(findings.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageFindings = findings.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  useEffect(() => { setPage(1); }, [findings]);

  return <section className="sca-layout"><div className="sca-toolbar panel full"><div><h2>AGENT 供应链安全</h2><p>扫描 Agent 指令、MCP 工具协议和插件配置，识别提示注入、权限过宽、工具滥用和密钥暴露风险。</p></div><div className="path-control"><input value={sourcePath} onChange={(event) => onSourcePathChange(event.target.value)} /><button className="primary-action" onClick={() => void onRunScan()} disabled={loading || !project}>{loading ? "执行中" : "执行 AGENT 扫描"}</button></div></div><section className="module-summary"><Metric label="Findings" value={findings.length} /><Metric label="Critical / High" value={(severitySummary.critical ?? 0) + (severitySummary.high ?? 0)} /><Metric label="风险分类" value={Object.keys(categorySummary).length} /><Metric label="当前项目" value={project?.name ?? "未连接"} /></section><div className="content-grid"><div className="panel"><div className="panel-header"><h2>风险分类</h2><span>Agent category</span></div><KeyValue data={categorySummary} /></div><div className="panel"><div className="panel-header"><h2>严重等级</h2><span>Severity</span></div><KeyValue data={severitySummary} /></div><div className="panel full"><div className="panel-header"><h2>Agent 风险发现</h2><span>共 {findings.length} 条</span></div><table><thead><tr><th>等级</th><th>分类</th><th>标题</th><th>位置</th><th>证据</th><th>修复建议 / 信任影响</th></tr></thead><tbody>{findings.length === 0 ? <tr><td colSpan={6} className="empty-cell">暂无 AGENT findings，执行 AGENT 扫描后显示结果。</td></tr> : pageFindings.map((finding) => <tr key={finding.id}><td><span className={`severity ${finding.severity}`}>{finding.severity}</span></td><td><span className="risk-badge review-required">{finding.ai_review?.category ?? "unknown"}</span></td><td><strong>{finding.title}</strong><span className="cell-subtext">{finding.ai_review?.description ?? finding.ai_review?.summary ?? "-"}</span></td><td>{finding.file_path ?? "-"}<span className="cell-subtext">Line {finding.line_start ?? "-"}</span></td><td>{finding.evidence ?? "-"}</td><td>{finding.ai_review?.remediation ?? "-"}<span className="cell-subtext">{finding.ai_review?.trust_impact ?? "-"}</span></td></tr>)}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div></section>;
}

function DastView({ project, validations, targetUrl, loading, onTargetUrlChange, onProbe }: { project: Project | null; validations: DastValidation[]; targetUrl: string; loading: boolean; onTargetUrlChange: (value: string) => void; onProbe: () => Promise<void> }) {
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const verdictSummary = countBy(validations, "verdict");
  const pageCount = Math.max(1, Math.ceil(validations.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageValidations = validations.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  useEffect(() => { setPage(1); }, [validations]);

  return <section className="sca-layout"><div className="sca-toolbar panel full"><div><h2>DAST 漏洞动态验证</h2><p>对目标 URL 发起 HTTP 探测，检查可达性、安全响应头、服务指纹并自动生成三色裁决和验证证据。</p></div><div className="path-control"><input value={targetUrl} onChange={(event) => onTargetUrlChange(event.target.value)} placeholder="https://example.com" /><button className="primary-action" onClick={() => void onProbe()} disabled={loading || !project}>{loading ? "验证中" : "执行 DAST 验证"}</button></div></div><section className="module-summary"><Metric label="验证记录" value={validations.length} /><Metric label="可利用" value={verdictSummary.exploitable ?? 0} /><Metric label="不确定" value={verdictSummary.uncertain ?? 0} /><Metric label="不可利用" value={verdictSummary.not_exploitable ?? 0} /></section><div className="content-grid"><div className="panel"><div className="panel-header"><h2>三色裁决</h2><span>Verdict</span></div><KeyValue data={verdictSummary} /></div><div className="panel"><div className="panel-header"><h2>当前目标</h2><span>{project?.name ?? "未连接"}</span></div><div className="kv-list"><div><span>Target</span><strong>{targetUrl}</strong></div></div></div><div className="panel full"><div className="panel-header"><h2>动态验证记录</h2><span>共 {validations.length} 条</span></div><table><thead><tr><th>裁决</th><th>目标</th><th>证据摘要</th><th>请求 / 响应</th><th>修复建议</th></tr></thead><tbody>{validations.length === 0 ? <tr><td colSpan={5} className="empty-cell">暂无 DAST 验证记录，执行 DAST 验证后显示结果。</td></tr> : pageValidations.map((validation) => <tr key={validation.id}><td><span className={`risk-badge ${validation.verdict}`}>{validation.verdict}</span><span className="cell-subtext">{validation.validator ?? "auto-dast"}</span></td><td>{validation.target_url}</td><td>{validation.evidence_summary ?? "-"}</td><td>{validation.request_summary ?? "-"}<span className="cell-subtext">{validation.response_summary ?? "-"}</span></td><td>{validation.remediation_hint ?? "-"}</td></tr>)}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div></section>;
}

function SandboxView({ project, evidence, templates, runCommand, sandboxImage, loading, onRunCommandChange, onSandboxImageChange, onRun }: { project: Project | null; evidence: SandboxEvidence[]; templates: SandboxTemplate[]; runCommand: string; sandboxImage: string; loading: boolean; onRunCommandChange: (value: string) => void; onSandboxImageChange: (value: string) => void; onRun: () => Promise<void> }) {
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const runtimeSummary = countBy(evidence.map((item) => ({ runtime: item.runtime_profile ?? "unknown" })), "runtime");
  const pageCount = Math.max(1, Math.ceil(evidence.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageEvidence = evidence.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const completed = evidence.filter((item) => item.observed_processes.some((process) => textValue(process.exit_code) !== "-")).length;
  useEffect(() => { setPage(1); }, [evidence]);

  return <section className="sca-layout"><div className="sca-toolbar panel full"><div><h2>SANDBOX 沙箱动态证据链</h2><p>识别项目可执行入口，并在 Docker 隔离容器中运行命令，源码只读挂载、默认禁用网络并限制资源。</p></div><div className="path-control"><input value={runCommand} onChange={(event) => onRunCommandChange(event.target.value)} placeholder="python app.py" /><input value={sandboxImage} onChange={(event) => onSandboxImageChange(event.target.value)} placeholder="python:3.12-slim" /><button className="primary-action" onClick={() => void onRun()} disabled={loading || !project}>{loading ? "执行中" : "执行 SANDBOX"}</button></div></div><section className="module-summary"><Metric label="证据记录" value={evidence.length} /><Metric label="推荐命令" value={templates.length} /><Metric label="进程完成" value={completed} /><Metric label="隔离策略" value="Docker / read-only" /></section><div className="content-grid"><div className="panel full"><div className="panel-header"><h2>推荐命令模板</h2><span>{templates.length ? "点击后填入执行框" : "未识别到可执行入口"}</span></div>{templates.length === 0 ? <div className="empty-project">当前项目未识别到 package.json、Python 入口、go.mod、pom.xml 或 Dockerfile。可以手动输入命令和镜像执行。</div> : <table><thead><tr><th>名称</th><th>命令</th><th>镜像</th><th>类型</th><th>说明</th></tr></thead><tbody>{templates.map((template) => <tr key={`${template.image}-${template.command}`}><td><button className="secondary-action" onClick={() => { onRunCommandChange(template.command); onSandboxImageChange(template.image); }}>{template.name}</button><span className="cell-subtext">风险：{template.risk_level}</span></td><td>{template.command}</td><td>{template.image}</td><td>{template.command_type}</td><td>{template.description}</td></tr>)}</tbody></table>}</div><div className="panel"><div className="panel-header"><h2>运行环境</h2><span>Runtime</span></div><KeyValue data={runtimeSummary} /></div><div className="panel"><div className="panel-header"><h2>执行策略</h2><span>Policy</span></div><div className="kv-list"><div><span>Network</span><strong>none</strong></div><div><span>Source</span><strong>readonly</strong></div><div><span>Memory</span><strong>512m</strong></div><div><span>CPU</span><strong>1</strong></div></div></div><div className="panel full"><div className="panel-header"><h2>沙箱证据记录</h2><span>共 {evidence.length} 条</span></div><table><thead><tr><th>命令</th><th>执行结果</th><th>输出摘要</th><th>策略 / 账本</th><th>时间线</th></tr></thead><tbody>{evidence.length === 0 ? <tr><td colSpan={5} className="empty-cell">暂无 SANDBOX 证据，执行 SANDBOX 后显示结果。</td></tr> : pageEvidence.map((item) => { const process = item.observed_processes[0] ?? {}; const execution = objectValue(process.execution); const output = objectValue(process.output); const timeline = listValue(process.timeline); const tool = item.observed_tool_calls[0] ?? {}; const limits = objectValue(tool.resource_limits); return <tr key={item.id}><td><strong>{item.run_command}</strong><span className="cell-subtext">{formatDateTime(item.created_at)}</span><span className="cell-subtext">{item.runtime_profile ?? "-"}</span></td><td>exit: {textValue(execution.exit_code ?? process.exit_code)}<span className="cell-subtext">image: {textValue(execution.image ?? process.image)}</span><span className="cell-subtext">{textValue(execution.elapsed_ms ?? process.elapsed_ms)}ms · timeout: {textValue(execution.timed_out ?? process.timed_out)}</span></td><td>{item.evidence_summary ?? "-"}<span className="cell-subtext">stdout: {textValue(output.stdout_summary)}</span><span className="cell-subtext">stderr: {textValue(output.stderr_summary ?? process.stderr)}</span><span className="cell-subtext">redacted: {textValue(output.redacted)} · truncated: {textValue(output.stdout_truncated || output.stderr_truncated)}</span></td><td>{item.network_policy}<span className="cell-subtext">{item.filesystem_policy}</span><span className="cell-subtext">cpu {textValue(limits.cpus)} · mem {textValue(limits.memory)} · pids {textValue(limits.pids_limit)}</span><span className="cell-subtext">tool: {textValue(tool.tool)} / {textValue(tool.event_type)}</span></td><td>{timeline.length === 0 ? "-" : timeline.map((event, index) => { const itemEvent = objectValue(event); return <span className="cell-subtext" key={`${item.id}-${index}`}>{textValue(itemEvent.stage)}: {textValue(itemEvent.status)} · {textValue(itemEvent.detail)}</span>; })}</td></tr>; })}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div></section>;
}

function SastView({ project, findings, categorySummary, sourcePath, loading, onSourcePathChange, onRunScan, onAgentReview }: { project: Project | null; findings: Finding[]; categorySummary: Record<string, number>; sourcePath: string; loading: boolean; onSourcePathChange: (value: string) => void; onRunScan: () => Promise<void>; onAgentReview: () => Promise<void> }) {
  const [page, setPage] = useState(1);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [profile, setProfile] = useState<SastProfile | null>(null);
  const [toolHealth, setToolHealth] = useState<SastToolHealth | null>(null);
  const [history, setHistory] = useState<SastScanHistoryItem[]>([]);
  const [scanDiff, setScanDiff] = useState<SastScanDiff | null>(null);
  const [suppression, setSuppression] = useState({ rule_id: "*", path_pattern: "**", reason: "", expires_at: "" });
  const [advancedMessage, setAdvancedMessage] = useState("");
  const pageSize = 10;
  const severitySummary = countBy(findings, "severity");
  const pageCount = Math.max(1, Math.ceil(findings.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageFindings = findings.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const reviewedCount = findings.filter((finding) => finding.ai_review?.agent_pipeline?.length).length;

  useEffect(() => { setPage(1); }, [findings]);
  useEffect(() => { void refreshAdvanced(); }, [project?.id, findings.length]);

  async function refreshAdvanced() {
    if (!project) {
      setProfile(null); setHistory([]); setScanDiff(null); return;
    }
    const [profileResult, healthResult, historyResult, diffResult] = await Promise.all([
      request<SastProfile>(`/sast/projects/${project.id}/profile`).catch(() => null),
      request<SastToolHealth>("/sast/tool-health").catch(() => null),
      request<SastScanHistoryItem[]>(`/sast/projects/${project.id}/scan-history`).catch(() => []),
      request<SastScanDiff>(`/sast/projects/${project.id}/scan-diff`).catch(() => null),
    ]);
    setProfile(profileResult);
    setToolHealth(healthResult);
    setHistory(historyResult);
    setScanDiff(diffResult);
  }

  async function saveProfile() {
    if (!project || !profile) return;
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/profile`, { method: "PATCH", body: JSON.stringify(profile) });
      setProfile(saved);
      setAdvancedMessage("扫描配置已保存；下一次扫描会保留该配置快照。");
    } catch (error) { setAdvancedMessage(`保存失败：${errorMessage(error)}`); }
  }

  async function addSuppression() {
    if (!project || !suppression.reason.trim()) return setAdvancedMessage("请填写豁免理由。");
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/suppressions`, { method: "POST", body: JSON.stringify({ ...suppression, expires_at: emptyToNull(suppression.expires_at) }) });
      setProfile(saved);
      setSuppression({ rule_id: "*", path_pattern: "**", reason: "", expires_at: "" });
      setAdvancedMessage("豁免已保存；下一次扫描会在结果中记录被抑制的 Finding。");
    } catch (error) { setAdvancedMessage(`豁免保存失败：${errorMessage(error)}`); }
  }

  async function toggleSuppression(item: SastSuppression) {
    if (!project) return;
    try {
      const saved = await request<SastProfile>(`/sast/projects/${project.id}/suppressions/${item.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !item.enabled }) });
      setProfile(saved);
    } catch (error) { setAdvancedMessage(`更新失败：${errorMessage(error)}`); }
  }

  async function exportSarif() {
    if (!project) return;
    try {
      const response = await fetch(`${API_BASE}/sast/projects/${project.id}/sarif`);
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `${project.name || "project"}-sast-results.sarif`;
      link.click();
      URL.revokeObjectURL(url);
      setAdvancedMessage("SARIF 已导出。");
    } catch (error) { setAdvancedMessage(`SARIF 导出失败：${errorMessage(error)}`); }
  }

  return <section className="sca-layout">
    <div className="sca-toolbar panel full"><div><h2>SAST 智能静态审计</h2><p>Semgrep 与本地规则的实际执行或降级状态会随扫描快照保留；规则化 Sub-agent 用于复核、证据归档和修复建议归一化。</p></div><div className="path-control"><input value={sourcePath} onChange={(event) => onSourcePathChange(event.target.value)} /><button className="primary-action" onClick={() => void onRunScan()} disabled={loading || !project}>{loading ? "执行中" : "执行 SAST 审计"}</button><button className="secondary-action" onClick={() => void onAgentReview()} disabled={loading || !project || findings.length === 0}>执行 Agent 复核</button><button className="secondary-action" onClick={() => setAdvancedOpen((value) => !value)} disabled={!project}>{advancedOpen ? "收起扫描治理" : "扫描治理与导出"}</button></div></div>
    <section className="module-summary"><Metric label="Findings" value={findings.length} /><Metric label="Agent 已复核" value={reviewedCount} /><Metric label="Critical / High" value={(severitySummary.critical ?? 0) + (severitySummary.high ?? 0)} /><Metric label="风险分类" value={Object.keys(categorySummary).length} /></section>
    {advancedOpen ? <section className="content-grid"><div className="panel full"><div className="panel-header"><h2>SAST 扫描治理</h2><span>{advancedMessage || `项目级配置版本 v${profile?.profile_version ?? "-"}；快照随扫描保存`}</span></div><div className="filter-grid"><label>Semgrep 规则包 / 本地规则文件<input value={profile?.semgrep_config ?? "p/default"} disabled={!profile} onChange={(event) => setProfile((current) => current ? { ...current, semgrep_config: event.target.value } : current)} /></label><label className="inline-check"><input type="checkbox" checked={profile?.semgrep_enabled ?? false} disabled={!profile} onChange={(event) => setProfile((current) => current ? { ...current, semgrep_enabled: event.target.checked } : current)} />启用 Semgrep</label><label className="inline-check"><input type="checkbox" checked={profile?.include_local_rules ?? false} disabled={!profile} onChange={(event) => setProfile((current) => current ? { ...current, include_local_rules: event.target.checked } : current)} />启用本地规则</label><label className="inline-check"><input type="checkbox" checked={profile?.clear_previous ?? true} disabled={!profile} onChange={(event) => setProfile((current) => current ? { ...current, clear_previous: event.target.checked } : current)} />新扫描关闭旧的活动 Finding</label><button className="secondary-action" onClick={() => void saveProfile()} disabled={!profile}>保存扫描配置</button><button className="secondary-action" onClick={() => void exportSarif()} disabled={history.length === 0}>导出最新 SARIF</button></div></div><div className="panel"><div className="panel-header"><h2>Semgrep 工具健康</h2><span>{toolHealth?.can_run_semgrep ? "可运行" : "将降级"}</span></div><div className="kv-list"><div><span>CLI</span><strong>{toolHealth?.semgrep_cli.available ? toolHealth.semgrep_cli.version ?? "可用" : "不可用"}</strong></div><div><span>Docker</span><strong>{toolHealth?.docker.available ? toolHealth.docker.version ?? "可用" : "不可用"}</strong></div><div><span>镜像</span><strong>{toolHealth?.docker_image.available ? "已就绪" : "未找到"}</strong></div></div></div><div className="panel"><div className="panel-header"><h2>最新扫描差异</h2><span>{scanDiff?.base_scan_id ? `${scanDiff.base_scan_id.slice(0, 8)} → ${scanDiff.target_scan_id.slice(0, 8)}` : "需要两次扫描"}</span></div><div className="kv-list"><div><span>新增</span><strong>{scanDiff?.summary.added ?? 0}</strong></div><div><span>消失</span><strong>{scanDiff?.summary.removed ?? 0}</strong></div><div><span>等级变化</span><strong>{scanDiff?.summary.severity_changed ?? 0}</strong></div><div><span>未变化</span><strong>{scanDiff?.summary.unchanged ?? 0}</strong></div></div></div><div className="panel full"><div className="panel-header"><h2>规则 / 路径豁免</h2><span>仅抑制下一次扫描结果，历史原始快照保持不变</span></div><div className="filter-grid"><label>规则 ID 或 *<input value={suppression.rule_id} onChange={(event) => setSuppression((current) => ({ ...current, rule_id: event.target.value }))} /></label><label>相对路径 glob<input value={suppression.path_pattern} onChange={(event) => setSuppression((current) => ({ ...current, path_pattern: event.target.value }))} /></label><label>失效日期（可选）<input type="date" value={suppression.expires_at} onChange={(event) => setSuppression((current) => ({ ...current, expires_at: event.target.value }))} /></label><label>豁免理由<input value={suppression.reason} onChange={(event) => setSuppression((current) => ({ ...current, reason: event.target.value }))} placeholder="例如：测试专用文件" /></label><button className="secondary-action" onClick={() => void addSuppression()} disabled={!project}>新增豁免</button></div>{profile?.suppressions.length ? <table><thead><tr><th>规则</th><th>路径</th><th>理由</th><th>失效</th><th>状态</th></tr></thead><tbody>{profile.suppressions.map((item) => <tr key={item.id}><td>{item.rule_id}</td><td>{item.path_pattern}</td><td>{item.reason}</td><td>{item.expires_at ? formatDateTime(item.expires_at) : "永久"}</td><td><button className="secondary-action" onClick={() => void toggleSuppression(item)}>{item.enabled ? "停用" : "启用"}</button></td></tr>)}</tbody></table> : <div className="empty-project">暂无项目级豁免。</div>}</div><div className="panel full"><div className="panel-header"><h2>扫描历史与引擎状态</h2><span>{history.length} 次扫描</span></div>{history.length ? <table><thead><tr><th>时间</th><th>Finding</th><th>抑制</th><th>Semgrep</th><th>本地规则</th></tr></thead><tbody>{history.slice(0, 10).map((item) => <tr key={item.scan_task_id}><td>{formatDateTime(item.finished_at ?? item.created_at)}<span className="cell-subtext">{item.scan_task_id.slice(0, 8)}</span></td><td>{item.finding_count}</td><td>{item.suppressed_count}</td><td>{item.engine_status.semgrep?.status ?? "旧扫描未记录"}<span className="cell-subtext">{item.engine_status.semgrep?.detail ?? item.engine_status.semgrep?.config ?? "-"}</span></td><td>{item.engine_status.local_rules?.status ?? "旧扫描未记录"}</td></tr>)}</tbody></table> : <div className="empty-project">尚无扫描历史；执行 SAST 后会保留规则配置、引擎状态、抑制数量和 Finding 快照。</div>}</div></section> : null}
    <div className="content-grid"><div className="panel"><div className="panel-header"><h2>规则分类</h2><span>Category</span></div><KeyValue data={categorySummary} /></div><div className="panel"><div className="panel-header"><h2>严重等级</h2><span>Severity</span></div><KeyValue data={severitySummary} /></div><div className="panel full"><div className="panel-header"><h2>SAST 风险发现</h2><span>共 {findings.length} 条</span></div><table><thead><tr><th>等级</th><th>分类</th><th>标题</th><th>位置</th><th>Agent 复核</th><th>修复建议</th></tr></thead><tbody>{findings.length === 0 ? <tr><td colSpan={6} className="empty-cell">暂无 SAST findings，执行 SAST 审计后显示结果。</td></tr> : pageFindings.map((finding) => <tr key={finding.id}><td><span className={`severity ${finding.severity}`}>{finding.severity}</span><span className="cell-subtext">{finding.ai_review?.priority ?? "-"}</span></td><td><span className="risk-badge review-required">{finding.ai_review?.category ?? "unknown"}</span><span className="cell-subtext">{finding.ai_review?.language ?? "Unknown"}</span></td><td><strong>{finding.title}</strong><span className="cell-subtext">{finding.evidence ?? "-"}</span></td><td>{finding.file_path ?? "-"}<span className="cell-subtext">Line {finding.line_start ?? "-"}</span><span className="cell-subtext">{finding.ai_review?.cwe ?? "-"} · {finding.ai_review?.owasp ?? "-"}</span></td><td>{finding.ai_review?.review_verdict ?? "未复核"}<span className="cell-subtext">误报概率：{finding.ai_review?.false_positive_likelihood ?? "-"}</span><span className="cell-subtext">{finding.ai_review?.evidence_summary ?? "-"}</span></td><td>{finding.ai_review?.fix_strategy ?? finding.ai_review?.remediation ?? "-"}</td></tr>)}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div>
  </section>;
}
function ScaView({ project, components, scanHistory, selectedScanId, scanDiff, dependencyGraph, sourcePath, toolScanEnabled, ecosystemSummary, riskSummary, loading, onSourcePathChange, onToolScanChange, onRunScan, onExportSbom, onExportReport, onSelectScan }: { project: Project | null; components: Component[]; scanHistory: ScaScanHistoryItem[]; selectedScanId: string | null; scanDiff: ScaScanDiff | null; dependencyGraph: DependencyGraph | null; sourcePath: string; toolScanEnabled: boolean; ecosystemSummary: Record<string, number>; riskSummary: Record<string, number>; loading: boolean; onSourcePathChange: (value: string) => void; onToolScanChange: (enabled: boolean) => void; onRunScan: () => Promise<void>; onExportSbom: (format: "cyclonedx" | "spdx") => Promise<void>; onExportReport: () => Promise<void>; onSelectScan: (scanTaskId: string) => Promise<void> }) {
  const [page, setPage] = useState(1);
  const [mode, setMode] = useState<"list" | "graph" | "history">("list");
  const [filters, setFilters] = useState({ ecosystem: "all", dependencyType: "all", riskStatus: "all", severity: "all", licensePolicy: "all" });
  const [toolHealth, setToolHealth] = useState<ScaToolHealth | null>(null);
  const [toolHealthLoading, setToolHealthLoading] = useState(false);
  const pageSize = 10;
  const filteredComponents = components.filter((component) => matchesScaFilters(component, filters));
  const pageCount = Math.max(1, Math.ceil(filteredComponents.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageComponents = filteredComponents.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const sourceSummary = countBy(filteredComponents.map((component) => ({ source: component.risk_source ?? "unknown" })), "source");
  const filteredEcosystemSummary = countBy(filteredComponents, "ecosystem");
  const dependencyTypeSummary = countBy(filteredComponents, "dependency_type");
  const licensePolicySummary = countBy(filteredComponents.map((component) => ({ policy: component.license_risk ?? "not_declared" })), "policy");
  const directCount = filteredComponents.filter((component) => component.dependency_type !== "transitive").length;
  const riskyTransitiveCount = filteredComponents.filter((component) => component.dependency_type === "transitive" && isRiskyScaComponent(component)).length;
  const edgeSummary = dependencyEdgeSummary(filteredComponents, dependencyGraph);
  const currentToolStatus = scanHistory.find((item) => item.scan_task_id === selectedScanId)?.tool_status ?? null;
  const currentAssurance = scanHistory.find((item) => item.scan_task_id === selectedScanId)?.assurance ?? null;
  const filterOptions = useMemo(() => ({
    ecosystems: uniqueValues(components.map((component) => component.ecosystem)),
    dependencyTypes: uniqueValues(components.map((component) => component.dependency_type)),
    riskStatuses: uniqueValues(components.map((component) => component.risk_status ?? "not_checked")),
    severities: uniqueValues(components.map((component) => component.severity ?? "none")),
    licensePolicies: uniqueValues(components.map((component) => component.license_risk ?? "not_declared")),
  }), [components]);
  useEffect(() => { setPage(1); }, [components, filters]);
  useEffect(() => { setMode("list"); }, [project?.id]);
  useEffect(() => { void refreshToolHealth(); }, []);

  async function refreshToolHealth() {
    setToolHealthLoading(true);
    try {
      setToolHealth(await request<ScaToolHealth>("/sca/tool-health"));
    } catch (error) {
      setToolHealth({
        status: "failed",
        recommended_grype_input: "unavailable",
        checks: [{ name: "api", status: "failed", detail: errorMessage(error), remediation: "确认后端 API 正常运行后重试。" }],
      });
    } finally {
      setToolHealthLoading(false);
    }
  }

  if (mode === "graph") {
    return <section className="sca-layout"><div className="sca-toolbar panel full"><div><h2>完整依赖图谱</h2><p>优先展示项目 Python 环境实际安装关系；其次为 NPM 原生依赖树，最后才是锁文件推断关系。</p></div><div className="path-control"><button className="secondary-action" onClick={() => setMode("list")}>返回 SCA 清单</button></div></div><section className="module-summary"><Metric label="节点" value={dependencyGraph?.summary.node_count ?? 0} /><Metric label="依赖边" value={dependencyGraph?.summary.edge_count ?? 0} /><Metric label="风险节点" value={dependencyGraph?.summary.risk_node_count ?? 0} /><Metric label="Python 实际 / NPM / 推断" value={`${dependencyGraph?.summary.python_environment_edge_count ?? 0} / ${dependencyGraph?.summary.native_tree_edge_count ?? 0} / ${dependencyGraph?.summary.lockfile_inferred_edge_count ?? 0}`} /></section><div className="content-grid"><div className="panel full"><div className="panel-header"><h2>完整图谱</h2><span>{selectedScanId ? `批次 ${selectedScanId.slice(0, 8)}` : project?.name ?? "未连接"}</span></div><DependencyGraphView graph={dependencyGraph} full /></div><div className="panel full"><div className="panel-header"><h2>升级杠杆</h2><span>{dependencyGraph?.upgrade_levers.length ?? 0} 项</span></div><UpgradeLeverTable levers={dependencyGraph?.upgrade_levers ?? []} /></div></div></section>;
  }

  if (mode === "history") {
    return <section className="sca-layout"><div className="sca-toolbar panel full"><div><h2>SCA 扫描历史</h2><p>查看项目历次 SCA 扫描快照，切换后组件清单、SBOM 和依赖图谱都会使用对应批次。</p></div><div className="path-control"><button className="secondary-action" onClick={() => setMode("list")}>返回 SCA 清单</button></div></div><section className="module-summary"><Metric label="历史批次" value={scanHistory.length} /><Metric label="当前批次" value={selectedScanId ? selectedScanId.slice(0, 8) : "-"} /><Metric label="当前组件" value={components.length} /><Metric label="最近完成" value={formatDateTime(scanHistory[0]?.finished_at)} /></section><div className="content-grid"><div className="panel full"><div className="panel-header"><h2>与上一批次对比</h2><span>{scanDiff?.base_scan_id ? `${scanDiff.base_scan_id.slice(0, 8)} → ${scanDiff.target_scan_id.slice(0, 8)}` : "需要至少两次扫描"}</span></div><ScaScanDiffView diff={scanDiff} /></div><div className="panel full"><div className="panel-header"><h2>全部历史记录</h2><span>{project?.name ?? "未连接"}</span></div><ScaScanHistoryTable history={scanHistory} selectedScanId={selectedScanId} loading={loading} onSelect={async (scanTaskId) => { await onSelectScan(scanTaskId); setMode("list"); }} /></div></div></section>;
  }

  return <section className="sca-layout"><div className="sca-toolbar panel full"><div><h2>SCA 供应链风险分析</h2><p>锁文件、实际环境或 Syft 提供精确版本后才会进行漏洞匹配；版本范围或情报不可用时明确标记“需要复核”，不会误报为无风险。</p></div><div className="path-control"><input value={sourcePath} onChange={(event) => onSourcePathChange(event.target.value)} /><label className="inline-check"><input type="checkbox" checked={toolScanEnabled} onChange={(event) => onToolScanChange(event.target.checked)} disabled={loading} />Syft/Grype 增强</label><button className="primary-action" onClick={() => void onRunScan()} disabled={loading || !project}>{loading ? "执行中" : "执行 SCA 风险分析"}</button><button className="secondary-action" onClick={() => void onExportSbom("cyclonedx")} disabled={loading || !project || components.length === 0}>导出 CycloneDX</button><button className="secondary-action" onClick={() => void onExportSbom("spdx")} disabled={loading || !project || components.length === 0}>导出 SPDX</button><button className="secondary-action" onClick={() => void onExportReport()} disabled={loading || !project || components.length === 0}>导出 SCA 报告</button></div></div><section className="module-summary"><Metric label="筛选结果" value={`${filteredComponents.length} / ${components.length}`} /><Metric label="直接 / 传递" value={`${directCount} / ${dependencyTypeSummary.transitive ?? 0}`} /><Metric label="风险传递依赖" value={riskyTransitiveCount} /><Metric label="漏洞情报覆盖" value={currentAssurance ? `${currentAssurance.vulnerability_coverage_percent ?? 0}%` : "旧批次未记录"} /></section><div className="content-grid"><ScaToolHealthPanel health={toolHealth} loading={toolHealthLoading} onRefresh={refreshToolHealth} /><div className="panel full"><div className="panel-header"><h2>扫描可信度</h2><span>{scanAssuranceLabel(currentAssurance?.status)} · {confidenceLabel(currentAssurance?.confidence)}</span></div><div className="kv-list"><div><span>组件 / 精确版本</span><strong>{currentAssurance?.component_count ?? components.length} / {currentAssurance?.resolved_component_count ?? 0}</strong></div><div><span>锁文件或实际环境</span><strong>{currentAssurance?.lock_or_environment_component_count ?? 0}</strong></div><div><span>版本范围待解析</span><strong>{currentAssurance?.constraint_component_count ?? 0}</strong></div><div><span>漏洞情报已验证 / 未验证</span><strong>{currentAssurance?.verified_component_count ?? 0} / {currentAssurance?.unverified_component_count ?? components.length}</strong></div><div><span>覆盖率</span><strong>{currentAssurance?.vulnerability_coverage_percent ?? 0}%</strong></div></div><p>{currentAssurance?.statement ?? "旧扫描批次没有可信度快照，建议重新执行 SCA。"}</p>{currentAssurance?.reasons?.length ? <p>待完善：{currentAssurance.reasons.join("；")}</p> : null}</div><div className="panel full"><div className="panel-header"><h2>增强引擎状态</h2><span>{toolStatusLabel(currentToolStatus?.status)}</span></div><div className="kv-list"><div><span>Syft</span><strong>{toolExecutionStatusLabel(currentToolStatus?.syft_status)} · {currentToolStatus?.syft_component_count ?? 0} 组件</strong></div><div><span>Grype</span><strong>{toolExecutionStatusLabel(currentToolStatus?.grype_status)} · {currentToolStatus?.grype_vulnerability_count ?? 0} 漏洞</strong></div><div><span>Trivy</span><strong>{toolExecutionStatusLabel(currentToolStatus?.trivy_status)} · {currentToolStatus?.trivy_vulnerability_count ?? 0} 漏洞</strong></div><div><span>错误</span><strong>{currentToolStatus?.errors.length ?? 0}</strong></div></div>{currentToolStatus?.errors.length ? <div className="empty-project">{currentToolStatus.errors.slice(0, 3).join("；")}</div> : null}</div><button className="graph-open-card panel full" onClick={() => setMode("history")} disabled={scanHistory.length === 0}><span>扫描历史</span><strong>{scanHistory.length ? `${scanHistory.length} 次扫描` : "暂无历史"}</strong><em>{scanDiff?.has_comparison ? `新增风险 ${scanDiff.summary.risk_added} · 已消失 ${scanDiff.summary.risk_removed} · 组件变化 ${scanDiff.summary.added_components + scanDiff.summary.removed_components + scanDiff.summary.version_changes}` : selectedScanId ? `当前批次 ${selectedScanId.slice(0, 8)} · 最近完成 ${formatDateTime(scanHistory[0]?.finished_at)}` : "执行 SCA 后可查看全部历史记录"}</em></button><button className="graph-open-card panel full" onClick={() => setMode("graph")} disabled={!dependencyGraph}><span>依赖图谱</span><strong>{dependencyGraph ? `${dependencyGraph.summary.node_count ?? 0} 节点 / ${dependencyGraph.summary.edge_count ?? 0} 边` : "暂无图谱"}</strong><em>Python 实际边 {dependencyGraph?.summary.python_environment_edge_count ?? 0} · NPM 原生边 {dependencyGraph?.summary.native_tree_edge_count ?? 0}</em></button><div className="panel full"><div className="panel-header"><h2>升级杠杆</h2><span>{dependencyGraph?.upgrade_levers.length ?? 0} 项</span></div><UpgradeLeverTable levers={dependencyGraph?.upgrade_levers ?? []} /></div><div className="panel full"><div className="panel-header"><h2>组件筛选</h2><span>Filter</span></div><div className="filter-grid"><FilterSelect label="生态" value={filters.ecosystem} options={filterOptions.ecosystems} onChange={(value) => setFilters((current) => ({ ...current, ecosystem: value }))} /><FilterSelect label="依赖类型" value={filters.dependencyType} options={filterOptions.dependencyTypes} formatOption={dependencyTypeLabel} onChange={(value) => setFilters((current) => ({ ...current, dependencyType: value }))} /><FilterSelect label="风险状态" value={filters.riskStatus} options={filterOptions.riskStatuses} formatOption={riskStatusLabel} onChange={(value) => setFilters((current) => ({ ...current, riskStatus: value }))} /><FilterSelect label="严重等级" value={filters.severity} options={filterOptions.severities} formatOption={severityLabel} onChange={(value) => setFilters((current) => ({ ...current, severity: value }))} /><FilterSelect label="许可证策略" value={filters.licensePolicy} options={filterOptions.licensePolicies} formatOption={licensePolicyLabel} onChange={(value) => setFilters((current) => ({ ...current, licensePolicy: value }))} /><button className="secondary-action" onClick={() => setFilters({ ecosystem: "all", dependencyType: "all", riskStatus: "all", severity: "all", licensePolicy: "all" })}>清空筛选</button></div></div><div className="panel"><div className="panel-header"><h2>生态分布</h2><span>SBOM ecosystem</span></div><KeyValue data={filteredEcosystemSummary} /></div><div className="panel"><div className="panel-header"><h2>依赖类型</h2><span>Dependency</span></div><KeyValue data={dependencyTypeSummary} formatKey={dependencyTypeLabel} /></div><div className="panel"><div className="panel-header"><h2>许可证策略</h2><span>License</span></div><KeyValue data={licensePolicySummary} formatKey={licensePolicyLabel} /></div><div className="panel full"><div className="panel-header"><h2>组件风险清单</h2><span>Project: {project?.name ?? "未连接"}</span></div><table><thead><tr><th>生态</th><th>组件</th><th>版本</th><th>类型</th><th>风险</th><th>来源 / OSV</th><th>漏洞编号</th><th>许可证</th><th>修复建议</th></tr></thead><tbody>{components.length === 0 ? <tr><td colSpan={9} className="empty-cell">暂无组件，执行 SCA 扫描后显示结果。</td></tr> : filteredComponents.length === 0 ? <tr><td colSpan={9} className="empty-cell">当前筛选条件下没有组件。</td></tr> : pageComponents.map((component) => <tr key={component.id}><td><span className="ecosystem-badge">{component.ecosystem}</span></td><td><strong>{component.name}</strong><span className="cell-subtext">{component.source_file}</span></td><td>{component.version ?? "-"}</td><td>{dependencyTypeLabel(component.dependency_type)}</td><td><RiskBadge status={component.risk_status ?? "not_checked"} severity={component.severity ?? null} /></td><td><span className="risk-badge review-required">{sourceLabel(component.risk_source)}</span><span className="cell-subtext">{component.osv_checked ? "OSV 已查询" : "OSV 未查询"}</span>{component.osv_error ? <span className="cell-subtext">{component.osv_error}</span> : null}</td><td>{component.vulnerability_ids?.length ? component.vulnerability_ids.join(", ") : "-"}</td><td>{component.license ?? "-"}{component.license_risk ? <span className="cell-subtext">策略：{licensePolicyLabel(component.license_risk)}</span> : null}</td><td>{component.remediation ?? component.risk_summary ?? "-"}</td></tr>)}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条，共 {filteredComponents.length} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div></section>;
}

function ScaScanHistoryTable({ history, selectedScanId, loading, onSelect }: { history: ScaScanHistoryItem[]; selectedScanId: string | null; loading: boolean; onSelect: (scanTaskId: string) => Promise<void> }) {
  const [page, setPage] = useState(1);
  if (history.length === 0) return <div className="empty-project">暂无 SCA 扫描历史，执行 SCA 风险分析后会保留每次扫描快照。</div>;
  const pagination = paginate(history, page);
  return <><table className="compact-table"><thead><tr><th>批次</th><th>状态</th><th>完成时间</th><th>组件</th><th>直接 / 传递</th><th>漏洞 / 高危</th><th>许可证风险</th><th>外部漏洞库</th><th>增强引擎</th><th>操作</th></tr></thead><tbody>{pagination.items.map((item) => <tr key={item.scan_task_id} className={selectedScanId === item.scan_task_id ? "selected-row" : ""}><td><strong>{item.scan_task_id.slice(0, 8)}</strong><span className="cell-subtext">{formatDateTime(item.started_at ?? item.created_at)}</span></td><td>{scanStatusLabel(item.status)}</td><td>{formatDateTime(item.finished_at)}</td><td>{item.component_count}</td><td>{item.direct_dependency_count} / {item.transitive_dependency_count}</td><td>{item.vulnerable_count}<span className="cell-subtext">严重 {item.critical_count} · 高危 {item.high_count}</span></td><td>{item.license_risk_count}</td><td>{osvLookupStatusLabel(item.osv_status)}<span className="cell-subtext">{item.osv_status === "offline_degraded" ? `网络不可用，已降级为本地规则（${item.osv_error_count} 项失败）` : ""}</span></td><td>{toolStatusLabel(item.tool_status?.status)}<span className="cell-subtext">Syft：{toolExecutionStatusLabel(item.tool_status?.syft_status)} · {item.tool_status?.syft_component_count ?? 0} 组件</span><span className="cell-subtext">Grype：{toolExecutionStatusLabel(item.tool_status?.grype_status)} · {item.tool_status?.grype_vulnerability_count ?? 0} 漏洞</span><span className="cell-subtext">Trivy：{toolExecutionStatusLabel(item.tool_status?.trivy_status)} · {item.tool_status?.trivy_vulnerability_count ?? 0} 漏洞</span>{item.tool_status?.errors?.length ? <span className="cell-subtext">{item.tool_status.errors[0]}</span> : null}</td><td><button className="secondary-action" disabled={loading || selectedScanId === item.scan_task_id} onClick={() => void onSelect(item.scan_task_id)}>{selectedScanId === item.scan_task_id ? "当前批次" : "查看快照"}</button></td></tr>)}</tbody></table><Pagination page={pagination.page} pageCount={pagination.pageCount} total={history.length} onPageChange={setPage} /></>;
}

function ScaToolHealthPanel({ health, loading, onRefresh }: { health: ScaToolHealth | null; loading: boolean; onRefresh: () => Promise<void> }) {
  const [page, setPage] = useState(1);
  const checks = health?.checks ?? [];
  const pagination = paginate(checks, page);
  return <div className="panel full">
    <div className="panel-header"><div><h2>Docker 增强扫描准备情况</h2><span>仅启用 Docker 增强扫描时需要检查</span></div><span>{toolHealthStatusLabel(health?.status)}</span></div>
    <div className="kv-list">
      <div><span>推荐扫描输入</span><strong>{grypeInputLabel(health?.recommended_grype_input)}</strong></div>
      <div><span>检查项</span><strong>{health?.checks.length ?? 0}</strong></div>
      <div><span>失败 / 警告</span><strong>{health?.checks.filter((item) => item.status !== "success").length ?? 0}</strong></div>
      <div><span>操作</span><button className="secondary-action" disabled={loading} onClick={() => void onRefresh()}>{loading ? "检查中" : "重新预检"}</button></div>
    </div>
    <table className="compact-table"><thead><tr><th>检查项</th><th>状态</th><th>详情</th><th>处理建议</th></tr></thead><tbody>{checks.length ? pagination.items.map((item) => <tr key={item.name}><td>{toolHealthNameLabel(item.name)}</td><td><span className={`risk-badge ${item.status === "success" ? "clean" : item.status === "warning" ? "review-required" : "vulnerable"}`}>{toolHealthStatusLabel(item.status)}</span></td><td>{item.detail ?? "-"}</td><td>{item.remediation ?? "-"}</td></tr>) : <tr><td colSpan={4} className="empty-cell">正在等待工具链预检结果。</td></tr>}</tbody></table><Pagination page={pagination.page} pageCount={pagination.pageCount} total={checks.length} onPageChange={setPage} />
  </div>;
}

function ScaScanDiffView({ diff }: { diff: ScaScanDiff | null }) {
  const [page, setPage] = useState(1);
  if (!diff || !diff.has_comparison) return <div className="empty-project">需要至少两次完成的 SCA 扫描才能生成对比。</div>;
  const summary = diff.summary;
  const pagination = paginate(diff.changes, page);
  return <div className="diff-stack"><div className="module-summary inline-summary"><Metric label="新增组件" value={summary.added_components} /><Metric label="移除组件" value={summary.removed_components} /><Metric label="版本变化" value={summary.version_changes} /><Metric label="新增 / 消失风险" value={`${summary.risk_added} / ${summary.risk_removed}`} /></div><table className="compact-table"><thead><tr><th>类型</th><th>组件</th><th>版本变化</th><th>风险变化</th><th>许可证策略</th><th>说明</th></tr></thead><tbody>{diff.changes.length === 0 ? <tr><td colSpan={6} className="empty-cell">与上一批次相比没有变化。</td></tr> : pagination.items.map((item, index) => <tr key={`${item.ecosystem}-${item.name}-${item.change_type}-${index}`}><td>{scaChangeTypeLabel(item.change_type)}</td><td><strong>{item.name}</strong><span className="cell-subtext">{item.ecosystem}</span></td><td>{item.base_version ?? "-"} → {item.target_version ?? "-"}</td><td>{riskStatusLabel(item.base_risk_status)} / {severityLabel(item.base_severity)}<span className="cell-subtext">→ {riskStatusLabel(item.target_risk_status)} / {severityLabel(item.target_severity)}</span><span className="cell-subtext">{item.base_vulnerability_ids.join(", ") || "-"} → {item.target_vulnerability_ids.join(", ") || "-"}</span></td><td>{licensePolicyLabel(item.base_license_risk)} → {licensePolicyLabel(item.target_license_risk)}</td><td>{item.summary}</td></tr>)}</tbody></table><Pagination page={pagination.page} pageCount={pagination.pageCount} total={diff.changes.length} onPageChange={setPage} /></div>;
}

function DependencyGraphView({ graph, full = false }: { graph: DependencyGraph | null; full?: boolean }) {
  const [page, setPage] = useState(1);
  if (!graph || graph.nodes.length === 0) return <div className="empty-project">暂无依赖图谱，执行 SCA 扫描后显示结果。</div>;
  const pagination = paginate(graph.nodes, page);
  const pageNodeIds = new Set(pagination.items.map((node) => node.id));
  const pageGraph = { ...graph, nodes: pagination.items, edges: graph.edges.filter((edge) => pageNodeIds.has(edge.source) && pageNodeIds.has(edge.target)) };
  const positions = graphLayout(pageGraph);
  const height = graphHeight(pageGraph);
  return <div className={full ? "graph-shell full-graph" : "graph-shell"}><div className="graph-page-note">当前展示 {pagination.items.length} 个节点及其页面内关系</div><svg viewBox={`0 0 960 ${height}`} role="img" aria-label="SCA 依赖图谱">
    <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#8aa0b8" /></marker></defs>
    {pageGraph.edges.map((edge) => {
      const source = positions.get(edge.source);
      const target = positions.get(edge.target);
      if (!source || !target) return null;
      return <line key={`${edge.source}-${edge.target}`} x1={source.x + 92} y1={source.y} x2={target.x - 92} y2={target.y} className={`graph-edge ${edge.quality}`} markerEnd="url(#arrow)" />;
    })}
    {pageGraph.nodes.map((node) => {
      const position = positions.get(node.id);
      if (!position) return null;
      return <g key={node.id} transform={`translate(${position.x - 82}, ${position.y - 26})`} className={`graph-node ${nodeRiskClass(node)}`}>
        <rect width="164" height="52" rx="8" />
        <text x="12" y="21">{truncateText(node.label, 20)}</text>
        <text x="12" y="39" className="graph-node-meta">{node.kind === "project" ? "项目" : `${dependencyTypeLabel(node.dependency_type)} · ${node.ecosystem ?? "-"}`}</text>
      </g>;
    })}
  </svg><div className="graph-legend"><span><i className="legend-dot clean" />无风险</span><span><i className="legend-dot vulnerable" />漏洞/高危</span><span><i className="legend-dot license-risk" />许可证风险</span><span>蓝实线：NPM 原生；紫实线：Python 实际环境；虚线：锁文件推断</span></div><Pagination page={pagination.page} pageCount={pagination.pageCount} total={graph.nodes.length} onPageChange={setPage} /></div>;
}

function UpgradeLeverTable({ levers }: { levers: UpgradeLever[] }) {
  const [page, setPage] = useState(1);
  if (levers.length === 0) return <div className="empty-project">暂无升级杠杆。通常表示当前没有直接依赖带入风险传递依赖。</div>;
  const pagination = paginate(levers, page);
  return <><table><thead><tr><th>直接依赖</th><th>风险传递依赖</th><th>最高等级</th><th>影响组件</th><th>建议动作</th></tr></thead><tbody>{pagination.items.map((lever) => <tr key={lever.component_id}><td><strong>{lever.component}</strong><span className="cell-subtext">{lever.ecosystem} · {lever.version ?? "-"}</span></td><td>{lever.risk_transitive_count}</td><td>{severityLabel(lever.highest_severity ?? "none")}</td><td>{lever.affected_components.slice(0, 5).join(", ") || "-"}{lever.affected_components.length > 5 ? <span className="cell-subtext">另 {lever.affected_components.length - 5} 个</span> : null}</td><td>{lever.recommendation}</td></tr>)}</tbody></table><Pagination page={pagination.page} pageCount={pagination.pageCount} total={levers.length} onPageChange={setPage} /></>;
}

function RiskBadge({ status, severity }: { status: string; severity: Severity | null }) {
  const label = severity ? `${riskStatusLabel(status)} / ${severityLabel(severity)}` : riskStatusLabel(status);
  return <span className={`risk-badge ${status}`}>{label}</span>;
}
function FilterSelect({ label, value, options, onChange, formatOption = (option) => option }: { label: string; value: string; options: string[]; onChange: (value: string) => void; formatOption?: (value: string) => string }) {
  return <label className="filter-control"><span>{label}</span><select value={value} onChange={(event) => onChange(event.target.value)}><option value="all">全部</option>{options.map((option) => <option key={option} value={option}>{formatOption(option)}</option>)}</select></label>;
}
function EvidenceGraphPanel({ graph }: { graph: EvidenceGraph | null }) {
  const [page, setPage] = useState(1);
  const nodeMap = new Map((graph?.nodes ?? []).map((node) => [node.id, node]));
  const relationEdges = (graph?.edges ?? []).filter((edge) => edge.relation_type !== "contains");
  const pagination = paginate(relationEdges, page);
  return (
    <section className="panel full evidence-graph-panel">
      <div className="panel-header">
        <h2>跨模块证据图谱</h2>
        <span>{relationEdges.length ? `${relationEdges.length} 条可信关系` : "等待显式关联证据"}</span>
      </div>
      <section className="module-summary inline-summary">
        <Metric label="图谱节点" value={graph?.summary.node_count ?? 0} />
        <Metric label="关联关系" value={graph?.summary.relation_edge_count ?? 0} />
        <Metric label="已关联 DAST" value={graph?.summary.linked_validation_count ?? 0} />
        <Metric label="已关联 SANDBOX" value={graph?.summary.linked_evidence_count ?? 0} />
      </section>
      {relationEdges.length === 0 ? <div className="empty-project">请在 DAST 或 SANDBOX 页面选择原始 Finding、SCA 组件或验证记录后执行任务。未关联记录不会生成攻击链。</div> : (
        <table className="compact-table">
          <thead><tr><th>来源</th><th>关系</th><th>目标</th><th>依据</th><th>可信度</th></tr></thead>
          <tbody>{pagination.items.map((edge) => {
            const source = nodeMap.get(edge.source);
            const target = nodeMap.get(edge.target);
            return <tr key={edge.id}><td><strong>{source?.module ?? "-"}</strong><span className="cell-subtext">{source?.label ?? edge.source}</span></td><td>{relationTypeLabel(edge.relation_type)}</td><td><strong>{target?.module ?? "-"}</strong><span className="cell-subtext">{target?.label ?? edge.target}</span></td><td>{edge.basis}</td><td>{edge.confidence}%</td></tr>;
          })}</tbody>
        </table>
      )}
      {relationEdges.length ? <Pagination page={pagination.page} pageCount={pagination.pageCount} total={relationEdges.length} onPageChange={setPage} /> : null}
    </section>
  );
}

function AspmView({ summary, findings, validations, evidence, onUpdateFinding }: { summary: AspmSummary | null; findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; onUpdateFinding: (findingId: string, patch: Partial<Pick<Finding, "status" | "remediation_owner" | "remediation_note" | "remediation_due_at">>) => Promise<void> }) {
  const [page, setPage] = useState(1);
  const [attackChainPage, setAttackChainPage] = useState(1);
  const pageSize = 10;
  const pageCount = Math.max(1, Math.ceil(findings.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageFindings = findings.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const governanceSummary = countBy(findings, "status");
  const attackChains = summary?.attack_chains ?? [];
  const attackChainPagination = paginate(attackChains, attackChainPage);
  const scaGovernance = summary?.sca_governance;
  useEffect(() => { setPage(1); }, [findings]);
  useEffect(() => { setAttackChainPage(1); }, [attackChains.length]);

  return <section className="sca-layout"><section className="module-summary"><Metric label="风险分" value={summary?.risk_score ?? 0} /><Metric label="攻击链" value={attackChains.length} /><Metric label="待处置" value={(governanceSummary.open ?? 0) + (governanceSummary.pending ?? 0) + (governanceSummary.confirmed ?? 0)} /><Metric label="验证/证据" value={`${summary?.dast_validation_count ?? validations.length}/${summary?.sandbox_evidence_count ?? evidence.length}`} /></section><div className="content-grid"><div className="panel"><div className="panel-header"><h2>模块来源统计</h2><span>Finding 维度</span></div><KeyValue data={summary?.findings_by_source ?? {}} /></div><div className="panel"><div className="panel-header"><h2>整改状态</h2><span>Workflow</span></div><KeyValue data={governanceSummary} /></div><ScaGovernancePanel summary={scaGovernance} /><div className="panel full"><div className="panel-header"><h2>攻击链关联</h2><span>{attackChains.length ? `共 ${attackChains.length} 条 · 每页 10 条` : "等待多模块证据"}</span></div>{attackChains.length === 0 ? <div className="empty-project">暂无攻击链。通常需要 SAST/AGENT/SCA 风险与 DAST 或 SANDBOX 证据同时存在后生成。</div> : <><table><thead><tr><th>链路</th><th>等级</th><th>涉及模块</th><th>证据步骤</th><th>建议动作</th></tr></thead><tbody>{attackChainPagination.items.map((chain) => <tr key={chain.id}><td><strong>{chain.name}</strong><span className="cell-subtext">{chain.summary}</span></td><td><span className={`severity ${chain.severity}`}>{chain.severity}</span></td><td>{chain.modules.join(" + ")}<span className="cell-subtext">{chain.evidence_count} 个证据点</span></td><td>{chain.steps.map((step) => <span className="cell-subtext" key={`${chain.id}-${step.module}-${step.title}`}>{step.module}: {step.title}</span>)}</td><td>{chain.recommended_action}</td></tr>)}</tbody></table><Pagination page={attackChainPagination.page} pageCount={attackChainPagination.pageCount} total={attackChains.length} onPageChange={setAttackChainPage} /></>}</div><div className="panel full"><div className="panel-header"><h2>整改闭环清单</h2><span>共 {findings.length} 条</span></div><table><thead><tr><th>风险</th><th>位置</th><th>状态</th><th>负责人</th><th>截止时间</th><th>处置备注</th></tr></thead><tbody>{findings.length === 0 ? <tr><td colSpan={6} className="empty-cell">暂无 findings。</td></tr> : pageFindings.map((finding) => <tr key={finding.id}><td><span className={`severity ${finding.severity}`}>{finding.severity}</span><strong>{finding.title}</strong><span className="cell-subtext">{finding.source} · {finding.rule_id}</span></td><td>{finding.file_path ?? "-"}<span className="cell-subtext">Line {finding.line_start ?? "-"}</span></td><td><select defaultValue={normalizeFindingStatus(finding.status)} onChange={(event) => void onUpdateFinding(finding.id, { status: event.target.value as FindingStatus })}>{FINDING_WORKFLOW_STATUSES.map((status) => <option key={status} value={status}>{statusLabel(status)}</option>)}</select><span className="cell-subtext">更新：{formatDateTime(finding.updated_at)}</span></td><td><input defaultValue={finding.remediation_owner ?? ""} placeholder="负责人" onBlur={(event) => void onUpdateFinding(finding.id, { remediation_owner: emptyToNull(event.target.value) })} /></td><td><input type="date" defaultValue={dateInputValue(finding.remediation_due_at)} onBlur={(event) => void onUpdateFinding(finding.id, { remediation_due_at: dateToIso(event.target.value) })} /></td><td><textarea defaultValue={finding.remediation_note ?? ""} placeholder="处置备注" onBlur={(event) => void onUpdateFinding(finding.id, { remediation_note: emptyToNull(event.target.value) })} /></td></tr>)}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div></section>;
}
function ScaGovernancePanel({ summary }: { summary?: ScaGovernanceSummary }) {
  const [page, setPage] = useState(1);
  const toolStatus = summary?.tool_status;
  const topComponents = summary?.top_components ?? [];
  const pagination = paginate(topComponents, page);
  return <div className="panel full sca-governance-panel">
    <div className="panel-header"><h2>SCA 供应链治理</h2><span>{summary?.latest_scan_id ? `最近扫描 ${formatDateTime(summary.latest_scan_finished_at)}` : "暂无 SCA 扫描"}</span></div>
    <section className="sca-governance-grid">
      <Metric label="最新扫描组件" value={summary?.component_count ?? 0} />
      <Metric label="风险组件" value={summary?.risky_component_count ?? 0} />
      <Metric label="漏洞组件" value={summary?.vulnerable_component_count ?? 0} />
      <Metric label="高危/严重组件" value={summary?.critical_high_component_count ?? 0} />
      <Metric label="最新扫描 Finding" value={summary?.latest_scan_finding_count ?? 0} />
      <Metric label="全部 SCA Finding" value={summary?.total_finding_count ?? 0} />
      <Metric label="漏洞 Finding" value={summary?.vulnerability_finding_count ?? 0} />
      <Metric label="许可证/版本复核" value={`${summary?.license_finding_count ?? 0}/${summary?.version_review_finding_count ?? 0}`} />
    </section>
    <div className="sca-tool-status">
      <div><span>增强引擎</span><strong>{toolStatus ? toolStatusLabel(toolStatus.status) : "未启用"}</strong></div>
      <div><span>Syft</span><strong>{toolExecutionStatusLabel(toolStatus?.syft_status)} · {toolStatus?.syft_component_count ?? 0} 组件</strong></div>
      <div><span>Grype</span><strong>{toolExecutionStatusLabel(toolStatus?.grype_status)} · {toolStatus?.grype_vulnerability_count ?? 0} 漏洞</strong></div>
      <div><span>Trivy</span><strong>{toolExecutionStatusLabel(toolStatus?.trivy_status)} · {toolStatus?.trivy_vulnerability_count ?? 0} 漏洞</strong></div>
      <div><span>Grype 输入</span><strong>{grypeInputLabel(toolStatus?.grype_input)}</strong></div>
      <div><span>扫描状态</span><strong>{scanStatusLabel(summary?.latest_scan_status)}</strong></div>
    </div>
    {toolStatus?.errors?.length ? <div className="sca-tool-errors">{toolStatus.errors.map((error, index) => <p key={`${index}-${error}`}>{error}</p>)}</div> : null}
    <table><thead><tr><th>Top 风险组件</th><th>风险</th><th>漏洞数</th><th>许可证</th><th>来源/建议</th></tr></thead><tbody>{topComponents.length ? pagination.items.map((component) => <tr key={`${component.ecosystem}-${component.name}-${component.version ?? "unknown"}`}><td><strong>{component.name}</strong><span className="cell-subtext">{component.ecosystem} · {component.version ?? "-"}</span></td><td><RiskBadge status={component.risk_status} severity={component.severity} /></td><td>{component.vulnerability_count}</td><td>{licensePolicyLabel(component.license_risk)}</td><td>{sourceLabel(component.risk_source)}<span className="cell-subtext">{component.remediation ?? "-"}</span></td></tr>) : <tr><td colSpan={5} className="empty-cell">暂无 SCA 风险组件。</td></tr>}</tbody></table><Pagination page={pagination.page} pageCount={pagination.pageCount} total={topComponents.length} onPageChange={setPage} />
  </div>;
}
function KeyValue({ data, formatKey = (key) => key }: { data: Record<string, number>; formatKey?: (key: string) => string }) { const entries = Object.entries(data); return <div className="kv-list">{entries.length === 0 ? <span className="empty-inline">暂无数据</span> : entries.map(([key, value]) => <div key={key}><span>{formatKey(key)}</span><strong>{value}</strong></div>)}</div>; }
function Metric({ label, value }: { label: string; value: string | number }) { return <div><span>{label}</span><strong>{value}</strong></div>; }
function objectValue(value: unknown): Record<string, unknown> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function listValue(value: unknown): unknown[] { return Array.isArray(value) ? value : []; }
function textValue(value: unknown) { return value === null || value === undefined || value === "" ? "-" : String(value); }
function downloadSecurityReport(report: SecurityReport, format: "json" | "html") {
  const filename = `${safeFilename(report.project.name)}-security-report.${format}`;
  const content = format === "json"
    ? JSON.stringify(localizeReportTimestamps(report), null, 2)
    : buildSecurityReportHtml(report);
  const blob = new Blob([content], { type: format === "json" ? "application/json" : "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
function buildSecurityReportHtml(report: SecurityReport) {
  const summaryRows = [["风险分", report.summary.risk_score], ["当前风险", report.findings.length], ["组件", report.components.length], ["动态验证", report.validations.length], ["运行时证据", report.sandbox_evidence.length], ["可信攻击链", report.summary.attack_chains.length]];
  const boundaries = Object.entries(report.capability_boundaries).map(([module, items]) => `<h3>${escapeHtml(module)}</h3><ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`).join("");
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>${escapeHtml(report.project.name)} 安全报告</title><style>body{font:14px/1.6 Arial,"Microsoft YaHei",sans-serif;color:#172b4d;margin:36px;max-width:1100px}h1{margin-bottom:4px}table{border-collapse:collapse;width:100%;margin:16px 0}th,td{border:1px solid #d8e0ec;padding:8px;text-align:left;vertical-align:top}th{background:#f3f6fb}pre{white-space:pre-wrap;word-break:break-word;background:#f7f9fc;padding:16px;border-radius:8px}section{margin:26px 0}</style></head><body><h1>${escapeHtml(report.project.name)} 项目安全报告</h1><p>生成时间：${escapeHtml(formatDateTime(report.generated_at))}。报告中的时间统一采用北京时间（UTC+8）。本 HTML 保留完整结构化数据，便于离线审阅或交付归档。</p><table><thead><tr>${summaryRows.map(([label]) => `<th>${escapeHtml(String(label))}</th>`).join("")}</tr></thead><tbody><tr>${summaryRows.map(([, value]) => `<td>${escapeHtml(String(value))}</td>`).join("")}</tr></tbody></table><section><h2>能力边界</h2>${boundaries}</section><section><h2>完整结构化数据（北京时间）</h2><pre>${escapeHtml(JSON.stringify(localizeReportTimestamps(report), null, 2))}</pre></section></body></html>`;
}
function escapeHtml(value: string) { return value.replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character] ?? character)); }
function safeFilename(value: string) { return value.replace(/[\\/:*?"<>|]/g, "-").trim() || "project"; }
function splitLines(value: string) { return value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean); }
function sastAgentRoleLabel(role: string) { return ({ strategy_agent: "审计策略 Agent", discovery_agent: "漏洞发现 Agent", review_agent: "漏洞复核 Agent", evidence_agent: "证据分析 Agent", knowledge_agent: "历史知识 Agent", fix_agent: "修复建议 Agent", independent_review_agent: "独立复核 Agent" } as Record<string, string>)[role] ?? role; }
function sourceLabel(value?: string | null) { return value === "osv" ? "OSV" : value === "osv_mirror" ? "OSV 本地镜像" : value === "osv_mirror+grype" ? "OSV 本地镜像 + Grype" : value === "osv_mirror+trivy" ? "OSV 本地镜像 + Trivy" : value === "local_rule" ? "本地规则" : value === "license_rule" ? "许可证" : value === "grype" ? "Grype" : value === "trivy" ? "Trivy（离线库）" : value === "syft" ? "Syft" : value === "osv+grype" ? "OSV + Grype" : value === "osv+trivy" ? "OSV + Trivy" : value === "local_rule+grype" ? "本地规则 + Grype" : value === "local_rule+trivy" ? "本地规则 + Trivy" : value === "version_missing" ? "版本缺失" : value === "osv_error" ? "漏洞情报未验证" : value === "clean" ? "情报已验证无匹配" : value === "not_supported" ? "不支持" : value ?? "未知"; }
function riskStatusLabel(value?: string | null) { return value === "vulnerable" ? "存在漏洞" : value === "license-risk" ? "许可证风险" : value === "review-required" ? "需要复核" : value === "accepted-risk" ? "已接受风险" : value === "clean" ? "已验证未发现" : value === "not_checked" ? "未检查" : value ?? "未知"; }
function severityLabel(value?: string | null) { return value === "critical" ? "严重" : value === "high" ? "高危" : value === "medium" ? "中危" : value === "low" ? "低危" : value === "info" ? "提示" : value === "none" ? "无等级" : value ?? "-"; }
function scaExceptionStatusLabel(value: string) { return value === "pending" ? "待审批" : value === "approved" ? "已批准" : value === "rejected" ? "已拒绝" : value === "revoked" ? "已撤销" : value; }
function vexStatusLabel(value: ScaVex["status"]) { return value === "not_affected" ? "未受影响" : value === "fixed" ? "已修复" : value === "affected" ? "受影响" : "调查中"; }
function dependencyTypeLabel(value?: string | null) { return value === "runtime" ? "运行依赖" : value === "development" ? "开发依赖" : value === "optional" ? "可选依赖" : value === "peer" ? "对等依赖" : value === "test" ? "测试依赖" : value === "transitive" ? "传递依赖" : value === "compile" ? "编译依赖" : value === "provided" ? "容器提供" : value === "system" ? "系统依赖" : value === "import" ? "导入依赖" : value ?? "-"; }
function licensePolicyLabel(value?: string | null) { return value === "allowed" ? "允许" : value === "review_required" ? "需合规复核" : value === "restricted" ? "受限需审批" : value === "unknown" ? "未知需确认" : value ?? "-"; }
function scanStatusLabel(value?: string | null) { return value === "queued" ? "排队中" : value === "running" ? "运行中" : value === "completed" ? "已完成" : value === "failed" ? "失败" : value === "cancelled" ? "已取消" : value ?? "-"; }
function scanStageLabel(value?: string | null) { return value === "queued" ? "等待执行" : value === "running" ? "正在扫描" : value === "completed" ? "执行完成" : value === "failed" ? "执行失败" : value === "cancelled" ? "已取消" : value ?? "-"; }
function toolStatusLabel(value?: string | null) { return value === "disabled" ? "未启用" : value === "success" || value === "completed" || value === "available" ? "已完成" : value === "bounded" ? "引擎完成（能力有边界）" : value === "partial_failed" || value === "degraded" || value === "partial" ? "部分完成（已降级）" : value === "failed" ? "失败" : value === "not_run" ? "未运行" : value ?? "未知"; }
function scanAssuranceLabel(value?: string | null) { return value === "complete" ? "完整验证" : value === "bounded" ? "静态证据（能力有边界）" : value === "partial" ? "部分验证" : value === "failed" ? "验证失败" : value ? toolStatusLabel(value) : "旧批次未记录"; }
function confidenceLabel(value?: string | null) { return value === "high" ? "高可信" : value === "medium" ? "中等可信" : value === "low" ? "低可信" : "可信度未记录"; }
function qualityGateStatusLabel(value?: string | null) { return value === "block" ? "未通过：存在达到阻断等级的问题" : value === "pass" ? "已通过" : "等待扫描"; }
function semgrepRuleStatusLabel(value: SastSemgrepRule["status"]) { return value === "draft" ? "草稿（不参与扫描）" : value === "published" ? "已发布" : "已归档"; }
function sastEngineDetailLabel(value?: string | null) { const text = value ?? ""; const timeout = text.match(/Semgrep scan timed out after (\d+)s/i); return timeout ? `Semgrep 扫描超过 ${timeout[1]} 秒，已超时；本地规则结果仍然有效。` : text || "无额外说明"; }
function toolExecutionStatusLabel(value?: string | null) { return value === "success" ? "成功" : value === "fallback" ? "已使用基础清单" : value === "failed" ? "失败" : value === "not_run" ? "未运行" : value ?? "旧批次未记录"; }
function scaDataStatusLabel(value?: unknown) { const status = String(value ?? ""); return status === "available" ? "已就绪" : status === "not_configured" ? "未导入（可选）" : status === "offline_degraded" ? "已使用基础本地规则" : status === "invalid" ? "数据不可用" : status === "missing" ? "未找到数据" : status || "未记录"; }
function nativeDependencyStatusLabel(value?: unknown) { const status = String(value ?? ""); return status === "not_applicable" ? "不适用（未发现该生态）" : status === "fallback_used" ? "已使用清单推断" : status === "captured" ? "已读取实际关系" : status === "tool_unavailable" ? "未使用本机工具" : status === "available" ? "已就绪" : status || "未记录"; }
function osvLookupStatusLabel(value?: string | null) { return value === "available" ? "OSV 已连接" : value === "mirror_used" ? "本地 OSV 镜像" : value === "offline_degraded" ? "离线降级" : value === "not_used" ? "未使用" : "历史批次未记录"; }
function grypeInputLabel(value?: string | null) { return value === "syft-sbom" ? "Syft SBOM" : value === "platform-sbom" ? "平台基础清单 SBOM" : value === "directory" ? "目录回退" : "-"; }
function toolHealthStatusLabel(value?: string | null) { return value === "success" ? "可用" : value === "warning" ? "有警告" : value === "failed" ? "不可用" : value ?? "未检查"; }
function relationTypeLabel(value: string) { return value === "reported_by" ? "产生风险" : value === "validated_by" ? "动态验证" : value === "observed_by" ? "运行时取证" : value; }
function confidenceLevelLabel(value: string) { return value === "high" ? "高置信度" : value === "medium" ? "中置信度" : "低置信度"; }
function executionStatusLabel(value: ExecutionStatus) { return value === "waiting" ? "等待执行" : value === "running" ? "正在执行" : value === "completed" ? "已完成" : value === "failed" ? "执行失败" : "已跳过"; }
function dastVerdictLabel(value: string) { return value === "baseline_attention" ? "基础观察：需复核" : value === "baseline_clear" ? "基础观察：未发现异常" : value === "exploitable" ? "可利用" : value === "uncertain" ? "不确定" : value === "not_exploitable" ? "不可利用" : value; }
function knowledgeTypeLabel(value: string) { return value === "false_positive_experience" ? "误报经验" : value === "remediation" ? "修复方案" : value === "validation_playbook" ? "验证剧本" : "漏洞模式"; }
function validationStatusLabel(value: string) { return value === "verified" ? "已验证" : value === "verifying" ? "验证中" : value === "failed" ? "验证失败" : "未验证"; }
function retestResultLabel(value: string) { return value === "still_present" ? "仍然存在" : value === "resolved" ? "已经消失" : value === "new" ? "新增问题" : value === "changed" ? "位置或等级变化" : value; }
function evidenceNodeStage(node: EvidenceGraphNode) { return node.kind === "component" ? "关联供应链组件" : node.kind === "validation" ? "动态验证" : node.kind === "evidence" ? "沙箱运行证据" : "关联风险"; }
function severityRank(value: Severity) { return value === "critical" ? 5 : value === "high" ? 4 : value === "medium" ? 3 : value === "low" ? 2 : 1; }
function agentTrustGradeLabel(value: string) { return ({ trusted: "证据较完整", guarded: "需带控制使用", controlled: "需带控制使用", restricted: "限制使用", untrusted: "不建议使用" } as Record<string, string>)[value] ?? value; }
function agentConfidenceLabel(value: string) { return ({ low: "低", medium: "中", high: "高" } as Record<string, string>)[value] ?? value; }
const AGENT_UI_TEXT_ZH: Record<string, string> = {
  "The score summarizes current scanner evidence; it is not a security guarantee or publisher identity attestation.": "该评分汇总当前扫描证据，不是安全保证，也不是发布者身份认证。",
  "Accepted-risk findings still reduce the score. A false-positive status removes only direct finding-based deductions; independent provenance, intelligence, permission or data-flow evidence can still reduce the score.": "已接受风险的问题仍会降低评分。标记为误报只会取消该问题的直接扣分；独立的来源、情报、权限或数据流证据仍可能降低评分。",
  "A local intelligence checked_no_match result means only that configured local sources did not match the exact version; it does not prove safety.": "本地情报“已检查但未命中”仅表示配置的本地来源没有匹配该精确版本，不能证明其安全。",
  "Static data-flow paths are confidence-labelled inferences, not observed runtime calls or transfers.": "静态数据流路径是带置信度的推断，不是已观察到的运行时调用或传输。",
  "Validated stdio MCP ledger events improve runtime evidence, but their target-visible log channel is not cryptographically authenticated.": "已验证的 stdio MCP 台账事件可以补充运行证据，但目标可见的日志通道没有经过密码学认证。",
  "A read-only MCP capability probe validates one server startup and inventory response only; it does not increase whole-Agent runtime assurance.": "只读 MCP 能力探测仅验证一次服务器启动和清单响应，不会提高整个 Agent 的运行时保证等级。",
  "A remote MCP capability probe validates one bounded public endpoint inventory response only; it does not authenticate the server or increase whole-Agent runtime assurance.": "远程 MCP 能力探测仅验证一个受限公网端点的清单响应，不会认证服务器身份，也不会提高整个 Agent 的运行时保证等级。",
  "Harmless fixture validation tests the laboratory controls and never increases the scanned target's trust score.": "无害夹具验证只测试实验室控制措施，绝不会提高被扫描目标的信任评分。",
  "Only bundled local rules and an explicitly configured local OSV mirror are queried; no network request is made.": "仅查询内置本地规则和显式配置的本地 OSV 镜像，不会发起网络请求。",
  "A checked-no-match result means only that the configured local sources did not match the exact version; it is not proof that the package is vulnerability-free.": "“已检查但未命中”仅表示配置的本地来源没有匹配该精确版本，不能证明该软件包不存在漏洞。",
  "Malicious-package and protected-name checks require a local threat-intelligence file; no package is labelled malicious without a matching local record.": "恶意包和受保护名称检查依赖本地威胁情报文件；没有本地匹配记录时，不会将任何软件包标记为恶意。",
  "Prompt context can reach a sensitive Agent capability": "Prompt 上下文可能触达敏感 Agent 能力",
  "Agent dependency source is not declared": "Agent 依赖来源未声明",
  "Generic configuration parsing requires schema review": "通用配置解析需要 Schema 复核",
  "Prompt can reach server-process": "Prompt 可能触达服务器进程能力",
  "The asset does not declare a registry, repository, container, endpoint, or governed local source.": "该资产没有声明注册表、代码仓库、容器、端点或受治理的本地来源。",
  "Static declarations connect Prompt or instruction context to a tool capability and resource boundary. The path is potential, not observed runtime execution.": "静态声明将 Prompt 或指令上下文关联到工具能力和资源边界；该路径只是潜在关系，不是已观察到的运行时执行。",
  "Review the static finding, its declared control boundary, and whether the proposed remediation fits the intended Agent capability.": "复核静态发现、声明的控制边界，以及建议修复是否符合预期的 Agent 能力。",
  "The scanner parsed these assets with generic structural rules rather than a vendor-specific schema contract.": "扫描器使用通用结构规则解析这些资产，而不是厂商专用 Schema 契约。",
  "This is a confidence-labelled static relationship, not an observed runtime call or transfer.": "这是带置信度的静态关系，不是已观察到的运行时调用或传输。",
  "This is a local review draft generated from existing static evidence; no external AI model was invoked.": "这是根据现有静态证据生成的本地复核草案，没有调用外部 AI 模型。",
  "Review candidates do not change finding severity, governance status, quality-gate decision, or trust score.": "复核候选不会改变问题等级、治理状态、质量门禁结论或信任评分。",
  "Static paths and source declarations are not observed runtime behavior, connectivity proof, publisher verification, or exploitability proof.": "静态路径和来源声明不是运行时行为观测、连通性证明、发布者验证或可利用性证明。",
  "The audit stores references and bounded summaries, not source credential values, tool parameters, response bodies, or prompt contents.": "审计只保存引用和受限摘要，不保存来源凭据值、工具参数、响应正文或 Prompt 内容。",
  "Review the static findings and coverage gaps; all require human validation before any action.": "复核静态发现和覆盖缺口；采取任何操作前都需要人工确认。",
  "The previous scan has no compatible offline audit draft, so current review candidates are not labelled as new.": "上一扫描批次没有兼容的离线审计草案，因此当前复核候选不会标记为新增。",
  "No comparison result is a statement about remediation, safety, runtime behavior, connectivity, or exploitability.": "没有对比结果并不代表已经修复、安全、缺少运行时行为、不可连接或不可利用。",
  "This graph is built from static declarations and local findings; it does not execute an Agent or prove that runtime data actually traversed a path.": "该图谱由静态声明和本地发现构建，不会执行 Agent，也不能证明运行时数据实际经过了某条路径。",
  "Prompt-to-asset and permission edges are explicit or co-declared relationships; every edge carries a confidence and basis instead of being presented as runtime fact.": "Prompt 到资产及权限的边来自显式声明或共同声明；每条边都标注置信度和依据，不会被描述成运行时事实。",
  "A project allowlist or approved exception is a governance decision, not a runtime security control, and therefore does not remove a path.": "项目 Allowlist 或已批准例外属于治理决策，不是运行时安全控制，因此不会消除路径。",
  "Declared approval is recorded as a control claim; enforcement is not verified until a future sandbox validation stage.": "声明的审批只记录为控制主张；在后续沙箱验证前，无法确认其是否真正执行。",
  "External resources are not assumed to enter model context unless a supported configuration provides a directional declaration.": "除非受支持的配置给出明确方向声明，否则不会推断外部资源已经进入模型上下文。",
  "Prompt or instruction is declared for the asset.": "该资产声明了 Prompt 或指令。",
  "The permission reaches command scope python.": "该权限可触达命令范围 python。",
  "The permission reaches command-arguments scope -I, -B.": "该权限可触达命令参数范围 -I、-B。",
  "SANDBOX module is enabled.": "SANDBOX 模块已启用。",
  "Project source directory exists.": "项目源码目录存在。",
  "Source root is not a symlink or junction.": "源码根目录不是符号链接或目录联接。",
  "An explicit command is configured.": "已配置明确的执行命令。",
  "Command passed the static preflight policy.": "命令已通过静态预检策略。",
  "An explicit container image is configured.": "已配置明确的容器镜像。",
  "Image reference passed the static credential and syntax policy.": "镜像引用已通过凭据和语法策略检查。",
  "Image is pinned by sha256 digest.": "镜像已使用 SHA-256 摘要锁定。",
  "Docker CLI is available.": "Docker CLI 可用。",
  "Container network must remain disabled.": "容器网络必须保持禁用。",
  "Container root filesystem must remain read-only.": "容器根文件系统必须保持只读。",
  "Docker/Podman and other host control sockets must not be mounted.": "不得挂载 Docker、Podman 或其他宿主控制套接字。",
  "Host environment variables, credentials and secret files must not be injected.": "不得注入宿主环境变量、凭据或密钥文件。",
  "CPU, memory, process and timeout limits are mandatory.": "必须设置 CPU、内存、进程数和超时限制。",
  "One or more staging builds exist, but this preflight has not selected and hash-verified a specific build.": "已存在一个或多个 staging 副本，但本次预检尚未选择并通过哈希验证某个精确副本。",
  "Select and re-verify one immutable staging build in the separately approved execution stage.": "请在单独审批的执行阶段选择并重新验证一个不可变 staging 副本。",
  "No explicit confirmation is recorded for this exact command, image and target.": "尚未记录对该精确命令、镜像和目标的明确确认。",
  "Confirm the exact target only after all other checks pass.": "仅在其他检查全部通过后确认精确目标。",
  "Resolve every blocking preflight check. Preflight itself never creates staging or runs a container; the separately confirmed staging action only creates a filtered copy.": "请先解决全部阻断项。预检本身不会创建 staging 或运行容器；单独确认的 staging 操作只会创建过滤副本。",
  "Preflight passed. Create and review a filtered staging copy through the separate confirmation action; Agent execution still requires another approval.": "预检已通过。请通过单独的确认操作创建并复核过滤副本；执行 Agent 仍需再次审批。",
  "A local digest-pinned Python image is available; no download is required.": "本地存在已用摘要锁定的 Python 镜像，无需下载。",
  "No local digest-pinned Python image is available. This endpoint never downloads one.": "本地没有已用摘要锁定的 Python 镜像；该接口不会下载镜像。",
  success: "成功",
  partial: "部分完成",
  pass: "通过",
  attention: "需要关注",
};
function agentUiText(value?: unknown) {
  const text = String(value ?? "").trim();
  const gate = text.match(/^(\d+) active findings meet or exceed ([a-z]+)$/i);
  if (gate) return `${gate[1]} 条活跃问题达到或超过${severityLabel(gate[2] as Severity)}阈值`;
  const packageGap = text.match(/^(\d+) Agent package coordinates lack complete local intelligence coverage$/i);
  if (packageGap) return `${packageGap[1]} 个 Agent 软件包坐标缺少完整的本地情报覆盖`;
  const declaredCapability = text.match(/^The asset declares (.+) for (.+)\.$/);
  if (declaredCapability) return `该资产为 ${declaredCapability[2]} 声明了 ${agentCapabilityLabel(declaredCapability[1])} 能力。`;
  const permissionScope = text.match(/^The permission reaches (.+) scope (.+)\.$/);
  if (permissionScope) return `该权限可触达 ${permissionScope[1]} 范围 ${permissionScope[2].replaceAll(", ", "、")}。`;
  return AGENT_UI_TEXT_ZH[text] ?? text;
}
function agentCheckLabel(value: string) { return ({ "sandbox-module": "SANDBOX 模块", "source-directory": "源码目录", "source-link-boundary": "源码链接边界", "explicit-command": "明确命令", "command-policy": "命令策略", "explicit-image": "明确镜像", "image-reference-policy": "镜像引用策略", "digest-pinned-image": "镜像摘要锁定", "docker-cli": "Docker CLI", "network-none": "禁用网络", "read-only-rootfs": "只读根文件系统", "no-host-sockets": "禁止宿主控制套接字", "no-host-secrets": "禁止宿主密钥注入", "resource-limits": "资源限制", "filtered-staging": "过滤副本", "operator-confirmation": "操作人确认" } as Record<string, string>)[value] ?? value; }
function containsEnglishProse(value?: string | null) { return Boolean(value && /(?:\b[A-Za-z][A-Za-z'-]*\b[\s,;:]+){4}/.test(value)); }
function moduleOverviewText(moduleKey: Exclude<ModuleKey, "aspm">, components: Component[], findings: Finding[], validations: DastValidation[], evidence: SandboxEvidence[]) {
  if (moduleKey === "sca") return `${components.length} 个组件，${components.filter(isRiskyScaComponent).length} 个需要关注`;
  if (moduleKey === "sast") return `${findings.filter((item) => item.source === "SAST").length} 个代码风险`;
  if (moduleKey === "agent") return `${findings.filter((item) => item.source === "AGENT").length} 个智能体相关风险`;
  if (moduleKey === "dast") return `${validations.length} 条验证记录，${validations.filter((item) => item.verdict === "uncertain").length} 项需要补充验证`;
  return `${evidence.length} 条沙箱证据，${evidence.filter((item) => item.finding_id || item.component_id || item.validation_id).length} 条已关联`;
}
function toolHealthNameLabel(value?: string | null) { return value === "docker_cli" ? "Docker CLI" : value === "docker_engine" ? "Docker Engine" : value === "syft_image" ? "Syft 镜像" : value === "grype_image" ? "Grype 镜像" : value === "grype_db" ? "Grype 离线漏洞库" : value === "trivy_image" ? "Trivy 镜像" : value === "trivy_db" ? "Trivy 离线漏洞库" : value === "trivy_java_db" ? "Trivy Java 索引库" : value === "api" ? "后端 API" : value ?? "-"; }
function scaChangeTypeLabel(value?: string | null) { return value === "added" ? "新增组件" : value === "removed" ? "移除组件" : value === "version_changed" ? "版本变化" : value === "risk_added" ? "新增风险" : value === "risk_removed" ? "风险消失" : value === "risk_changed" ? "风险变化" : value === "license_risk_changed" ? "许可证变化" : value ?? "-"; }
function normalizeFindingStatus(status: FindingStatus) { return status === "pending" ? "open" : status === "retest" ? "fixing" : status === "closed" ? "fixed" : status; }
function statusLabel(status: FindingStatus) { return status === "open" ? "待确认" : status === "confirmed" ? "已确认" : status === "fixing" ? "修复中" : status === "fixed" ? "已修复" : status === "accepted_risk" ? "接受风险" : status === "false_positive" ? "误报" : status; }
function dateInputValue(value?: string | null) { return value ? value.slice(0, 10) : ""; }
function dateToIso(value: string) { return value ? `${value}T00:00:00` : null; }
function apiDateTime(value: string) { const text = value.trim(); return new Date(/(?:Z|[+-]\d{2}:?\d{2})$/i.test(text) ? text : `${text}Z`); }
function formatDateTime(value?: string | null) {
  if (!value) return "-";
  const date = apiDateTime(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${new Intl.DateTimeFormat("zh-CN", { timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(date)}（北京时间）`;
}
function beijingIsoDateTime(value: string) {
  const date = apiDateTime(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Date(date.getTime() + 8 * 60 * 60 * 1000).toISOString().replace("Z", "+08:00");
}
function localizeReportTimestamps(value: unknown): unknown {
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?$/.test(value)) return beijingIsoDateTime(value);
  if (Array.isArray(value)) return value.map(localizeReportTimestamps);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, localizeReportTimestamps(item)]));
  return value;
}
function countBy<T extends Record<string, unknown>>(items: T[], key: keyof T) { return items.reduce<Record<string, number>>((acc, item) => { const value = String(item[key] ?? "unknown"); acc[value] = (acc[value] ?? 0) + 1; return acc; }, {}); }
function uniqueValues(values: Array<string | null | undefined>) { return Array.from(new Set(values.filter((value): value is string => Boolean(value)))).sort(); }
function isRiskyScaComponent(component: Component) { return component.risk_status === "vulnerable" || component.risk_status === "license-risk" || component.severity === "critical" || component.severity === "high"; }
function dependencyEdgeSummary(components: Component[], graph?: DependencyGraph | null) {
  if (graph) {
    return {
      manifestDirect: graph.summary.manifest_direct_edge_count ?? 0,
      nativeTree: graph.summary.native_tree_edge_count ?? 0,
      pythonEnvironment: graph.summary.python_environment_edge_count ?? 0,
      mavenNativeTree: graph.summary.maven_native_tree_edge_count ?? 0,
      goNativeTree: graph.summary.go_native_tree_edge_count ?? 0,
      lockfileInferred: graph.summary.lockfile_inferred_edge_count ?? 0,
      total: graph.summary.edge_count ?? 0,
    };
  }
  const direct = components.filter((component) => component.dependency_type !== "transitive");
  const transitive = components.filter((component) => component.dependency_type === "transitive");
  let lockfileInferred = 0;
  for (const parent of direct) {
    for (const child of transitive) {
      if (componentsShareDependencyContext(parent, child)) lockfileInferred += 1;
    }
  }
  return { manifestDirect: direct.length, nativeTree: 0, pythonEnvironment: 0, mavenNativeTree: 0, goNativeTree: 0, lockfileInferred, total: direct.length + lockfileInferred };
}
function dependencyRelationshipSourceLabel(value: string) { return value === "python_environment" ? "Python 实际环境（pip inspect）" : value === "native_tree" ? "NPM 原生依赖树" : value === "maven_native_tree" ? "Maven 原生依赖树" : value === "go_native_tree" ? "Go 原生依赖树" : value === "lockfile_inferred" ? "锁文件推断" : value === "manifest_direct" ? "项目依赖清单" : value; }
function graphLayout(graph: DependencyGraph) {
  const groups = {
    project: graph.nodes.filter((node) => node.kind === "project"),
    direct: graph.nodes.filter((node) => node.kind !== "project" && node.dependency_type !== "transitive"),
    transitive: graph.nodes.filter((node) => node.dependency_type === "transitive"),
  };
  const positions = new Map<string, { x: number; y: number }>();
  placeGraphNodes(groups.project, 110, positions);
  placeGraphNodes(groups.direct, 450, positions);
  placeGraphNodes(groups.transitive, 790, positions);
  return positions;
}
function placeGraphNodes(nodes: DependencyGraphNode[], x: number, positions: Map<string, { x: number; y: number }>) {
  const gap = 76;
  const offset = Math.max(40, 180 - ((nodes.length - 1) * gap) / 2);
  nodes.forEach((node, index) => positions.set(node.id, { x, y: offset + index * gap }));
}
function graphHeight(graph: DependencyGraph) {
  const directCount = graph.nodes.filter((node) => node.kind !== "project" && node.dependency_type !== "transitive").length;
  const transitiveCount = graph.nodes.filter((node) => node.dependency_type === "transitive").length;
  const maxCount = Math.max(1, directCount, transitiveCount);
  return Math.max(360, 100 + maxCount * 76);
}
function nodeRiskClass(node: DependencyGraphNode) {
  if (node.kind === "project") return "project";
  if (node.risk_status === "license-risk") return "license-risk";
  if (node.risk_status === "vulnerable" || node.severity === "critical" || node.severity === "high") return "vulnerable";
  return "clean";
}
function truncateText(value: string, maxLength: number) {
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}…` : value;
}
function componentsShareDependencyContext(parent: Component, child: Component) {
  if (parent.ecosystem !== child.ecosystem) return false;
  const parentSources = splitSources(parent.source_file);
  const childSources = splitSources(child.source_file);
  if (parentSources.some((source) => childSources.includes(source))) return true;
  return Boolean(parent.package_manager && child.package_manager && parent.package_manager === child.package_manager);
}
function splitSources(sourceFile?: string | null) {
  return (sourceFile ?? "").split(",").map((item) => item.trim()).filter(Boolean);
}
function matchesScaFilters(component: Component, filters: { ecosystem: string; dependencyType: string; riskStatus: string; severity: string; licensePolicy: string }) {
  return matchesFilter(component.ecosystem, filters.ecosystem)
    && matchesFilter(component.dependency_type, filters.dependencyType)
    && matchesFilter(component.risk_status ?? "not_checked", filters.riskStatus)
    && matchesFilter(component.severity ?? "none", filters.severity)
    && matchesFilter(component.license_risk ?? "not_declared", filters.licensePolicy);
}
function matchesFilter(value: string, selected: string) { return selected === "all" || value === selected; }
function paginate<T>(items: T[], requestedPage: number, pageSize = 10) { const pageCount = Math.max(1, Math.ceil(items.length / pageSize)); const page = Math.min(Math.max(1, requestedPage), pageCount); return { items: items.slice((page - 1) * pageSize, page * pageSize), page, pageCount }; }
function emptyToNull(value: string) { const trimmed = value.trim(); return trimmed ? trimmed : null; }
async function enableProjectModule(projectId: string, moduleKey: ModuleKey, enabled: boolean) { return request<ProjectModule>(`/modules/projects/${projectId}`, { method: "POST", body: JSON.stringify({ module_key: moduleKey, enabled, config: {} }) }); }
async function updateProjectModule(projectId: string, moduleKey: ModuleKey, enabled: boolean) { return request<ProjectModule>(`/modules/projects/${projectId}/${moduleKey}`, { method: "PATCH", body: JSON.stringify({ enabled }) }); }
function readLastProjectId() { try { return window.localStorage.getItem(LAST_PROJECT_STORAGE_KEY); } catch { return null; } }
function persistLastProjectId(projectId: string | null) { try { if (projectId) window.localStorage.setItem(LAST_PROJECT_STORAGE_KEY, projectId); else window.localStorage.removeItem(LAST_PROJECT_STORAGE_KEY); } catch { /* Browsers with storage disabled still keep the in-memory selection. */ } }
function errorMessage(error: unknown) { return error instanceof Error ? error.message : "未知错误"; }
function readinessStatusLabel(status: ProjectReadiness["overall_status"]) { return status === "ready" ? "可快速检测" : status === "warning" ? "可检测 · 有边界" : "暂不可检测"; }
function readinessCheckLabel(status: ProjectReadinessCheck["status"]) { return status === "ready" ? "就绪" : status === "warning" ? "需注意" : status === "blocked" ? "阻塞" : "按需配置"; }
function formatBytes(value: number) { if (value < 1024) return `${value} B`; if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`; return `${(value / (1024 * 1024)).toFixed(1)} MiB`; }

async function uploadZipProject(file: File, draft: ProjectDraft): Promise<ProjectImportResult> {
  const query = new URLSearchParams({ name: draft.name.trim(), default_branch: draft.default_branch.trim() || "main" });
  if (draft.business_owner.trim()) query.set("business_owner", draft.business_owner.trim());
  if (draft.security_owner.trim()) query.set("security_owner", draft.security_owner.trim());
  if (draft.runtime_url.trim()) query.set("runtime_url", draft.runtime_url.trim());
  if (draft.api_base_url.trim()) query.set("api_base_url", draft.api_base_url.trim());
  if (draft.sandbox_command.trim()) query.set("sandbox_command", draft.sandbox_command.trim());
  if (draft.sandbox_image.trim()) query.set("sandbox_image", draft.sandbox_image.trim());
  const response = await fetch(`${API_BASE}/projects/import/zip?${query.toString()}`, { method: "POST", headers: { "Content-Type": "application/zip" }, body: file });
  if (!response.ok) { let detail = `${response.status} ${response.statusText}`; try { const payload = await response.json(); detail = typeof payload.detail === "string" ? payload.detail : JSON.stringify(payload.detail ?? payload); } catch { /* keep status */ } throw new Error(detail); }
  return response.json() as Promise<ProjectImportResult>;
}

async function requestWithTimeout<T>(path: string, init: RequestInit, timeoutMs: number): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try { return await request<T>(path, { ...init, signal: controller.signal }); }
  catch (error) { if (controller.signal.aborted) throw new Error(`扫描超过 ${Math.round(timeoutMs / 1000)} 秒客户端等待上限；服务端会保存已经完成的有界结果`); throw error; }
  finally { window.clearTimeout(timeout); }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> { const method = String(init.method ?? "GET").toUpperCase(); const response = await fetch(`${API_BASE}${path}`, { ...init, cache: method === "GET" ? "no-store" : init.cache, headers: { "Content-Type": "application/json", ...(init.headers ?? {}) } }); if (!response.ok) { let detail = `${response.status} ${response.statusText}`; try { const payload = await response.json(); detail = typeof payload.detail === "string" ? payload.detail : payload.detail?.message ? String(payload.detail.message) : JSON.stringify(payload.detail ?? payload); } catch { /* keep HTTP status */ } throw new Error(detail); } if (response.status === 204) return undefined as T; return response.json() as Promise<T>; }

ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><Root /></React.StrictMode>);












