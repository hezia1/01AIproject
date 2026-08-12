import React, { useEffect, useMemo, useState } from "react";
import ReactDOM from "react-dom/client";
import { Activity, ArrowRight, BookOpen, Boxes, Bug, Check, FlaskConical, FolderKanban, GitBranch, Lock, Network, Play, Plus, ShieldCheck, SlidersHorizontal } from "lucide-react";
import "./styles.css";

type ViewKey = "projects" | "assets" | "detection" | "governance" | "knowledge" | "modules" | "sca" | "sast" | "agent" | "dast" | "sandbox" | "tasks" | "aspm";
type ModuleKey = "sast" | "sca" | "agent" | "dast" | "sandbox" | "aspm";
type ExecutableModuleKey = Exclude<ModuleKey, "aspm">;
type ModuleLoadingState = Record<ExecutableModuleKey, boolean>;
type Severity = "critical" | "high" | "medium" | "low" | "info";
type FindingStatus = "open" | "pending" | "confirmed" | "fixing" | "fixed" | "accepted_risk" | "false_positive" | "retest" | "closed";

type SecurityModule = { key: ModuleKey; code: string; name: string; subtitle: string; category: string; description: string; capabilities: { title: string; description: string }[]; dependencies: ModuleKey[]; default_config: Record<string, unknown> };
type Project = { id: string; name: string; business_owner: string | null; security_owner: string | null; repository_url: string | null; source_path: string | null; runtime_url: string | null; api_base_url: string | null; sandbox_command: string | null; sandbox_image: string | null; default_branch: string; risk_score: number; created_at: string };
type ProjectDraft = { name: string; business_owner: string; security_owner: string; repository_url: string; source_path: string; runtime_url: string; api_base_url: string; sandbox_command: string; sandbox_image: string; default_branch: string };
type ProjectAssetDraft = Pick<ProjectDraft, "runtime_url" | "api_base_url" | "sandbox_command" | "sandbox_image">;
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
type DastValidation = { id: string; finding_id?: string | null; component_id?: string | null; link_source: string; link_confidence: number; target_url: string; verdict: string; validator: string | null; strategy_id: string; strategy_name?: string | null; scope_summary?: string | null; limitations?: string | null; evidence_summary: string | null; request_summary?: string | null; response_summary?: string | null; reproduction_steps?: string | null; remediation_hint?: string | null; created_at: string };
type SandboxExecutionPlan = { strategyName: string; purpose: string; limitations: string };
type SandboxEvidence = { id: string; finding_id?: string | null; component_id?: string | null; validation_id?: string | null; link_source: string; link_confidence: number; run_command: string; runtime_profile: string | null; network_policy: string; filesystem_policy: string; observed_files: Record<string, unknown>[]; observed_network: Record<string, unknown>[]; observed_processes: Record<string, unknown>[]; observed_tool_calls: Record<string, unknown>[]; evidence_summary: string | null; operator: string | null; strategy_name?: string | null; purpose?: string | null; limitations?: string | null; created_at: string };
type SandboxTemplate = { name: string; command: string; command_type: string; image: string; risk_level: string; description: string };
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
type AgentScanCoverage = { discovered_asset_count: number; parsed_asset_count: number; failed_asset_count: number; skipped_file_count: number; findings_by_asset_type: Record<string, number>; asset_types: Record<string, number> };
type AgentQualityGate = { decision?: "pass" | "block"; exit_code?: number; reasons?: string[]; blocking_finding_count?: number; blocking_permission_count?: number; blocking_asset_count?: number; blocking_intelligence_count?: number; blocking_dataflow_count?: number; trust_score?: { score?: number; grade?: string; confidence?: string; trust_sha256?: string }; policy?: AgentGatePolicy };
type AgentGatePolicy = { enabled: boolean; threshold: "critical" | "high" | "medium" | "low" | "info" | "none"; block_new_only: boolean; max_blocking_findings: number; block_wildcard_permissions: boolean; block_parse_failures: boolean; block_skipped_files: boolean; block_permission_expansion: boolean; require_approval_for_high_risk: boolean; block_unpinned_sources: boolean; block_insecure_sources: boolean; block_unknown_sources: boolean; block_partial_integrity: boolean; block_integrity_changes: boolean; block_source_changes: boolean; block_known_vulnerabilities: boolean; block_malicious_packages: boolean; block_package_confusion: boolean; block_intelligence_gaps: boolean; block_stale_intelligence: boolean; max_intelligence_age_days: number; block_high_risk_dataflow_paths: boolean; block_low_trust_score: boolean; minimum_trust_score: number };
type AgentAllowlistItem = { id?: string; path_pattern: string; subject_pattern: string; capability: string; scope_pattern: string; reason: string };
type AgentException = { id: string; kind: "finding" | "permission"; disposition: "suppress" | "accept_risk"; rule_id?: string; path_pattern: string; subject_pattern?: string; capability?: string; scope_pattern?: string; reason: string; expires_at?: string | null; status: "pending" | "approved" | "rejected" | "revoked"; requester?: string | null; approver?: string | null; approval_note?: string | null; created_at?: string | null };
type AgentAuditItem = { id: string; action: string; actor: string; at: string; detail: Record<string, unknown> };
type AgentProfile = { profile_version: number; rule_version: string; disabled_rule_ids: string[]; excluded_paths: string[]; permission_allowlist: AgentAllowlistItem[]; required_approval_capabilities: string[]; target_runtime_execution_enabled: boolean; exceptions: AgentException[]; audit_log: AgentAuditItem[]; quality_gate: AgentGatePolicy };
type AgentScanHistoryItem = { scan_task_id: string; status: string; created_at: string; started_at: string | null; finished_at: string | null; source_path: string | null; finding_count: number; rule_version: string | null; coverage: AgentScanCoverage; gate_decision?: string | null };
type AgentPermission = { asset_path: string; subject: string; capability: string; access: string; resource_type: string; scope: string; approval: string; risk_level: string; source: string };
type AgentProvenance = { subject: string; package_name: string | null; package_version: string | null; source_type: string; source_ref: string | null; installation_method: string; version_status: string; publisher_claim: string | null; publisher_status: string; issues: string[] };
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
type AgentTargetEvidence = { schema: string; scope: string; status: string; decision: "pass" | "attention"; execution_id: string; started_at: string; finished_at: string; elapsed_ms: number; policy_verified: boolean; behavioral_telemetry_complete: boolean; evidence_sha256: string; evidence_path: string; image: { reference: string; digest: string; local_image_id: string; download_performed: boolean }; staging: { build_id: string; path: string; staging_sha256: string; manifest_sha256: string; unchanged_after_run: boolean }; container: { command_sha256: string; command_preview: string; exit_code: number | null; timed_out: boolean; removed_after_run: boolean }; policy_checks: Record<string, boolean>; telemetry_coverage: Record<string, string>; path_results: { dataflow_path_id: string; runtime_status: string; reason: string }[]; output: { stdout_char_count: number; stderr_char_count: number; stdout_sha256: string; stderr_sha256: string; truncated: boolean; redacted_before_hashing: boolean; content_stored: boolean }; limitations: string[]; trust_score?: AgentTrustScore };
type AgentScanSnapshot = { project_id: string; scan_task_id: string; created_at: string; source_path: string | null; rule_version: string | null; assets: AgentAsset[]; permissions: AgentPermission[]; skipped_files: { path: string; reason: string }[]; quality_gate?: AgentQualityGate; intelligence?: AgentIntelligence; dataflow?: AgentDataflow; runtime_validation?: AgentRuntimePlan; trust_score?: AgentTrustScore };
type AgentAssetDiffItem = { identity: string; change_type: "added" | "removed" | "changed"; path: string; asset_type: string; changes: string[] };
type AgentPermissionDiffItem = { identity: string; change_type: "added" | "removed" | "changed"; direction: "expanded" | "reduced" | "changed"; permission: AgentPermission };
type AgentScanDiff = { project_id: string; target_scan_id: string; base_scan_id: string | null; has_comparison: boolean; summary: { assets_added: number; assets_removed: number; assets_changed: number; permissions_added: number; permissions_removed: number; permissions_changed: number; source_changes: number; integrity_changes: number }; assets: AgentAssetDiffItem[]; permissions: AgentPermissionDiffItem[] };
type ScaGovernanceComponent = { ecosystem: string; name: string; version: string | null; risk_status: string; severity: Severity | null; vulnerability_count: number; license_risk: string | null; risk_source: string | null; remediation: string | null };
type ScaGovernanceSummary = { latest_scan_id: string | null; latest_scan_status: string | null; latest_scan_finished_at: string | null; component_count: number; risky_component_count: number; vulnerable_component_count: number; critical_high_component_count: number; total_finding_count: number; latest_scan_finding_count: number; vulnerability_finding_count: number; license_finding_count: number; version_review_finding_count: number; tool_status: ScaToolStatus | null; top_components: ScaGovernanceComponent[] };
type AspmSummary = { project_id: string; project_name: string; enabled_modules: ModuleKey[]; risk_score: number; component_count: number; finding_count: number; dast_validation_count: number; sandbox_evidence_count: number; scan_task_count: number; findings_by_source: Record<string, number>; findings_by_severity: Record<string, number>; findings_by_status: Record<string, number>; dast_by_verdict: Record<string, number>; sca_governance: ScaGovernanceSummary; attack_chains: AttackChain[] };
type SecurityReport = { generated_at: string; project: Project; summary: AspmSummary; components: Component[]; findings: Finding[]; validations: DastValidation[]; sandbox_evidence: SandboxEvidence[]; dependency_graph: DependencyGraph; evidence_graph: EvidenceGraph; retest_comparisons: Record<string, FindingRetestComparison>; capability_boundaries: Record<string, string[]> };
type ReportRow = { id: string; title: string; subtitle: string; summary: string; details: [string, string][] };

const API_BASE = "http://127.0.0.1:8000/api";
const DEFAULT_ENABLED_MODULES: ModuleKey[] = ["sast", "sca", "aspm"];
const OPTIONAL_MODULES: ModuleKey[] = ["sast", "sca", "agent", "dast", "sandbox"];
const EMPTY_MODULE_LOADING: ModuleLoadingState = { sca: false, sast: false, agent: false, dast: false, sandbox: false };
const DEFAULT_SOURCE_PATH = "D:\\project\\PYproject\\AI网安项目\\outputs\\sca-sample";
const DEFAULT_SAST_PATH = "D:\\project\\PYproject\\AI网安项目\\outputs\\sast-sample";
const DEFAULT_AGENT_PATH = "D:\\project\\PYproject\\AI网安项目\\outputs\\agent-sample";
const FINDING_WORKFLOW_STATUSES: FindingStatus[] = ["open", "confirmed", "fixing", "fixed", "accepted_risk", "false_positive"];

const fallbackModules: SecurityModule[] = [
  { key: "sast", code: "SAST", name: "智能静态审计", subtitle: "定制化安全 Skill + 多 Sub-agent 编排 + 行业历史漏洞知识库", category: "detection", description: "面向代码仓库执行智能静态审计，将规则扫描、AI 审计、历史漏洞经验和多 Agent 复核组合为代码风险发现能力。", capabilities: [{ title: "定制化安全 Skill", description: "按行业、框架和业务场景生成审计策略。" }, { title: "多 Sub-agent 编排", description: "发现、复核、证据和修复建议分工协同。" }, { title: "行业历史漏洞知识库", description: "沉淀通用漏洞、业务漏洞和误报经验。" }], dependencies: [], default_config: {} },
  { key: "sca", code: "SCA", name: "供应链风险分析", subtitle: "SBOM + 组件漏洞匹配 + 许可证风险归一化 + 依赖影响分析", category: "detection", description: "解析多语言工程依赖，生成 SBOM，识别漏洞、许可证和直接/传递依赖风险，并给出修复优先级。", capabilities: [{ title: "SBOM 生成", description: "生成项目组件清单和依赖来源。" }, { title: "组件漏洞匹配", description: "匹配 CVE、受影响版本和修复版本。" }, { title: "许可证风险归一化", description: "识别许可证类型并归一化风险等级。" }, { title: "依赖影响分析", description: "分析直接/传递依赖、版本归一化和修复影响。" }], dependencies: [], default_config: {} },
  { key: "agent", code: "AGENT", name: "Agent 供应链安全", subtitle: "统一资产模型 + 能力权限矩阵 + 语义差异", category: "detection", description: "结构化解析 Agent 指令、MCP、工具和插件配置，形成资产、能力、资源范围、审批边界和批次变化。", capabilities: [{ title: "多格式资产解析", description: "解析 Markdown Frontmatter、JSON、YAML 与 TOML。" }, { title: "能力权限矩阵", description: "归一化工具、文件、网络、命令、凭据和审批边界。" }, { title: "证据脱敏", description: "保存发现和快照前遮蔽凭据和值。" }, { title: "语义差异", description: "比较资产新增/移除、配置变化与权限扩大/收缩。" }], dependencies: [], default_config: {} },
  { key: "dast", code: "DAST", name: "漏洞动态验证", subtitle: "Web 业务验证 + 静态发现联动验证 + 三色裁决", category: "validation", description: "将静态发现、供应链风险和运行时目标联动验证，输出可利用、不确定、不可利用三态裁决和完整验证证据。", capabilities: [{ title: "Web 业务验证", description: "对目标 Web 应用执行业务化安全验证。" }, { title: "静态发现联动验证", description: "将 SAST/SCA/Agent 发现转为验证策略。" }, { title: "三色裁决", description: "输出可利用、不确定、不可利用的验证结论。" }, { title: "证据归档", description: "保留执行日志、请求响应、截图和验证过程。" }], dependencies: ["sast"], default_config: {} },
  { key: "sandbox", code: "SANDBOX", name: "沙箱动态证据链", subtitle: "隔离环境 + 行为监控 + 调用账本 + AI 驱动动态验证", category: "evidence", description: "在隔离环境中运行目标程序、插件或 Agent，采集文件、网络、进程、工具调用和运行时行为证据。", capabilities: [{ title: "隔离环境", description: "以容器或受控运行时隔离目标执行。" }, { title: "行为监控", description: "监控文件访问、网络连接、进程启动和环境变量读取。" }, { title: "调用账本", description: "结构化采集 Agent 工具调用和运行时覆盖。" }, { title: "策略化探测", description: "适配多类 Agent 运行时并支持 AI 驱动验证。" }], dependencies: ["agent"], default_config: {} },
  { key: "aspm", code: "ASPM", name: "平台治理与交付", subtitle: "项目组 + 攻击链 + 风险趋势 + 整改闭环 + 安全门禁", category: "governance", description: "聚合各模块结果，提供跨项目关联、攻击链、风险趋势、整改闭环、开放接口、流水线门禁和合规报告。", capabilities: [{ title: "风险治理", description: "管理项目组、跨项目关联、攻击链、风险趋势和整改闭环。" }, { title: "开放接口", description: "提供开放工具接口、批量任务和研发流水线安全门禁。" }, { title: "权限与配额", description: "管理模块权限、授权配额和审计日志。" }, { title: "交付报告", description: "输出诊断导出、合规报告和治理看板。" }], dependencies: [], default_config: {} },
];

const moduleIcons: Record<ModuleKey, React.ReactNode> = { sast: <Bug size={20} />, sca: <Boxes size={20} />, agent: <Network size={20} />, dast: <Activity size={20} />, sandbox: <FlaskConical size={20} />, aspm: <ShieldCheck size={20} /> };

function Root() {
  return <App />;
}

function App() {
  const [activeView, setActiveView] = useState<ViewKey>("detection");
  const [modules, setModules] = useState<SecurityModule[]>(fallbackModules);
  const [projects, setProjects] = useState<Project[]>([]);
  const [project, setProject] = useState<Project | null>(null);
  const emptyProjectDraft: ProjectDraft = { name: "", business_owner: "", security_owner: "", repository_url: "", source_path: "", runtime_url: "", api_base_url: "", sandbox_command: "", sandbox_image: "", default_branch: "main" };
  const [projectDraft, setProjectDraft] = useState<ProjectDraft>(emptyProjectDraft);
  const [assetProbe, setAssetProbe] = useState<ProjectAssetProbe | null>(null);
  const [enabledModules, setEnabledModules] = useState<Set<ModuleKey>>(() => new Set(DEFAULT_ENABLED_MODULES));
  const [components, setComponents] = useState<Component[]>([]);
  const [scaScanHistory, setScaScanHistory] = useState<ScaScanHistoryItem[]>([]);
  const [agentScanHistory, setAgentScanHistory] = useState<AgentScanHistoryItem[]>([]);
  const [agentSnapshot, setAgentSnapshot] = useState<AgentScanSnapshot | null>(null);
  const [agentScanDiff, setAgentScanDiff] = useState<AgentScanDiff | null>(null);
  const [selectedScaScanId, setSelectedScaScanId] = useState<string | null>(null);
  const [scaScanDiff, setScaScanDiff] = useState<ScaScanDiff | null>(null);
  const [dependencyGraph, setDependencyGraph] = useState<DependencyGraph | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [validations, setValidations] = useState<DastValidation[]>([]);
  const [dastStrategies, setDastStrategies] = useState<DastStrategy[]>([]);
  const [dastStrategyId, setDastStrategyId] = useState("web-baseline");
  const [evidence, setEvidence] = useState<SandboxEvidence[]>([]);
  const [sandboxTemplates, setSandboxTemplates] = useState<SandboxTemplate[]>([]);
  const [summary, setSummary] = useState<AspmSummary | null>(null);
  const [evidenceGraph, setEvidenceGraph] = useState<EvidenceGraph | null>(null);
  const [sourcePath, setSourcePath] = useState(DEFAULT_SOURCE_PATH);
  const [scaToolScanEnabled, setScaToolScanEnabled] = useState(true);
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
          console.error(error);
          if (activeView === "dast") setDastLinkSuggestions([]);
          else setSandboxLinkSuggestions([]);
        });
    }, 350);
    return () => window.clearTimeout(timer);
  }, [activeView, project?.id, targetUrl, runCommand]);

  useEffect(() => {
    if (!project || !enabledModules.has("dast")) { setDastStrategies([]); return; }
    const findingQuery = correlationFindingId ? `?finding_id=${correlationFindingId}` : "";
    void request<DastStrategy[]>(`/dast/projects/${project.id}/strategies${findingQuery}`)
      .then((items) => {
        setDastStrategies(items);
        if (items.length && !items.some((item) => item.id === dastStrategyId)) setDastStrategyId(items[0].id);
      })
      .catch(() => setDastStrategies([]));
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
        clearProjectData();
        setProject(null);
        setStatus("API 已连接，请先创建项目");
        return;
      }
      const nextProject = projectData.find((item) => item.id === project?.id) ?? projectData[0];
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
    setSelectedScaScanId(null);
    setScaScanDiff(null);
    setDependencyGraph(null);
    setFindings([]);
    setValidations([]);
    setDastStrategies([]);
    setDastStrategyId("web-baseline");
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
  }

  async function selectProject(nextProject: Project, knownProjects = projects) {
    setLoading(true);
    try {
      setCorrelationFindingId("");
      setCorrelationComponentId("");
      setCorrelationValidationId("");
      setCorrelationLinkSource("unlinked");
      setCorrelationLinkConfidence(0);
      setDastLinkSuggestions([]);
      setSandboxLinkSuggestions([]);
      setProject(nextProject);
      setProjects(knownProjects.length ? knownProjects : await request<Project[]>("/projects"));
      if (nextProject.source_path) {
        setSourcePath(nextProject.source_path);
        setSastPath(nextProject.source_path);
        setAgentPath(nextProject.source_path);
      }
      if (nextProject.runtime_url || nextProject.api_base_url) {
        setTargetUrl(nextProject.runtime_url ?? nextProject.api_base_url ?? "");
      }
      if (nextProject.sandbox_command) setRunCommand(nextProject.sandbox_command);
      if (nextProject.sandbox_image) setSandboxImage(nextProject.sandbox_image);
      await refreshProjectContext(nextProject.id);
      setStatus(`已切换到项目：${nextProject.name}`);
    } catch (error) {
      console.error(error);
      setStatus("项目切换失败");
    } finally {
      setLoading(false);
    }
  }

  async function refreshProjectContext(projectId = project?.id, scaScanId: string | null = selectedScaScanId) {
    if (!projectId) return;
    const [projectModules, probeData] = await Promise.all([
      request<ProjectModule[]>(`/modules/projects/${projectId}`),
      request<ProjectAssetProbe>(`/projects/${projectId}/asset-probe`),
    ]);
    if (!projectModules.some((item) => item.module_key === "aspm" && item.enabled)) {
      await enableProjectModule(projectId, "aspm", true);
    }
    setEnabledModules(new Set([...projectModules.filter((item) => item.enabled).map((item) => item.module_key), "aspm"]));
    setAssetProbe(probeData);
    await refreshProjectData(projectId, scaScanId);
  }

  async function refreshProjectData(projectId = project?.id, scaScanId: string | null = selectedScaScanId) {
    if (!projectId) return;
    const [historyData, agentHistoryData, agentSnapshotData, agentDiffData] = await Promise.all([
      request<ScaScanHistoryItem[]>(`/sca/projects/${projectId}/scan-history`).catch(() => []),
      request<AgentScanHistoryItem[]>(`/agent/projects/${projectId}/scan-history`).catch(() => []),
      request<AgentScanSnapshot>(`/agent/projects/${projectId}/snapshot`).catch(() => null),
      request<AgentScanDiff>(`/agent/projects/${projectId}/scan-diff`).catch(() => null),
    ]);
    const effectiveScaScanId = scaScanId ?? historyData[0]?.scan_task_id ?? null;
    const scaQuery = effectiveScaScanId ? `?scan_task_id=${effectiveScaScanId}` : "";
    const diffQuery = effectiveScaScanId ? `?target_scan_id=${effectiveScaScanId}` : "";
    const [componentData, graphData, diffData, findingData, validationData, evidenceData, templateData, summaryData, evidenceGraphData] = await Promise.all([
      request<Component[]>(`/sca/projects/${projectId}/components${scaQuery}`),
      request<DependencyGraph>(`/sca/projects/${projectId}/dependency-graph${scaQuery}`).catch(() => null),
      request<ScaScanDiff>(`/sca/projects/${projectId}/scan-diff${diffQuery}`).catch(() => null),
      request<Finding[]>(`/findings?project_id=${projectId}`),
      request<DastValidation[]>(`/dast/projects/${projectId}/validations`),
      request<SandboxEvidence[]>(`/sandbox/projects/${projectId}/evidence`),
      request<SandboxTemplate[]>(`/sandbox/projects/${projectId}/templates`),
      request<AspmSummary>(`/aspm/projects/${projectId}/summary`),
      request<EvidenceGraph>(`/aspm/projects/${projectId}/evidence-graph`),
    ]);
    setScaScanHistory(historyData);
    setAgentScanHistory(agentHistoryData);
    setAgentSnapshot(agentSnapshotData);
    setAgentScanDiff(agentDiffData);
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
    const [scaRetest, sastRetest, agentRetest] = await Promise.all([
      request<FindingRetestComparison>(`/findings/projects/${projectId}/retest-comparison?source=SCA`).catch(() => null),
      request<FindingRetestComparison>(`/findings/projects/${projectId}/retest-comparison?source=SAST`).catch(() => null),
      request<FindingRetestComparison>(`/findings/projects/${projectId}/retest-comparison?source=AGENT`).catch(() => null),
    ]);
    setRetestComparisons({ sca: scaRetest, sast: sastRetest, agent: agentRetest });
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
    setLoading(true);
    try {
      const created = await request<Project>("/projects", {
        method: "POST",
        body: JSON.stringify({
          name: projectDraft.name.trim(),
          business_owner: emptyToNull(projectDraft.business_owner),
          security_owner: emptyToNull(projectDraft.security_owner),
          repository_url: emptyToNull(projectDraft.repository_url),
          source_path: emptyToNull(projectDraft.source_path),
          runtime_url: emptyToNull(projectDraft.runtime_url),
          api_base_url: emptyToNull(projectDraft.api_base_url),
          sandbox_command: emptyToNull(projectDraft.sandbox_command),
          sandbox_image: emptyToNull(projectDraft.sandbox_image),
          default_branch: projectDraft.default_branch.trim() || "main",
        }),
      });
      await Promise.all(DEFAULT_ENABLED_MODULES.map((moduleKey) => enableProjectModule(created.id, moduleKey, true)));
      const projectData = await request<Project[]>("/projects");
      setProjectDraft(emptyProjectDraft);
      await selectProject(created, projectData);
      setStatus(`项目已创建，并默认启用 ${DEFAULT_ENABLED_MODULES.map((item) => item.toUpperCase()).join(" + ")}`);
    } catch (error) {
      console.error(error);
      setStatus("项目创建失败");
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
      const result = await request<ScaScanResult | unknown>(`/${moduleKey}/scan`, {
        method: "POST",
        body: JSON.stringify({
          project_id: project.id,
          source_path: configuredSource,
          ...(moduleKey === "sast" ? {} : moduleKey === "sca" ? { clear_previous: false, enable_tool_scan: scaToolScanEnabled } : { clear_previous: true }),
        }),
      });
      return {
        status: "completed",
        detail: moduleKey === "agent" ? "扫描完成，批次结果与覆盖信息已保存" : "扫描完成，已更新批次对比",
        scanId: moduleKey === "sca" ? (result as ScaScanResult).scan_task_id : selectedScaScanId,
      };
    }
    if (moduleKey === "dast") {
      if (!targetUrl.trim()) return { status: "skipped", detail: "未配置目标地址" };
      const suggestions = await request<LinkSuggestion[]>("/dast/link-suggestions", {
        method: "POST",
        body: JSON.stringify({ project_id: project.id, target_url: targetUrl }),
      }).catch(() => []);
      const recommendation = suggestions[0]?.confidence >= 80 ? suggestions[0] : null;
      await request("/dast/probe", {
        method: "POST",
        body: JSON.stringify({
          project_id: project.id,
          target_url: targetUrl,
          validator: "module-retest-dast",
          finding_id: recommendation?.finding_id ?? null,
          component_id: recommendation?.component_id ?? null,
          link_source: recommendation ? `${recommendation.source}-confirmed` : "unlinked",
          link_confidence: recommendation?.confidence ?? 0,
        }),
      });
      return { status: "completed", detail: "动态验证完成，已保留新的验证记录" };
    }
    if (!runCommand.trim()) return { status: "skipped", detail: "未配置沙箱命令" };
    const suggestions = await request<LinkSuggestion[]>("/sandbox/link-suggestions", {
      method: "POST",
      body: JSON.stringify({ project_id: project.id, run_command: runCommand }),
    }).catch(() => []);
    const recommendation = suggestions[0]?.confidence >= 80 ? suggestions[0] : null;
    await request("/sandbox/run", {
      method: "POST",
      body: JSON.stringify({
        project_id: project.id,
        run_command: runCommand,
        image: emptyToNull(sandboxImage),
        timeout_seconds: 10,
        operator: "module-retest-runner",
        finding_id: recommendation?.finding_id ?? null,
        component_id: recommendation?.component_id ?? null,
        validation_id: recommendation?.validation_id ?? null,
        link_source: recommendation ? `${recommendation.source}-confirmed` : "unlinked",
        link_confidence: recommendation?.confidence ?? 0,
      }),
    });
    return { status: "completed", detail: "沙箱执行完成，已保留新的运行证据" };
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

  async function runScan(kind: "sca" | "sast" | "agent") {
    if (!project) return setStatus("API 未连接，无法执行任务");
    const source = kind === "sca" ? sourcePath : kind === "sast" ? sastPath : agentPath;
    if (loading || unifiedLoadingRef.current || moduleLoadingRef.current[kind]) return setStatus(`${kind.toUpperCase()} 已有任务正在执行`);
    setModuleBusy(kind, true);
    try {
      const result = await request<ScaScanResult | unknown>(`/${kind}/scan`, { method: "POST", body: JSON.stringify({ project_id: project.id, source_path: source, ...(kind === "sast" ? {} : kind === "sca" ? { clear_previous: false, enable_tool_scan: scaToolScanEnabled } : { clear_previous: true }) }) });
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
        const result = await request<ScaScanResult | unknown>(`/${kind}/scan`, { method: "POST", body: JSON.stringify({ project_id: project.id, source_path: project.source_path ?? sourcePath, ...(kind === "sast" ? {} : kind === "sca" ? { clear_previous: false, enable_tool_scan: scaToolScanEnabled } : { clear_previous: true }) }) });
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
      }) });
      await refreshSingleModuleData("dast", project.id);
      setStatus("DAST 自动验证已完成");
    } catch (error) { console.error(error); setStatus("DAST 记录创建失败，请确认模块已启用"); } finally { setModuleBusy("dast", false); }
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
    setCorrelationLinkSource(`${suggestion.source}-confirmed`);
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
        {activeView === "projects" && <ProjectWorkspace projects={projects} project={project} draft={projectDraft} loading={projectControlsLoading} onDraftChange={setProjectDraft} onCreate={createProject} onSelect={(nextProject) => void selectProject(nextProject)} onDelete={deleteProject} />}
        {activeView === "assets" && <><ProjectAssetConfig project={project} loading={projectControlsLoading} onSave={updateProjectAssets} /><ProjectAssets project={project} assetProbe={assetProbe} enabledModules={enabledModules} components={components} findings={findings} validations={validations} evidence={evidence} summary={summary} onOpenTasks={() => setActiveView("detection")} onOpenModules={() => setActiveView("detection")} /></>}
        {activeView === "detection" && <SecurityDetectionCenter modules={optionalModules} project={project} enabledModules={enabledModules} savingKey={savingKey} loading={loading || unifiedLoading} runBlocked={anyModuleLoading} moduleLoading={moduleLoading} executionSteps={executionSteps} sourcePath={sourcePath} targetUrl={targetUrl} runCommand={runCommand} sandboxImage={sandboxImage} onToggle={toggleModule} onEnableRelated={enableRelatedModules} onSourcePathChange={(value) => { setSourcePath(value); setSastPath(value); setAgentPath(value); }} onTargetUrlChange={setTargetUrl} onRunCommandChange={setRunCommand} onSandboxImageChange={setSandboxImage} onRun={runUnifiedSecurityCheck} />}
    {activeView === "governance" && <GovernanceCenter project={project} enabledModules={enabledModules} summary={summary} components={components} findings={findings} validations={validations} evidence={evidence} graph={evidenceGraph} retestComparisons={retestComparisons} scaScanHistory={scaScanHistory} agentScanHistory={agentScanHistory} agentSnapshot={agentSnapshot} agentScanDiff={agentScanDiff} selectedScaScanId={selectedScaScanId} scaScanDiff={scaScanDiff} dependencyGraph={dependencyGraph} scaToolScanEnabled={scaToolScanEnabled} sandboxTemplates={sandboxTemplates} dastStrategies={dastStrategies} dastStrategyId={dastStrategyId} loading={loading} unifiedLoading={unifiedLoading} moduleLoading={moduleLoading} targetUrl={targetUrl} runCommand={runCommand} sandboxImage={sandboxImage} selectedFindingId={correlationFindingId} selectedValidationId={correlationValidationId} onTargetUrlChange={setTargetUrl} onRunCommandChange={setRunCommand} onSandboxImageChange={setSandboxImage} onDastStrategyChange={setDastStrategyId} onScaToolScanChange={setScaToolScanEnabled} onSelectScaScan={selectScaScanSnapshot} onExportScaSbom={exportScaSbom} onExportScaReport={exportScaReport} onRunSastAgentReview={runSastAgentReview} onSelectDastRisk={selectDastRisk} onSelectSandboxRisk={selectSandboxRisk} onSelectSandboxValidation={selectSandboxValidation} onRunDast={createDastValidation} onRunSandbox={createSandboxEvidence} onRunModule={runSingleModuleCheck} onUpdateFinding={updateFindingGovernance} />}
        {activeView === "knowledge" && <KnowledgeHubView project={project} findings={findings} validations={validations} evidence={evidence} summary={summary} />}
      </section>
    </main>
  );
}

function NavButton({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) { return <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}>{icon}{label}</button>; }
function viewEyebrow(view: ViewKey) { return view === "projects" ? "项目空间" : view === "assets" ? "项目资产画像" : view === "detection" ? "模块接入与统一执行" : view === "knowledge" ? "可学习、可传递、可治理" : "项目安全治理"; }
function viewTitle(view: ViewKey) { return view === "projects" ? "创建项目并切换当前项目" : view === "assets" ? "确认待检测的项目资产" : view === "detection" ? "选择安全模块并一键执行检测" : view === "knowledge" ? "安全知识中枢" : "从风险发现到修复复测的完整闭环"; }

function ProjectWorkspace({ projects, project, draft, loading, onDraftChange, onCreate, onSelect, onDelete }: { projects: Project[]; project: Project | null; draft: ProjectDraft; loading: boolean; onDraftChange: (draft: ProjectDraft) => void; onCreate: (event: React.FormEvent<HTMLFormElement>) => Promise<void>; onSelect: (project: Project) => void; onDelete: (projectId: string) => Promise<void> }) {
  return <section className="project-workspace"><div className="panel project-create"><div className="panel-header"><h2>项目创建向导</h2><span>ASPM 默认内置，SCA + SAST 默认启用</span></div><form className="project-form" onSubmit={(event) => void onCreate(event)}><label>项目名称<input value={draft.name} onChange={(event) => onDraftChange({ ...draft, name: event.target.value })} placeholder="例如：政企门户应用" /></label><label>业务负责人<input value={draft.business_owner} onChange={(event) => onDraftChange({ ...draft, business_owner: event.target.value })} placeholder="业务系统部" /></label><label>安全负责人<input value={draft.security_owner} onChange={(event) => onDraftChange({ ...draft, security_owner: event.target.value })} placeholder="应用安全组" /></label><label>代码仓库<input value={draft.repository_url} onChange={(event) => onDraftChange({ ...draft, repository_url: event.target.value })} placeholder="git.example.com/team/repo" /></label><label>本地源码路径<input value={draft.source_path} onChange={(event) => onDraftChange({ ...draft, source_path: event.target.value })} placeholder="D:\\project\\demo-repo" /></label><label>运行地址<input value={draft.runtime_url} onChange={(event) => onDraftChange({ ...draft, runtime_url: event.target.value })} placeholder="http://localhost:3000" /></label><label>API 地址<input value={draft.api_base_url} onChange={(event) => onDraftChange({ ...draft, api_base_url: event.target.value })} placeholder="http://localhost:3000/api" /></label><label>沙箱命令<input value={draft.sandbox_command} onChange={(event) => onDraftChange({ ...draft, sandbox_command: event.target.value })} placeholder="npm test" /></label><label>沙箱镜像<input value={draft.sandbox_image} onChange={(event) => onDraftChange({ ...draft, sandbox_image: event.target.value })} placeholder="node:20-alpine" /></label><label>默认分支<input value={draft.default_branch} onChange={(event) => onDraftChange({ ...draft, default_branch: event.target.value })} placeholder="main" /></label><button className="primary-action" disabled={loading || !draft.name.trim()}><Plus size={16} />创建项目</button></form></div><div className="panel project-directory"><div className="panel-header"><h2>项目列表</h2><span>{projects.length} 个项目</span></div><div className="project-list">{projects.length === 0 ? <div className="empty-project">暂无项目。创建项目后，安全检测配置和治理结果会按项目隔离。</div> : projects.map((item) => <div className={`project-row ${project?.id === item.id ? "active" : ""}`} key={item.id}><button className="project-main" onClick={() => onSelect(item)} disabled={loading}><div><strong>{item.name}</strong><span>{item.repository_url ?? "未配置仓库"} · {item.default_branch}</span><span>{item.source_path ?? "未配置本地源码路径"}</span></div><span>{item.business_owner ?? "未配置业务负责人"}</span><span>{item.security_owner ?? "未配置安全负责人"}</span></button><button className="danger-action" disabled={loading} onClick={() => void onDelete(item.id)}>删除</button></div>)}</div></div><div className="panel current-project"><div className="panel-header"><h2>当前项目</h2><span>{project ? "已选择" : "未选择"}</span></div>{project ? <div className="project-detail"><strong>{project.name}</strong><span>业务：{project.business_owner ?? "未配置"}</span><span>安全：{project.security_owner ?? "未配置"}</span><span>仓库：{project.repository_url ?? "未配置"}</span><span>源码路径：{project.source_path ?? "未配置"}</span><span>运行地址：{project.runtime_url ?? "未配置"}</span><span>API 地址：{project.api_base_url ?? "未配置"}</span><span>沙箱命令：{project.sandbox_command ?? "未配置"}</span><span>沙箱镜像：{project.sandbox_image ?? "未配置"}</span><span>分支：{project.default_branch}</span></div> : <div className="empty-project">请先创建或选择一个项目。</div>}</div></section>;
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

  return <section className="panel full asset-config"><div className="panel-header"><h2>项目资产配置</h2><span>{project ? "影响 DAST 与 SANDBOX 默认参数" : "请先选择项目"}</span></div><div className="asset-config-grid"><label>运行地址<input value={draft.runtime_url} onChange={(event) => setDraft({ ...draft, runtime_url: event.target.value })} placeholder="http://localhost:3000" disabled={!project || loading} /></label><label>API 地址<input value={draft.api_base_url} onChange={(event) => setDraft({ ...draft, api_base_url: event.target.value })} placeholder="http://localhost:3000/api" disabled={!project || loading} /></label><label>沙箱命令<input value={draft.sandbox_command} onChange={(event) => setDraft({ ...draft, sandbox_command: event.target.value })} placeholder="npm test" disabled={!project || loading} /></label><label>沙箱镜像<input value={draft.sandbox_image} onChange={(event) => setDraft({ ...draft, sandbox_image: event.target.value })} placeholder="node:20-alpine" disabled={!project || loading} /></label></div><div className="asset-config-actions"><button className="primary-action" disabled={!project || loading} onClick={() => void onSave(draft)}>保存资产配置</button></div></section>;
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
  dast: { name: "DAST 动态验证", purpose: "访问运行中的系统，验证风险是否能够触发" },
  sandbox: { name: "SANDBOX 沙箱证据", purpose: "隔离运行程序并采集进程、输出和策略证据" },
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
  sourcePath,
  targetUrl,
  runCommand,
  sandboxImage,
  onToggle,
  onEnableRelated,
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
  sourcePath: string;
  targetUrl: string;
  runCommand: string;
  sandboxImage: string;
  onToggle: (module: SecurityModule) => Promise<void>;
  onEnableRelated: (moduleKeys: ModuleKey[]) => Promise<void>;
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
      relationNotices.push({ text: "SANDBOX 可以独立运行，但与 AGENT 或 DAST 组合后更容易形成可追溯证据。", action: "同时接入 AGENT", modules: ["agent"] });
    } else {
      relationNotices.push({ text: "SANDBOX 将在其他检测完成后执行，为相关风险补充隔离运行证据。" });
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
        {enabledModules.has("sandbox") ? <><label><span>沙箱运行命令</span><input value={runCommand} onChange={(event) => onRunCommandChange(event.target.value)} placeholder="例如：python app.py" /></label><label><span>沙箱镜像</span><input value={sandboxImage} onChange={(event) => onSandboxImageChange(event.target.value)} placeholder="例如：python:3.12-slim" /></label></> : null}
      </div>}
    </section>

    <section className="panel detection-run-panel">
      <div className="detection-run-copy"><h2>一键执行安全检测</h2><p>系统按照 SCA → SAST → AGENT → DAST → SANDBOX 的顺序执行已接入模块，单个模块失败不会阻断后续检查。</p></div>
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
  selectedScaScanId,
  scaScanDiff,
  dependencyGraph,
  scaToolScanEnabled,
  sandboxTemplates,
  dastStrategies,
  dastStrategyId,
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
  onScaToolScanChange,
  onSelectScaScan,
  onExportScaSbom,
  onExportScaReport,
  onRunSastAgentReview,
  onSelectDastRisk,
  onSelectSandboxRisk,
  onSelectSandboxValidation,
  onRunDast,
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
  selectedScaScanId: string | null;
  scaScanDiff: ScaScanDiff | null;
  dependencyGraph: DependencyGraph | null;
  scaToolScanEnabled: boolean;
  sandboxTemplates: SandboxTemplate[];
  dastStrategies: DastStrategy[];
  dastStrategyId: string;
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
  onScaToolScanChange: (enabled: boolean) => void;
  onSelectScaScan: (scanTaskId: string) => Promise<void>;
  onExportScaSbom: (format: "cyclonedx" | "spdx") => Promise<void>;
  onExportScaReport: () => Promise<void>;
  onRunSastAgentReview: () => Promise<void>;
  onSelectDastRisk: (findingId: string) => void;
  onSelectSandboxRisk: (findingId: string) => void;
  onSelectSandboxValidation: (validationId: string) => void;
  onRunDast: () => Promise<void>;
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
    {scope === "agent" ? <FindingModuleGovernance project={project} moduleKey="agent" findings={findings.filter((item) => item.source === "AGENT")} validations={validations} evidence={evidence} graph={graph} comparison={retestComparisons.agent} scanHistory={agentScanHistory} agentSnapshot={agentSnapshot} agentScanDiff={agentScanDiff} loading={scopeLoading("agent")} onRun={() => onRunModule("agent")} onUpdateFinding={onUpdateFinding} /> : null}
    {scope === "dast" ? <DastGovernanceView findings={findings} validations={validations} strategies={dastStrategies} strategyId={dastStrategyId} targetUrl={targetUrl} selectedFindingId={selectedFindingId} loading={scopeLoading("dast")} onTargetUrlChange={onTargetUrlChange} onStrategyChange={onDastStrategyChange} onSelectRisk={onSelectDastRisk} onRun={onRunDast} /> : null}
    {scope === "sandbox" ? <SandboxGovernanceView findings={findings} validations={validations} evidence={evidence} graph={graph} templates={sandboxTemplates} runCommand={runCommand} sandboxImage={sandboxImage} selectedFindingId={selectedFindingId} selectedValidationId={selectedValidationId} loading={scopeLoading("sandbox")} onRunCommandChange={onRunCommandChange} onSandboxImageChange={onSandboxImageChange} onSelectRisk={onSelectSandboxRisk} onSelectValidation={onSelectSandboxValidation} onRun={onRunSandbox} /> : null}
  </section>;
}

function SastGovernanceWorkspace({ project, findings, validations, evidence, graph, comparison, loading, onRunReview, onRun, onUpdateFinding }: { project: Project; findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; graph: EvidenceGraph | null; comparison: FindingRetestComparison | null; loading: boolean; onRunReview: () => Promise<void>; onRun: () => Promise<void>; onUpdateFinding: (findingId: string, patch: Partial<Pick<Finding, "status">>) => Promise<void> }) {
  return <section className="sast-governance-workspace">
    <section className="panel full"><div className="panel-header"><div><h2>SAST 日常检测</h2><span>日常只需关注引擎状态、风险列表和 DeepSeek 审计</span></div></div><p>点击“重新扫描并复测”即可执行完整 SAST。下方高级管理仅用于 Git 增量、规则开发、CI/Worker、豁免和报告导出，不配置也不会影响基础扫描。</p></section>
    <SastDailyEngineStatus project={project} />
    <FindingModuleGovernance moduleKey="sast" findings={findings} validations={validations} evidence={evidence} graph={graph} comparison={comparison} loading={loading} onRunReview={onRunReview} onRun={onRun} onUpdateFinding={onUpdateFinding} />
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
  return <details className="advanced-details governance-advanced-details" open><summary>DeepSeek 真实多 Agent 深度审计</summary><div className="advanced-details-body"><section className="content-grid">
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
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState("");
  const rules = uniqueValues(findings.map((item) => item.rule_id));
  const categories = uniqueValues(findings.map((item) => item.ai_review?.category ?? "未分类"));
  const falsePositiveCount = findings.filter((item) => item.status === "false_positive").length;
  const fixedCount = findings.filter((item) => item.status === "fixed" || item.status === "closed").length;
  const linkedValidationCount = validations.filter((item) => item.finding_id || item.component_id).length;
  const linkedEvidenceCount = evidence.filter((item) => item.finding_id || item.component_id || item.validation_id).length;
  const knowledgeStages = [
    ["业务上下文", project.name, `仓库、源码、运行地址和负责人共同限定扫描范围`],
    ["规则与 Skill", `${rules.length} 条规则`, `${categories.length} 类风险知识用于发现与复核`],
    ["动态验证经验", `${linkedValidationCount} 条`, `保存目标、请求响应、三色裁决和复现过程`],
    ["运行时证据", `${linkedEvidenceCount} 份`, `保存隔离策略、进程、文件、网络和工具调用账本`],
    ["治理经验", `${fixedCount + falsePositiveCount} 条`, `修复结论与误报判断形成后续可复用上下文`],
  ] as const;
  const [knowledgePage, setKnowledgePage] = useState(1);
  const knowledgeItems = [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const knowledgePagination = paginate(knowledgeItems, knowledgePage);
  useEffect(() => { setKnowledgePage(1); }, [findings]);
  async function generateReportPreview() {
    setReportLoading(true);
    setReportError("");
    try {
      setReport(await request<SecurityReport>(`/aspm/projects/${projectId}/report`));
    } catch (error) {
      console.error(error);
      setReportError(`报告生成失败：${errorMessage(error)}`);
    } finally {
      setReportLoading(false);
    }
  }
  return <section className="knowledge-hub">
    <section className="knowledge-hero panel">
      <div><span className="section-kicker">安全知识中枢</span><h2>让检测结果变成企业可以复用的安全经验</h2><p>当前版本先把项目上下文、规则命中、动态证据、修复和误报结论组织在一起；后续再将这些经验反馈给规则和安全 Skill。</p></div>
      <div className="knowledge-core"><BookOpen size={30} /><strong>{project.name}</strong><span>项目安全上下文</span></div>
    </section>
    <section className="knowledge-flow panel">
      <div className="panel-header"><h2>知识如何形成</h2><span>上下文更专 → 多源发现 → 动态证明 → 知识组织</span></div>
      <div className="knowledge-stage-grid">{knowledgeStages.map(([label, value, description], index) => <React.Fragment key={label}><article><span>0{index + 1}</span><h3>{label}</h3><strong>{value}</strong><p>{description}</p></article>{index < knowledgeStages.length - 1 ? <ArrowRight size={18} /> : null}</React.Fragment>)}</div>
    </section>
    <section className="knowledge-metrics">
      <Metric label="规则经验" value={rules.length} />
      <Metric label="风险分类" value={categories.length} />
      <Metric label="动态验证" value={validations.length} />
      <Metric label="运行证据" value={evidence.length} />
      <Metric label="可信攻击链" value={summary?.attack_chains.length ?? 0} />
    </section>
    <section className="panel">
      <div className="panel-header"><h2>当前项目知识条目</h2><span>完整结果 · 每页 10 条</span></div>
      <table className="concise-table"><thead><tr><th>规则 / 分类</th><th>项目风险知识</th><th>验证与证据</th><th>治理结论</th></tr></thead><tbody>{knowledgeItems.length === 0 ? <tr><td colSpan={4} className="empty-cell">执行检测后，规则命中和复核结论会进入这里。</td></tr> : knowledgePagination.items.map((finding) => { const linkedValidations = validations.filter((item) => item.finding_id === finding.id); const validationIds = new Set(linkedValidations.map((item) => item.id)); const linkedEvidence = evidence.filter((item) => item.finding_id === finding.id || Boolean(item.validation_id && validationIds.has(item.validation_id))); return <tr key={finding.id}><td><strong>{finding.rule_id}</strong><span className="cell-subtext">{finding.source} · {finding.ai_review?.category ?? "未分类"}</span></td><td><span className={`severity ${finding.severity}`}>{severityLabel(finding.severity)}</span><strong>{finding.title}</strong><span className="cell-subtext">{truncateText(finding.ai_review?.description ?? finding.evidence ?? "暂无风险说明", 120)}</span></td><td>{linkedValidations.length ? `${linkedValidations.length} 次 DAST` : "未动态验证"}<span className="cell-subtext">{linkedEvidence.length ? `${linkedEvidence.length} 份 SANDBOX 证据` : "无运行时证据"}</span></td><td>{statusLabel(normalizeFindingStatus(finding.status))}<span className="cell-subtext">{finding.remediation_note ?? finding.ai_review?.remediation ?? "等待治理结论"}</span></td></tr>; })}</tbody></table><Pagination page={knowledgePagination.page} pageCount={knowledgePagination.pageCount} total={knowledgeItems.length} onPageChange={setKnowledgePage} />
    </section>
    <section className="panel report-delivery">
      <div className="panel-header"><div><span className="section-kicker">项目安全报告</span><h2>生成可交付的项目安全快照</h2></div><span>{report ? `生成于 ${formatDateTime(report.generated_at)}` : "报告不会改变现有数据"}</span></div>
      <p>报告汇总当前项目的已接入模块、风险、动态验证、运行时证据、可信关系、攻击链、复测结果和能力边界。先生成预览确认内容，再导出 JSON 或 HTML。</p>
      <div className="report-actions"><button className="primary-action" disabled={reportLoading} onClick={() => void generateReportPreview()}>{reportLoading ? "正在生成报告…" : report ? "刷新报告预览" : "生成报告预览"}</button><button className="secondary-action" disabled={!report} onClick={() => report && downloadSecurityReport(report, "json")}>导出 JSON</button><button className="secondary-action" disabled={!report} onClick={() => report && downloadSecurityReport(report, "html")}>导出 HTML</button></div>
      {reportError ? <div className="report-error">{reportError}</div> : null}
    </section>
    {report ? <SecurityReportPreview report={report} /> : null}
    <section className="knowledge-boundary"><strong>当前能力边界</strong><span>目前已完成知识组织和追溯视图；规则自动生成、跨项目知识推荐和基于反馈的自主演进仍属于后续能力，不会在界面中伪装成已实现。</span></section>
  </section>;
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
  return <details className="advanced-details governance-advanced-details" open><summary>AGENT 策略、例外审批、质量门禁与交付</summary><div className="advanced-details-body"><section className="content-grid">
    <div className="panel full"><div className="panel-header"><h2>项目扫描策略</h2><span>{message || `配置 v${profile.profile_version} · 规则 ${profile.rule_version}`}</span></div><p>保存后从下一次扫描生效；历史扫描与原始 Finding 不会被重写。操作人用于本项目策略审计，不等同于平台身份认证。</p><div className="filter-grid"><label>操作人<input value={actor} onChange={(event) => setActor(event.target.value)} /></label><label>停用规则 ID（每行一个）<textarea rows={4} value={profile.disabled_rule_ids.join("\n")} onChange={(event) => setProfile({ ...profile, disabled_rule_ids: splitLines(event.target.value) })} /></label><label>排除路径 glob（每行一个）<textarea rows={4} value={profile.excluded_paths.join("\n")} onChange={(event) => setProfile({ ...profile, excluded_paths: splitLines(event.target.value) })} placeholder="例如 fixtures/**" /></label><label>强制审批能力（每行一个）<textarea rows={4} value={profile.required_approval_capabilities.join("\n")} onChange={(event) => setProfile({ ...profile, required_approval_capabilities: splitLines(event.target.value) })} /></label><label className="inline-check"><input type="checkbox" checked={profile.target_runtime_execution_enabled} onChange={(event) => setProfile({ ...profile, target_runtime_execution_enabled: event.target.checked })} />允许本项目显示真实目标执行入口（默认关闭；仍需精确 staging、固定镜像和二次确认）</label><button className="primary-action" onClick={() => void saveProfile()}>保存项目策略</button></div></div>
    <div className="panel full">
      <div className="panel-header"><h2>质量门禁</h2><span className={`severity ${gate?.decision === "block" ? "high" : "info"}`}>{gate?.decision === "block" ? "阻断" : gate?.decision === "pass" ? "通过" : "等待扫描"}</span></div>
      <div className="filter-grid">
        <label>Finding 阈值<select value={policy.threshold} onChange={(event) => setProfile({ ...profile, quality_gate: { ...policy, threshold: event.target.value as AgentGatePolicy["threshold"] } })}>{["critical", "high", "medium", "low", "info", "none"].map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
        <label>最大阻断 Finding 数<input type="number" min={0} value={policy.max_blocking_findings} onChange={(event) => setProfile({ ...profile, quality_gate: { ...policy, max_blocking_findings: Math.max(0, Number(event.target.value)) } })} /></label>
        <label>情报最大年龄（天）<input type="number" min={1} max={3650} value={policy.max_intelligence_age_days} onChange={(event) => setProfile({ ...profile, quality_gate: { ...policy, max_intelligence_age_days: Math.max(1, Number(event.target.value)) } })} /></label>
        <label>最低信任分（显式启用后生效）<input type="number" min={0} max={100} value={policy.minimum_trust_score} onChange={(event) => setProfile({ ...profile, quality_gate: { ...policy, minimum_trust_score: Math.max(0, Math.min(100, Number(event.target.value))) } })} /></label>
        {([['enabled', '启用门禁'], ['block_new_only', '只阻断新增 Finding'], ['block_wildcard_permissions', '阻断通配权限'], ['block_parse_failures', '阻断结构化解析失败'], ['block_skipped_files', '阻断跳过文件'], ['block_permission_expansion', '阻断权限扩大'], ['require_approval_for_high_risk', '高风险权限必须声明审批'], ['block_unpinned_sources', '阻断未锁定依赖'], ['block_insecure_sources', '阻断不安全来源'], ['block_unknown_sources', '阻断来源未知'], ['block_partial_integrity', '阻断不完整哈希证据'], ['block_integrity_changes', '阻断完整性变化'], ['block_source_changes', '阻断来源变化'], ['block_known_vulnerabilities', '阻断已命中漏洞'], ['block_malicious_packages', '阻断恶意包情报命中'], ['block_package_confusion', '阻断包名混淆信号'], ['block_intelligence_gaps', '阻断情报未覆盖或版本未解析'], ['block_stale_intelligence', '阻断已配置但过期的本地情报'], ['block_high_risk_dataflow_paths', '阻断高风险 Prompt→工具→资源路径'], ['block_low_trust_score', '阻断低于最低信任分的扫描']] as Array<[keyof AgentGatePolicy, string]>).map(([key, label]) => <label className="inline-check" key={key}><input type="checkbox" checked={Boolean(policy[key])} onChange={(event) => setProfile({ ...profile, quality_gate: { ...policy, [key]: event.target.checked } })} />{label}</label>)}
        <button className="primary-action" onClick={() => void saveProfile()}>保存门禁</button>
      </div>
      <div className="kv-list"><div><span>阻断 Finding</span><strong>{gate?.blocking_finding_count ?? 0}</strong></div><div><span>阻断权限</span><strong>{gate?.blocking_permission_count ?? 0}</strong></div><div><span>阻断来源资产</span><strong>{gate?.blocking_asset_count ?? 0}</strong></div><div><span>阻断情报命中</span><strong>{gate?.blocking_intelligence_count ?? 0}</strong></div><div><span>阻断数据流路径</span><strong>{gate?.blocking_dataflow_count ?? 0}</strong></div></div>
      {gate?.reasons?.length ? <ul>{gate.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : <p>最近扫描没有门禁阻断原因；修改策略后需重新扫描才能重新裁决。</p>}
    </div>
    <div className="panel full"><div className="panel-header"><h2>权限 Allowlist</h2><span>{profile.permission_allowlist.length} 条项目级边界</span></div><div className="filter-grid"><label>资产路径 glob<input value={allowlist.path_pattern} onChange={(event) => setAllowlist({ ...allowlist, path_pattern: event.target.value })} /></label><label>主体 glob<input value={allowlist.subject_pattern} onChange={(event) => setAllowlist({ ...allowlist, subject_pattern: event.target.value })} /></label><label>能力<input value={allowlist.capability} onChange={(event) => setAllowlist({ ...allowlist, capability: event.target.value })} /></label><label>范围 glob<input value={allowlist.scope_pattern} onChange={(event) => setAllowlist({ ...allowlist, scope_pattern: event.target.value })} /></label><label>治理理由<input value={allowlist.reason} onChange={(event) => setAllowlist({ ...allowlist, reason: event.target.value })} /></label><button className="primary-action" onClick={addAllowlist}>新增并保存</button></div>{profile.permission_allowlist.length ? <table className="compact-table"><thead><tr><th>资产 / 主体</th><th>能力 / 范围</th><th>理由</th><th>操作</th></tr></thead><tbody>{profile.permission_allowlist.map((item, index) => <tr key={item.id ?? index}><td>{item.path_pattern}<span className="cell-subtext">{item.subject_pattern}</span></td><td>{item.capability}<span className="cell-subtext">{item.scope_pattern}</span></td><td>{item.reason}</td><td><button className="secondary-action" onClick={() => { const next = { ...profile, permission_allowlist: profile.permission_allowlist.filter((_, itemIndex) => itemIndex !== index) }; setProfile(next); void saveProfile(next); }}>移除</button></td></tr>)}</tbody></table> : <div className="empty-project">暂无 Allowlist；新权限与高风险权限按门禁策略裁决。</div>}</div>
    <div className="panel full"><div className="panel-header"><h2>Finding / 权限例外审批</h2><span>申请与批准分离记录；批准后下一次扫描生效</span></div><div className="filter-grid"><label>对象<select value={exception.kind} onChange={(event) => setException({ ...exception, kind: event.target.value as "finding" | "permission" })}><option value="finding">Finding</option><option value="permission">权限</option></select></label><label>处置<select value={exception.disposition} onChange={(event) => setException({ ...exception, disposition: event.target.value as "suppress" | "accept_risk" })}><option value="accept_risk">接受风险</option><option value="suppress">抑制 / 误报</option></select></label><label>规则 ID<input value={exception.rule_id} disabled={exception.kind !== "finding"} onChange={(event) => setException({ ...exception, rule_id: event.target.value })} /></label><label>资产路径 glob<input value={exception.path_pattern} onChange={(event) => setException({ ...exception, path_pattern: event.target.value })} /></label><label>主体 glob<input value={exception.subject_pattern} disabled={exception.kind !== "permission"} onChange={(event) => setException({ ...exception, subject_pattern: event.target.value })} /></label><label>能力<input value={exception.capability} disabled={exception.kind !== "permission"} onChange={(event) => setException({ ...exception, capability: event.target.value })} /></label><label>范围 glob<input value={exception.scope_pattern} disabled={exception.kind !== "permission"} onChange={(event) => setException({ ...exception, scope_pattern: event.target.value })} /></label><label>失效日期<input type="date" value={exception.expires_at} onChange={(event) => setException({ ...exception, expires_at: event.target.value })} /></label><label>申请理由<input value={exception.reason} onChange={(event) => setException({ ...exception, reason: event.target.value })} /></label><button className="primary-action" onClick={() => void createException()}>提交例外申请</button></div><label>审批说明<input value={decisionNote} onChange={(event) => setDecisionNote(event.target.value)} placeholder="批准、拒绝或撤销前必填" /></label>{profile.exceptions.length ? <table className="compact-table"><thead><tr><th>对象 / 选择器</th><th>理由 / 有效期</th><th>状态 / 审批</th><th>操作</th></tr></thead><tbody>{profile.exceptions.map((item) => <tr key={item.id}><td>{item.kind === "finding" ? item.rule_id : item.capability}<span className="cell-subtext">{item.path_pattern}</span></td><td>{item.reason}<span className="cell-subtext">{item.expires_at ? formatDateTime(item.expires_at) : "永久"}</span></td><td>{item.status}<span className="cell-subtext">申请：{item.requester ?? "-"} · 审批：{item.approver ?? "-"}</span></td><td>{item.status === "pending" ? <><button className="secondary-action" onClick={() => void decideException(item.id, "approved")}>批准</button><button className="secondary-action" onClick={() => void decideException(item.id, "rejected")}>拒绝</button></> : item.status === "approved" ? <button className="secondary-action" onClick={() => void decideException(item.id, "revoked")}>撤销</button> : "-"}</td></tr>)}</tbody></table> : <div className="empty-project">暂无例外申请。</div>}</div>
    <div className="panel full"><div className="panel-header"><h2>报告、离线 CI 与策略审计</h2><span>JSON / SARIF / HTML 均来自同一扫描快照</span></div><div className="probe-actions"><button className="secondary-action" disabled={!snapshot} onClick={() => void downloadAgentArtifact("json")}>导出 JSON</button><button className="secondary-action" disabled={!snapshot} onClick={() => void downloadAgentArtifact("sarif")}>导出 SARIF</button><button className="secondary-action" disabled={!snapshot} onClick={() => void downloadAgentArtifact("html")}>导出 HTML</button><button className="secondary-action" onClick={() => void downloadAgentArtifact("ci")}>导出离线 CI 配置</button></div><p>CI 命令只做本地静态解析；不下载资源、不联网，也不运行目标 Agent/MCP/插件。使用基线报告时可只阻断新增 Finding 和权限扩大。</p>{profile.audit_log.length ? <details><summary>最近 {profile.audit_log.length} 条策略审计</summary><table className="compact-table"><thead><tr><th>时间</th><th>事件</th><th>操作人</th><th>详情</th></tr></thead><tbody>{profile.audit_log.slice(-20).reverse().map((item) => <tr key={item.id}><td>{formatDateTime(item.at)}</td><td>{item.action}</td><td>{item.actor}</td><td>{Object.entries(item.detail ?? {}).map(([key, value]) => <span className="cell-subtext" key={key}>{key}: {textValue(value)}</span>)}</td></tr>)}</tbody></table></details> : <div className="empty-project">暂无策略变更记录。</div>}</div>
  </section></div></details>;
}

function AgentScanCoveragePanel({ history }: { history: AgentScanHistoryItem[] }) {
  const latest = history[0];
  if (!latest) return <section className="retest-panel"><div className="panel-header"><h3>扫描覆盖</h3><span>尚无批次</span></div><p>执行一次 AGENT 扫描后，这里会显示识别到的资产类型、解析结果和规则版本。</p></section>;
  const coverage = latest.coverage;
  return <section className="retest-panel">
    <div className="panel-header"><h3>最近扫描覆盖</h3><span>{formatDateTime(latest.finished_at ?? latest.created_at)}</span></div>
    <div className="retest-summary"><Metric label="识别资产" value={coverage.discovered_asset_count} /><Metric label="解析成功" value={coverage.parsed_asset_count} /><Metric label="解析失败" value={coverage.failed_asset_count} /><Metric label="跳过文件" value={coverage.skipped_file_count} /></div>
    <p className="retest-note">规则版本：{latest.rule_version ?? "旧批次未记录"}。资产类型：{Object.entries(coverage.asset_types).length ? Object.entries(coverage.asset_types).map(([key, value]) => `${agentAssetTypeLabel(key)} ${value}`).join("、") : "未识别到受支持的 Agent 资产"}。</p>
    {history.length > 1 ? <details className="advanced-details"><summary>查看最近 {Math.min(history.length, 10)} 个扫描批次</summary><table className="compact-table"><thead><tr><th>时间</th><th>状态</th><th>资产</th><th>问题</th><th>规则版本</th></tr></thead><tbody>{history.slice(0, 10).map((item) => <tr key={item.scan_task_id}><td>{formatDateTime(item.finished_at ?? item.created_at)}</td><td>{scanStatusLabel(item.status)}</td><td>{item.coverage.discovered_asset_count}</td><td>{item.finding_count}</td><td>{item.rule_version ?? "旧批次未记录"}</td></tr>)}</tbody></table></details> : null}
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
  const partial = assets.filter((asset) => asset.integrity_status === "partial").length;
  useEffect(() => { setPage(1); }, [snapshot?.scan_task_id]);
  return <section className="retest-panel">
    <div className="panel-header"><h3>来源与完整性证据</h3><span>{records.length} 条安装或来源声明</span></div>
    <div className="retest-summary"><Metric label="来源记录" value={records.length} /><Metric label="未锁定版本" value={unpinned} /><Metric label="不安全来源" value={unsafe} /><Metric label="哈希不完整" value={partial} /></div>
    <p className="retest-note">SHA-256 用于比较本地字节是否变化；发布者字段只表示配置声明，当前没有签名、Registry 身份或发布者真实性验证。</p>
    {!snapshot ? <p>完成一次 AGENT 扫描后显示包来源、安装方式、版本锁定和本地哈希。</p> : <>
      <table className="concise-table"><thead><tr><th>资产 / 主体</th><th>包与版本</th><th>来源 / 安装</th><th>发布者状态</th><th>本地完整性</th></tr></thead><tbody>{pagination.items.length === 0 ? <tr><td colSpan={5} className="empty-cell">当前资产没有可提取的安装来源；配置文件 SHA-256 仍保存在资产快照中。</td></tr> : pagination.items.map(({ asset, item }, index) => <tr key={`${asset.path}-${item.subject}-${index}`}><td><strong>{item.subject}</strong><span className="cell-subtext">{asset.path}</span></td><td><strong>{item.package_name ?? "未声明包名"}</strong><span className="cell-subtext">{item.package_version ?? "未声明版本"} · {agentVersionStatusLabel(item.version_status)}</span>{item.issues.length ? <span className="cell-subtext">问题：{item.issues.map(agentProvenanceIssueLabel).join("、")}</span> : null}</td><td><strong>{agentSourceTypeLabel(item.source_type)}</strong><span className="cell-subtext">{item.source_ref ?? "未声明来源"}</span><span className="cell-subtext">安装：{item.installation_method}</span></td><td>{item.publisher_claim ?? "未声明"}<span className="cell-subtext">{item.publisher_status === "claim-only" ? "仅声明，未验证" : "无发布者声明"}</span></td><td><span className={`severity ${asset.integrity_status === "partial" ? "medium" : "info"}`}>{asset.integrity_status === "recorded" ? "已记录" : "部分记录"}</span><span className="cell-subtext">{truncateText(asset.directory_sha256 ?? asset.file_sha256 ?? "无哈希", 22)}</span><span className="cell-subtext">{asset.directory_sha256 ? "目录 SHA-256" : "文件 SHA-256"}</span></td></tr>)}</tbody></table>
      <Pagination page={pagination.page} pageCount={pagination.pageCount} total={records.length} onPageChange={setPage} />
    </>}
  </section>;
}

function AgentIntelligencePanel({ snapshot }: { snapshot: AgentScanSnapshot | null }) {
  const intelligence = snapshot?.intelligence;
  if (!intelligence) return <section className="retest-panel"><div className="panel-header"><h3>依赖漏洞与恶意包情报</h3><span>等待扫描</span></div><p>完成一次新 AGENT 扫描后，这里会显示包坐标、本地漏洞匹配和可选恶意包情报覆盖。</p></section>;
  const summary = intelligence.summary ?? {};
  const packages = intelligence.packages ?? [];
  return <section className="retest-panel">
    <div className="panel-header"><h3>依赖漏洞与恶意包情报</h3><span>严格离线 · {packages.length} 个包坐标</span></div>
    <div className="retest-summary"><Metric label="本地源已覆盖" value={summary.covered_count ?? 0} /><Metric label="漏洞包" value={summary.vulnerable_package_count ?? 0} /><Metric label="恶意包命中" value={summary.malicious_match_count ?? 0} /><Metric label="包名混淆" value={summary.package_confusion_count ?? 0} /></div>
    <p className="retest-note">“本地源未命中”只表示已配置的离线规则或镜像未匹配该精确版本，不代表组件无漏洞。恶意包和受保护包名检查仅在本地情报文件已配置时有效。</p>
    <table className="compact-table"><thead><tr><th>情报源</th><th>状态</th><th>记录</th><th>更新时间 / 年龄</th></tr></thead><tbody>{Object.entries(intelligence.sources ?? {}).map(([name, source]) => <tr key={name}><td>{agentIntelligenceSourceLabel(name)}<span className="cell-subtext">{source.path}</span></td><td><span className={`severity ${source.status === "invalid" ? "high" : source.status === "available" ? "info" : "low"}`}>{source.status === "available" ? "可用" : source.status === "not_configured" ? "未配置" : "无效"}</span>{source.detail ? <span className="cell-subtext">{source.detail}</span> : null}</td><td>{source.entry_count ?? 0}{source.protected_package_count ? <span className="cell-subtext">受保护包名 {source.protected_package_count}</span> : null}</td><td>{source.updated_at ? formatDateTime(source.updated_at) : "未记录"}<span className="cell-subtext">{typeof source.age_days === "number" ? `${source.age_days} 天` : "年龄未知"}</span></td></tr>)}</tbody></table>
    <table className="concise-table"><thead><tr><th>资产 / 包坐标</th><th>版本与覆盖</th><th>漏洞</th><th>恶意包 / 混淆</th></tr></thead><tbody>{packages.length === 0 ? <tr><td className="empty-cell" colSpan={4}>当前资产没有提取到 npm 或 PyPI 包坐标；Git、容器或来源不明的记录会明确标记为暂不支持。</td></tr> : packages.map((item, index) => <tr key={`${item.asset_path}-${item.subject}-${index}`}><td><strong>{item.package_name}</strong><span className="cell-subtext">{item.ecosystem} · {item.subject}</span><span className="cell-subtext">{item.asset_path}</span>{item.purl ? <span className="cell-subtext">{item.purl}</span> : null}</td><td><span className={`severity ${item.lookup_status === "vulnerable" ? "high" : item.lookup_status === "checked_no_match" ? "info" : "low"}`}>{agentIntelligenceStatusLabel(item.lookup_status)}</span><span className="cell-subtext">{item.package_version ?? "版本未解析"} · {agentVersionStatusLabel(item.version_status)}</span><span className="cell-subtext">{item.coverage_sources.length ? item.coverage_sources.join("、") : "无适用本地覆盖源"}</span></td><td>{item.vulnerabilities.length ? item.vulnerabilities.map((match) => <span className="cell-subtext" key={`${match.source}-${match.id}`}>{match.id ?? "本地记录"} · {match.severity ?? "未知等级"} · {match.source ?? "未知来源"}</span>) : "未记录命中"}</td><td>{item.threats.map((match) => <span className="cell-subtext" key={`${match.source}-${match.id}`}>恶意包：{match.id ?? "本地记录"}</span>)}{item.confusion_signals.map((match) => <span className="cell-subtext" key={`${match.source}-${match.protected_package}`}>疑似混淆：{match.protected_package}（编辑距离 {match.distance}）</span>)}{!item.threats.length && !item.confusion_signals.length ? "未记录命中" : null}</td></tr>)}</tbody></table>
    {intelligence.limitations?.length ? <details className="advanced-details"><summary>查看能力边界</summary><ul>{intelligence.limitations.map((item) => <li key={item}>{item}</li>)}</ul></details> : null}
  </section>;
}

function AgentDataflowPanel({ snapshot }: { snapshot: AgentScanSnapshot | null }) {
  const [page, setPage] = useState(1);
  const dataflow = snapshot?.dataflow;
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
      return <tr key={item.id}><td><span className={`severity ${item.severity}`}>{severityLabel(item.severity)}</span><span className="cell-subtext">{agentDataflowConfidenceLabel(item.confidence)}</span><span className="cell-subtext">{item.source_trust === "adversarial-signal" ? "存在可疑指令信号" : "输入信任状态未知"}</span></td><td><strong>{item.title}</strong><span className="cell-subtext">{sequence || item.id}</span><span className="cell-subtext">Prompt 资产：{item.asset_path}</span>{item.tool_asset_path ? <span className="cell-subtext">工具资产：{item.tool_asset_path}</span> : null}<details className="record-evidence"><summary>查看路径证据</summary><ul>{item.evidence.map((value) => <li key={value}>{value}</li>)}</ul></details></td><td><strong>{agentCapabilityLabel(item.capability)}</strong><span className="cell-subtext">{item.resource_type}: {item.resource_scope}</span><span className="cell-subtext">审批声明：{item.approval}</span></td><td>{item.controls.length ? item.controls.map((control, index) => <span className="cell-subtext" key={`${control.type}-${index}`}>已有：{agentDataflowControlLabel(control.type)}{control.runtime_verified === false ? "（未验证执行）" : ""}</span>) : <span className="cell-subtext">未识别到已声明控制</span>}{item.missing_controls.map((control) => <span className="cell-subtext" key={control}>缺少：{agentDataflowControlLabel(control)}</span>)}</td></tr>;
    })}</tbody></table>
    <Pagination page={pagination.page} pageCount={pagination.pageCount} total={paths.length} onPageChange={setPage} />
    {(dataflow.limitations ?? []).length ? <details className="advanced-details"><summary>查看模型边界</summary><ul>{dataflow.limitations.map((item) => <li key={item}>{item}</li>)}</ul></details> : null}
  </section>;
}

function AgentTrustScorePanel({ snapshot }: { snapshot: AgentScanSnapshot | null }) {
  const trust = snapshot?.trust_score;
  if (!trust) return <section className="retest-panel"><div className="panel-header"><h3>AGENT 可解释信任评分</h3><span>等待新扫描</span></div><p>完成一次新版本 AGENT 扫描后，这里会根据来源、哈希、情报、权限、数据流和运行证据给出可解释评分。</p></section>;
  const gradeLabels: Record<string, string> = { "provisional-high": "静态证据较完整", guarded: "需带控制使用", low: "低信任", untrusted: "不可信", "insufficient-evidence": "证据不足" };
  const confidenceLabels = { low: "低", medium: "中", high: "高" };
  const statusLabels: Record<string, string> = { complete: "证据完整", partial: "证据部分完整", insufficient_evidence: "证据不足", not_applicable: "不适用", missing: "证据缺失", risk_detected: "发现风险路径", preflight_only: "仅完成预检", not_run: "未运行", observed: "已观察", limited_observation: "有限运行观测" };
  const runtimeObserved = Boolean(trust.evidence_summary.target_runtime_observed);
  return <section className="retest-panel">
    <div className="panel-header"><h3>AGENT 可解释信任评分</h3><span className={`severity ${trust.score < 50 ? "high" : trust.score < 75 ? "medium" : "info"}`}>{trust.score} / 100 · {gradeLabels[trust.grade] ?? trust.grade}</span></div>
    <div className="retest-summary"><Metric label="当前分数" value={`${trust.score} / 100`} /><Metric label="证据完整度" value={`${trust.evidence_completeness}%`} /><Metric label="证据置信度" value={confidenceLabels[trust.confidence]} /><Metric label="目标运行证据" value={runtimeObserved ? "已观察" : "尚未观察"} /></div>
    <p className="retest-note">这是现有扫描证据的治理摘要，不是“安全认证”。接受风险不会抹掉技术扣分；误报只取消对应 Finding 的直接扣分，独立的来源、情报、权限或路径证据仍可能扣分。本地情报未命中也不等于组件安全。{runtimeObserved ? `当前评分已纳入目标运行证据，总分上限为 ${trust.score_cap}。` : `当前没有目标 Agent 运行证据，总分最高为 ${trust.score_cap}。`}</p>
    <table className="compact-table"><thead><tr><th>分项</th><th>得分</th><th>证据状态</th><th>扣分依据</th></tr></thead><tbody>{trust.dimensions.map((item) => <tr key={item.id}><td><strong>{item.label}</strong></td><td>{item.score} / {item.max_score}</td><td>{statusLabels[item.status] ?? item.status}</td><td>{item.deductions.length ? item.deductions.map((value) => <span className="cell-subtext" key={value.id}>-{value.points}：{value.detail}{value.count > 1 ? `（${value.count} 项）` : ""}</span>) : <span className="cell-subtext">本分项没有技术扣分</span>}</td></tr>)}</tbody></table>
    {trust.improvements.length ? <div><strong>优先改进建议</strong><ol>{trust.improvements.map((item) => <li key={item.id}><strong>{item.title}</strong>：{item.action}</li>)}</ol></div> : <p>当前没有生成额外改进建议。</p>}
    <details className="advanced-details"><summary>查看评分上限、限制与证据哈希</summary>{trust.score_caps.length ? <ul>{trust.score_caps.map((item) => <li key={item.id}>{item.detail}</li>)}</ul> : <p>当前没有额外评分上限。</p>}<ul>{trust.limitations.map((item) => <li key={item}>{item}</li>)}</ul><p>算法：{trust.algorithm_version}；证据摘要 SHA-256：{trust.trust_sha256}</p></details>
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
    void Promise.all([
      request<AgentFixtureStatus>(`/agent/projects/${project.id}/runtime-fixture-status`).catch(() => null),
      request<AgentFixtureEvidence[]>(`/agent/projects/${project.id}/runtime-fixture-evidence`).catch(() => []),
      request<AgentTargetStatus>(`/agent/projects/${project.id}/runtime-target-status`).catch(() => null),
      request<AgentTargetEvidence[]>(`/agent/projects/${project.id}/runtime-target-evidence`).catch(() => []),
    ]).then(([status, evidence, nextTargetStatus, targetEvidenceItems]) => {
      setFixtureStatus(status);
      setFixtureImage(status?.recommended_image ?? "");
      setFixtureEvidence(evidence[0] ?? null);
      setTargetStatus(nextTargetStatus);
      setTargetBuildId(nextTargetStatus?.builds[0]?.build_id ?? "");
      setTargetEvidence(savedPlan?.evidence ?? targetEvidenceItems[0] ?? null);
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
  return <section className="retest-panel">
    <div className="panel-header"><h3>AGENT 受控运行预检</h3><span className={`severity ${targetEvidence?.policy_verified ? "info" : plan.decision === "blocked" ? "high" : "info"}`}>{targetEvidence?.policy_verified ? "已有有限目标运行证据" : plan.decision === "blocked" ? "预检尚未通过" : "等待单独执行批准"}</span></div>
    <div className="retest-summary"><Metric label="通过 / 阻断检查" value={`${Number(summary.pass_count ?? 0)} / ${Number(summary.blocking_count ?? 0)}`} /><Metric label="候选高风险路径" value={Number(summary.candidate_path_count ?? 0)} /><Metric label="敏感文件名命中" value={Number(summary.sensitive_file_count ?? 0)} /><Metric label="预检自身会执行" value={plan.execution_enabled ? "是" : "否"} /></div>
    <p className="retest-note">“只执行安全预检”不会复制文件或联系 Docker。下方只有在你单独勾选确认后，才会把普通文件复制到 D 盘唯一目录并生成哈希清单；它会排除 `.env`、凭据、私钥信号、链接和版本库/构建元数据，绝不直接挂载项目源码。</p>
    <div className="filter-grid"><label>拟执行命令<input value={command} onChange={(event) => { setCommand(event.target.value); setConfirmed(false); setStagingConfirmed(false); }} placeholder="必须由操作人明确选择，不自动推断" /></label><label>本地镜像（必须固定 digest）<input value={image} onChange={(event) => { setImage(event.target.value); setConfirmed(false); setStagingConfirmed(false); }} placeholder="name@sha256:...；预检不会下载" /></label><label>超时秒数<input type="number" min={1} max={30} value={timeoutSeconds} onChange={(event) => { setTimeoutSeconds(Math.max(1, Math.min(30, Number(event.target.value)))); setConfirmed(false); setStagingConfirmed(false); }} /></label><label className="inline-check"><input type="checkbox" checked={confirmed} onChange={(event) => { setConfirmed(event.target.checked); setStagingConfirmed(false); }} />我只确认预检这组命令、镜像和目标；不授权执行</label><button className="primary-action" disabled={loading} onClick={() => void runPreflight()}>{loading ? "预检中" : "只执行安全预检"}</button></div>
    {message ? <p>{message}</p> : null}
    <div className="filter-grid"><label className="inline-check"><input type="checkbox" disabled={!exactPlanConfirmed} checked={stagingConfirmed} onChange={(event) => setStagingConfirmed(event.target.checked)} />我确认创建本计划对应的 D 盘过滤副本；不授权运行 Agent 或容器</label><button className="secondary-action" disabled={loading || !stagingConfirmed || !exactPlanConfirmed} onClick={() => void buildStaging()}>{loading ? "处理中" : "创建并校验过滤副本"}</button>{!exactPlanConfirmed ? <span>请先勾选上方目标确认并重新执行安全预检。</span> : null}</div>
    {stagingResult ? <div className="kv-list"><div><span>过滤副本状态</span><strong>{stagingResult.staging.verification.status === "verified" ? "已校验" : stagingResult.staging.verification.status}</strong><span>{stagingResult.staging.destination_path}</span></div><div><span>复制 / 排除文件</span><strong>{stagingResult.staging.summary.copied_file_count} / {stagingResult.staging.summary.excluded_count}</strong><span>{stagingResult.staging.summary.copied_bytes} 字节；未执行运行时</span></div><div><span>Staging SHA-256</span><strong>{truncateText(stagingResult.staging.staging_sha256, 20)}</strong><span>Manifest：{truncateText(stagingResult.staging.manifest_sha256, 20)}</span></div></div> : null}
    <details className="advanced-details"><summary>无害夹具容器策略验收</summary><p className="retest-note">该操作会真实启动一次仓库自带的固定无害夹具，但不会使用项目源码或运行真实 Agent。镜像必须已在本地且固定 digest，Docker 使用 `--pull=never`；容器结束后会删除，仅在 D 盘保留过滤副本和证据 JSON。</p><div className="filter-grid"><label>本地 Python digest 镜像<select value={fixtureImage} onChange={(event) => { setFixtureImage(event.target.value); setFixtureConfirmed(false); }}><option value="">{fixtureStatus?.available ? "选择本地镜像" : "没有可用的本地 digest 镜像"}</option>{(fixtureStatus?.images ?? []).map((item) => <option key={item.reference} value={item.reference}>{item.reference}（{item.size}）</option>)}</select></label><label className="inline-check"><input type="checkbox" disabled={!fixtureImage} checked={fixtureConfirmed} onChange={(event) => setFixtureConfirmed(event.target.checked)} />我确认只运行仓库无害夹具并验证固定隔离策略</label><button className="secondary-action" disabled={loading || !fixtureConfirmed || !fixtureImage} onClick={() => void validateHarmlessFixture()}>{loading ? "验收中" : "运行无害夹具策略验收"}</button></div>{fixtureStatus ? <p>{fixtureStatus.message} 未执行任何下载。</p> : <p>正在检查本地镜像；不会自动下载。</p>}{fixtureEvidence ? <div className="kv-list"><div><span>最近验收</span><strong>{fixtureEvidence.decision === "pass" ? "通过" : "阻断"}</strong><span>{fixtureEvidence.run_id} · {fixtureEvidence.elapsed_ms} ms</span></div><div><span>策略检查</span><strong>{Object.values(fixtureEvidence.policy_checks).filter(Boolean).length} / {Object.keys(fixtureEvidence.policy_checks).length}</strong><span>真实 Agent 执行：未启用</span></div><div><span>证据 SHA-256</span><strong>{truncateText(fixtureEvidence.evidence_sha256, 20)}</strong><span>{fixtureEvidence.evidence_path}</span></div></div> : null}</details>
    <div className="kv-list"><div><span>过滤工作副本</span><strong>{plan.staging.status === "not_created" ? "未创建" : plan.staging.status === "unverified_existing" ? "检测到未绑定副本" : plan.staging.status}</strong><span>{plan.staging.path}</span></div><div><span>未来容器策略</span><strong>禁网 · 只读 · drop-all</strong><span>无宿主环境变量、无宿主控制 Socket</span></div><div><span>计划 SHA-256</span><strong>{truncateText(plan.plan_sha256, 20)}</strong><span>用于未来证据关联</span></div></div>
    <table className="compact-table"><thead><tr><th>状态</th><th>检查</th><th>结果</th><th>处理建议</th></tr></thead><tbody>{plan.checks.map((item) => <tr key={item.id}><td><span className={`severity ${item.status === "block" ? "high" : item.status === "warn" ? "medium" : "info"}`}>{item.status === "pass" ? "通过" : item.status === "warn" ? "警告" : "阻断"}</span></td><td>{item.id}</td><td>{item.detail}</td><td>{item.remediation ?? "-"}</td></tr>)}</tbody></table>
    {plan.candidate_dataflow_paths.length ? <details className="advanced-details"><summary>查看计划验证的 {plan.candidate_dataflow_paths.length} 条静态路径</summary><table className="compact-table"><thead><tr><th>风险</th><th>路径</th><th>能力 / 资源</th></tr></thead><tbody>{plan.candidate_dataflow_paths.map((item) => <tr key={item.id}><td><span className={`severity ${item.severity}`}>{severityLabel(item.severity)}</span><span className="cell-subtext">{agentDataflowConfidenceLabel(item.confidence)}</span></td><td>{item.title}<span className="cell-subtext">{item.asset_path}{item.tool_asset_path ? ` → ${item.tool_asset_path}` : ""}</span></td><td>{agentCapabilityLabel(item.capability)}<span className="cell-subtext">{item.resource_type}: {item.resource_scope}</span></td></tr>)}</tbody></table></details> : null}
    <details className="advanced-details"><summary>指定项目 Agent 受控运行（高风险，默认关闭）</summary>
      <p className="retest-note">这里会真实启动所选 staging 中的 Agent。服务器会重新核验扫描批次、计划、命令指纹、镜像 digest、staging/manifest 哈希和 Docker 隔离配置；使用 `--pull=never`，不会下载镜像。当前只观察主进程和工作区前后完整性，子进程、逐文件访问、网络尝试目的地和工具调用尚未完整插桩。</p>
      <div className="retest-summary"><Metric label="项目执行开关" value={targetStatus?.execution_enabled_by_project_policy ? "已启用" : "默认关闭"} /><Metric label="可执行绑定副本" value={targetStatus?.builds.length ?? 0} /><Metric label="最近策略验证" value={targetEvidence?.policy_verified ? "通过" : targetEvidence ? "需关注" : "尚未运行"} /><Metric label="行为插桩" value={targetEvidence?.behavioral_telemetry_complete ? "完整" : "有限"} /></div>
      <div className="filter-grid"><label>绑定的 D 盘 staging<select value={targetBuildId} onChange={(event) => { setTargetBuildId(event.target.value); setTargetConfirmed(false); setTargetPhrase(""); }}><option value="">选择已验证副本</option>{(targetStatus?.builds ?? []).map((item) => <option key={item.build_id} value={item.build_id}>{item.build_id} · {item.file_count} 文件 · {formatDateTime(item.created_at)}</option>)}</select></label><label>固定绑定镜像<input value={selectedTargetBuild?.image ?? ""} readOnly placeholder="由 staging 清单绑定" /></label><label>输入确认短语 <code>{targetStatus?.authorization_phrase ?? "RUN ISOLATED AGENT"}</code><input value={targetPhrase} onChange={(event) => { setTargetPhrase(event.target.value); setTargetConfirmed(false); }} /></label><label className="inline-check"><input type="checkbox" disabled={!selectedTargetBuild || targetPhrase !== targetStatus?.authorization_phrase || !targetStatus?.execution_enabled_by_project_policy} checked={targetConfirmed} onChange={(event) => setTargetConfirmed(event.target.checked)} />我确认真实运行这个精确副本、命令和镜像；理解当前插桩仍有限</label><button className="secondary-action" disabled={loading || !targetConfirmed || !selectedTargetBuild || targetPhrase !== targetStatus?.authorization_phrase || !targetStatus?.execution_enabled_by_project_policy} onClick={() => void validateTargetAgent()}>{loading ? "运行中" : "运行所选真实 Agent"}</button><button className="secondary-action" disabled={loading} onClick={() => void refreshTargetRuntime()}>刷新执行状态</button></div>
      {!targetStatus?.execution_enabled_by_project_policy ? <p>项目策略仍保持默认关闭。只有在上方“项目扫描策略”明确开启并保存后，本按钮才可能使用；开启策略本身不会运行 Agent。</p> : null}
      {selectedTargetBuild && (command.trim() !== plan.proposed_command?.trim() || image.trim() !== selectedTargetBuild.image || timeoutSeconds !== selectedTargetBuild.timeout_seconds) ? <p className="report-error">当前命令、镜像或超时与所选 staging 的绑定可能不同，服务器将拒绝执行。请重新预检并创建新副本。</p> : null}
      {targetEvidence ? <><div className="kv-list"><div><span>最近目标证据</span><strong>{targetEvidence.decision === "pass" ? "策略通过" : "需要关注"}</strong><span>{targetEvidence.execution_id} · {targetEvidence.elapsed_ms} ms</span></div><div><span>退出 / 超时 / 清理</span><strong>{targetEvidence.container.exit_code ?? "无"} / {targetEvidence.container.timed_out ? "是" : "否"} / {targetEvidence.container.removed_after_run ? "已删除" : "失败"}</strong><span>工作区保持不变：{targetEvidence.staging.unchanged_after_run ? "是" : "否"}</span></div><div><span>证据 SHA-256</span><strong>{truncateText(targetEvidence.evidence_sha256, 20)}</strong><span>{targetEvidence.evidence_path}</span></div></div><details><summary>查看运行观测覆盖</summary><div className="kv-list">{Object.entries(targetEvidence.telemetry_coverage).map(([key, value]) => <div key={key}><span>{key}</span><strong>{value}</strong></div>)}</div><p>“未观察”不代表行为不可能发生；当前没有展示 Agent 标准输出，以降低敏感信息二次暴露风险。</p></details></> : null}
    </details>
    <p>{plan.next_action}</p>
    <details className="advanced-details"><summary>查看未来运行证据模型</summary><p>当前状态：{plan.evidence_template.status}。未来证据会分别记录进程、文件访问、网络尝试和工具调用，并把每条静态路径标记为“已观察”“被策略阻断”“未观察”或“未插桩”，不会把“未观察”写成“不可利用”。</p><p>证据脱敏：{plan.evidence_template.redaction.applied ? "启用" : "未启用"}；保存密钥值：{plan.evidence_template.redaction.secret_values_stored ? "是" : "否"}。</p></details>
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

function FindingModuleGovernance({ project, moduleKey, findings, validations, evidence, graph, comparison, scanHistory = [], agentSnapshot = null, agentScanDiff = null, loading, onRunReview, onRun, onUpdateFinding }: { project?: Project; moduleKey: "sast" | "agent"; findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; graph: EvidenceGraph | null; comparison: FindingRetestComparison | null; scanHistory?: AgentScanHistoryItem[]; agentSnapshot?: AgentScanSnapshot | null; agentScanDiff?: AgentScanDiff | null; loading: boolean; onRunReview?: () => Promise<void>; onRun: () => Promise<void>; onUpdateFinding: (findingId: string, patch: Partial<Pick<Finding, "status">>) => Promise<void> }) {
  const [filters, setFilters] = useState({ keyword: "", severity: "all", status: "all", category: "all" });
  const [page, setPage] = useState(1);
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
  return <ModuleGovernanceShell moduleKey={moduleKey} lastStatus={moduleKey === "agent" ? latestAgentScan?.status ?? null : findings.length ? "completed" : null} metrics={moduleKey === "agent" ? [["已识别资产", latestAgentScan?.coverage.discovered_asset_count ?? 0], ["问题总数", findings.length], ["严重 / 高危", high], ["待人工复核", pendingReview]] : [["问题总数", findings.length], ["严重 / 高危", high], ["待处理", open], ["已复核", reviewed]]} action={high ? `优先处理 ${high} 个严重或高危问题，确认影响后分配整改负责人。` : findings.length ? "逐项确认中低风险问题，记录误报或修复结论。" : latestAgentScan?.status === "completed" ? "本批次已完成，已识别资产中未命中当前规则；可查看覆盖情况确认扫描边界。" : "当前没有检测结果，请先在安全检测中执行该模块。"} loading={loading} onRun={onRun}>
    <ModuleFilterBar><input value={filters.keyword} onChange={(event) => setFilters({ ...filters, keyword: event.target.value })} placeholder="搜索风险、文件或规则" /><SimpleFilter value={filters.severity} label="全部等级" options={["critical", "high", "medium", "low", "info"]} format={severityLabel} onChange={(value) => setFilters({ ...filters, severity: value })} /><SimpleFilter value={filters.status} label="全部处理状态" options={FINDING_WORKFLOW_STATUSES} format={(value) => statusLabel(value as FindingStatus)} onChange={(value) => setFilters({ ...filters, status: value })} /><SimpleFilter value={filters.category} label="全部风险分类" options={uniqueValues(findings.map((item) => item.ai_review?.category ?? "unknown"))} format={moduleKey === "agent" ? agentCategoryLabel : (value) => value} onChange={(value) => setFilters({ ...filters, category: value })} /></ModuleFilterBar>
    <ConciseFindingTable findings={pagination.items} validations={validations} evidence={evidence} graph={graph} onUpdateFinding={onUpdateFinding} />
    <Pagination page={pagination.page} pageCount={pagination.pageCount} total={filtered.length} onPageChange={setPage} />
    {moduleKey === "agent" ? <>{project ? <AgentGovernanceConsole project={project} snapshot={agentSnapshot} /> : null}<AgentScanCoveragePanel history={scanHistory} /><AgentAssetInventoryPanel snapshot={agentSnapshot} /><AgentProvenancePanel snapshot={agentSnapshot} /><AgentIntelligencePanel snapshot={agentSnapshot} /><AgentDataflowPanel snapshot={agentSnapshot} /><AgentTrustScorePanel snapshot={agentSnapshot} />{project ? <AgentRuntimePreflightPanel project={project} snapshot={agentSnapshot} /> : null}<AgentPermissionMatrixPanel snapshot={agentSnapshot} /><AgentSemanticDiffPanel diff={agentScanDiff} /></> : null}
    <RetestComparisonPanel comparison={comparison} />
    <details className="advanced-details"><summary>查看高级分析与复核信息</summary><div className="advanced-details-body"><div className="advanced-summary-grid"><div><span>风险分类</span><KeyValue data={countBy(findings.map((item) => ({ category: item.ai_review?.category ?? "unknown" })), "category")} formatKey={moduleKey === "agent" ? agentCategoryLabel : (value) => value} /></div><div><span>严重等级</span><KeyValue data={countBy(findings, "severity")} formatKey={severityLabel} /></div></div>{moduleKey === "sast" ? <section className="advanced-inline-action"><div><strong>SAST Agent 复核</strong><span>启用 DeepSeek 后执行真实七角色审计；未启用时使用本地规则化复核。修复内容始终只保存为人工评审草案，不会直接修改源码。</span></div><button className="secondary-action" disabled={loading || findings.length === 0} onClick={() => void onRunReview?.()}>{loading ? "复核中" : "执行 Agent 复核"}</button></section> : <section className="advanced-inline-action"><div><strong>Agent 安全能力边界</strong><span>默认扫描仍是本地只读；指定目标只有在项目开关、精确绑定和二次确认全部满足后才会受控运行。当前仍未实现 AGENT 专用人工或 AI 复核。</span></div></section>}</div></details>
  </ModuleGovernanceShell>;
}

function DastGovernanceView({ findings, validations, strategies, strategyId, targetUrl, selectedFindingId, loading, onTargetUrlChange, onStrategyChange, onSelectRisk, onRun }: { findings: Finding[]; validations: DastValidation[]; strategies: DastStrategy[]; strategyId: string; targetUrl: string; selectedFindingId: string; loading: boolean; onTargetUrlChange: (value: string) => void; onStrategyChange: (strategyId: string) => void; onSelectRisk: (findingId: string) => void; onRun: () => Promise<void> }) {
  const [filters, setFilters] = useState({ keyword: "", verdict: "all", linked: "all" });
  const [page, setPage] = useState(1);
  const findingMap = new Map(findings.map((item) => [item.id, item]));
  const selectedFinding = findingMap.get(selectedFindingId);
  const selectedStrategy = strategies.find((item) => item.id === strategyId) ?? strategies[0];
  const exploitable = validations.filter((item) => item.verdict === "exploitable").length;
  const uncertain = validations.filter((item) => item.verdict === "uncertain").length;
  const linked = validations.filter((item) => item.finding_id || item.component_id).length;
  const filtered = validations.filter((item) => {
    const isLinked = Boolean(item.finding_id || item.component_id);
    return (!filters.keyword.trim() || item.target_url.toLowerCase().includes(filters.keyword.trim().toLowerCase()))
      && (filters.verdict === "all" || item.verdict === filters.verdict)
      && (filters.linked === "all" || (filters.linked === "linked") === isLinked);
  });
  const pagination = paginate(filtered, page);
  useEffect(() => { setPage(1); }, [filters.keyword, filters.verdict, filters.linked]);
  return <ModuleGovernanceShell moduleKey="dast" lastStatus={validations.length ? "completed" : null} metrics={[["验证记录", validations.length], ["基础风险信号", exploitable], ["需要补充验证", uncertain], ["已关联风险", linked]]} action={exploitable ? `有 ${exploitable} 条旧记录带有基础风险信号；它们不是漏洞利用证明，应按策略补充业务验证。` : uncertain ? `有 ${uncertain} 项需要补充登录态、业务参数或专用验证策略。` : "当前基础检查未发现明显配置风险；这不代表上游漏洞已经排除。"} loading={loading} hideRunButton onRun={onRun}>
    <section className="validation-workbench">
      <div className="workbench-heading"><span>动态证明</span><h3>选择一条已发现风险，在运行系统中验证它是否能被触发</h3><p>只有从具体风险发起的验证才会进入证据链；当前自动能力属于 Web 基础验证，业务漏洞应补充对应测试策略。</p></div>
        <div className="validation-form">
          <label><span>① 待验证风险</span><select value={selectedFindingId} onChange={(event) => onSelectRisk(event.target.value)}><option value="">请选择 SAST / SCA / AGENT 风险</option>{findings.map((finding) => <option value={finding.id} key={finding.id}>{finding.source} · {severityLabel(finding.severity)} · {finding.title}</option>)}</select></label>
          <ArrowRight size={18} />
          <label><span>② 验证策略</span><select value={strategyId} onChange={(event) => onStrategyChange(event.target.value)} disabled={!selectedFinding || strategies.length === 0}><option value="">请选择策略</option>{strategies.map((strategy) => <option value={strategy.id} key={strategy.id}>{strategy.name}</option>)}</select></label>
          <label><span>③ 运行目标</span><input value={targetUrl} onChange={(event) => onTargetUrlChange(event.target.value)} placeholder="https://项目运行地址/具体接口" /></label>
          <ArrowRight size={18} />
          <button className="primary-action" disabled={loading || !selectedFindingId || !targetUrl.trim() || !selectedStrategy} onClick={() => void onRun()}>{loading ? "验证中" : "④ 执行验证"}</button>
        </div>
        {selectedStrategy ? <section className="verification-strategy-card"><div><span>本次会检查</span><strong>{selectedStrategy.name}</strong><p>{selectedStrategy.description}</p><ul>{selectedStrategy.check_items.map((item) => <li key={item}>{item}</li>)}</ul></div><div><span>明确不检查</span><p>{selectedStrategy.scope_summary}</p><ul>{selectedStrategy.limitations.map((item) => <li key={item}>{item}</li>)}</ul></div></section> : <div className="workbench-empty">先选择风险，系统才会给出适合该风险的安全验证策略。</div>}
      {selectedFinding ? <div className="selected-risk-context"><span className={`severity ${selectedFinding.severity}`}>{severityLabel(selectedFinding.severity)}</span><div><strong>{selectedFinding.title}</strong><small>{selectedFinding.source} · {selectedFinding.file_path ?? "项目级风险"} · {selectedFinding.rule_id}</small></div><b>本次结果将回写到这条风险的证据链</b></div> : <div className="workbench-empty">请先选择风险。没有上游风险的 URL 检查只属于 Web 基础检查，不计入漏洞证据闭环。</div>}
    </section>
    <ModuleFilterBar><input value={filters.keyword} onChange={(event) => setFilters({ ...filters, keyword: event.target.value })} placeholder="搜索验证地址" /><SimpleFilter value={filters.verdict} label="全部验证结论" options={["exploitable", "uncertain", "not_exploitable"]} format={dastVerdictLabel} onChange={(value) => setFilters({ ...filters, verdict: value })} /><SimpleFilter value={filters.linked} label="全部关联状态" options={["linked", "unlinked"]} format={(value) => value === "linked" ? "已关联风险" : "独立验证"} onChange={(value) => setFilters({ ...filters, linked: value })} /></ModuleFilterBar>
    <table className="concise-table"><thead><tr><th>关联的原始风险</th><th>验证目标 / 策略</th><th>三色裁决</th><th>验证证据</th></tr></thead><tbody>{pagination.items.length === 0 ? <tr><td colSpan={4} className="empty-cell">没有符合筛选条件的动态验证记录。</td></tr> : pagination.items.map((item) => { const linkedFinding = item.finding_id ? findingMap.get(item.finding_id) : null; return <tr key={item.id}><td>{linkedFinding ? <><strong>{linkedFinding.title}</strong><span className="cell-subtext">{linkedFinding.source} · {severityLabel(linkedFinding.severity)}</span></> : <><strong>独立 Web 基础检查</strong><span className="cell-subtext">不计入漏洞证据链</span></>}</td><td><strong>{item.target_url}</strong><span className="cell-subtext">{item.strategy_name ?? "旧记录：未保存策略"}</span><span className="cell-subtext">{formatDateTime(item.created_at)}</span></td><td><span className={`verdict-badge ${item.verdict}`}>{dastVerdictLabel(item.verdict)}</span><span className="cell-subtext">关联可信度 {item.link_confidence}%</span></td><td><details className="record-evidence"><summary>{truncateText(item.evidence_summary ?? "查看验证过程", 80)}</summary><dl><div><dt>策略范围</dt><dd>{item.scope_summary ?? "旧记录未保存检查范围"}</dd></div><div><dt>能力边界</dt><dd>{item.limitations ?? "旧记录未保存能力边界"}</dd></div><div><dt>请求</dt><dd>{item.request_summary ?? "未记录"}</dd></div><div><dt>响应</dt><dd>{item.response_summary ?? "未记录"}</dd></div><div><dt>复现过程</dt><dd>{item.reproduction_steps ?? "未记录"}</dd></div><div><dt>修复提示</dt><dd>{item.remediation_hint ?? "未记录"}</dd></div></dl></details></td></tr>; })}</tbody></table>
    <Pagination page={pagination.page} pageCount={pagination.pageCount} total={filtered.length} onPageChange={setPage} />
  </ModuleGovernanceShell>;
}

function SandboxGovernanceView({ findings, validations, evidence, graph, templates, runCommand, sandboxImage, selectedFindingId, selectedValidationId, loading, onRunCommandChange, onSandboxImageChange, onSelectRisk, onSelectValidation, onRun }: { findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; graph: EvidenceGraph | null; templates: SandboxTemplate[]; runCommand: string; sandboxImage: string; selectedFindingId: string; selectedValidationId: string; loading: boolean; onRunCommandChange: (value: string) => void; onSandboxImageChange: (value: string) => void; onSelectRisk: (findingId: string) => void; onSelectValidation: (validationId: string) => void; onRun: (plan: SandboxExecutionPlan) => Promise<void> }) {
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

function ModuleGovernanceShell({ moduleKey, lastStatus, metrics, action, loading, runDisabled = false, runLabel, hideRunButton = false, onRun, children }: { moduleKey: Exclude<ModuleKey, "aspm">; lastStatus: string | null; metrics: Array<[string, string | number]>; action: string; loading: boolean; runDisabled?: boolean; runLabel?: string; hideRunButton?: boolean; onRun: () => Promise<void>; children: React.ReactNode }) {
  return <div className="governance-view module-governance-view">
    <section className="module-governance-heading"><div className="module-icon">{moduleIcons[moduleKey]}</div><div><h2>{MODULE_DISPLAY[moduleKey].name}</h2><p>{MODULE_DISPLAY[moduleKey].purpose}</p></div><div className="module-run-actions"><span>{lastStatus ? scanStatusLabel(lastStatus) : "尚未执行"}</span>{hideRunButton ? null : <button className="primary-action" disabled={loading || runDisabled} onClick={() => void onRun()}>{loading ? "执行中" : runLabel ?? (moduleKey === "dast" || moduleKey === "sandbox" ? "再次执行" : moduleKey === "agent" ? "重新扫描并对比" : "重新扫描并复测")}</button>}</div></section>
    <section className="governance-metrics">{metrics.map(([label, value]) => <Metric key={label} label={label} value={value} />)}</section>
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
  return <><table className="concise-table"><thead><tr><th>风险问题</th><th>等级</th><th>位置</th><th>处理状态</th><th>验证证据</th></tr></thead><tbody>{findings.length === 0 ? <tr><td colSpan={5} className="empty-cell">当前没有需要展示的风险问题。</td></tr> : findings.map((finding) => { const displayTitle = findingTitle(finding); const description = finding.ai_review?.description ?? finding.evidence ?? "暂无影响说明"; const evidenceNodes = findingEvidenceNodes(finding.id, graph); const validationCount = validations.filter((item) => item.finding_id === finding.id).length; const evidenceCount = evidence.filter((item) => item.finding_id === finding.id || Boolean(item.validation_id && validations.some((validation) => validation.id === item.validation_id && validation.finding_id === finding.id))).length; return <tr key={finding.id}><td><strong title={displayTitle}>{truncateText(displayTitle, 100)}</strong><span className="cell-subtext" title={description}>{truncateText(description, 140)}</span></td><td><span className={`severity ${finding.severity}`}>{severityLabel(finding.severity)}</span></td><td>{finding.file_path ?? "项目级问题"}<span className="cell-subtext">{finding.line_start ? `第 ${finding.line_start} 行` : finding.source}</span></td><td><select value={normalizeFindingStatus(finding.status)} onChange={(event) => void onUpdateFinding(finding.id, { status: event.target.value as FindingStatus })}>{FINDING_WORKFLOW_STATUSES.map((status) => <option key={status} value={status}>{statusLabel(status)}</option>)}</select></td><td><button className="secondary-action" onClick={() => setSelectedFinding(finding)}>{validationCount || evidenceCount ? `查看证据（${validationCount + evidenceCount}）` : evidenceNodes.length ? `查看关系（${evidenceNodes.length}）` : "尚未验证"}</button></td></tr>; })}</tbody></table>{selectedFinding ? <FindingEvidenceDetail finding={selectedFinding} validations={validations} evidence={evidence} graph={graph ?? null} onClose={() => setSelectedFinding(null)} /> : null}</>;
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
  if (!comparison?.has_comparison) return <section className="retest-panel"><div className="panel-header"><h3>扫描批次对比</h3><span>等待第二次扫描</span></div><p>再次扫描后，系统会比较最近两个批次，显示风险记录仍存在、消失、新增或变化；首次扫描不会被表述为已经完成复测。</p></section>;
  const filtered = comparison.items.filter((item) => resultFilter === "all" || item.result === resultFilter);
  const pagination = paginate(filtered, page);
  return <section className="retest-panel">
    <div className="panel-header"><h3>最近两个扫描批次对比</h3><span>{formatDateTime(comparison.previous_scan_at)} → {formatDateTime(comparison.current_scan_at)}</span></div>
    <div className="retest-summary"><Metric label="仍然存在的风险记录" value={comparison.still_present_count} /><Metric label="已消失的风险记录" value={comparison.resolved_count} /><Metric label="新增风险记录" value={comparison.new_count} /><Metric label="内容发生变化" value={comparison.changed_count} /></div>
    <p className="retest-note">这里统计的是风险记录，不是组件数量。SCA 中一个组件可能同时对应多个漏洞、许可证或版本风险，因此风险记录数可能大于组件数。“已消失”表示本次未再次发现；“仍然存在”表示需要继续整改。</p>
    <details className="retest-details">
      <summary>查看全部风险记录复测明细（{comparison.items.length} 条）</summary>
      <div className="module-filter-bar"><SimpleFilter value={resultFilter} label="全部复测结果" options={["still_present", "resolved", "new", "changed"]} format={retestResultLabel} onChange={(value) => { setResultFilter(value); setPage(1); }} /></div>
      <table className="concise-table"><thead><tr><th>风险记录</th><th>复测结论</th><th>位置变化</th><th>等级变化</th></tr></thead><tbody>{pagination.items.length === 0 ? <tr><td colSpan={4} className="empty-cell">没有符合筛选条件的复测结果。</td></tr> : pagination.items.map((item) => <tr key={item.identity}><td><strong>{item.title}</strong><span className="cell-subtext">{item.file_path ?? "项目级问题"}</span></td><td><span className={`retest-badge ${item.result}`}>{retestResultLabel(item.result)}</span></td><td>{item.previous_line_start ?? "-"} → {item.current_line_start ?? "-"}</td><td>{severityLabel(item.previous_severity)} → {severityLabel(item.current_severity)}</td></tr>)}</tbody></table>
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
    <div className="panel-header"><div><h3>风险证据链</h3><span>{finding.title}</span></div><button className="secondary-action" onClick={onClose}>关闭</button></div>
    <div className="evidence-conclusion"><strong>{conclusion}</strong><span>{nodes.length ? "以下内容来自已保存的显式关联，不代表自动确认漏洞成立。" : "当前问题还没有关联 DAST 或 SANDBOX 证据。"}</span></div>
      {finding.source === "SAST" && ["critical", "high"].includes(finding.severity) ? <details className="record-evidence"><summary>人工评审修复草案（不会修改源码）</summary><p>草案仅供开发人员参考，不会写入文件、创建提交、创建 PR 或自动执行回归。</p><button className="secondary-action" disabled={fixDraftLoading} onClick={() => void loadFixDraft()}>{fixDraftLoading ? "正在生成" : fixDraft ? "重新生成草案" : "生成修复草案"}</button>{fixDraftMessage ? <div className="empty-project">{fixDraftMessage}</div> : null}{fixDraft ? <dl><div><dt>建议修改</dt><dd>{fixDraft.recommended_change}</dd></div><div><dt>补丁草案</dt><dd><pre className="code-preview">{fixDraft.patch}</pre></dd></div><div><dt>限制</dt><dd>{fixDraft.limitations.join("；") || "无额外说明"}</dd></div><div><dt>回归入口</dt><dd>{fixDraft.regression_scan.endpoint}（必填：{fixDraft.regression_scan.required_fields.join("、")}）</dd></div></dl> : null}</details> : null}
      {finding.ai_review?.ai_provider ? <details className="record-evidence" open><summary>DeepSeek 多 Agent 复核：{finding.ai_review.review_verdict ?? "等待人工确认"} · 置信度 {finding.ai_review.ai_confidence ?? 0}%</summary><dl><div><dt>证据摘要</dt><dd>{finding.ai_review.evidence_summary ?? finding.ai_review.summary}</dd></div><div><dt>Agent 流程</dt><dd>{(finding.ai_review.agent_pipeline ?? []).map(sastAgentRoleLabel).join(" → ")}</dd></div><div><dt>修复建议</dt><dd>{finding.ai_review.fix_draft?.recommended_change ?? finding.ai_review.fix_strategy ?? finding.ai_review.remediation}</dd></div><div><dt>补丁草案</dt><dd>{finding.ai_review.fix_draft?.patch ? <pre className="code-preview">{finding.ai_review.fix_draft.patch}</pre> : "未保存补丁草案"}</dd></div></dl></details> : null}
      <ol className="evidence-timeline">
      <li><b>{finding.source}</b><div><strong>发现风险</strong><span>{finding.file_path ?? "项目级问题"} · {severityLabel(finding.severity)}</span></div></li>
        {nodes.map((node) => <li key={node.id}><b>{node.module}</b><div><strong>{evidenceNodeStage(node)}</strong><span>{node.label}</span><small>{node.detail ?? "未记录证据摘要"} · {formatDateTime(node.created_at)}</small></div></li>)}
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
function dastVerdictLabel(value: string) { return value === "exploitable" ? "基础风险信号（旧记录）" : value === "uncertain" ? "需要进一步确认" : value === "not_exploitable" ? "基础检查未发现异常" : value; }
function retestResultLabel(value: string) { return value === "still_present" ? "仍然存在" : value === "resolved" ? "已经消失" : value === "new" ? "新增问题" : value === "changed" ? "位置或等级变化" : value; }
function evidenceNodeStage(node: EvidenceGraphNode) { return node.kind === "component" ? "关联供应链组件" : node.kind === "validation" ? "动态验证" : node.kind === "evidence" ? "沙箱运行证据" : "关联风险"; }
function severityRank(value: Severity) { return value === "critical" ? 5 : value === "high" ? 4 : value === "medium" ? 3 : value === "low" ? 2 : 1; }
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
function errorMessage(error: unknown) { return error instanceof Error ? error.message : "未知错误"; }
async function request<T>(path: string, init: RequestInit = {}): Promise<T> { const response = await fetch(`${API_BASE}${path}`, { ...init, headers: { "Content-Type": "application/json", ...(init.headers ?? {}) } }); if (!response.ok) { let detail = `${response.status} ${response.statusText}`; try { const payload = await response.json(); detail = typeof payload.detail === "string" ? payload.detail : detail; } catch { /* keep HTTP status */ } throw new Error(detail); } if (response.status === 204) return undefined as T; return response.json() as Promise<T>; }

ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><Root /></React.StrictMode>);












