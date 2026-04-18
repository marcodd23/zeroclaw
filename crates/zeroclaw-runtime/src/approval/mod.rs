//! Interactive approval workflow for supervised mode.
//!
//! Provides a pre-execution hook that prompts the user before tool calls,
//! with session-scoped "Always" allowlists and audit logging.

use crate::security::AutonomyLevel;
use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use zeroclaw_config::schema::AutonomyConfig;

// ── Types ────────────────────────────────────────────────────────

/// A request to approve a tool call before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub tool_name: String,
    pub arguments: serde_json::Value,
}

/// The user's response to an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalResponse {
    /// Execute this one call.
    Yes,
    /// Deny this call.
    No,
    /// Execute and add tool to session-scoped allowlist.
    Always,
}

/// A single audit log entry for an approval decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalLogEntry {
    pub timestamp: String,
    pub tool_name: String,
    pub arguments_summary: String,
    pub decision: ApprovalResponse,
    pub channel: String,
}

// ── ApprovalManager ──────────────────────────────────────────────

/// Manages the approval workflow for tool calls.
///
/// - Checks config-level `auto_approve` / `always_ask` lists
/// - Maintains a session-scoped "always" allowlist
/// - Records an audit trail of all decisions
///
/// Two modes:
/// - **Interactive** (CLI): tools needing approval trigger a stdin prompt.
/// - **Non-interactive** (channels): tools needing approval are auto-denied
///   because there is no interactive operator to approve them. `auto_approve`
///   policy is still enforced, and `always_ask` / supervised-default tools are
///   denied rather than silently allowed.
pub struct ApprovalManager {
    /// Tools that never need approval (from config).
    auto_approve: HashSet<String>,
    /// Tools that always need approval, ignoring session allowlist.
    always_ask: HashSet<String>,
    /// Autonomy level from config.
    autonomy_level: AutonomyLevel,
    /// When `true`, tools that would require interactive approval are
    /// auto-denied instead. Used for channel-driven (non-CLI) runs.
    non_interactive: bool,
    /// Session-scoped allowlist built from "Always" responses.
    session_allowlist: Mutex<HashSet<String>>,
    /// Audit trail of approval decisions.
    audit_log: Mutex<Vec<ApprovalLogEntry>>,
}

impl ApprovalManager {
    /// Create an interactive (CLI) approval manager from autonomy config.
    pub fn from_config(config: &AutonomyConfig) -> Self {
        Self {
            auto_approve: config.auto_approve.iter().cloned().collect(),
            always_ask: config.always_ask.iter().cloned().collect(),
            autonomy_level: config.level,
            non_interactive: false,
            session_allowlist: Mutex::new(HashSet::new()),
            audit_log: Mutex::new(Vec::new()),
        }
    }

    /// Create a non-interactive approval manager for channel-driven runs.
    ///
    /// Enforces the same `auto_approve` / `always_ask` / supervised policies
    /// as the CLI manager, but tools that would require interactive approval
    /// are auto-denied instead of prompting (since there is no operator).
    pub fn for_non_interactive(config: &AutonomyConfig) -> Self {
        Self {
            auto_approve: config.auto_approve.iter().cloned().collect(),
            always_ask: config.always_ask.iter().cloned().collect(),
            autonomy_level: config.level,
            non_interactive: true,
            session_allowlist: Mutex::new(HashSet::new()),
            audit_log: Mutex::new(Vec::new()),
        }
    }

    /// Returns `true` when this manager operates in non-interactive mode
    /// (i.e. for channel-driven runs where no operator can approve).
    pub fn is_non_interactive(&self) -> bool {
        self.non_interactive
    }

    /// Check whether a tool call requires interactive approval.
    ///
    /// Returns `true` if the call needs a prompt, `false` if it can proceed.
    pub fn needs_approval(&self, tool_name: &str) -> bool {
        // Full autonomy never prompts.
        if self.autonomy_level == AutonomyLevel::Full {
            return false;
        }

        // ReadOnly blocks everything — handled elsewhere; no prompt needed.
        if self.autonomy_level == AutonomyLevel::ReadOnly {
            return false;
        }

        // always_ask overrides everything.
        if pattern_set_matches(&self.always_ask, tool_name) {
            return true;
        }

        // Channel-driven shell execution is still guarded by the shell tool's
        // own command allowlist and risk policy. Skipping the outer approval
        // gate here lets low-risk allowlisted commands (e.g. `ls`) work in
        // non-interactive channels without silently allowing medium/high-risk
        // commands.
        if self.non_interactive && tool_name == "shell" {
            return false;
        }

        // auto_approve skips the prompt.
        if pattern_set_matches(&self.auto_approve, tool_name) {
            return false;
        }

        // Session allowlist (from prior "Always" responses).
        let allowlist = self.session_allowlist.lock();
        if allowlist.contains(tool_name) {
            return false;
        }

        // Default: supervised mode requires approval.
        true
    }

    /// Record an approval decision and update session state.
    pub fn record_decision(
        &self,
        tool_name: &str,
        args: &serde_json::Value,
        decision: ApprovalResponse,
        channel: &str,
    ) {
        // If "Always", add to session allowlist.
        if decision == ApprovalResponse::Always {
            let mut allowlist = self.session_allowlist.lock();
            allowlist.insert(tool_name.to_string());
        }

        // Append to audit log.
        let summary = summarize_args(args);
        let entry = ApprovalLogEntry {
            timestamp: Utc::now().to_rfc3339(),
            tool_name: tool_name.to_string(),
            arguments_summary: summary,
            decision,
            channel: channel.to_string(),
        };
        let mut log = self.audit_log.lock();
        log.push(entry);
    }

    /// Get a snapshot of the audit log.
    pub fn audit_log(&self) -> Vec<ApprovalLogEntry> {
        self.audit_log.lock().clone()
    }

    /// Get the current session allowlist.
    pub fn session_allowlist(&self) -> HashSet<String> {
        self.session_allowlist.lock().clone()
    }

    /// Prompt the user on the CLI and return their decision.
    ///
    /// Only called for interactive (CLI) managers. Non-interactive managers
    /// auto-deny in the tool-call loop before reaching this point.
    pub fn prompt_cli(&self, request: &ApprovalRequest) -> ApprovalResponse {
        prompt_cli_interactive(request)
    }
}

// ── CLI prompt ───────────────────────────────────────────────────

/// Display the approval prompt and read user input from stdin.
fn prompt_cli_interactive(request: &ApprovalRequest) -> ApprovalResponse {
    let summary = summarize_args(&request.arguments);
    eprintln!();
    eprintln!("🔧 Agent wants to execute: {}", request.tool_name);
    eprintln!("   {summary}");
    eprint!("   [Y]es / [N]o / [A]lways for {}: ", request.tool_name);
    let _ = io::stderr().flush();

    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_err() {
        return ApprovalResponse::No;
    }

    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => ApprovalResponse::Yes,
        "a" | "always" => ApprovalResponse::Always,
        _ => ApprovalResponse::No,
    }
}

/// Produce a short human-readable summary of tool arguments.
pub fn summarize_args(args: &serde_json::Value) -> String {
    match args {
        serde_json::Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| {
                    let val = match v {
                        serde_json::Value::String(s) => truncate_for_summary(s, 80),
                        other => {
                            let s = other.to_string();
                            truncate_for_summary(&s, 80)
                        }
                    };
                    format!("{k}: {val}")
                })
                .collect();
            parts.join(", ")
        }
        other => {
            let s = other.to_string();
            truncate_for_summary(&s, 120)
        }
    }
}

fn truncate_for_summary(input: &str, max_chars: usize) -> String {
    let mut chars = input.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}…")
    } else {
        input.to_string()
    }
}

// ── Pattern matching ─────────────────────────────────────────────

/// Return `true` when `tool_name` matches any entry in `patterns`.
///
/// Two pattern forms are supported:
///   1. Exact string match, e.g. `"file_read"` matches `"file_read"` only.
///   2. Suffix-glob: an entry ending in `*` matches any tool name that
///      starts with the prefix. The bare pattern `"*"` keeps its existing
///      "match anything" semantic.
///
/// The glob form exists specifically for MCP tool names, which are emitted
/// at runtime with a server-name prefix (e.g. `composio__COMPOSIO_SEARCH_TOOLS`,
/// `composio__GMAIL_FETCH_EMAILS`, …). MCP servers like Composio expose
/// hundreds of subtools that are discovered dynamically at `tool_search`
/// time — enumerating them all statically in config would be impossible.
/// A single entry like `"composio__*"` covers every tool from that server.
///
/// The match is kept intentionally narrow (terminal `*` only — no
/// mid-string globs, no character classes, no escapes) so the config
/// surface stays easy to audit: one character of pattern language, one
/// code path.
fn pattern_set_matches(patterns: &HashSet<String>, tool_name: &str) -> bool {
    if patterns.contains("*") || patterns.contains(tool_name) {
        return true;
    }
    patterns.iter().any(|p| {
        // Require at least one character before the `*` so a stray one-char
        // `"*"` entry keeps going through the exact-match branch above —
        // preserves today's "wildcard only as the literal string `*`"
        // semantic without loosening it accidentally.
        p.len() > 1
            && p.ends_with('*')
            && tool_name.starts_with(&p[..p.len() - 1])
    })
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_config::schema::AutonomyConfig;

    fn supervised_config() -> AutonomyConfig {
        AutonomyConfig {
            level: AutonomyLevel::Supervised,
            auto_approve: vec!["file_read".into(), "memory_recall".into()],
            always_ask: vec!["shell".into()],
            ..AutonomyConfig::default()
        }
    }

    fn full_config() -> AutonomyConfig {
        AutonomyConfig {
            level: AutonomyLevel::Full,
            ..AutonomyConfig::default()
        }
    }

    // ── needs_approval ───────────────────────────────────────

    #[test]
    fn auto_approve_tools_skip_prompt() {
        let mgr = ApprovalManager::from_config(&supervised_config());
        assert!(!mgr.needs_approval("file_read"));
        assert!(!mgr.needs_approval("memory_recall"));
    }

    #[test]
    fn always_ask_tools_always_prompt() {
        let mgr = ApprovalManager::from_config(&supervised_config());
        assert!(mgr.needs_approval("shell"));
    }

    #[test]
    fn unknown_tool_needs_approval_in_supervised() {
        let mgr = ApprovalManager::from_config(&supervised_config());
        assert!(mgr.needs_approval("file_write"));
        assert!(mgr.needs_approval("http_request"));
    }

    #[test]
    fn full_autonomy_never_prompts() {
        let mgr = ApprovalManager::from_config(&full_config());
        assert!(!mgr.needs_approval("shell"));
        assert!(!mgr.needs_approval("file_write"));
        assert!(!mgr.needs_approval("anything"));
    }

    #[test]
    fn readonly_never_prompts() {
        let config = AutonomyConfig {
            level: AutonomyLevel::ReadOnly,
            ..AutonomyConfig::default()
        };
        let mgr = ApprovalManager::from_config(&config);
        assert!(!mgr.needs_approval("shell"));
    }

    // ── session allowlist ────────────────────────────────────

    #[test]
    fn always_response_adds_to_session_allowlist() {
        let mgr = ApprovalManager::from_config(&supervised_config());
        assert!(mgr.needs_approval("file_write"));

        mgr.record_decision(
            "file_write",
            &serde_json::json!({"path": "test.txt"}),
            ApprovalResponse::Always,
            "cli",
        );

        // Now file_write should be in session allowlist.
        assert!(!mgr.needs_approval("file_write"));
    }

    #[test]
    fn always_ask_overrides_session_allowlist() {
        let mgr = ApprovalManager::from_config(&supervised_config());

        // Even after "Always" for shell, it should still prompt.
        mgr.record_decision(
            "shell",
            &serde_json::json!({"command": "ls"}),
            ApprovalResponse::Always,
            "cli",
        );

        // shell is in always_ask, so it still needs approval.
        assert!(mgr.needs_approval("shell"));
    }

    #[test]
    fn yes_response_does_not_add_to_allowlist() {
        let mgr = ApprovalManager::from_config(&supervised_config());
        mgr.record_decision(
            "file_write",
            &serde_json::json!({}),
            ApprovalResponse::Yes,
            "cli",
        );
        assert!(mgr.needs_approval("file_write"));
    }

    // ── audit log ────────────────────────────────────────────

    #[test]
    fn audit_log_records_decisions() {
        let mgr = ApprovalManager::from_config(&supervised_config());

        mgr.record_decision(
            "shell",
            &serde_json::json!({"command": "rm -rf ./build/"}),
            ApprovalResponse::No,
            "cli",
        );
        mgr.record_decision(
            "file_write",
            &serde_json::json!({"path": "out.txt", "content": "hello"}),
            ApprovalResponse::Yes,
            "cli",
        );

        let log = mgr.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].tool_name, "shell");
        assert_eq!(log[0].decision, ApprovalResponse::No);
        assert_eq!(log[1].tool_name, "file_write");
        assert_eq!(log[1].decision, ApprovalResponse::Yes);
    }

    #[test]
    fn audit_log_contains_timestamp_and_channel() {
        let mgr = ApprovalManager::from_config(&supervised_config());
        mgr.record_decision(
            "shell",
            &serde_json::json!({"command": "ls"}),
            ApprovalResponse::Yes,
            "telegram",
        );

        let log = mgr.audit_log();
        assert_eq!(log.len(), 1);
        assert!(!log[0].timestamp.is_empty());
        assert_eq!(log[0].channel, "telegram");
    }

    // ── summarize_args ───────────────────────────────────────

    #[test]
    pub fn summarize_args_object() {
        let args = serde_json::json!({"command": "ls -la", "cwd": "/tmp"});
        let summary = summarize_args(&args);
        assert!(summary.contains("command: ls -la"));
        assert!(summary.contains("cwd: /tmp"));
    }

    #[test]
    pub fn summarize_args_truncates_long_values() {
        let long_val = "x".repeat(200);
        let args = serde_json::json!({ "content": long_val });
        let summary = summarize_args(&args);
        assert!(summary.contains('…'));
        assert!(summary.len() < 200);
    }

    #[test]
    pub fn summarize_args_unicode_safe_truncation() {
        let long_val = "🦀".repeat(120);
        let args = serde_json::json!({ "content": long_val });
        let summary = summarize_args(&args);
        assert!(summary.contains("content:"));
        assert!(summary.contains('…'));
    }

    #[test]
    pub fn summarize_args_non_object() {
        let args = serde_json::json!("just a string");
        let summary = summarize_args(&args);
        assert!(summary.contains("just a string"));
    }

    // ── non-interactive (channel) mode ────────────────────────

    #[test]
    fn non_interactive_manager_reports_non_interactive() {
        let mgr = ApprovalManager::for_non_interactive(&supervised_config());
        assert!(mgr.is_non_interactive());
    }

    #[test]
    fn interactive_manager_reports_interactive() {
        let mgr = ApprovalManager::from_config(&supervised_config());
        assert!(!mgr.is_non_interactive());
    }

    #[test]
    fn non_interactive_auto_approve_tools_skip_approval() {
        let mgr = ApprovalManager::for_non_interactive(&supervised_config());
        // auto_approve tools (file_read, memory_recall) should not need approval.
        assert!(!mgr.needs_approval("file_read"));
        assert!(!mgr.needs_approval("memory_recall"));
    }

    #[test]
    fn non_interactive_shell_skips_outer_approval_by_default() {
        let mgr = ApprovalManager::for_non_interactive(&AutonomyConfig::default());
        assert!(!mgr.needs_approval("shell"));
    }

    #[test]
    fn non_interactive_always_ask_tools_need_approval() {
        let mgr = ApprovalManager::for_non_interactive(&supervised_config());
        // always_ask tools (shell) still report as needing approval,
        // so the tool-call loop will auto-deny them in non-interactive mode.
        assert!(mgr.needs_approval("shell"));
    }

    #[test]
    fn non_interactive_unknown_tools_need_approval_in_supervised() {
        let mgr = ApprovalManager::for_non_interactive(&supervised_config());
        // Unknown tools in supervised mode need approval (will be auto-denied
        // by the tool-call loop for non-interactive managers).
        assert!(mgr.needs_approval("file_write"));
        assert!(mgr.needs_approval("http_request"));
    }

    #[test]
    fn non_interactive_full_autonomy_never_needs_approval() {
        let mgr = ApprovalManager::for_non_interactive(&full_config());
        // Full autonomy means no approval needed, even in non-interactive mode.
        assert!(!mgr.needs_approval("shell"));
        assert!(!mgr.needs_approval("file_write"));
        assert!(!mgr.needs_approval("anything"));
    }

    #[test]
    fn non_interactive_readonly_never_needs_approval() {
        let config = AutonomyConfig {
            level: AutonomyLevel::ReadOnly,
            ..AutonomyConfig::default()
        };
        let mgr = ApprovalManager::for_non_interactive(&config);
        // ReadOnly blocks execution elsewhere; approval manager does not prompt.
        assert!(!mgr.needs_approval("shell"));
    }

    #[test]
    fn non_interactive_session_allowlist_still_works() {
        let mgr = ApprovalManager::for_non_interactive(&supervised_config());
        assert!(mgr.needs_approval("file_write"));

        // Simulate an "Always" decision (would come from a prior channel run
        // if the tool was auto-approved somehow, e.g. via config change).
        mgr.record_decision(
            "file_write",
            &serde_json::json!({"path": "test.txt"}),
            ApprovalResponse::Always,
            "telegram",
        );

        assert!(!mgr.needs_approval("file_write"));
    }

    #[test]
    fn non_interactive_always_ask_overrides_session_allowlist() {
        let mgr = ApprovalManager::for_non_interactive(&supervised_config());

        mgr.record_decision(
            "shell",
            &serde_json::json!({"command": "ls"}),
            ApprovalResponse::Always,
            "telegram",
        );

        // shell is in always_ask, so it still needs approval even after "Always".
        assert!(mgr.needs_approval("shell"));
    }

    // ── ApprovalResponse serde ───────────────────────────────

    #[test]
    fn approval_response_serde_roundtrip() {
        let json = serde_json::to_string(&ApprovalResponse::Always).unwrap();
        assert_eq!(json, "\"always\"");
        let parsed: ApprovalResponse = serde_json::from_str("\"no\"").unwrap();
        assert_eq!(parsed, ApprovalResponse::No);
    }

    // ── ApprovalRequest ──────────────────────────────────────

    #[test]
    fn approval_request_serde() {
        let req = ApprovalRequest {
            tool_name: "shell".into(),
            arguments: serde_json::json!({"command": "echo hi"}),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tool_name, "shell");
    }

    // ── Regression: #4247 default approved tools in channels ──

    #[test]
    fn non_interactive_allows_default_auto_approve_tools() {
        let config = AutonomyConfig::default();
        let mgr = ApprovalManager::for_non_interactive(&config);

        for tool in &config.auto_approve {
            assert!(
                !mgr.needs_approval(tool),
                "default auto_approve tool '{tool}' should not need approval in non-interactive mode"
            );
        }
    }

    #[test]
    fn non_interactive_denies_unknown_tools() {
        let config = AutonomyConfig::default();
        let mgr = ApprovalManager::for_non_interactive(&config);
        assert!(
            mgr.needs_approval("some_unknown_tool"),
            "unknown tool should need approval"
        );
    }

    #[test]
    fn non_interactive_weather_is_auto_approved() {
        let config = AutonomyConfig::default();
        let mgr = ApprovalManager::for_non_interactive(&config);
        assert!(
            !mgr.needs_approval("weather"),
            "weather tool must not need approval — it is in the default auto_approve list"
        );
    }

    #[test]
    fn always_ask_overrides_auto_approve() {
        let config = AutonomyConfig {
            always_ask: vec!["weather".into()],
            ..AutonomyConfig::default()
        };
        let mgr = ApprovalManager::for_non_interactive(&config);
        assert!(
            mgr.needs_approval("weather"),
            "always_ask must override auto_approve"
        );
    }

    // ── Suffix-glob patterns (MCP tool names) ────────────────────

    #[test]
    fn auto_approve_prefix_glob_matches_name_with_prefix() {
        // Motivating case: Composio's MCP server exposes tools with names
        // like composio__COMPOSIO_SEARCH_TOOLS, composio__GMAIL_FETCH_EMAILS,
        // composio__CALENDAR_CREATE_EVENT. A single `composio__*` entry in
        // auto_approve should cover all of them — we can't statically
        // enumerate 500+ Composio subtools.
        let config = AutonomyConfig {
            level: AutonomyLevel::Supervised,
            auto_approve: vec!["composio__*".into()],
            always_ask: vec![],
            ..AutonomyConfig::default()
        };
        let mgr = ApprovalManager::for_non_interactive(&config);
        assert!(!mgr.needs_approval("composio__COMPOSIO_SEARCH_TOOLS"));
        assert!(!mgr.needs_approval("composio__GMAIL_FETCH_EMAILS"));
        assert!(!mgr.needs_approval("composio__CALENDAR_CREATE_EVENT"));
    }

    #[test]
    fn auto_approve_prefix_glob_does_not_match_other_prefixes() {
        // Regression guard: the glob must be anchored to the prefix.
        // composio__* must not match slack__SEND_MESSAGE or a bare
        // `composio` tool name (different namespace, not an MCP tool).
        let config = AutonomyConfig {
            level: AutonomyLevel::Supervised,
            auto_approve: vec!["composio__*".into()],
            always_ask: vec![],
            ..AutonomyConfig::default()
        };
        let mgr = ApprovalManager::for_non_interactive(&config);
        assert!(mgr.needs_approval("slack__SEND_MESSAGE"));
        assert!(mgr.needs_approval("composio")); // bare — not prefixed
        assert!(mgr.needs_approval("other__composio_thing"));
    }

    #[test]
    fn auto_approve_prefix_glob_requires_at_least_one_char_before_star() {
        // The bare `"*"` keeps its existing "match anything" semantic.
        // A one-character entry that happens to be `"*"` must go through
        // the exact-match / wildcard branch, not the prefix-glob branch.
        // This test pins the behaviour so a future refactor doesn't
        // accidentally broaden wildcard matching via the glob path.
        let config = AutonomyConfig {
            level: AutonomyLevel::Supervised,
            auto_approve: vec!["*".into()],
            always_ask: vec![],
            ..AutonomyConfig::default()
        };
        let mgr = ApprovalManager::for_non_interactive(&config);
        assert!(!mgr.needs_approval("any_tool_at_all"));
        assert!(!mgr.needs_approval(""));
    }

    #[test]
    fn always_ask_prefix_glob_overrides_auto_approve() {
        // always_ask should support the same suffix-glob as auto_approve.
        // Motivating case: allow `composio__*` broadly via auto_approve,
        // but keep Composio's remote code-exec tools (bash, workbench)
        // behind approval — on non-interactive channels these auto-deny.
        let config = AutonomyConfig {
            level: AutonomyLevel::Supervised,
            auto_approve: vec!["composio__*".into()],
            always_ask: vec![
                "composio__COMPOSIO_REMOTE_BASH_TOOL".into(),
                "composio__COMPOSIO_REMOTE_WORKBENCH".into(),
            ],
            ..AutonomyConfig::default()
        };
        let mgr = ApprovalManager::for_non_interactive(&config);
        // The ordinary Composio tools are still allowed.
        assert!(!mgr.needs_approval("composio__COMPOSIO_SEARCH_TOOLS"));
        assert!(!mgr.needs_approval("composio__GMAIL_FETCH_EMAILS"));
        // The two code-exec tools still require approval (= deny on non-interactive).
        assert!(mgr.needs_approval("composio__COMPOSIO_REMOTE_BASH_TOOL"));
        assert!(mgr.needs_approval("composio__COMPOSIO_REMOTE_WORKBENCH"));
    }

    #[test]
    fn always_ask_prefix_glob_gates_whole_server() {
        // always_ask with a prefix-glob should gate every tool under
        // that prefix. Useful if an operator wants to keep a whole
        // MCP server behind approval.
        let config = AutonomyConfig {
            level: AutonomyLevel::Supervised,
            auto_approve: vec![],
            always_ask: vec!["dangerous__*".into()],
            ..AutonomyConfig::default()
        };
        let mgr = ApprovalManager::for_non_interactive(&config);
        assert!(mgr.needs_approval("dangerous__do_stuff"));
        assert!(mgr.needs_approval("dangerous__other_stuff"));
        // Non-matching prefix still falls through to the default
        // (supervised → needs approval for unknown tools).
        assert!(mgr.needs_approval("safe__thing"));
    }

    // ── pattern_set_matches unit coverage ────────────────────────

    #[test]
    fn pattern_set_matches_exact_wildcard_prefix() {
        let mut patterns = HashSet::new();
        patterns.insert("exact_tool".to_string());
        patterns.insert("composio__*".to_string());

        // Exact match.
        assert!(pattern_set_matches(&patterns, "exact_tool"));
        // Prefix-glob match.
        assert!(pattern_set_matches(&patterns, "composio__anything"));
        assert!(pattern_set_matches(&patterns, "composio__"));
        // No match.
        assert!(!pattern_set_matches(&patterns, "not_listed"));
        assert!(!pattern_set_matches(&patterns, "composio")); // prefix without `__`

        // Bare `*` still matches everything.
        let mut star_only = HashSet::new();
        star_only.insert("*".to_string());
        assert!(pattern_set_matches(&star_only, "anything"));
    }
}
