//! Code execution tool — runs Python/Node.js/bash in an isolated sandbox container.
//!
//! Executes code in a separate network-isolated container managed by the Chelar
//! platform. The sandbox has no internet access, can only read/write the workspace
//! directory, and is separate from the main agent container.
//!
//! The tool calls the Go API directly via an internal endpoint. The API address
//! and tenant ID are provided via env vars (CHELAR_SANDBOX_API_URL, CHELAR_TENANT_ID).

use super::traits::{Tool, ToolResult};
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

/// Code execution tool — delegates to the Chelar sandbox sidecar container.
pub struct CodeExecTool {
    security: Arc<SecurityPolicy>,
    /// Full URL for the sandbox exec endpoint (e.g. "http://172.17.0.1:8081/api/sandbox/exec").
    api_url: String,
    /// Tenant ID for the sandbox request.
    tenant_id: String,
}

impl CodeExecTool {
    /// Create a new CodeExecTool from environment variables.
    /// Returns None if the required env vars are not set.
    pub fn from_env(security: Arc<SecurityPolicy>) -> Option<Self> {
        let api_url = std::env::var("CHELAR_SANDBOX_API_URL").ok()?;
        let tenant_id = std::env::var("CHELAR_TENANT_ID").ok()?;
        if api_url.is_empty() || tenant_id.is_empty() {
            return None;
        }
        tracing::info!("code_exec tool registered (sandbox API: {api_url})");
        Some(Self {
            security,
            api_url,
            tenant_id,
        })
    }
}

#[async_trait]
impl Tool for CodeExecTool {
    fn name(&self) -> &str {
        "code_exec"
    }

    fn description(&self) -> &str {
        "Execute Python, Node.js, or bash code in an isolated sandbox container. \
         The sandbox has no internet access and can only read/write workspace files. \
         Use for data processing, calculations, file transformations, and scripting tasks. \
         Available languages: python, node, bash."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "language": {
                    "type": "string",
                    "description": "Programming language: 'python', 'node', or 'bash'",
                    "enum": ["python", "node", "bash"]
                },
                "code": {
                    "type": "string",
                    "description": "The code to execute"
                },
                "timeout_secs": {
                    "type": "integer",
                    "description": "Execution timeout in seconds (default: 30, max: 60)"
                }
            },
            "required": ["language", "code"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        // Check autonomy policy.
        if !self.security.can_act() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Action blocked: autonomy is read-only".into()),
            });
        }
        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Action blocked: rate limit exceeded".into()),
            });
        }

        let language = args
            .get("language")
            .and_then(|v| v.as_str())
            .unwrap_or("python");
        let code = args
            .get("code")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'code' parameter"))?;
        let timeout_secs = args
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .map(|v| v.min(60) as i32)
            .unwrap_or(30);

        // Call the Go API sandbox endpoint directly.
        // The API URL points to a dedicated internal port that is allowed
        // through iptables (unlike the main API on port 8080).
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs((timeout_secs as u64) + 10))
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {e}"))?;

        let body = json!({
            "language": language,
            "code": code,
            "timeout_secs": timeout_secs,
        });

        let url = format!(
            "{}/api/tenants/{}/sandbox/exec",
            self.api_url, self.tenant_id
        );
        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                let result: serde_json::Value = r.json().await.unwrap_or_default();
                let stdout = result["stdout"].as_str().unwrap_or("");
                let stderr = result["stderr"].as_str().unwrap_or("");
                let exit_code = result["exit_code"].as_i64().unwrap_or(-1);
                let duration_ms = result["duration_ms"].as_i64().unwrap_or(0);

                let mut output = String::new();
                if !stdout.is_empty() {
                    output.push_str(stdout);
                }
                if !stderr.is_empty() {
                    if !output.is_empty() {
                        output.push_str("\n--- stderr ---\n");
                    }
                    output.push_str(stderr);
                }
                if output.is_empty() {
                    output = format!("(no output, exit code: {exit_code})");
                } else {
                    output.push_str(&format!("\n[exit code: {exit_code}, {duration_ms}ms]"));
                }

                Ok(ToolResult {
                    success: exit_code == 0,
                    output,
                    error: if exit_code != 0 {
                        Some(format!("Process exited with code {exit_code}"))
                    } else {
                        None
                    },
                })
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Sandbox exec failed: HTTP {status} — {body}")),
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Sandbox exec request failed: {e}")),
            }),
        }
    }
}
