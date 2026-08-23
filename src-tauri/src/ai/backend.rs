//! `AiBackend` trait and its implementations (§21.10). Every backend
//! returns [`AiOutcome`] rather than a bare `Result` — a failed,
//! timed-out, or unavailable AI call is not an error condition the
//! pipeline propagates, it's a normal, always-handled outcome (§21.9:
//! "the transaction proceeds on deterministic policy alone"), so the type
//! itself has no `Err` variant for callers to be tempted to `?`-propagate
//! past the point where §21.9's fallback is supposed to happen.

use std::time::Duration;

use crate::ai::schema::{AiPlan, AiRequest};
use crate::ai::validation;

#[derive(Debug, Clone, PartialEq)]
pub enum AiOutcome {
    Analyzed(AiPlan),
    /// §21.9: "the `ai_skipped` flag is set with a reason." Timeout,
    /// transport failure, schema-validation failure, and "AI disabled"
    /// all land here — the pipeline treats every one of them identically,
    /// which is the whole point of collapsing them into one variant
    /// rather than a backend-specific error enum callers would need to
    /// match on to decide whether to fall back (they never need to
    /// decide; falling back is the only behavior that exists).
    Skipped {
        reason: String,
    },
}

pub trait AiBackend {
    fn name(&self) -> &'static str;
    fn analyze(&self, request: &AiRequest) -> AiOutcome;
}

/// §21.10: "`NullBackend` is a first-class supported configuration:
/// SafeShell is fully functional, including all security properties,
/// with the AI disabled entirely."
pub struct NullBackend;

impl AiBackend for NullBackend {
    fn name(&self) -> &'static str {
        "NullBackend"
    }

    fn analyze(&self, _request: &AiRequest) -> AiOutcome {
        AiOutcome::Skipped {
            reason: "AI disabled (NullBackend)".to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum TransportError {
    #[error("AI call timed out")]
    Timeout,
    #[error("AI call failed: {0}")]
    Other(String),
}

/// §21.10's MVP default: a remote HTTP endpoint returning §21.6's JSON
/// shape directly in the response body. Deliberately vendor-agnostic —
/// the architecture specifies "remote API" but no particular vendor
/// contract, and hardcoding one specific provider's request/response
/// envelope here would be a claim this document never makes. Point
/// `endpoint` at whatever adapter translates to/from a specific vendor's
/// API; this type's job is exactly the two things §21 actually specifies:
/// a hard timeout (§21.9) and mandatory validation of whatever comes back
/// (§21.7) before it's ever treated as real.
///
/// **Unverified against a real model in this dev environment**: no API
/// key is configured here, and this project makes no outbound call to a
/// real AI provider as part of its own test suite. What *is* real and
/// tested (`tests/ai_schema_validation_tests` and this module's own unit
/// tests) is the HTTP/timeout/parse-failure machinery itself, exercised
/// against a local, in-process HTTP server the tests spin up — the exact
/// same code path a real endpoint would go through, just pointed at
/// `127.0.0.1` instead of a real host.
pub struct RemoteBackend {
    endpoint: String,
    api_key: Option<String>,
    timeout: Duration,
}

impl RemoteBackend {
    /// §21.9: "Hard 2.5 s default deadline."
    const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2500);

    pub fn new(endpoint: impl Into<String>) -> Self {
        RemoteBackend {
            endpoint: endpoint.into(),
            api_key: None,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn call(&self, request: &AiRequest) -> Result<String, TransportError> {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .build();
        let agent: ureq::Agent = config.into();

        let mut builder = agent
            .post(&self.endpoint)
            .header("Content-Type", "application/json");
        if let Some(key) = &self.api_key {
            builder = builder.header("Authorization", &format!("Bearer {key}"));
        }

        let mut response = builder.send_json(request).map_err(|e| match e {
            ureq::Error::Timeout(_) => TransportError::Timeout,
            other => TransportError::Other(other.to_string()),
        })?;

        response
            .body_mut()
            .read_to_string()
            .map_err(|e| TransportError::Other(e.to_string()))
    }
}

impl AiBackend for RemoteBackend {
    fn name(&self) -> &'static str {
        "RemoteBackend"
    }

    fn analyze(&self, request: &AiRequest) -> AiOutcome {
        let raw = match self.call(request) {
            Ok(body) => body,
            Err(e) => {
                return AiOutcome::Skipped {
                    reason: e.to_string(),
                }
            }
        };

        match validation::validate(&raw) {
            Ok(plan) => AiOutcome::Analyzed(plan),
            Err(e) => AiOutcome::Skipped {
                reason: format!("AI response failed validation: {e}"),
            },
        }
    }
}

/// §21.10's "local... model" deployment option, spoken as Ollama's actual
/// `/api/generate` contract — unlike [`RemoteBackend`], whose whole point
/// is staying vendor-agnostic by expecting the endpoint to already speak
/// §21.6's JSON shape directly. A real Ollama server doesn't: it wants
/// `{model, prompt, stream, format}` and hands back the model's raw text
/// wrapped in its own `{"response": "...", ...}` envelope. This backend's
/// only two jobs are building the prompt that asks the model for exactly
/// §21.6's schema (closed enum values spelled out, since an LLM has no
/// other way to know them) and unwrapping that envelope — the extracted
/// text then goes through the **exact same** [`validation::validate`]
/// [`RemoteBackend`] uses. Nothing about §21.7's "discarded wholesale,
/// never partially salvaged, adversarial output cannot alter any
/// decision" changes just because the source is a local model instead of
/// a hosted one — a compromised or hallucinating local model is exactly
/// as untrusted as a compromised remote one, and both are `AiBackend`s
/// whose output the deterministic Policy Engine never depends on (§21.7,
/// `tests/ai_schema_validation_tests`).
///
/// **Default timeout is 30s, not §21.9's 2.5s.** That figure is written
/// with a fast hosted API's round trip in mind and §21.9 itself calls it
/// "default... configurable," not a fixed constant — a local model doing
/// CPU-bound token generation for a ~170-token structured JSON response
/// routinely takes several seconds even once loaded (measured ~9s for a
/// 3B model against a real local server during development), so reusing
/// `RemoteBackend`'s figure here would mean every real call times out and
/// the backend never actually returns an analysis in practice, which
/// defeats the point of supporting it at all. Still fully overridable via
/// [`with_timeout`](Self::with_timeout) — `main.rs` exposes
/// `SAFESHELL_OLLAMA_TIMEOUT_MS` for tuning to the host's actual hardware.
pub struct OllamaBackend {
    endpoint: String,
    model: String,
    timeout: Duration,
}

impl OllamaBackend {
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn new(endpoint: impl Into<String>, model: impl Into<String>) -> Self {
        OllamaBackend {
            endpoint: endpoint.into(),
            model: model.into(),
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn call(&self, prompt: &str) -> Result<String, TransportError> {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .build();
        let agent: ureq::Agent = config.into();

        let url = format!("{}/api/generate", self.endpoint.trim_end_matches('/'));
        let body = OllamaGenerateRequest {
            model: &self.model,
            prompt,
            stream: false,
            // Ollama-level guarantee that the model emits syntactically
            // valid JSON — it says nothing about matching §21.6's
            // *specific* schema, which is still `validation::validate`'s
            // job below, exactly as with any other backend's output.
            format: "json",
        };

        let mut response = agent
            .post(&url)
            .header("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| match e {
                ureq::Error::Timeout(_) => TransportError::Timeout,
                other => TransportError::Other(other.to_string()),
            })?;

        let raw = response
            .body_mut()
            .read_to_string()
            .map_err(|e| TransportError::Other(e.to_string()))?;

        let envelope: OllamaGenerateResponse = serde_json::from_str(&raw)
            .map_err(|e| TransportError::Other(format!("malformed Ollama response: {e}")))?;
        Ok(envelope.response)
    }
}

#[derive(serde::Serialize)]
struct OllamaGenerateRequest<'a> {
    model: &'a str,
    prompt: &'a str,
    stream: bool,
    format: &'a str,
}

#[derive(serde::Deserialize)]
struct OllamaGenerateResponse {
    response: String,
}

/// Builds the prompt sent as Ollama's `prompt` field: the command and
/// deterministic policy context §21.1 says the AI receives, plus §21.6's
/// schema spelled out field-by-field with every closed enum's exact
/// snake_case values (an LLM has no other way to learn a taxonomy this
/// codebase enforces at the type level) and an explicit "JSON only, no
/// prose" instruction. Free-standing and unit-tested on its own — the
/// wording matters (a vague prompt reliably produces output
/// `validation::validate` rejects), so it's worth being able to assert on
/// without a real model or network call.
fn build_prompt(request: &AiRequest) -> String {
    format!(
        r#"You are the advisory AI planner for SafeShell, a transactional shell sandbox. You analyze a command that a deterministic Policy Engine has already classified; your output is advisory only and never changes what is allowed to run. Respond with a single JSON object and nothing else — no markdown, no code fences, no commentary before or after it.

Command: {command_text}
Policy category: {category}
Policy risk level: {risk_level}
Policy reasons: {policy_reasons}

Respond with exactly this JSON shape:
{{
  "schema_version": "1.0",
  "command": "<the command text, verbatim>",
  "intent": "<one of: navigation, file_read, file_write, directory_create, recursive_delete, permission_change, ownership_change, package_removal, other>",
  "risk_level": "<one of: low, medium, high, critical>",
  "affected_resources": ["<path or resource strings>"],
  "predicted_effects": {{
    "files_deleted_estimate": <integer>,
    "directories_deleted_estimate": <integer>,
    "escapes_sandbox": <true|false>
  }},
  "preconditions": ["<strings describing what must be true beforehand>"],
  "reversible_within_safeshell": <true|false>,
  "recovery_recommendation": {{
    "strategy": "<one of: restore_pre_transaction_snapshot, no_recovery_needed, not_reversible>",
    "description": "<short human-readable recovery guidance>"
  }},
  "external_side_effects": <true|false>,
  "confidence": <number between 0.0 and 1.0>,
  "explanation": "<a short, plain-language explanation of what this command does>"
}}

Every enum field must use exactly one of the listed values — no other strings are valid. Output only the JSON object."#,
        command_text = request.command_text,
        category = request.category.unwrap_or("unknown"),
        risk_level = request
            .risk_level
            .map(|r| format!("{r:?}"))
            .unwrap_or_else(|| "none".to_string()),
        policy_reasons = if request.policy_reasons.is_empty() {
            "none".to_string()
        } else {
            request.policy_reasons.join("; ")
        },
    )
}

impl AiBackend for OllamaBackend {
    fn name(&self) -> &'static str {
        "OllamaBackend"
    }

    fn analyze(&self, request: &AiRequest) -> AiOutcome {
        let prompt = build_prompt(request);
        let raw = match self.call(&prompt) {
            Ok(text) => text,
            Err(e) => {
                return AiOutcome::Skipped {
                    reason: e.to_string(),
                }
            }
        };

        match validation::validate(&raw) {
            Ok(plan) => AiOutcome::Analyzed(plan),
            Err(e) => AiOutcome::Skipped {
                reason: format!("AI response failed validation: {e}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn sample_request() -> AiRequest {
        AiRequest {
            command_text: "mkdir project".to_string(),
            category: Some("safe"),
            risk_level: None,
            policy_reasons: vec![],
        }
    }

    fn valid_plan_json() -> &'static str {
        r#"{
            "schema_version": "1.0",
            "command": "mkdir project",
            "intent": "directory_create",
            "risk_level": "low",
            "affected_resources": ["project"],
            "predicted_effects": {
                "files_deleted_estimate": 0,
                "directories_deleted_estimate": 0,
                "escapes_sandbox": false
            },
            "preconditions": [],
            "reversible_within_safeshell": true,
            "recovery_recommendation": {
                "strategy": "no_recovery_needed",
                "description": "Nothing to recover."
            },
            "external_side_effects": false,
            "confidence": 0.95,
            "explanation": "Creates a new directory named project."
        }"#
    }

    /// Spins up a real, in-process TCP server on `127.0.0.1` that reads
    /// exactly one HTTP request and responds with `body` verbatim after
    /// waiting `delay`. No mocking of `RemoteBackend` or `ureq` — the
    /// backend under test makes a real HTTP request over a real socket.
    fn serve_once(body: &'static str, delay: Duration) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf); // discard the request itself
            thread::sleep(delay);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        });
        format!("http://{addr}")
    }

    /// Same as [`serve_once`] but for a body assembled at test-run time
    /// (e.g. via `serde_json::json!`) rather than a `&'static str`
    /// literal — leaks it to get the `'static` lifetime the spawned
    /// thread needs, which is fine for a short-lived test process.
    fn serve_once_leaked(body: String, delay: Duration) -> String {
        serve_once(Box::leak(body.into_boxed_str()), delay)
    }

    #[test]
    fn null_backend_always_skips_and_never_touches_the_network() {
        let backend = NullBackend;
        let outcome = backend.analyze(&sample_request());
        assert!(matches!(outcome, AiOutcome::Skipped { .. }));
        assert_eq!(backend.name(), "NullBackend");
    }

    #[test]
    fn remote_backend_analyzes_a_well_formed_response_from_a_real_http_call() {
        let endpoint = serve_once(valid_plan_json(), Duration::from_millis(0));
        let backend = RemoteBackend::new(endpoint);

        let outcome = backend.analyze(&sample_request());
        match outcome {
            AiOutcome::Analyzed(plan) => assert_eq!(plan.command, "mkdir project"),
            AiOutcome::Skipped { reason } => panic!("expected Analyzed, got Skipped: {reason}"),
        }
    }

    #[test]
    fn remote_backend_skips_on_malformed_response_body() {
        let endpoint = serve_once("this is not json", Duration::from_millis(0));
        let backend = RemoteBackend::new(endpoint);

        let outcome = backend.analyze(&sample_request());
        assert!(matches!(outcome, AiOutcome::Skipped { .. }));
    }

    #[test]
    fn remote_backend_skips_when_the_server_is_slower_than_the_configured_timeout() {
        let endpoint = serve_once(valid_plan_json(), Duration::from_millis(300));
        let backend = RemoteBackend::new(endpoint).with_timeout(Duration::from_millis(50));

        let outcome = backend.analyze(&sample_request());
        match outcome {
            AiOutcome::Skipped { reason } => assert!(reason.contains("timed out")),
            AiOutcome::Analyzed(_) => panic!("expected a timeout, got a successful analysis"),
        }
    }

    #[test]
    fn remote_backend_skips_when_nothing_is_listening_at_all() {
        // A real, guaranteed-closed port: bind then immediately drop the
        // listener, so the address is real but refuses the connection.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let backend = RemoteBackend::new(format!("http://{addr}"));
        let outcome = backend.analyze(&sample_request());
        assert!(matches!(outcome, AiOutcome::Skipped { .. }));
    }

    fn ollama_envelope(inner_response_json: &str) -> String {
        serde_json::json!({
            "model": "llama3.1",
            "response": inner_response_json,
            "done": true
        })
        .to_string()
    }

    #[test]
    fn ollama_backend_analyzes_a_well_formed_response_from_a_real_http_call() {
        let endpoint =
            serve_once_leaked(ollama_envelope(valid_plan_json()), Duration::from_millis(0));
        let backend = OllamaBackend::new(endpoint, "llama3.1");

        let outcome = backend.analyze(&sample_request());
        match outcome {
            AiOutcome::Analyzed(plan) => assert_eq!(plan.command, "mkdir project"),
            AiOutcome::Skipped { reason } => panic!("expected Analyzed, got Skipped: {reason}"),
        }
    }

    #[test]
    fn ollama_backend_skips_when_the_envelope_itself_is_not_json() {
        let endpoint = serve_once("not an ollama envelope at all", Duration::from_millis(0));
        let backend = OllamaBackend::new(endpoint, "llama3.1");

        let outcome = backend.analyze(&sample_request());
        match outcome {
            AiOutcome::Skipped { reason } => assert!(reason.contains("malformed Ollama response")),
            AiOutcome::Analyzed(_) => panic!("expected Skipped for a non-JSON envelope"),
        }
    }

    #[test]
    fn ollama_backend_skips_when_the_models_response_field_is_not_a_valid_plan() {
        let endpoint = serve_once_leaked(
            ollama_envelope("the model rambled instead of returning JSON"),
            Duration::from_millis(0),
        );
        let backend = OllamaBackend::new(endpoint, "llama3.1");

        let outcome = backend.analyze(&sample_request());
        assert!(matches!(outcome, AiOutcome::Skipped { .. }));
    }

    #[test]
    fn ollama_backend_skips_when_the_server_is_slower_than_the_configured_timeout() {
        let endpoint = serve_once_leaked(
            ollama_envelope(valid_plan_json()),
            Duration::from_millis(300),
        );
        let backend =
            OllamaBackend::new(endpoint, "llama3.1").with_timeout(Duration::from_millis(50));

        let outcome = backend.analyze(&sample_request());
        match outcome {
            AiOutcome::Skipped { reason } => assert!(reason.contains("timed out")),
            AiOutcome::Analyzed(_) => panic!("expected a timeout, got a successful analysis"),
        }
    }

    #[test]
    fn ollama_backend_default_timeout_tolerates_slow_local_generation() {
        // Regression guard: a real local model generating a ~170-token
        // structured response routinely takes several seconds (measured
        // ~9s against a real Ollama server during development) — the
        // default must comfortably exceed that, not `RemoteBackend`'s
        // 2.5s figure written for a fast hosted API's round trip.
        let endpoint = serve_once_leaked(
            ollama_envelope(valid_plan_json()),
            Duration::from_millis(800),
        );
        let backend = OllamaBackend::new(endpoint, "llama3.1");

        let outcome = backend.analyze(&sample_request());
        assert!(
            matches!(outcome, AiOutcome::Analyzed(_)),
            "expected the default timeout to tolerate an 800ms response, got: {outcome:?}"
        );
    }

    #[test]
    fn ollama_backend_skips_when_nothing_is_listening_at_all() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let backend = OllamaBackend::new(format!("http://{addr}"), "llama3.1");
        let outcome = backend.analyze(&sample_request());
        assert!(matches!(outcome, AiOutcome::Skipped { .. }));
    }

    #[test]
    fn build_prompt_embeds_the_command_and_every_closed_enum_value() {
        let prompt = build_prompt(&sample_request());
        assert!(prompt.contains("mkdir project"));
        for intent in [
            "navigation",
            "file_read",
            "file_write",
            "directory_create",
            "recursive_delete",
            "permission_change",
            "ownership_change",
            "package_removal",
            "other",
        ] {
            assert!(prompt.contains(intent), "missing intent value: {intent}");
        }
        for risk in ["low", "medium", "high", "critical"] {
            assert!(prompt.contains(risk), "missing risk_level value: {risk}");
        }
        for strategy in [
            "restore_pre_transaction_snapshot",
            "no_recovery_needed",
            "not_reversible",
        ] {
            assert!(
                prompt.contains(strategy),
                "missing recovery strategy: {strategy}"
            );
        }
    }
}
