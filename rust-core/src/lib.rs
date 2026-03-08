// rust-core/src/lib.rs
//
// fraud-sentinel-core: multi-cloud fraud signal processing library
//
// Exposes:
//   - Pure Rust API (EventProcessor trait) for native Rust consumers
//   - PyO3 Python bindings for AWS Lambda adapter
//   - C FFI header (future: CGO for Go Cloud Run adapter)

pub mod models;
pub mod storage;
pub mod transform;
pub mod validation;

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use pyo3::types::PyModule;
use serde_json::json;

use models::{ActivityKind, EventSource, FraudEvent};

// ── Native Rust API ───────────────────────────────────────────────────────────

/// High-level processor: validate → score → store
pub struct EventProcessor<S: storage::EventStore> {
    store: S,
}

impl<S: storage::EventStore> EventProcessor<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn process(
        &self,
        event: FraudEvent,
    ) -> Result<models::ProcessedFraudEvent, ProcessingError> {
        // Step 1: Validate
        validation::validate(&event).map_err(|errs| ProcessingError::Validation {
            messages: errs.iter().map(|e| e.to_string()).collect(),
        })?;

        // Step 2: Score & transform
        let processed = transform::score_and_transform(&event)
            .map_err(|e| ProcessingError::Transform { reason: e.to_string() })?;

        // Step 3: Store
        self.store
            .store(&processed)
            .map_err(|e| ProcessingError::Storage { reason: e.to_string() })?;

        tracing::info!(
            event_id = %processed.event_id,
            risk_level = processed.risk_level.label(),
            score = processed.risk_score,
            action = %processed.recommended_action,
            "Event processed"
        );

        Ok(processed)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessingError {
    #[error("Validation failed: {}", messages.join(", "))]
    Validation { messages: Vec<String> },

    #[error("Transform failed: {reason}")]
    Transform { reason: String },

    #[error("Storage failed: {reason}")]
    Storage { reason: String },
}

// ── PyO3 Python Bindings ──────────────────────────────────────────────────────

/// Python-visible result type
#[pyclass]
#[derive(Clone)]
pub struct PyFraudResult {
    #[pyo3(get)]
    pub event_id: String,
    #[pyo3(get)]
    pub user_id: String,
    #[pyo3(get)]
    pub risk_score: f32,
    #[pyo3(get)]
    pub risk_level: String,
    #[pyo3(get)]
    pub triggered_rules: Vec<String>,
    #[pyo3(get)]
    pub recommended_action: String,
}

#[pymethods]
impl PyFraudResult {
    fn __repr__(&self) -> String {
        format!(
            "FraudResult(event_id={}, user_id={}, risk_level={}, score={:.3}, action={})",
            self.event_id, self.user_id, self.risk_level, self.risk_score, self.recommended_action
        )
    }

    /// Serialize to JSON string for Lambda response bodies
    fn to_json(&self) -> String {
        json!({
            "event_id": self.event_id,
            "user_id": self.user_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "triggered_rules": self.triggered_rules,
            "recommended_action": self.recommended_action,
        })
        .to_string()
    }
}

/// Core function exposed to Python.
///
/// Args:
///   user_id (str): The account identifier
///   ip_address (str): Source IP of the request
///   event_type (str): "transaction" | "login_attempt" | "api_call" | "account_change"
///   payload_json (str): JSON string with event-specific fields
///   amount_cents (int | None): For transactions only
///   country_code (str | None): ISO 3166-1 alpha-2
///
/// Returns:
///   FraudResult: Scored and classified event
///
/// Raises:
///   ValueError: On validation or processing failure
#[pyfunction]
#[pyo3(signature = (user_id, ip_address, event_type, payload_json, amount_cents=None, country_code=None))]
pub fn process_event(
    user_id: &str,
    ip_address: &str,
    event_type: &str,
    payload_json: &str,
    amount_cents: Option<i64>,
    country_code: Option<&str>,
) -> PyResult<PyFraudResult> {
    let kind = parse_event_kind(event_type)?;

    let payload: serde_json::Value = serde_json::from_str(payload_json).map_err(|e| {
        PyValueError::new_err(format!("Invalid payload JSON: {e}"))
    })?;

    let mut event = FraudEvent::new(
        EventSource::AwsApiGateway, // overridden by adapter layer
        kind,
        user_id,
        ip_address,
        payload,
    );

    if let Some(cents) = amount_cents {
        event = event.with_amount(cents);
    }
    if let Some(cc) = country_code {
        event = event.with_country(cc);
    }

    // Use in-memory store for Python bindings; real stores live in adapter layer
    let processor = EventProcessor::new(storage::InMemoryStore::new());
    let result = processor.process(event).map_err(|e| {
        PyValueError::new_err(e.to_string())
    })?;

    Ok(PyFraudResult {
        event_id: result.event_id.to_string(),
        user_id: result.user_id,
        risk_score: result.risk_score,
        risk_level: result.risk_level.label().to_string(),
        triggered_rules: result.triggered_rules,
        recommended_action: result.recommended_action,
    })
}

fn parse_event_kind(s: &str) -> PyResult<ActivityKind> {
    match s {
        "transaction" => Ok(ActivityKind::Transaction),
        "login_attempt" => Ok(ActivityKind::LoginAttempt),
        "api_call" => Ok(ActivityKind::ApiCall),
        "account_change" => Ok(ActivityKind::AccountChange),
        other => Err(PyValueError::new_err(format!(
            "Unknown event_type '{}'. Must be one of: transaction, login_attempt, api_call, account_change",
            other
        ))),
    }
}

/// Module registration
#[pymodule]
fn fraud_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(process_event))?;
    m.add_class::<PyFraudResult>()?;
    Ok(())
}