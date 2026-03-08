// rust-core/src/validation/mod.rs
use crate::models::FraudEvent;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Missing required field: {field}")]
    MissingField { field: String },

    #[error("Invalid IP address format: {ip}")]
    InvalidIpAddress { ip: String },

    #[error("Invalid amount: {reason}")]
    InvalidAmount { reason: String },

    #[error("Event too old: timestamp is {age_secs}s in the past (max {max_secs}s)")]
    EventTooOld { age_secs: i64, max_secs: i64 },

    #[error("Payload validation failed: {reason}")]
    PayloadError { reason: String },
}

const MAX_EVENT_AGE_SECS: i64 = 300; // 5 minutes

pub fn validate(event: &FraudEvent) -> Result<(), Vec<ValidationError>> {
    let mut errors: Vec<ValidationError> = Vec::new();

    // user_id must be non-empty
    if event.user_id.trim().is_empty() {
        errors.push(ValidationError::MissingField {
            field: "user_id".into(),
        });
    }

    // ip_address basic sanity check
    if !is_valid_ip(&event.ip_address) {
        errors.push(ValidationError::InvalidIpAddress {
            ip: event.ip_address.clone(),
        });
    }

    // Transaction events must have a positive amount
    if let crate::models::ActivityKind::Transaction = event.kind {
        match event.amount_cents {
            None => errors.push(ValidationError::InvalidAmount {
                reason: "Transaction events require amount_cents".into(),
            }),
            Some(a) if a <= 0 => errors.push(ValidationError::InvalidAmount {
                reason: format!("amount_cents must be positive, got {a}"),
            }),
            _ => {}
        }
    }

    // Reject stale events (replay attacks)
    let age_secs = (chrono::Utc::now() - event.timestamp).num_seconds();
    if age_secs > MAX_EVENT_AGE_SECS {
        errors.push(ValidationError::EventTooOld {
            age_secs,
            max_secs: MAX_EVENT_AGE_SECS,
        });
    }

    // Payload must be a JSON object (not array/null/primitive)
    if !event.payload.is_object() {
        errors.push(ValidationError::PayloadError {
            reason: "payload must be a JSON object".into(),
        });
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn is_valid_ip(ip: &str) -> bool {
    if ip.trim().is_empty() {
        return false;
    }
    // Accept IPv4 and IPv6 — lean on std parse
    ip.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ActivityKind, EventSource, FraudEvent};
    use serde_json::json;

    fn base_event() -> FraudEvent {
        FraudEvent::new(
            EventSource::AwsSqs,
            ActivityKind::LoginAttempt,
            "user-123",
            "192.168.1.1",
            json!({"device": "mobile"}),
        )
    }

    #[test]
    fn valid_event_passes() {
        assert!(validate(&base_event()).is_ok());
    }

    #[test]
    fn empty_user_id_fails() {
        let mut e = base_event();
        e.user_id = "".into();
        let errs = validate(&e).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::MissingField { .. })));
    }

    #[test]
    fn invalid_ip_fails() {
        let mut e = base_event();
        e.ip_address = "not-an-ip".into();
        let errs = validate(&e).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::InvalidIpAddress { .. })));
    }

    #[test]
    fn transaction_without_amount_fails() {
        let e = FraudEvent::new(
            EventSource::AwsApiGateway,
            ActivityKind::Transaction,
            "user-456",
            "10.0.0.1",
            json!({"merchant": "acme"}),
        );
        let errs = validate(&e).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ValidationError::InvalidAmount { .. })));
    }

    #[test]
    fn transaction_with_positive_amount_passes() {
        let e = FraudEvent::new(
            EventSource::AwsApiGateway,
            ActivityKind::Transaction,
            "user-456",
            "10.0.0.1",
            json!({"merchant": "acme"}),
        )
        .with_amount(9999);
        assert!(validate(&e).is_ok());
    }
}
