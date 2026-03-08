// rust-core/src/transform/mod.rs
//
// Fraud signal scoring pipeline. Each rule returns a weighted score contribution
// in [0.0, 1.0]. The final score is a weighted sum clamped to [0.0, 1.0].

use crate::models::{ActivityKind, FraudEvent, ProcessedFraudEvent, RiskLevel};
use chrono::Utc;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransformError {
    #[error("Scoring pipeline failed: {reason}")]
    ScoringFailed { reason: String },
}

// ── Rule weights ──────────────────────────────────────────────────────────────

const WEIGHT_HIGH_VALUE_TXN: f32 = 0.35;
const WEIGHT_SUSPICIOUS_COUNTRY: f32 = 0.25;
const WEIGHT_RAPID_API_CALLS: f32 = 0.20;
const WEIGHT_FAILED_LOGIN_BURST: f32 = 0.30;
const WEIGHT_ACCOUNT_CHANGE_AFTER_TXN: f32 = 0.15;
const WEIGHT_UNKNOWN_IP_CLASS: f32 = 0.10;

/// High-risk country codes (illustrative subset)
const HIGH_RISK_COUNTRIES: &[&str] = &["XX", "YY", "ZZ"];

// ── Public API ────────────────────────────────────────────────────────────────

pub fn score_and_transform(event: &FraudEvent) -> Result<ProcessedFraudEvent, TransformError> {
    let mut total_score: f32 = 0.0;
    let mut triggered: Vec<String> = Vec::new();

    // Run all signal evaluators
    evaluate_high_value_transaction(event, &mut total_score, &mut triggered);
    evaluate_suspicious_country(event, &mut total_score, &mut triggered);
    evaluate_failed_login_burst(event, &mut total_score, &mut triggered);
    evaluate_rapid_api_calls(event, &mut total_score, &mut triggered);
    evaluate_account_change_post_txn(event, &mut total_score, &mut triggered);
    evaluate_unknown_ip_class(event, &mut total_score, &mut triggered);

    let risk_score = total_score.clamp(0.0, 1.0);
    let risk_level = RiskLevel::from_score(risk_score);
    let recommended_action = recommend_action(&risk_level, &event.kind);

    Ok(ProcessedFraudEvent {
        event_id: event.id,
        processed_at: Utc::now(),
        user_id: event.user_id.clone(),
        risk_score,
        risk_level,
        triggered_rules: triggered,
        recommended_action,
        metadata: json!({
            "source": event.source,
            "kind": event.kind,
            "ip": event.ip_address,
            "country": event.country_code,
        }),
    })
}

// ── Signal evaluators ─────────────────────────────────────────────────────────

fn evaluate_high_value_transaction(
    event: &FraudEvent,
    score: &mut f32,
    triggered: &mut Vec<String>,
) {
    if let ActivityKind::Transaction = event.kind {
        if let Some(cents) = event.amount_cents {
            // Flag transactions over $5,000
            if cents > 500_000 {
                *score += WEIGHT_HIGH_VALUE_TXN;
                triggered.push(format!(
                    "HIGH_VALUE_TXN(${:.2})",
                    cents as f32 / 100.0
                ));
            }
        }
    }
}

fn evaluate_suspicious_country(
    event: &FraudEvent,
    score: &mut f32,
    triggered: &mut Vec<String>,
) {
    if let Some(ref cc) = event.country_code {
        if HIGH_RISK_COUNTRIES.contains(&cc.as_str()) {
            *score += WEIGHT_SUSPICIOUS_COUNTRY;
            triggered.push(format!("SUSPICIOUS_COUNTRY({})", cc));
        }
    }
}

fn evaluate_failed_login_burst(
    event: &FraudEvent,
    score: &mut f32,
    triggered: &mut Vec<String>,
) {
    if let ActivityKind::LoginAttempt = event.kind {
        // In production: query a sliding-window counter from Redis/DynamoDB.
        // Here we inspect the payload for a pre-aggregated attempt count.
        let attempt_count = event
            .payload
            .get("attempt_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        if attempt_count >= 5 {
            *score += WEIGHT_FAILED_LOGIN_BURST;
            triggered.push(format!("FAILED_LOGIN_BURST(count={})", attempt_count));
        }
    }
}

fn evaluate_rapid_api_calls(
    event: &FraudEvent,
    score: &mut f32,
    triggered: &mut Vec<String>,
) {
    if let ActivityKind::ApiCall = event.kind {
        let calls_per_min = event
            .payload
            .get("calls_per_minute")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        if calls_per_min > 120 {
            *score += WEIGHT_RAPID_API_CALLS;
            triggered.push(format!("RAPID_API_CALLS(rpm={})", calls_per_min));
        }
    }
}

fn evaluate_account_change_post_txn(
    event: &FraudEvent,
    score: &mut f32,
    triggered: &mut Vec<String>,
) {
    if let ActivityKind::AccountChange = event.kind {
        // Payload may carry a `seconds_since_last_txn` hint from upstream
        let secs = event
            .payload
            .get("seconds_since_last_txn")
            .and_then(|v| v.as_i64())
            .unwrap_or(i64::MAX);

        if secs < 60 {
            *score += WEIGHT_ACCOUNT_CHANGE_AFTER_TXN;
            triggered.push(format!(
                "ACCOUNT_CHANGE_POST_TXN({}s after txn)",
                secs
            ));
        }
    }
}

fn evaluate_unknown_ip_class(
    event: &FraudEvent,
    score: &mut f32,
    triggered: &mut Vec<String>,
) {
    // Flag Tor exit nodes, data-center ranges, or unroutable blocks
    // In production: check against a threat-intel IP list.
    // Here: flag 10.x.x.x as "internal/unexpected" for demo purposes.
    if event.ip_address.starts_with("10.") {
        *score += WEIGHT_UNKNOWN_IP_CLASS;
        triggered.push(format!("UNEXPECTED_IP_CLASS({})", event.ip_address));
    }
}

fn recommend_action(level: &RiskLevel, kind: &ActivityKind) -> String {
    match level {
        RiskLevel::Critical => "BLOCK_AND_ALERT".into(),
        RiskLevel::High => match kind {
            ActivityKind::Transaction => "HOLD_FOR_REVIEW".into(),
            ActivityKind::LoginAttempt => "REQUIRE_MFA".into(),
            _ => "FLAG_FOR_REVIEW".into(),
        },
        RiskLevel::Medium => "STEP_UP_AUTH".into(),
        RiskLevel::Low => "ALLOW".into(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ActivityKind, EventSource, FraudEvent};
    use serde_json::json;

    #[test]
    fn low_risk_event_scores_low() {
        let event = FraudEvent::new(
            EventSource::AwsSqs,
            ActivityKind::LoginAttempt,
            "user-1",
            "1.2.3.4",
            json!({"attempt_count": 1}),
        );
        let result = score_and_transform(&event).unwrap();
        assert_eq!(result.risk_level, RiskLevel::Low);
        assert_eq!(result.recommended_action, "ALLOW");
    }

    #[test]
    fn high_value_transaction_raises_score() {
        let event = FraudEvent::new(
            EventSource::AwsApiGateway,
            ActivityKind::Transaction,
            "user-2",
            "1.2.3.4",
            json!({"merchant": "acme"}),
        )
        .with_amount(600_000) // $6,000
        .with_country("US");

        let result = score_and_transform(&event).unwrap();
        assert!(result.risk_score >= WEIGHT_HIGH_VALUE_TXN);
        assert!(result
            .triggered_rules
            .iter()
            .any(|r| r.starts_with("HIGH_VALUE_TXN")));
    }

    #[test]
    fn multiple_signals_accumulate() {
        let event = FraudEvent::new(
            EventSource::GcpPubSub,
            ActivityKind::Transaction,
            "user-3",
            "1.2.3.4",
            json!({}),
        )
        .with_amount(750_000) // $7,500 — triggers HIGH_VALUE_TXN
        .with_country("XX"); // triggers SUSPICIOUS_COUNTRY

        let result = score_and_transform(&event).unwrap();
        assert!(result.risk_score >= WEIGHT_HIGH_VALUE_TXN + WEIGHT_SUSPICIOUS_COUNTRY - 0.01);
        assert!(result.risk_level == RiskLevel::High || result.risk_level == RiskLevel::Critical);
    }

    #[test]
    fn login_burst_triggers_mfa() {
        let event = FraudEvent::new(
            EventSource::AwsSqs,
            ActivityKind::LoginAttempt,
            "user-4",
            "203.0.113.5",
            json!({"attempt_count": 7}),
        );
        let result = score_and_transform(&event).unwrap();
        assert!(result
            .triggered_rules
            .iter()
            .any(|r| r.starts_with("FAILED_LOGIN_BURST")));
    }
}
