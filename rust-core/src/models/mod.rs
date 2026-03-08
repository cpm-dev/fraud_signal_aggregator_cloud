// rust-core/src/models/mod.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The source cloud/trigger for this event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    AwsSqs,
    AwsApiGateway,
    GcpPubSub,
    GcpCloudRun,
}

/// The type of activity being evaluated for fraud
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    Transaction,
    LoginAttempt,
    ApiCall,
    AccountChange,
}

/// Raw inbound event from any cloud source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub kind: ActivityKind,
    pub user_id: String,
    pub ip_address: String,
    pub payload: serde_json::Value,
    /// Optional: amount in cents (for Transaction events)
    pub amount_cents: Option<i64>,
    /// Optional: country ISO code
    pub country_code: Option<String>,
}

impl FraudEvent {
    pub fn new(
        source: EventSource,
        kind: ActivityKind,
        user_id: impl Into<String>,
        ip_address: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source,
            kind,
            user_id: user_id.into(),
            ip_address: ip_address.into(),
            payload,
            amount_cents: None,
            country_code: None,
        }
    }

    pub fn with_amount(mut self, cents: i64) -> Self {
        self.amount_cents = Some(cents);
        self
    }

    pub fn with_country(mut self, code: impl Into<String>) -> Self {
        self.country_code = Some(code.into());
        self
    }
}

/// Risk classification output from the scoring engine
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s < 0.25 => RiskLevel::Low,
            s if s < 0.55 => RiskLevel::Medium,
            s if s < 0.80 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }
}

/// Fully processed and scored fraud event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedFraudEvent {
    pub event_id: Uuid,
    pub processed_at: DateTime<Utc>,
    pub user_id: String,
    pub risk_score: f32,
    pub risk_level: RiskLevel,
    pub triggered_rules: Vec<String>,
    pub recommended_action: String,
    pub metadata: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(0.1), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(0.3), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(0.7), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(0.9), RiskLevel::Critical);
    }

    #[test]
    fn test_fraud_event_creation() {
        let payload = serde_json::json!({"key": "value"});
        let event = FraudEvent::new(
            EventSource::AwsSqs,
            ActivityKind::Transaction,
            "user123",
            "192.168.1.1",
            payload.clone(),
        );
        assert_eq!(event.source, EventSource::AwsSqs);
        assert_eq!(event.kind, ActivityKind::Transaction);
        assert_eq!(event.user_id, "user123");
        assert_eq!(event.ip_address, "192.168.1.1");
        assert_eq!(event.payload, payload);
    }
    
    #[test]
    fn test_fraud_event_with_country(){
        let payload = serde_json::json!({"key": "value"});
        let event = FraudEvent::new(
            EventSource::AwsSqs,
            ActivityKind::Transaction,
            "user123",
            "192.168.1.1",
            payload,
        )
        .with_country("US");
        assert_eq!(event.country_code, Some("US".into()));
    }
}