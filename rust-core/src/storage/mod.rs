// rust-core/src/storage/mod.rs
use crate::models::ProcessedFraudEvent;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Connection failed: {reason}")]
    ConnectionFailed { reason: String },

    #[error("Write failed for event {event_id}: {reason}")]
    WriteFailed { event_id: String, reason: String },

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Cloud-agnostic storage interface. Each cloud backend implements this trait.
pub trait EventStore: Send + Sync {
    fn store(&self, event: &ProcessedFraudEvent) -> Result<(), StorageError>;
    fn backend_name(&self) -> &'static str;
}

// ── AWS DynamoDB backend ──────────────────────────────────────────────────────

pub struct DynamoDbStore {
    pub table_name: String,
    pub region: String,
}

impl DynamoDbStore {
    pub fn new(table_name: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            region: region.into(),
        }
    }
}

impl EventStore for DynamoDbStore {
    fn store(&self, event: &ProcessedFraudEvent) -> Result<(), StorageError> {
        // In production: use aws-sdk-dynamodb crate
        // aws_sdk_dynamodb::Client::from_env()
        //   .put_item()
        //   .table_name(&self.table_name)
        //   .item("event_id", AttributeValue::S(event.event_id.to_string()))
        //   .item("risk_score", AttributeValue::N(event.risk_score.to_string()))
        //   ...
        //   .send().await?;
        tracing::info!(
            backend = self.backend_name(),
            table = %self.table_name,
            event_id = %event.event_id,
            risk_level = event.risk_level.label(),
            "Stored fraud event"
        );
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "dynamodb"
    }
}

// ── GCP BigQuery backend ──────────────────────────────────────────────────────

pub struct BigQueryStore {
    pub project_id: String,
    pub dataset_id: String,
    pub table_id: String,
}

impl BigQueryStore {
    pub fn new(
        project_id: impl Into<String>,
        dataset_id: impl Into<String>,
        table_id: impl Into<String>,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            dataset_id: dataset_id.into(),
            table_id: table_id.into(),
        }
    }

    fn full_table_ref(&self) -> String {
        format!("{}.{}.{}", self.project_id, self.dataset_id, self.table_id)
    }
}

impl EventStore for BigQueryStore {
    fn store(&self, event: &ProcessedFraudEvent) -> Result<(), StorageError> {
        // In production: use google-cloud-bigquery crate
        // Serialize to JSON row and call insertAll API
        let row = serde_json::to_value(event)?;
        tracing::info!(
            backend = self.backend_name(),
            table = %self.full_table_ref(),
            event_id = %event.event_id,
            risk_level = event.risk_level.label(),
            row_size_bytes = row.to_string().len(),
            "Inserted fraud event row"
        );
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "bigquery"
    }
}

// ── In-memory backend (tests / local dev) ────────────────────────────────────

use std::sync::{Arc, Mutex};

pub struct InMemoryStore {
    pub events: Arc<Mutex<Vec<ProcessedFraudEvent>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl EventStore for InMemoryStore {
    fn store(&self, event: &ProcessedFraudEvent) -> Result<(), StorageError> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "in_memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{RiskLevel, ProcessedFraudEvent};
    use chrono::Utc;
    use uuid::Uuid;

    fn dummy_event() -> ProcessedFraudEvent {
        ProcessedFraudEvent {
            event_id: Uuid::new_v4(),
            processed_at: Utc::now(),
            user_id: "user-test".into(),
            risk_score: 0.42,
            risk_level: RiskLevel::Medium,
            triggered_rules: vec!["SOME_RULE".into()],
            recommended_action: "STEP_UP_AUTH".into(),
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn in_memory_store_accumulates() {
        let store = InMemoryStore::new();
        store.store(&dummy_event()).unwrap();
        store.store(&dummy_event()).unwrap();
        assert_eq!(store.len(), 2);
    }
}
