package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── Mock FraudProcessor ────────────────────────────────────────────────────────

type MockProcessor struct {
	ProcessFunc func(req FraudRequest) (*FraudResult, error)
}

func (m *MockProcessor) Process(req FraudRequest) (*FraudResult, error) {
	return m.ProcessFunc(req)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

func TestHandleEvaluate_Success(t *testing.T) {
	mock := &MockProcessor{
		ProcessFunc: func(req FraudRequest) (*FraudResult, error) {
			return &FraudResult{
				EventID:           "evt-123",
				UserID:            req.UserID,
				RiskScore:         0.1,
				RiskLevel:         "LOW",
				TriggeredRules:    []string{},
				RecommendedAction: "ALLOW",
				ProcessedAt:       time.Now().UTC().Format(time.RFC3339),
			}, nil
		},
	}
	handler := &Handler{processor: mock, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	req := FraudRequest{
		UserID:    "user123",
		IPAddress: "192.168.1.1",
		EventType: "transaction",
		Payload:   map[string]interface{}{},
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/evaluate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.handleEvaluate(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-Fraud-Risk-Level") != "LOW" {
		t.Errorf("expected X-Fraud-Risk-Level: LOW, got %s", w.Header().Get("X-Fraud-Risk-Level"))
	}
}

func TestHandleEvaluate_InvalidJSON(t *testing.T) {
	mock := &MockProcessor{
		ProcessFunc: func(req FraudRequest) (*FraudResult, error) {
			return nil, nil
		},
	}
	handler := &Handler{processor: mock, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	r := httptest.NewRequest("POST", "/evaluate", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	handler.handleEvaluate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleEvaluate_HighValueTransaction(t *testing.T) {
	mock := &MockProcessor{
		ProcessFunc: func(req FraudRequest) (*FraudResult, error) {
			return &FraudResult{
				EventID:           "evt-123",
				UserID:            req.UserID,
				RiskScore:         0.65,
				RiskLevel:         "HIGH",
				TriggeredRules:    []string{"HIGH_VALUE_TXN"},
				RecommendedAction: "HOLD_FOR_REVIEW",
				ProcessedAt:       time.Now().UTC().Format(time.RFC3339),
			}, nil
		},
	}
	handler := &Handler{processor: mock, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	amount := int64(600_000)
	req := FraudRequest{
		UserID:      "user123",
		IPAddress:   "192.168.1.1",
		EventType:   "transaction",
		AmountCents: &amount,
		Payload:     map[string]interface{}{},
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/evaluate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.handleEvaluate(w, r)

	var result FraudResult
	json.NewDecoder(w.Body).Decode(&result)
	if result.RiskLevel != "HIGH" {
		t.Errorf("expected HIGH, got %s", result.RiskLevel)
	}
}

func TestHandlePubSub_Success(t *testing.T) {
	mock := &MockProcessor{
		ProcessFunc: func(req FraudRequest) (*FraudResult, error) {
			return &FraudResult{
				EventID:           "evt-123",
				UserID:            req.UserID,
				RiskScore:         0.1,
				RiskLevel:         "LOW",
				TriggeredRules:    []string{},
				RecommendedAction: "ALLOW",
				ProcessedAt:       time.Now().UTC().Format(time.RFC3339),
			}, nil
		},
	}
	handler := &Handler{processor: mock, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	fraudReq := FraudRequest{
		UserID:    "user123",
		IPAddress: "192.168.1.1",
		EventType: "transaction",
		Payload:   map[string]interface{}{},
	}
	data, _ := json.Marshal(fraudReq)
	msg := PubSubMessage{
		Subscription: "test-sub",
	}
	msg.Message.Data = data
	msg.Message.MessageID = "msg-123"

	body, _ := json.Marshal(msg)
	r := httptest.NewRequest("POST", "/pubsub", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.handlePubSub(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandlePubSub_InvalidEnvelope(t *testing.T) {
	mock := &MockProcessor{
		ProcessFunc: func(req FraudRequest) (*FraudResult, error) {
			return nil, nil
		},
	}
	handler := &Handler{processor: mock, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	r := httptest.NewRequest("POST", "/pubsub", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	handler.handlePubSub(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandlePubSub_BadMessageData(t *testing.T) {
	mock := &MockProcessor{
		ProcessFunc: func(req FraudRequest) (*FraudResult, error) {
			return nil, nil
		},
	}
	handler := &Handler{processor: mock, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	msg := PubSubMessage{
		Subscription: "test-sub",
	}
	msg.Message.Data = []byte("invalid json")
	msg.Message.MessageID = "msg-123"

	body, _ := json.Marshal(msg)
	r := httptest.NewRequest("POST", "/pubsub", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.handlePubSub(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (ack), got %d", w.Code)
	}
}

func TestHandleHealth(t *testing.T) {
	mock := &MockProcessor{
		ProcessFunc: func(req FraudRequest) (*FraudResult, error) {
			return nil, nil
		},
	}
	handler := &Handler{processor: mock, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	r := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handler.handleHealth(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Error("expected status=ok")
	}
}

func TestScoreToLevel(t *testing.T) {
	tests := []struct {
		score    float32
		expected string
	}{
		{0.1, "LOW"},
		{0.3, "MEDIUM"},
		{0.6, "HIGH"},
		{0.9, "CRITICAL"},
	}
	for _, tt := range tests {
		if got := scoreToLevel(tt.score); got != tt.expected {
			t.Errorf("scoreToLevel(%.2f) = %s, want %s", tt.score, got, tt.expected)
		}
	}
}

func TestLevelToAction(t *testing.T) {
	tests := []struct {
		level     string
		eventType string
		expected  string
	}{
		{"CRITICAL", "transaction", "BLOCK_AND_ALERT"},
		{"HIGH", "transaction", "HOLD_FOR_REVIEW"},
		{"HIGH", "login_attempt", "REQUIRE_MFA"},
		{"MEDIUM", "transaction", "STEP_UP_AUTH"},
		{"LOW", "transaction", "ALLOW"},
	}
	for _, tt := range tests {
		if got := levelToAction(tt.level, tt.eventType); got != tt.expected {
			t.Errorf("levelToAction(%s, %s) = %s, want %s", tt.level, tt.eventType, got, tt.expected)
		}
	}
}

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	time.Sleep(1 * time.Millisecond)
	id2 := generateID()
	if id1 == id2 {
		t.Error("generateID() should produce unique IDs")
	}
}

func TestProcessEvent_SuspiciousCountry(t *testing.T) {
	country := "XX"
	req := FraudRequest{
		UserID:      "user123",
		IPAddress:   "192.168.1.1",
		EventType:   "transaction",
		CountryCode: &country,
		Payload:     map[string]interface{}{},
	}
	result, err := processEvent(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RiskLevel == "LOW" {
		t.Errorf("expected risk > LOW for suspicious country, got %s", result.RiskLevel)
	}
}

func TestProcessEvent_FailedLoginBurst(t *testing.T) {
	req := FraudRequest{
		UserID:    "user123",
		IPAddress: "192.168.1.1",
		EventType: "login_attempt",
		Payload: map[string]interface{}{
			"attempt_count": float64(6),
		},
	}
	result, err := processEvent(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RiskLevel == "LOW" {
		t.Errorf("expected risk > LOW for burst attempts, got %s", result.RiskLevel)
	}
}
func TestLoadConfig(t *testing.T) {
	cfg := loadConfig()
	if cfg.Port == "" {
		t.Error("Port should have default value")
	}
}

func TestPubSubMessage(t *testing.T) {
	mock := &MockProcessor{
		ProcessFunc: func(req FraudRequest) (*FraudResult, error) {
			return &FraudResult{
				EventID:           "evt-123",
				UserID:            req.UserID,
				RiskScore:         0.1,
				RiskLevel:         "LOW",
				TriggeredRules:    []string{},
				RecommendedAction: "ALLOW",
				ProcessedAt:       time.Now().UTC().Format(time.RFC3339),
			}, nil
		},
	}
	msg := PubSubMessage{
		Subscription: "test-sub",
	}
	req := FraudRequest{
		UserID:    "user123",
		IPAddress: "192.168.1.1",
		EventType: "transaction",
		Payload:   map[string]interface{}{},
	}
	data, _ := json.Marshal(req)
	msg.Message.Data = data
	msg.Message.MessageID = "msg-123"

	body, _ := json.Marshal(msg)
	r := httptest.NewRequest("POST", "/pubsub", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler := &Handler{processor: mock, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Test the Pub/Sub handler
	handler.handlePubSub(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
