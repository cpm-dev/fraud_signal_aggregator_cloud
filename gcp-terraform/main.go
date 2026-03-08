// gcp-go/main.go
//
// Fraud Sentinel — GCP Cloud Run service
//
// Handles two request types:
//   POST /pubsub   — Pub/Sub push subscription messages
//   POST /evaluate — Direct HTTP evaluation (mirrors AWS API Gateway endpoint)
//
// The Rust core is called via CGO bindings (see rust_core.go).
// For the initial stub, calls are proxied to the fraud_sentinel shared library.

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	Port        string
	GCPProject  string
	PubSubTopic string
	Environment string
}

func loadConfig() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return Config{
		Port:        port,
		GCPProject:  os.Getenv("GCP_PROJECT_ID"),
		PubSubTopic: os.Getenv("PUBSUB_TOPIC"),
		Environment: os.Getenv("ENVIRONMENT"),
	}
}

// ── Request / Response types ──────────────────────────────────────────────────

// FraudRequest is the normalised payload used by both endpoints.
type FraudRequest struct {
	UserID      string                 `json:"user_id"`
	IPAddress   string                 `json:"ip_address"`
	EventType   string                 `json:"event_type"`
	Payload     map[string]interface{} `json:"payload"`
	AmountCents *int64                 `json:"amount_cents,omitempty"`
	CountryCode *string                `json:"country_code,omitempty"`
}

// FraudResult mirrors the Rust ProcessedFraudEvent.
type FraudResult struct {
	EventID           string   `json:"event_id"`
	UserID            string   `json:"user_id"`
	RiskScore         float32  `json:"risk_score"`
	RiskLevel         string   `json:"risk_level"`
	TriggeredRules    []string `json:"triggered_rules"`
	RecommendedAction string   `json:"recommended_action"`
	ProcessedAt       string   `json:"processed_at"`
}

// PubSubMessage is the Pub/Sub push envelope.
type PubSubMessage struct {
	Message struct {
		Data        []byte            `json:"data"`
		MessageID   string            `json:"messageId"`
		Attributes  map[string]string `json:"attributes"`
		PublishTime time.Time         `json:"publishTime"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// ── HTTP server ───────────────────────────────────────────────────────────────

func main() {
	cfg := loadConfig()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	processor := &RealProcessor{}
	handler := &Handler{processor: processor, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /evaluate", handler.handleEvaluate)
	mux.HandleFunc("POST /pubsub", handler.handlePubSub)
	mux.HandleFunc("GET /health", handler.handleHealth)

	addr := fmt.Sprintf(":%s", cfg.Port)
	slog.Info("Fraud Sentinel Cloud Run starting", "addr", addr, "env", cfg.Environment)

	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}

// ── FraudProcessor interface ──────────────────────────────────────────────────────

type FraudProcessor interface {
	Process(req FraudRequest) (*FraudResult, error)
}

type RealProcessor struct{}

func (rp *RealProcessor) Process(req FraudRequest) (*FraudResult, error) {
	return processEvent(req)
}

// ── Handlers ──────────────────────────────────────────────────────────────────────
type Handler struct {
	processor FraudProcessor
	logger    *slog.Logger
}

func (h *Handler) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req FraudRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	result, err := h.processor.Process(req)
	if err != nil {
		slog.Error("Processing failed", "error", err, "user_id", req.UserID)
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	slog.Info("Event evaluated",
		"event_id", result.EventID,
		"user_id", result.UserID,
		"risk_level", result.RiskLevel,
		"action", result.RecommendedAction,
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Fraud-Risk-Level", result.RiskLevel)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) handlePubSub(w http.ResponseWriter, r *http.Request) {
	var msg PubSubMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid Pub/Sub envelope")
		return
	}

	var req FraudRequest
	if err := json.Unmarshal(msg.Message.Data, &req); err != nil {
		slog.Error("Failed to decode Pub/Sub message data",
			"messageId", msg.Message.MessageID,
			"error", err,
		)
		// Return 200 to ack the message and avoid infinite retry of bad data
		w.WriteHeader(http.StatusOK)
		return
	}

	result, err := h.processor.Process(req)
	if err != nil {
		slog.Error("Pub/Sub event processing failed",
			"messageId", msg.Message.MessageID,
			"error", err,
		)
		// Non-200 triggers Pub/Sub retry with backoff
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	slog.Info("Pub/Sub event processed",
		"messageId", msg.Message.MessageID,
		"event_id", result.EventID,
		"risk_level", result.RiskLevel,
	)

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ── Core processing (delegates to Rust via CGO) ───────────────────────────────

// processEvent calls the Rust core library via CGO.
// See rust_core.go for the CGO binding implementation.
//
// In the stub phase this contains Go-native scoring logic that mirrors
// the Rust implementation — useful for rapid demo without the CGO build step.
func processEvent(req FraudRequest) (*FraudResult, error) {
	if req.UserID == "" {
		return nil, fmt.Errorf("missing required field: user_id")
	}
	if req.IPAddress == "" {
		return nil, fmt.Errorf("missing required field: ip_address")
	}

	// ── Stub scoring (mirrors Rust logic for demo) ────────────────────────────
	// TODO: replace with CGO call to fraud_sentinel_process_event()
	var score float32
	var rules []string

	if req.AmountCents != nil && *req.AmountCents > 500_000 {
		score += 0.35
		rules = append(rules, fmt.Sprintf("HIGH_VALUE_TXN($%.2f)", float64(*req.AmountCents)/100))
	}

	if req.CountryCode != nil {
		for _, risky := range []string{"XX", "YY", "ZZ"} {
			if *req.CountryCode == risky {
				score += 0.25
				rules = append(rules, fmt.Sprintf("SUSPICIOUS_COUNTRY(%s)", *req.CountryCode))
				break
			}
		}
	}

	if attempts, ok := req.Payload["attempt_count"].(float64); ok && attempts >= 5 {
		score += 0.30
		rules = append(rules, fmt.Sprintf("FAILED_LOGIN_BURST(count=%.0f)", attempts))
	}

	if score > 1.0 {
		score = 1.0
	}

	riskLevel := scoreToLevel(score)
	action := levelToAction(riskLevel, req.EventType)

	return &FraudResult{
		EventID:           generateID(),
		UserID:            req.UserID,
		RiskScore:         score,
		RiskLevel:         riskLevel,
		TriggeredRules:    rules,
		RecommendedAction: action,
		ProcessedAt:       time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func scoreToLevel(score float32) string {
	switch {
	case score < 0.25:
		return "LOW"
	case score < 0.55:
		return "MEDIUM"
	case score < 0.80:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

func levelToAction(level, eventType string) string {
	if level == "CRITICAL" {
		return "BLOCK_AND_ALERT"
	}
	if level == "HIGH" {
		if eventType == "transaction" {
			return "HOLD_FOR_REVIEW"
		}
		if eventType == "login_attempt" {
			return "REQUIRE_MFA"
		}
		return "FLAG_FOR_REVIEW"
	}
	if level == "MEDIUM" {
		return "STEP_UP_AUTH"
	}
	return "ALLOW"
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
