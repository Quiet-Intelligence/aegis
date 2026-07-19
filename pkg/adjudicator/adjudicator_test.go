package adjudicator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis/pkg/graph"
	"aegis/pkg/telemetry"
)

func testEvent() graph.FlaggedEvent {
	ev := &telemetry.Event{Type: "file_open", FileOpen: &telemetry.FileOpenEvent{Pid: 42}}
	copy(ev.FileOpen.Path[:], "/etc/shadow")
	return graph.FlaggedEvent{
		SessionID: "42-100",
		Event:     ev,
		Context:   []*telemetry.Event{ev},
		Rule:      "File access outside workspace sandbox (Cold Start)",
	}
}

func openRouterStub(t *testing.T, status int, content string, checkReq func(*http.Request, chatRequest)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode outbound request: %v", err)
		}
		if checkReq != nil {
			checkReq(r, req)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message":       map[string]any{"role": "assistant", "content": content},
				"finish_reason": "stop",
			}},
		})
	}))
}

func TestAdjudicate_ParsesDecision(t *testing.T) {
	srv := openRouterStub(t, http.StatusOK, `{"decision":"Deny","rationale":"reads /etc/shadow"}`, func(r *http.Request, req chatRequest) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer sk-or-v1-test" {
			t.Errorf("bad Authorization header: %q", auth)
		}
		if req.Model != "anthropic/claude-3.5-sonnet" {
			t.Errorf("wrong model on the wire: %q", req.Model)
		}
		if !strings.Contains(req.Messages[1].Content, "/etc/shadow") {
			t.Errorf("prompt missing event summary, got: %q", req.Messages[1].Content)
		}
	})
	defer srv.Close()

	a := &OpenAIAdjudicator{APIKey: "sk-or-v1-test", URL: srv.URL, Model: "anthropic/claude-3.5-sonnet"}
	dec, rat, err := a.Adjudicate(context.Background(), 1, testEvent())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec != DecisionDeny {
		t.Fatalf("expected Deny, got %q", dec)
	}
	if rat != "reads /etc/shadow" {
		t.Fatalf("unexpected rationale: %q", rat)
	}
}

func TestAdjudicate_ToleratesMarkdownFences(t *testing.T) {
	srv := openRouterStub(t, http.StatusOK, "```json\n{\"decision\":\"Allow\",\"rationale\":\"benign git op\"}\n```", nil)
	defer srv.Close()

	a := &OpenAIAdjudicator{APIKey: "k", URL: srv.URL, Model: "m"}
	dec, rat, err := a.Adjudicate(context.Background(), 1, testEvent())
	if err != nil || dec != DecisionAllow {
		t.Fatalf("expected Allow, got %q (err=%v)", dec, err)
	}
	if rat != "benign git op" {
		t.Fatalf("unexpected rationale: %q", rat)
	}
}

func TestAdjudicate_AsksUserOnHTTPError(t *testing.T) {
	srv := openRouterStub(t, http.StatusUnauthorized, ``, nil)
	defer srv.Close()

	a := &OpenAIAdjudicator{APIKey: "bad-key", URL: srv.URL, Model: "m"}
	dec, _, err := a.Adjudicate(context.Background(), 1, testEvent())
	if err == nil {
		t.Fatal("expected error on HTTP 401")
	}
	if dec != DecisionAskUser {
		t.Fatalf("provider errors must not poison the deny map, got %q", dec)
	}
}

func TestAdjudicate_AsksUserWhenUnconfigured(t *testing.T) {
	a := &OpenAIAdjudicator{Model: "gpt-4"} // no URL, no key (evalrunner path)
	dec, _, err := a.Adjudicate(context.Background(), 1, testEvent())
	if err == nil {
		t.Fatal("expected error when unconfigured")
	}
	if dec != DecisionAskUser {
		t.Fatalf("missing config must not create a block, got %q", dec)
	}
}

func TestAdjudicate_AsksUserOnGarbageOutput(t *testing.T) {
	srv := openRouterStub(t, http.StatusOK, `I think this is fine honestly`, nil)
	defer srv.Close()

	a := &OpenAIAdjudicator{APIKey: "k", URL: srv.URL, Model: "m"}
	dec, _, err := a.Adjudicate(context.Background(), 1, testEvent())
	if err == nil {
		t.Fatal("expected parse error")
	}
	if dec != DecisionAskUser {
		t.Fatalf("garbage output must not create a block, got %q", dec)
	}
}

func TestAdjudicate_ContentParts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message": map[string]any{"content": []map[string]any{{
					"type": "text", "text": `{"decision":"Allow","rationale":"safe list"}`,
				}}},
				"finish_reason": "stop",
			}},
		})
	}))
	defer srv.Close()

	a := &OpenAIAdjudicator{APIKey: "k", URL: srv.URL, Model: "m"}
	dec, rat, err := a.Adjudicate(context.Background(), 1, testEvent())
	if err != nil || dec != DecisionAllow || rat != "safe list" {
		t.Fatalf("content-parts response failed: dec=%q rat=%q err=%v", dec, rat, err)
	}
}

func TestAdjudicate_EmptyContentAsksUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message":       map[string]any{"content": ""},
				"finish_reason": "length",
			}},
		})
	}))
	defer srv.Close()

	a := &OpenAIAdjudicator{APIKey: "k", URL: srv.URL, Model: "m"}
	dec, rat, err := a.Adjudicate(context.Background(), 1, testEvent())
	if err == nil || dec != DecisionAskUser {
		t.Fatalf("empty content must AskUser: dec=%q rat=%q err=%v", dec, rat, err)
	}
	if !strings.Contains(rat, `finish_reason="length"`) {
		t.Fatalf("missing useful finish reason: %q", rat)
	}
}
