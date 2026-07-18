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
		resp := chatResponse{Choices: []struct {
			Message chatMessage `json:"message"`
		}{{Message: chatMessage{Role: "assistant", Content: content}}}}
		json.NewEncoder(w).Encode(resp)
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

func TestAdjudicate_FailsClosedOnHTTPError(t *testing.T) {
	srv := openRouterStub(t, http.StatusUnauthorized, ``, nil)
	defer srv.Close()

	a := &OpenAIAdjudicator{APIKey: "bad-key", URL: srv.URL, Model: "m"}
	dec, _, err := a.Adjudicate(context.Background(), 1, testEvent())
	if err == nil {
		t.Fatal("expected error on HTTP 401")
	}
	if dec != DecisionDeny {
		t.Fatalf("expected fail-closed Deny, got %q", dec)
	}
}

func TestAdjudicate_FailsClosedWhenUnconfigured(t *testing.T) {
	a := &OpenAIAdjudicator{Model: "gpt-4"} // no URL, no key (evalrunner path)
	dec, _, err := a.Adjudicate(context.Background(), 1, testEvent())
	if err == nil {
		t.Fatal("expected error when unconfigured")
	}
	if dec != DecisionDeny {
		t.Fatalf("expected fail-closed Deny, got %q", dec)
	}
}

func TestAdjudicate_FailsClosedOnGarbageOutput(t *testing.T) {
	srv := openRouterStub(t, http.StatusOK, `I think this is fine honestly`, nil)
	defer srv.Close()

	a := &OpenAIAdjudicator{APIKey: "k", URL: srv.URL, Model: "m"}
	dec, _, err := a.Adjudicate(context.Background(), 1, testEvent())
	if err == nil {
		t.Fatal("expected parse error")
	}
	if dec != DecisionDeny {
		t.Fatalf("expected fail-closed Deny, got %q", dec)
	}
}
