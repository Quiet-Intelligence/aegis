package control

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
	"aegis/pkg/policy"
)

type gateStub struct {
	mu        sync.Mutex
	calls     int
	decision  adjudicator.Decision
	rationale string
}

const testSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func (s *gateStub) Adjudicate(ctx context.Context, repoID int64, event graph.FlaggedEvent) (adjudicator.Decision, string, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.decision, s.rationale, nil
}

func sendGateRequest(t *testing.T, socket string, req ExecRequest) ExecResponse {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}
	var resp ExecResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestBootstrapIsOneTrustedShellAndSkipsLLM(t *testing.T) {
	dir := t.TempDir()
	stub := &gateStub{decision: adjudicator.DecisionDeny, rationale: "should not be called"}
	enforcer, err := policy.NewEnforcer(filepath.Join(dir, "audit.jsonl"), nil, nil, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	defer enforcer.LogFile.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := filepath.Join(dir, "gate.sock")
	server, err := StartExecGate(ctx, socket, stub, enforcer, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	resp := sendGateRequest(t, socket, ExecRequest{PID: 10, Path: "/bin/bash", Argv: []string{"/bin/bash"}, SHA256: testSHA, Bootstrap: true})
	if resp.Decision != adjudicator.DecisionAllow {
		t.Fatalf("bootstrap = %q, want Allow", resp.Decision)
	}
	if stub.calls != 0 {
		t.Fatalf("bootstrap must not call LLM, calls=%d", stub.calls)
	}

	// A client cannot mark an arbitrary executable as bootstrap.
	resp = sendGateRequest(t, socket, ExecRequest{PID: 11, Path: "/usr/bin/rm", Argv: []string{"rm", "-rf", "/"}, SHA256: testSHA, Bootstrap: true})
	if resp.Decision != adjudicator.DecisionDeny || stub.calls != 1 {
		t.Fatalf("fake bootstrap bypassed LLM: resp=%+v calls=%d", resp, stub.calls)
	}
}

func TestGateAuditKeepsFullCommandBeyondTelemetryLimit(t *testing.T) {
	dir := t.TempDir()
	stub := &gateStub{decision: adjudicator.DecisionAllow, rationale: "approved"}
	auditPath := filepath.Join(dir, "audit.jsonl")
	enforcer, err := policy.NewEnforcer(auditPath, nil, nil, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := StartExecGate(ctx, filepath.Join(dir, "gate.sock"), stub, enforcer, 1)
	if err != nil {
		t.Fatal(err)
	}

	args := []string{"tool", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "final-dangerous-arg"}
	resp := sendGateRequest(t, filepath.Join(dir, "gate.sock"), ExecRequest{PID: 12, Path: "/usr/bin/tool", Argv: args, SHA256: testSHA})
	if resp.Decision != adjudicator.DecisionAllow {
		t.Fatalf("response = %+v", resp)
	}
	server.Close()
	enforcer.LogFile.Close()
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "final-dangerous-arg") {
		t.Fatalf("full command was truncated in audit: %s", data)
	}
}
