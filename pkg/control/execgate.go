// Package control exposes local, privileged control-plane endpoints.
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
	"aegis/pkg/policy"
	"aegis/pkg/telemetry"
)

// ExecRequest is sent by the seccomp-notify supervisor while execve is
// blocked in the kernel. Argv includes argv[0].
type ExecRequest struct {
	PID     int      `json:"pid"`
	Path    string   `json:"path"`
	RawPath string   `json:"raw_path"`
	Argv    []string `json:"argv"`
	CWD     string   `json:"cwd"`
	SHA256 string   `json:"sha256"`
	// Bootstrap is true only for the gate child's first exact entrypoint
	// exec. It is trusted harness infrastructure, not a user command.
	Bootstrap bool `json:"bootstrap,omitempty"`
}

type ExecResponse struct {
	Decision  adjudicator.Decision `json:"decision"`
	Rationale string               `json:"rationale"`
}

type ExecGateServer struct {
	listener net.Listener
	adj      adjudicator.Adjudicator
	enforcer *policy.Enforcer
	repoID   int64
	wg       sync.WaitGroup
}

// StartExecGate starts a newline-delimited JSON server on a unix socket.
// The containing directory is bind-mounted into the agent container.
func StartExecGate(ctx context.Context, socketPath string, adj adjudicator.Adjudicator, enforcer *policy.Enforcer, repoID int64) (*ExecGateServer, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		return nil, err
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	// The socket only accepts adjudication requests. Container processes
	// need write access; policy mutations remain inside aegisd.
	if err := os.Chmod(socketPath, 0666); err != nil {
		ln.Close()
		return nil, err
	}

	s := &ExecGateServer{listener: ln, adj: adj, enforcer: enforcer, repoID: repoID}
	s.wg.Add(1)
	go s.serve(ctx, socketPath)
	return s, nil
}

func (s *ExecGateServer) serve(ctx context.Context, socketPath string) {
	defer s.wg.Done()
	defer os.Remove(socketPath)
	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.handle(conn)
		}()
	}
}

func (s *ExecGateServer) handle(conn net.Conn) {
	_ = conn.SetDeadline(deadlineFromNow())
	var req ExecRequest
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		json.NewEncoder(conn).Encode(ExecResponse{Decision: adjudicator.DecisionDeny, Rationale: "invalid gate request: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.Path) == "" {
		json.NewEncoder(conn).Encode(ExecResponse{Decision: adjudicator.DecisionDeny, Rationale: "empty executable path"})
		return
	}
	if !validSHA256(req.SHA256) {
		json.NewEncoder(conn).Encode(ExecResponse{Decision: adjudicator.DecisionDeny, Rationale: "missing or invalid executable SHA-256"})
		return
	}

	ev := &telemetry.Event{Type: "exec", Exec: &telemetry.ExecEvent{Pid: uint32(req.PID), Argc: uint32(len(req.Argv))}}
	copy(ev.Exec.Path[:], req.Path)
	for i, arg := range req.Argv {
		if i >= telemetry.MaxArgCount {
			break
		}
		copy(ev.Exec.Args[i][:], arg)
	}
	parts := []string{req.Path}
	if len(req.Argv) > 1 {
		parts = append(parts, req.Argv[1:]...)
	}
	command := strings.TrimSpace(strings.Join(parts, " "))
	flagged := graph.FlaggedEvent{
		SessionID:  fmt.Sprintf("gate-%d", req.PID),
		Event:      ev,
		Context:    []*telemetry.Event{ev},
		Rule:       "Synchronous command gate v2 (workspace writes allowed)",
		Resource:   command,
		BinaryHash: req.SHA256,
	}

	var decision adjudicator.Decision
	var rationale string
	var err error
	canonicalBash := req.Path == "/bin/bash" || req.Path == "/usr/bin/bash"
	argvBash := len(req.Argv) > 0 && (req.Argv[0] == "/bin/bash" || req.Argv[0] == "/usr/bin/bash")
	trustedBootstrap := req.Bootstrap && canonicalBash && argvBash
	if trustedBootstrap {
		flagged.Rule = "Trusted harness bootstrap"
		decision = adjudicator.DecisionAllow
		rationale = "Trusted harness bootstrap shell; the seccomp exec gate remains active for every descendant command."
	} else {
		decision, rationale, err = s.adj.Adjudicate(context.Background(), s.repoID, flagged)
		if err != nil && decision == "" {
			decision = adjudicator.DecisionAskUser
			rationale = "adjudication unavailable: " + err.Error()
		}
	}
	// The kernel gate only continues on an explicit, valid Allow. AskUser,
	// errors and Deny all remain blocked before execution.
	if decision == adjudicator.DecisionAllow {
		approvalPath := req.RawPath
		if approvalPath == "" {
			approvalPath = req.Path
		}
		if err := s.enforcer.ApproveExec(approvalPath); err != nil {
			decision = adjudicator.DecisionAskUser
			rationale = "could not arm the kernel exec approval: " + err.Error()
		}
	}
	s.enforcer.Enforce(flagged, decision, rationale)
	json.NewEncoder(conn).Encode(ExecResponse{Decision: decision, Rationale: rationale})
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func (s *ExecGateServer) Close() error {
	err := s.listener.Close()
	s.wg.Wait()
	return err
}

func deadlineFromNow() (deadline time.Time) {
	return time.Now().Add(45 * time.Second)
}
