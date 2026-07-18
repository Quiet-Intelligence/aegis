package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
	"aegis/pkg/telemetry"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type AuditLog struct {
	Timestamp  time.Time            `json:"timestamp"`
	SessionID  string               `json:"session_id"`
	Event      *telemetry.Event     `json:"event"`
	Rule       string               `json:"rule"`
	Actor      string               `json:"actor,omitempty"`
	Resource   string               `json:"resource,omitempty"`
	BinaryHash string               `json:"binary_sha256,omitempty"`
	Decision   adjudicator.Decision `json:"decision"`
	Rationale  string               `json:"rationale"`
}

type Enforcer struct {
	DeniedPathsMap  *ebpf.Map
	ApprovedExecMap *ebpf.Map
	LogFile         *os.File
	// AuditOnly disables all kernel-side blocking (BPF map writes). Decisions
	// are still logged and recorded. Forced on when monitoring is unscoped.
	AuditOnly bool
	db        *sql.DB
	repoID    int64
	mu        sync.Mutex
}

type execApprovalKey struct {
	Path [256]byte
}

func (e *Enforcer) SetApprovedExecMap(m *ebpf.Map) {
	e.ApprovedExecMap = m
}

// ApproveExec writes the exact one-use token consumed by the BPF LSM exec
// guard. In audit-only unit tests a missing map is allowed; production startup
// rejects a missing map before the control socket is exposed.
func (e *Enforcer) ApproveExec(path string) error {
	if e.ApprovedExecMap == nil {
		if e.AuditOnly {
			return nil
		}
		return fmt.Errorf("approved_exec_map is unavailable")
	}
	key := execApprovalKey{}
	copy(key.Path[:], path)
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return err
	}
	expires := uint64(now.Sec)*1_000_000_000 + uint64(now.Nsec) + uint64(5*time.Second)
	return e.ApprovedExecMap.Put(&key, &expires)
}

func NewEnforcer(logPath string, coll *ebpf.Collection, db *sql.DB, repoID int64, auditOnly bool) (*Enforcer, error) {
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	var m *ebpf.Map
	if coll != nil {
		m = coll.Maps["denied_paths_map"]
	}

	e := &Enforcer{
		LogFile:        f,
		DeniedPathsMap: m,
		AuditOnly:      auditOnly,
		db:             db,
		repoID:         repoID,
	}

	e.SyncPolicies()

	return e, nil
}

func (e *Enforcer) SyncPolicies() {
	if e.db == nil || e.DeniedPathsMap == nil || e.AuditOnly {
		return
	}
	rows, err := e.db.Query(`SELECT match_value FROM policy_entries WHERE repo_id = ? AND match_type = 'path' AND revoked_at IS NULL AND expires_at > ?`, e.repoID, time.Now())
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var path string
		rows.Scan(&path)
		var pathBuf [256]byte
		copy(pathBuf[:], path)
		val := uint32(1)
		e.DeniedPathsMap.Put(&pathBuf, &val)
	}
}

func (e *Enforcer) Enforce(flagged graph.FlaggedEvent, decision adjudicator.Decision, rationale string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ev := flagged.Event
	logEntry := AuditLog{
		Timestamp:  time.Now(),
		SessionID:  flagged.SessionID,
		Event:      ev,
		Rule:       flagged.Rule,
		Actor:      flagged.Actor,
		Resource:   flagged.Resource,
		BinaryHash: flagged.BinaryHash,
		Decision:   decision,
		Rationale:  rationale,
	}

	b, _ := json.Marshal(logEntry)
	e.LogFile.Write(append(b, '\n'))

	if decision == adjudicator.DecisionDeny && e.DeniedPathsMap != nil && !e.AuditOnly {
		// Determine what to block. For file_open it's the opened path.
		// For exec it's the binary itself: execve() opens the executable,
		// which fires file_open, so denying the binary path prevents
		// future runs. (Before this, denied execs blocked nothing.)
		var path string
		switch ev.Type {
		case "file_open":
			if ev.FileOpen != nil {
				path = ev.FileOpen.GetPath()
			}
		case "exec":
			if ev.Exec != nil {
				path = ev.Exec.GetPath()
			}
		}

		if path != "" {
			var pathBuf [256]byte
			copy(pathBuf[:], path)
			val := uint32(1)
			if err := e.DeniedPathsMap.Put(&pathBuf, &val); err != nil {
				fmt.Printf("Failed to write to BPF policy map: %v\n", err)
			} else {
				fmt.Printf("  -> [BLOCKED] %s added to kernel deny map\n", path)
			}
		}
	}
}
