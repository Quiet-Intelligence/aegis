package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"aegis/pkg/adjudicator"
	"aegis/pkg/telemetry"
	"github.com/cilium/ebpf"
)

type AuditLog struct {
	Timestamp time.Time            `json:"timestamp"`
	SessionID string               `json:"session_id"`
	Event     *telemetry.Event     `json:"event"`
	Decision  adjudicator.Decision `json:"decision"`
	Rationale string               `json:"rationale"`
}

type Enforcer struct {
	DeniedPathsMap *ebpf.Map
	LogFile        *os.File
	// AuditOnly disables all kernel-side blocking (BPF map writes). Decisions
	// are still logged and recorded. Forced on when monitoring is unscoped.
	AuditOnly bool
	db        *sql.DB
	repoID    int64
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

func (e *Enforcer) Enforce(sessionID string, ev *telemetry.Event, decision adjudicator.Decision, rationale string) {
	logEntry := AuditLog{
		Timestamp: time.Now(),
		SessionID: sessionID,
		Event:     ev,
		Decision:  decision,
		Rationale: rationale,
	}

	b, _ := json.Marshal(logEntry)
	e.LogFile.Write(append(b, '\n'))

	if decision == adjudicator.DecisionDeny && e.DeniedPathsMap != nil && !e.AuditOnly {
		if ev.Type == "file_open" && ev.FileOpen != nil {
			var pathBuf [256]byte
			copy(pathBuf[:], ev.FileOpen.GetPath())
			val := uint32(1)
			err := e.DeniedPathsMap.Put(&pathBuf, &val)
			if err != nil {
				fmt.Printf("Failed to write to BPF policy map: %v\n", err)
			}
		}
	}
}
