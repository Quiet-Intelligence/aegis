package graph

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"aegis/pkg/telemetry"
)

type Node struct {
	SyscallClass string
	Resource     string
}

type Edge struct {
	From      Node
	To        Node
	Timestamp time.Time
}

type SessionGraph struct {
	mu     sync.Mutex
	Nodes  []Node
	Edges  []Edge
	Events []*telemetry.Event
}

type FlaggedEvent struct {
	SessionID string
	Event     *telemetry.Event
	Context   []*telemetry.Event
	Rule      string
	// Resource is the human-readable subject of the event (file path,
	// exec path, or ip:port) so operators can see WHAT was flagged.
	Resource string
}

type Scorer struct {
	db           *sql.DB
	repoID       int64
	graphs       map[string]*SessionGraph
	mu           sync.Mutex
	flaggedChan  chan FlaggedEvent
	workspaceDir string
	// FlagCooldown suppresses repeat flags for the same session+rule within
	// the window, so one noisy process cannot flood adjudication (or the
	// LLM budget). 0 disables suppression. Defaults to 15s.
	FlagCooldown time.Duration
	lastFlag     map[string]time.Time
	// FlagNet also routes outbound socket_connect events to adjudication
	// (cold-start only). Off by default: network is normally governed by
	// the Layer-0 egress allowlist. Enable with AEGIS_FLAG_NET=1.
	FlagNet bool
}

func NewScorer(db *sql.DB, repoID int64, workspaceDir string) *Scorer {
	return &Scorer{
		db:           db,
		repoID:       repoID,
		graphs:       make(map[string]*SessionGraph),
		flaggedChan:  make(chan FlaggedEvent, 100),
		workspaceDir: workspaceDir,
		FlagCooldown: 15 * time.Second,
		lastFlag:     make(map[string]time.Time),
	}
}

func (s *Scorer) Flagged() <-chan FlaggedEvent {
	return s.flaggedChan
}

func (s *Scorer) Consume(ctx context.Context, eventChan <-chan *telemetry.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-eventChan:
			s.processEvent(ev)
		}
	}
}

func (s *Scorer) processEvent(ev *telemetry.Event) {
	var sessionID string
	var resource string

	switch ev.Type {
	case "file_open":
		if ev.FileOpen != nil {
			sessionID = fmt.Sprintf("%d-%d", ev.FileOpen.Pid, ev.FileOpen.CgroupId)
			resource = ev.FileOpen.GetPath()
		}
	case "exec":
		if ev.Exec != nil {
			sessionID = fmt.Sprintf("%d-%d", ev.Exec.Pid, ev.Exec.CgroupId)
			resource = strings.TrimSpace(ev.Exec.GetPath() + " " + ev.Exec.GetArgs())
		}
	case "net":
		if ev.Net != nil {
			sessionID = fmt.Sprintf("%d-%d", ev.Net.Pid, ev.Net.CgroupId)
			resource = ev.Net.GetAddr()
		}
	}

	if sessionID == "" {
		return
	}

	s.mu.Lock()
	sg, ok := s.graphs[sessionID]
	if !ok {
		sg = &SessionGraph{}
		s.graphs[sessionID] = sg
	}
	s.mu.Unlock()

	sg.mu.Lock()
	defer sg.mu.Unlock()

	node := Node{SyscallClass: ev.Type, Resource: resource}
	sg.Nodes = append(sg.Nodes, node)
	sg.Events = append(sg.Events, ev)

	if len(sg.Nodes) > 1 {
		sg.Edges = append(sg.Edges, Edge{
			From:      sg.Nodes[len(sg.Nodes)-2],
			To:        node,
			Timestamp: time.Now(),
		})
	}

	var emaValue float64
	err := s.db.QueryRow("SELECT ema_value FROM semantic_baseline WHERE repo_id = ? AND feature_key = 'flagged_event_count'", s.repoID).Scan(&emaValue)

	isFlagged := false
	ruleName := ""

	if err == sql.ErrNoRows {
		if ev.Type == "file_open" {
			if !strings.HasPrefix(resource, s.workspaceDir) && !strings.HasPrefix(resource, "/lib") && !strings.HasPrefix(resource, "/usr") {
				isFlagged = true
				ruleName = "File access outside workspace sandbox (Cold Start)"
			}
		} else if ev.Type == "net" && s.FlagNet {
			isFlagged = true
			ruleName = "Outbound network connection (Cold Start)"
		}
	} else if err == nil {
		currentScore := float64(len(sg.Events))
		if currentScore > emaValue*2.0 {
			isFlagged = true
			ruleName = "High deviation from semantic baseline"
		}
	}

	if isFlagged {
		// Cooldown: at most one flag per session+rule per window. Events keep
		// accumulating in the graph above regardless — only the adjudication
		// channel is gated.
		if s.FlagCooldown > 0 {
			key := sessionID + "|" + ruleName
			s.mu.Lock()
			last, seen := s.lastFlag[key]
			if seen && time.Since(last) < s.FlagCooldown {
				s.mu.Unlock()
				return
			}
			s.lastFlag[key] = time.Now()
			s.mu.Unlock()
		}

		k := 5
		if len(sg.Events) < k {
			k = len(sg.Events)
		}
		contextEvents := sg.Events[len(sg.Events)-k:]

		s.flaggedChan <- FlaggedEvent{
			SessionID: sessionID,
			Event:     ev,
			Context:   contextEvents,
			Rule:      ruleName,
			Resource:  resource,
		}
	}
}
