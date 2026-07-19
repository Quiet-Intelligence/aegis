package graph

import (
	"context"
	"database/sql"
	"fmt"
	"os"
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
	// exec path + argv, or ip:port) so operators and the TUI can see
	// WHAT was flagged, not just a session id.
	Resource string
	// Actor is the full command line of the process that caused this
	// event (the most recent exec in the same session), e.g.
	// "/usr/bin/ls -la". Empty when no exec is known (e.g. the flagged
	// event is itself the exec).
	Actor string
	// BinaryHash binds exec decisions/cache entries to executable content.
	BinaryHash string
}

type Scorer struct {
	db           *sql.DB
	repoID       int64
	graphs       map[string]*SessionGraph
	mu           sync.Mutex
	flaggedChan  chan FlaggedEvent
	workspaceDir string
	// FlagCooldown suppresses repeat flags for the same session+rule
	// within the window, so one noisy process cannot flood adjudication
	// (or the LLM budget). 0 disables. Defaults to 15s.
	FlagCooldown time.Duration
	lastFlag     map[string]time.Time
	// FlagNet also routes outbound socket_connect events to
	// adjudication. Off by default; enable with AEGIS_FLAG_NET=1.
	FlagNet bool
	// AdjudicateAllExec makes the command itself the primary event sent
	// to the LLM, with full argv. Enabled by default for scoped agents.
	AdjudicateAllExec bool
}

func NewScorer(db *sql.DB, repoID int64, workspaceDir string) *Scorer {
	return &Scorer{
		db:                db,
		repoID:            repoID,
		graphs:            make(map[string]*SessionGraph),
		flaggedChan:       make(chan FlaggedEvent, 100),
		workspaceDir:      workspaceDir,
		FlagCooldown:      15 * time.Second,
		lastFlag:          make(map[string]time.Time),
		AdjudicateAllExec: true,
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
	case "file_open", "path_unlink", "path_rmdir":
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

	// Always flag out-of-bounds file accesses and sensitive modifications
	if ev.Type == "file_open" || ev.Type == "path_unlink" || ev.Type == "path_rmdir" {
		isLoaderNoise := resource == "/etc/ld.so.cache"
		if !isLoaderNoise && !strings.HasPrefix(resource, s.workspaceDir) && !strings.HasPrefix(resource, "/lib") && !strings.HasPrefix(resource, "/usr") && !strings.HasPrefix(resource, "/proc") && !strings.HasPrefix(resource, "/dev") {
			isFlagged = true
			if ev.Type == "file_open" {
				ruleName = "File access outside workspace sandbox"
			} else {
				ruleName = "File deletion outside workspace sandbox"
			}
		}
		// Catch .git/config modifications (O_WRONLY=1, O_RDWR=2)
		if strings.Contains(resource, ".git/config") {
			if ev.Type == "file_open" && (ev.FileOpen.Flags&3 != 0) {
				isFlagged = true
				ruleName = "Modification of repository configuration"
			} else if ev.Type == "path_unlink" || ev.Type == "path_rmdir" {
				isFlagged = true
				ruleName = "Deletion of repository configuration"
			}
		}
	}

	// Catch dangerous executions. Match on the BINARY PATH, never on
	// resource: resource now carries argv, so a suffix match against it
	// would never fire.
	if ev.Type == "exec" {
		binPath := ev.Exec.GetPath()
		if s.AdjudicateAllExec {
			isFlagged = true
			ruleName = "Command execution"
		}
		
		highRisk := os.Getenv("AEGIS_HIGH_RISK_BINARIES")
		if highRisk == "" {
			highRisk = "rm,wget,curl,nc"
		}
		
		actorFull := strings.TrimSpace(binPath + " " + ev.Exec.GetArgs())
		for _, b := range strings.Split(highRisk, ",") {
			b = strings.TrimSpace(b)
			if b == "" {
				continue
			}
			// Match full argv, not just suffix of binary
			if strings.Contains(actorFull, "/"+b+" ") || strings.HasSuffix(actorFull, "/"+b) || strings.HasPrefix(actorFull, b+" ") || actorFull == b {
				isFlagged = true
				ruleName = "Execution of high-risk binary (" + b + ")"
				break
			}
		}
	}

	// Network egress (opt-in via AEGIS_FLAG_NET=1)
	if ev.Type == "net" && s.FlagNet {
		isFlagged = true
		ruleName = "Outbound network connection"
	}

	// Baseline deviation (if not already flagged)
	if !isFlagged && err == nil {
		currentScore := float64(len(sg.Events))
		if currentScore > emaValue*2.0 {
			isFlagged = true
			ruleName = "High deviation from semantic baseline"
		}
	} else if !isFlagged && err == sql.ErrNoRows {
		// Cold start: if no baseline, we just rely on the static rules above
	}

	if isFlagged {
		// Cooldown: at most one flag per session+rule per window. Events
		// keep accumulating in the graph above regardless; only the
		// adjudication channel is gated.
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

		// Attribute the flag to the command that caused it: the most
		// recent exec in this session, excluding the current event.
		actor := ""
		for i := len(sg.Events) - 2; i >= 0; i-- {
			prev := sg.Events[i]
			if prev.Type == "exec" && prev.Exec != nil {
				actor = strings.TrimSpace(prev.Exec.GetPath() + " " + prev.Exec.GetArgs())
				break
			}
		}

		s.flaggedChan <- FlaggedEvent{
			SessionID: sessionID,
			Event:     ev,
			Context:   contextEvents,
			Rule:      ruleName,
			Resource:  resource,
			Actor:     actor,
		}
	}
}
