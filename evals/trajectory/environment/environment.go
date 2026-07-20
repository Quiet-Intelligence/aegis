package environment

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"aegis/internal/memory/embed"
	"aegis/internal/memory/episodic"
	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
	"aegis/pkg/telemetry"
	_ "github.com/mattn/go-sqlite3"
)

type ActionType string

const (
	ActionMkdir       ActionType = "mkdir"
	ActionTouch       ActionType = "touch"
	ActionWrite       ActionType = "write"
	ActionGitWorktree ActionType = "git_worktree_add"
	ActionGitInit     ActionType = "git_init"
)

type Action struct {
	Type   ActionType
	Target string
	Args   string
}

type Response struct {
	Decision adjudicator.Decision
	Flagged  bool
	Reason   string
	TraceID  string // EV2-6 support
}

type Environment struct {
	db          *sql.DB
	scorer      *graph.Scorer
	eventChan   chan *telemetry.Event
	adj         *episodic.RetrievalAugmentedAdjudicator
	repoID      int64
	ctx         context.Context
	cancel      context.CancelFunc
	pid         uint32
	timeCounter uint64
}

// NewEnvironment scaffolds the stateful sandbox (EV2-1).
// It directly instantiates the real scorer and adjudicator code paths,
// rather than using mocks, to evaluate trajectory steps.
func NewEnvironment(baseLLM adjudicator.Adjudicator, db *sql.DB, repoID int64) (*Environment, error) {
	embedder := &embed.HeuristicEmbedder{}
	store := episodic.NewStore(db, embedder)

	adj := &episodic.RetrievalAugmentedAdjudicator{
		LLM:      baseLLM,
		Store:    store,
		Embedder: embedder,
	}

	scorer := graph.NewScorer(db, repoID, "/workspace")
	scorer.AdjudicateAllExec = false

	eventChan := make(chan *telemetry.Event, 100)
	ctx, cancel := context.WithCancel(context.Background())

	go scorer.Consume(ctx, eventChan)

	return &Environment{
		db:          db,
		scorer:      scorer,
		eventChan:   eventChan,
		adj:         adj,
		repoID:      repoID,
		ctx:         ctx,
		cancel:      cancel,
		pid:         1000,
		timeCounter: 1000,
	}, nil
}

func (e *Environment) Close() {
	e.cancel()
}

// simulateAction translates a high-level action into eBPF-like telemetry events.
// This allows the environment to remain stateful and fast without needing real kernel hooks in CI.
func (e *Environment) simulateAction(a Action) []telemetry.Event {
	e.timeCounter++
	nowNs := e.timeCounter * 1000000

	var events []telemetry.Event
	switch a.Type {
	case ActionGitInit:
		events = append(events, telemetry.Event{
			Type: "exec",
			Exec: &telemetry.ExecEvent{
				Pid: e.pid,
				TimestampNs: nowNs,
			},
		})
		e.setPath(&events[0], "/usr/bin/git")
	case ActionGitWorktree:
		events = append(events, telemetry.Event{
			Type: "exec",
			Exec: &telemetry.ExecEvent{
				Pid: e.pid,
				TimestampNs: nowNs,
			},
		})
		e.setPath(&events[0], "/usr/bin/git")
		e.setArgs(&events[0], "worktree add")
		
		events = append(events, telemetry.Event{
			Type: "file_open",
			FileOpen: &telemetry.FileOpenEvent{
				Pid: e.pid,
				TimestampNs: nowNs + 1000,
				Flags: 2, // O_RDWR
			},
		})
		e.setPath(&events[1], fmt.Sprintf("/workspace/.git/worktrees/%s/config", a.Target))
	case ActionTouch, ActionWrite:
		flags := int32(0)
		if a.Type == ActionWrite {
			flags = 2
		}
		events = append(events, telemetry.Event{
			Type: "file_open",
			FileOpen: &telemetry.FileOpenEvent{
				Pid: e.pid,
				TimestampNs: nowNs,
				Flags: flags,
			},
		})
		
		targetPath := a.Target
		if !strings.HasPrefix(targetPath, "/") {
			targetPath = "/workspace/" + targetPath
		}
		e.setPath(&events[0], targetPath)
	case ActionMkdir:
		// Mkdir often triggers a file open or is tracked in a real environment.
		// For simulation, we might skip it or emit a benign event.
	}
	return events
}

func (e *Environment) setPath(ev *telemetry.Event, path string) {
	if ev.Exec != nil {
		for i, c := range []byte(path) {
			if i < len(ev.Exec.Path) {
				ev.Exec.Path[i] = c
			}
		}
	} else if ev.FileOpen != nil {
		for i, c := range []byte(path) {
			if i < len(ev.FileOpen.Path) {
				ev.FileOpen.Path[i] = c
			}
		}
	}
}

func (e *Environment) setArgs(ev *telemetry.Event, args string) {
	if ev.Exec != nil {
		ev.Exec.Argc = 2 // Include the binary itself and one arg (simplified)
		for i, c := range []byte(args) {
			if i < len(ev.Exec.Args[1]) {
				ev.Exec.Args[1][i] = c
			}
		}
	}
}

// Step applies one action at a time and returns Aegis's live response.
func (e *Environment) Step(action Action) (Response, error) {
	events := e.simulateAction(action)
	for _, ev := range events {
		eventCopy := ev // Avoid pointer loop capture issue
		e.eventChan <- &eventCopy
	}

	// Wait briefly to see if the scorer flags the events.
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()

	select {
	case flagged := <-e.scorer.Flagged():
		// Action was flagged! We must adjudicate.
		decision, reason, _ := e.adj.Adjudicate(e.ctx, e.repoID, flagged)
		return Response{
			Decision: decision,
			Flagged:  true,
			Reason:   reason,
			TraceID:  flagged.SessionID,
		}, nil
	case <-timer.C:
		// No flag occurred within the window, so it is implicitly allowed by the runtime.
		return Response{
			Decision: adjudicator.DecisionAllow,
			Flagged:  false,
			Reason:   "Auto-Allowed by Scorer Baseline",
		}, nil
	}
}
