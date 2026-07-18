package graph

import (
	"context"
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
	Events []telemetry.Event
}

type FlaggedEvent struct {
	SessionID string
	Event     telemetry.Event
	Context   []telemetry.Event
	Rule      string
}

type Scorer struct {
	graphs       map[string]*SessionGraph
	mu           sync.Mutex
	flaggedChan  chan FlaggedEvent
	workspaceDir string
}

func NewScorer(workspaceDir string) *Scorer {
	return &Scorer{
		graphs:       make(map[string]*SessionGraph),
		flaggedChan:  make(chan FlaggedEvent, 100),
		workspaceDir: workspaceDir,
	}
}

func (s *Scorer) Flagged() <-chan FlaggedEvent {
	return s.flaggedChan
}

func (s *Scorer) Consume(ctx context.Context, eventChan <-chan telemetry.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-eventChan:
			s.processEvent(ev)
		}
	}
}

func (s *Scorer) processEvent(ev telemetry.Event) {
	var sessionID string
	var resource string

	switch ev.Type {
	case "file_open":
		sessionID = fmt.Sprintf("%d-%d", ev.FileOpen.Pid, ev.FileOpen.CgroupId)
		resource = ev.FileOpen.GetPath()
	case "exec":
		sessionID = fmt.Sprintf("%d-%d", ev.Exec.Pid, ev.Exec.CgroupId)
		resource = ev.Exec.GetPath()
	case "net":
		sessionID = fmt.Sprintf("%d-%d", ev.Net.Pid, ev.Net.CgroupId)
		resource = fmt.Sprintf("%d:%d", ev.Net.Daddr, ev.Net.Dport)
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

	// Rule 1: file_open outside allow-listed workspace prefix
	if ev.Type == "file_open" {
		if !strings.HasPrefix(resource, s.workspaceDir) && !strings.HasPrefix(resource, "/lib") && !strings.HasPrefix(resource, "/usr") {
			k := 5
			if len(sg.Events) < k {
				k = len(sg.Events)
			}
			contextEvents := sg.Events[len(sg.Events)-k:]

			s.flaggedChan <- FlaggedEvent{
				SessionID: sessionID,
				Event:     ev,
				Context:   contextEvents,
				Rule:      "File access outside workspace sandbox",
			}
		}
	}
}
