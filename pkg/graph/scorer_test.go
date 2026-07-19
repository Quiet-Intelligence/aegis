package graph

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"aegis/internal/memory"
	"aegis/pkg/telemetry"
	_ "github.com/mattn/go-sqlite3"
)

func fileEvent(pid uint32, path string, flags int32) *telemetry.Event {
	ev := &telemetry.Event{Type: "file_open", FileOpen: &telemetry.FileOpenEvent{Pid: pid, CgroupId: 1, Flags: flags}}
	copy(ev.FileOpen.Path[:], path)
	return ev
}

func execEvent(pid uint32, path, args string, argc uint32) *telemetry.Event {
	ev := &telemetry.Event{Type: "exec", Exec: &telemetry.ExecEvent{Pid: pid, CgroupId: 1, Argc: argc}}
	copy(ev.Exec.Path[:], path)
	for i, value := range strings.Split(strings.TrimSuffix(args, "\x00"), "\x00") {
		if i >= telemetry.MaxArgCount {
			break
		}
		copy(ev.Exec.Args[i][:], value)
	}
	return ev
}

func netEvent(pid uint32, daddr uint32, dport uint16) *telemetry.Event {
	return &telemetry.Event{Type: "net", Net: &telemetry.NetEvent{Pid: pid, CgroupId: 1, Daddr: daddr, Dport: dport}}
}

func newTestScorer(t *testing.T) *Scorer {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := memory.InitSchema(db); err != nil {
		t.Fatal(err)
	}
	return NewScorer(db, 1, "/workspace")
}

func consume(t *testing.T, s *Scorer) chan<- *telemetry.Event {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := make(chan *telemetry.Event, 64)
	go s.Consume(ctx, ch)
	return ch
}

func flagWithin(s *Scorer, d time.Duration) *FlaggedEvent {
	select {
	case f := <-s.Flagged():
		return &f
	case <-time.After(d):
		return nil
	}
}

func TestScorer_OutsideWorkspaceFlaggedWithResource(t *testing.T) {
	s := newTestScorer(t)
	ch := consume(t, s)

	ch <- fileEvent(100, "/etc/shadow", 0)
	f := flagWithin(s, 200*time.Millisecond)
	if f == nil {
		t.Fatal("expected /etc/shadow open to be flagged")
	}
	if f.Resource != "/etc/shadow" {
		t.Errorf("Resource = %q, want /etc/shadow", f.Resource)
	}
	if f.Rule != "File access outside workspace sandbox" {
		t.Errorf("unexpected rule: %q", f.Rule)
	}
}

func TestScorer_WorkspaceNotFlagged(t *testing.T) {
	s := newTestScorer(t)
	ch := consume(t, s)

	ch <- fileEvent(100, "/workspace/src/main.go", 0)
	if flagWithin(s, 150*time.Millisecond) != nil {
		t.Fatal("workspace path must not be flagged")
	}
}

func TestScorer_GitConfigWriteFlagged(t *testing.T) {
	s := newTestScorer(t)
	ch := consume(t, s)

	ch <- fileEvent(100, "/workspace/.git/config", 1) // O_WRONLY
	f := flagWithin(s, 200*time.Millisecond)
	if f == nil {
		t.Fatal(".git/config write should be flagged")
	}
	if f.Rule != "Modification of repository configuration" {
		t.Errorf("unexpected rule: %q", f.Rule)
	}
}

func TestScorer_GitConfigReadOnlyNotFlagged(t *testing.T) {
	s := newTestScorer(t)
	ch := consume(t, s)

	ch <- fileEvent(100, "/workspace/.git/config", 0) // O_RDONLY
	if flagWithin(s, 150*time.Millisecond) != nil {
		t.Fatal(".git/config read-only open inside workspace must not flag")
	}
}

// The exec high-risk rule must match on the binary path even though
// Resource now carries argv (a suffix match on resource would never fire).
func TestScorer_HighRiskBinaryWithArgs(t *testing.T) {
	s := newTestScorer(t)
	ch := consume(t, s)

	ch <- execEvent(100, "/usr/bin/rm", "rm\x00-rf\x00/\x00", 3)
	f := flagWithin(s, 200*time.Millisecond)
	if f == nil {
		t.Fatal("rm execution should be flagged")
	}
	if f.Rule != "Execution of high-risk binary (rm)" {
		t.Errorf("unexpected rule: %q", f.Rule)
	}
	want := "/usr/bin/rm -rf /"
	if f.Resource != want {
		t.Errorf("Resource = %q, want %q (full command line visible)", f.Resource, want)
	}
}

func TestScorer_AttributesFileAccessToCommand(t *testing.T) {
	s := newTestScorer(t)
	s.AdjudicateAllExec = false // isolate attribution on the later file event
	ch := consume(t, s)

	// Same PID/session: exec is the cause, file_open is the flagged symptom.
	ch <- execEvent(300, "/usr/bin/ls", "ls\x00-la\x00", 2)
	ch <- fileEvent(300, "/etc/passwd", 0)
	f := flagWithin(s, 200*time.Millisecond)
	if f == nil {
		t.Fatal("expected out-of-workspace file access to be flagged")
	}
	if f.Actor != "/usr/bin/ls -la" {
		t.Errorf("Actor = %q, want /usr/bin/ls -la", f.Actor)
	}
	if f.Resource != "/etc/passwd" {
		t.Errorf("Resource = %q, want /etc/passwd", f.Resource)
	}
}

func TestScorer_AllExecsAreAdjudicated(t *testing.T) {
	s := newTestScorer(t)
	ch := consume(t, s)

	ch <- execEvent(100, "/usr/bin/ls", "ls\x00-la\x00", 2)
	f := flagWithin(s, 200*time.Millisecond)
	if f == nil {
		t.Fatal("ls should be sent for command adjudication")
	}
	if f.Rule != "Command execution" || f.Resource != "/usr/bin/ls -la" {
		t.Errorf("unexpected flag: rule=%q resource=%q", f.Rule, f.Resource)
	}
}

func TestScorer_AllExecCanBeDisabled(t *testing.T) {
	s := newTestScorer(t)
	s.AdjudicateAllExec = false
	ch := consume(t, s)

	ch <- execEvent(100, "/usr/bin/ls", "ls\x00-la\x00", 2)
	if flagWithin(s, 150*time.Millisecond) != nil {
		t.Fatal("ls should not flag when all-exec adjudication is disabled")
	}
}

func TestScorer_NetOptIn(t *testing.T) {
	off := newTestScorer(t)
	offCh := consume(t, off)

	// Default off
	offCh <- netEvent(100, 134744072, 443) // 8.8.8.8:443
	if flagWithin(off, 150*time.Millisecond) != nil {
		t.Fatal("net events must not flag when FlagNet is off")
	}

	on := newTestScorer(t)
	on.FlagNet = true // configure before the consumer goroutine starts
	onCh := consume(t, on)
	onCh <- netEvent(101, 134744072, 443)
	f := flagWithin(on, 200*time.Millisecond)
	if f == nil {
		t.Fatal("net event should flag when FlagNet is on")
	}
	if f.Resource != "8.8.8.8:443" {
		t.Errorf("Resource = %q, want 8.8.8.8:443", f.Resource)
	}
}

func TestScorer_CooldownSuppressesRepeats(t *testing.T) {
	s := newTestScorer(t)
	s.FlagCooldown = time.Second
	ch := consume(t, s)

	ch <- fileEvent(100, "/etc/shadow", 0)
	if flagWithin(s, 200*time.Millisecond) == nil {
		t.Fatal("first offense should flag")
	}
	ch <- fileEvent(100, "/etc/passwd", 0)
	if flagWithin(s, 200*time.Millisecond) != nil {
		t.Fatal("repeat within cooldown should be suppressed")
	}
	ch <- fileEvent(200, "/etc/passwd", 0)
	if flagWithin(s, 200*time.Millisecond) == nil {
		t.Fatal("different session should still flag")
	}
}
