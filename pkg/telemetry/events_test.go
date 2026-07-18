package telemetry

import (
	"testing"
)

func TestExecGetArgs(t *testing.T) {
	ev := &ExecEvent{Argc: 4}
	for i, value := range []string{"git", "remote", "add", "origin"} {
		copy(ev.Args[i][:], value)
	}

	got := ev.GetArgs()
	want := "remote add origin"
	if got != want {
		t.Fatalf("GetArgs() = %q, want %q (argv[0] skipped, envp excluded)", got, want)
	}
}

func TestExecGetArgsZeroArgc(t *testing.T) {
	ev := &ExecEvent{Argc: 0}
	copy(ev.Args[0][:], "git")
	if got := ev.GetArgs(); got != "" {
		t.Fatalf("expected empty args for argc=0, got %q", got)
	}
}

func TestNetGetAddr(t *testing.T) {
	// 134744072 = 0x08080808 = 8.8.8.8 (network byte order)
	ev := &NetEvent{Daddr: 134744072, Dport: 443}
	if got := ev.GetAddr(); got != "8.8.8.8:443" {
		t.Fatalf("GetAddr() = %q, want 8.8.8.8:443", got)
	}
}
