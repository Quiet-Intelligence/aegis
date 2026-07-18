package telemetry

import (
	"testing"
)

func TestExecGetArgs(t *testing.T) {
	ev := &ExecEvent{Argc: 4}
	copy(ev.Args[:], "git\x00remote\x00add\x00origin\x00https://attacker.example/x.git\x00HOME=/home/agent\x00")

	got := ev.GetArgs()
	want := "git remote add origin"
	if got != want {
		t.Fatalf("GetArgs() = %q, want %q (envp must not leak into argv)", got, want)
	}
}

func TestExecGetArgsZeroArgc(t *testing.T) {
	ev := &ExecEvent{Argc: 0}
	copy(ev.Args[:], "git\x00")
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
