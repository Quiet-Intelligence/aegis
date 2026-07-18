package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestAuditEntryResource(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{
			name: "file_open",
			json: `{"timestamp":"2026-07-18T10:00:00Z","session_id":"1-2","event":{"Type":"file_open","FileOpen":{"Pid":7,"Path":"/etc/passwd"}},"rule":"outside workspace","actor":"/usr/bin/cat /etc/passwd","decision":"Deny","rationale":"reads user db"}`,
			want: "/etc/passwd",
		},
		{
			name: "exec with args",
			json: `{"timestamp":"2026-07-18T10:00:00Z","session_id":"1-2","event":{"Type":"exec","Exec":{"Pid":8,"Path":"/usr/bin/git","Args":"remote add origin https://x"}},"decision":"Allow","rationale":"ok"}`,
			want: "/usr/bin/git remote add origin https://x",
		},
		{
			name: "net",
			json: `{"timestamp":"2026-07-18T10:00:00Z","session_id":"1-2","event":{"Type":"net","Net":{"Daddr":134744072,"Dport":443}},"decision":"Allow","rationale":"dns"}`,
			want: "8.8.8.8:443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var e auditEntry
			if err := json.Unmarshal([]byte(tc.json), &e); err != nil {
				t.Fatal(err)
			}
			if got := e.resource(); got != tc.want {
				t.Errorf("resource() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuditEntryActor(t *testing.T) {
	var e auditEntry
	data := `{"event":{"Type":"file_open","FileOpen":{"Path":"/etc/ld.so.cache"}},"actor":"/usr/bin/ls -la","decision":"Allow","rationale":"normal loader"}`
	if err := json.Unmarshal([]byte(data), &e); err != nil {
		t.Fatal(err)
	}
	if e.Actor != "/usr/bin/ls -la" {
		t.Errorf("Actor = %q", e.Actor)
	}
}

func TestReadNewAuditLines(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	line1 := `{"timestamp":"2026-07-18T10:00:00Z","session_id":"1-2","event":{"Type":"file_open","FileOpen":{"Pid":7,"Path":"/etc/passwd"}},"decision":"Deny","rationale":"first"}` + "\n"
	line2 := `{"timestamp":"2026-07-18T10:00:01Z","session_id":"1-2","event":{"Type":"file_open","FileOpen":{"Pid":7,"Path":"/etc/shadow"}},"decision":"Allow","rationale":"second"}` + "\n"

	if err := os.WriteFile("audit.jsonl", []byte(line1), 0644); err != nil {
		t.Fatal(err)
	}

	m := &model{}
	m.readNewAuditLines()
	if len(m.feed) != 1 {
		t.Fatalf("expected 1 feed item, got %d", len(m.feed))
	}

	// Append: only the new line should be read.
	f, _ := os.OpenFile("audit.jsonl", os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString(line2)
	f.Close()

	m.readNewAuditLines()
	if len(m.feed) != 2 {
		t.Fatalf("expected 2 feed items, got %d", len(m.feed))
	}
	// Newest first
	if m.feed[0].entry.Rationale != "second" {
		t.Errorf("newest entry should be first, got %q", m.feed[0].entry.Rationale)
	}

	// Idle read: nothing new, no duplicates.
	m.readNewAuditLines()
	if len(m.feed) != 2 {
		t.Errorf("idle read duplicated entries: %d", len(m.feed))
	}

	// Truncation (log rotate): offset resets instead of going negative.
	os.WriteFile("audit.jsonl", []byte(line1), 0644)
	m.readNewAuditLines()
	if len(m.feed) == 0 {
		t.Error("feed should survive log rotation")
	}
}

func TestRefreshStatsHandlesMissingDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	m := &model{}
	m.refreshStats() // must not panic
	if m.stats.dbPresent {
		t.Error("dbPresent should be false without aegis.db")
	}
}

func TestProviderStringNeverPanics(t *testing.T) {
	t.Chdir(t.TempDir()) // no providers.json here; embedded fallback engages
	if got := providerString(); !strings.Contains(got, "openai") {
		t.Errorf("providerString should resolve the default, got %q", got)
	}
}
