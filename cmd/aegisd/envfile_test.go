package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyEnvFile(t *testing.T) {
	for _, k := range []string{"TEST_AEGIS_KEY", "TEST_AEGIS_MODEL", "TEST_AEGIS_URL", "TEST_AEGIS_EMPTY"} {
		os.Unsetenv(k)
		t.Cleanup(func() { os.Unsetenv(k) })
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "aegis.env")
	content := `
# a comment
TEST_AEGIS_KEY=sk-or-v1-abc123
export TEST_AEGIS_MODEL="openai/gpt-4o"
TEST_AEGIS_URL='https://openrouter.ai/api/v1/chat/completions'
BROKEN_LINE_NO_EQUALS

TEST_AEGIS_EMPTY=
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Process env must win over the file.
	t.Setenv("TEST_AEGIS_URL", "https://process-env-wins.example")

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	n := applyEnvFile(f)
	if n != 3 {
		t.Fatalf("expected 3 loaded values, got %d", n)
	}
	if got := os.Getenv("TEST_AEGIS_KEY"); got != "sk-or-v1-abc123" {
		t.Errorf("key not loaded: %q", got)
	}
	if got := os.Getenv("TEST_AEGIS_MODEL"); got != "openai/gpt-4o" {
		t.Errorf("quoted value not unwrapped: %q", got)
	}
	if got := os.Getenv("TEST_AEGIS_URL"); got != "https://process-env-wins.example" {
		t.Errorf("process env should win, got: %q", got)
	}
	if got := os.Getenv("TEST_AEGIS_EMPTY"); got != "" {
		t.Errorf("empty value should set empty string, got: %q", got)
	}
	if _, exists := os.LookupEnv("TEST_AEGIS_EMPTY"); !exists {
		t.Error("empty value should still be set")
	}
}

func TestLoadEnvFileExplicitPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.env")
	if err := os.WriteFile(path, []byte("TEST_AEGIS_EXPLICIT=from_file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("TEST_AEGIS_EXPLICIT")
	t.Cleanup(func() { os.Unsetenv("TEST_AEGIS_EXPLICIT") })
	t.Setenv("AEGIS_ENV_FILE", path)

	loadEnvFile()

	if got := os.Getenv("TEST_AEGIS_EXPLICIT"); got != "from_file" {
		t.Fatalf("explicit AEGIS_ENV_FILE not honored, got: %q", got)
	}
}

func TestLoadEnvFileMissingIsSilent(t *testing.T) {
	t.Setenv("AEGIS_ENV_FILE", "/nonexistent/aegis.env")
	loadEnvFile() // must not panic or exit
}
