package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clearEnv unsets every variable that can influence resolution,
// restoring them after the test.
func clearEnv(t *testing.T) {
	t.Helper()
	vars := []string{
		"AEGIS_PROVIDER", "AEGIS_LLM_URL", "AEGIS_LLM_KEY", "AEGIS_LLM_MODEL",
		"AEGIS_CHEAP_MODEL", "AEGIS_FLAGSHIP_MODEL", "OPENAI_API_KEY",
		"AEGIS_PROVIDERS_FILE", "AEGIS_ENV_FILE", "OPENROUTER_API_KEY",
		"GROQ_API_KEY", "TOGETHER_API_KEY",
	}
	for _, v := range vars {
		old, had := os.LookupEnv(v)
		os.Unsetenv(v)
		t.Cleanup(func() {
			if had {
				os.Setenv(v, old)
			} else {
				os.Unsetenv(v)
			}
		})
	}
}

// loadEmbedded loads the fallback registry, bypassing any repo-root
// providers.json so tests are deterministic.
func loadEmbedded(t *testing.T) *Registry {
	t.Helper()
	clearEnv(t)
	t.Setenv("AEGIS_PROVIDERS_FILE", filepath.Join(t.TempDir(), "does-not-exist.json"))
	reg, err := Load()
	if err != nil {
		t.Fatalf("Load() with no file present should use fallback: %v", err)
	}
	if reg.Source != "embedded fallback" {
		t.Fatalf("expected embedded fallback, got %q", reg.Source)
	}
	return reg
}

func TestDefaultResolution(t *testing.T) {
	reg := loadEmbedded(t)
	cfg, err := reg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProviderName != "openai" {
		t.Errorf("default provider = %q, want openai", cfg.ProviderName)
	}
	if cfg.CheapModel != "gpt-4o" || cfg.FlagshipModel != "gpt-5.6-sol" {
		t.Errorf("default models = %q/%q, want gpt-4o/gpt-5.6-sol", cfg.CheapModel, cfg.FlagshipModel)
	}
	if cfg.Key != "" || cfg.KeySource != "" {
		t.Errorf("expected no key, got source=%q", cfg.KeySource)
	}
	if cfg.URL != "https://api.openai.com/v1/chat/completions" {
		t.Errorf("unexpected default URL: %q", cfg.URL)
	}
}

func TestPresetFill(t *testing.T) {
	reg := loadEmbedded(t)
	t.Setenv("AEGIS_PROVIDER", "ollama")
	cfg, err := reg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth != "none" {
		t.Errorf("ollama auth = %q, want none", cfg.Auth)
	}
	if cfg.URL != "http://localhost:11434/v1/chat/completions" {
		t.Errorf("ollama url = %q", cfg.URL)
	}
	if cfg.Key != "" {
		t.Errorf("auth=none must not produce a key, got %q", cfg.MaskedKey())
	}
	if cfg.CheapModel != "llama3.1:8b" || cfg.FlagshipModel != "llama3.3:70b" {
		t.Errorf("ollama models = %q/%q", cfg.CheapModel, cfg.FlagshipModel)
	}
}

func TestEnvOverridesPreset(t *testing.T) {
	reg := loadEmbedded(t)
	t.Setenv("AEGIS_PROVIDER", "openai")
	t.Setenv("AEGIS_LLM_MODEL", "some/custom-model")
	cfg, err := reg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CheapModel != "some/custom-model" || cfg.FlagshipModel != "some/custom-model" {
		t.Errorf("AEGIS_LLM_MODEL should set both tiers, got %q/%q", cfg.CheapModel, cfg.FlagshipModel)
	}

	t.Setenv("AEGIS_FLAGSHIP_MODEL", "big-model")
	cfg, err = reg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CheapModel != "some/custom-model" || cfg.FlagshipModel != "big-model" {
		t.Errorf("tier override wrong: cheap=%q flagship=%q", cfg.CheapModel, cfg.FlagshipModel)
	}
}

func TestExplicitURLBeatsPreset(t *testing.T) {
	reg := loadEmbedded(t)
	t.Setenv("AEGIS_LLM_URL", "http://127.0.0.1:9999/v1/chat/completions")
	cfg, err := reg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "http://127.0.0.1:9999/v1/chat/completions" {
		t.Errorf("explicit URL lost: %q", cfg.URL)
	}
}

func TestUnknownProviderListsNames(t *testing.T) {
	reg := loadEmbedded(t)
	t.Setenv("AEGIS_PROVIDER", "doesnotexist")
	_, err := reg.Resolve()
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "openrouter") || !strings.Contains(err.Error(), "ollama") {
		t.Errorf("error should list valid names, got: %v", err)
	}
}

func TestKeyPrecedence(t *testing.T) {
	reg := loadEmbedded(t)
	// openrouter declares AEGIS_LLM_KEY as its key_env; it must beat the
	// legacy OPENAI_API_KEY fallback.
	t.Setenv("AEGIS_PROVIDER", "openrouter")

	t.Setenv("OPENAI_API_KEY", "sk-legacy-1234567890")
	cfg, err := reg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KeySource != "OPENAI_API_KEY" {
		t.Errorf("legacy fallback should win when nothing else set, got %q", cfg.KeySource)
	}

	t.Setenv("AEGIS_LLM_KEY", "sk-or-v1-abcdef1234567890")
	cfg, err = reg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KeySource != "AEGIS_LLM_KEY" {
		t.Errorf("preset key_env should win, got %q", cfg.KeySource)
	}
	if strings.Contains(cfg.MaskedKey(), "abcdef1234567890") {
		t.Errorf("MaskedKey leaks the key: %q", cfg.MaskedKey())
	}
}

func TestMalformedProvidersFile(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "providers.json")
	os.WriteFile(path, []byte("{not json"), 0600)
	t.Setenv("AEGIS_PROVIDERS_FILE", path)

	_, err := Load()
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error should name the file, got: %v", err)
	}
}

func TestFileOverridesEmbedded(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "providers.json")
	content := `{"providers": {"mine": {"url": "http://example.invalid/v1/chat/completions", "auth": "none", "default_model": "m1"}}}`
	os.WriteFile(path, []byte(content), 0600)
	t.Setenv("AEGIS_PROVIDERS_FILE", path)
	t.Setenv("AEGIS_PROVIDER", "mine")

	reg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if reg.Source != path {
		t.Fatalf("expected source %q, got %q", path, reg.Source)
	}
	cfg, err := reg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CheapModel != "m1" || cfg.FlagshipModel != "m1" {
		t.Errorf("custom file models wrong: %q/%q", cfg.CheapModel, cfg.FlagshipModel)
	}
}

func TestCustomRequiresURL(t *testing.T) {
	reg := loadEmbedded(t)
	t.Setenv("AEGIS_PROVIDER", "custom")
	_, err := reg.Resolve()
	if err == nil || !strings.Contains(err.Error(), "AEGIS_LLM_URL") {
		t.Fatalf("custom without URL should point at AEGIS_LLM_URL, got: %v", err)
	}
}

func TestSetEnvVars(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aegis.env")
	original := "# my config\nAEGIS_PROVIDER=openai\nAEGIS_LLM_KEY=sk-secret-do-not-touch\n"
	os.WriteFile(path, []byte(original), 0600)

	changes, err := SetEnvVars(path, map[string]string{
		"AEGIS_PROVIDER":  "openrouter",
		"AEGIS_LLM_MODEL": "deepseek/deepseek-v4-flash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Errorf("expected 2 changes, got %v", changes)
	}

	out, _ := os.ReadFile(path)
	text := string(out)
	if !strings.Contains(text, "# my config") {
		t.Error("comment line was lost")
	}
	if !strings.Contains(text, "AEGIS_PROVIDER=openrouter") {
		t.Error("provider not updated in place")
	}
	if !strings.Contains(text, "AEGIS_LLM_MODEL=deepseek/deepseek-v4-flash") {
		t.Error("new model var not appended")
	}
	if !strings.Contains(text, "AEGIS_LLM_KEY=sk-secret-do-not-touch") {
		t.Error("existing key line was modified")
	}

	// Idempotent second run
	if _, err := SetEnvVars(path, map[string]string{"AEGIS_PROVIDER": "openrouter"}); err != nil {
		t.Fatal(err)
	}
	out2, _ := os.ReadFile(path)
	if strings.Count(string(out2), "AEGIS_PROVIDER=") != 1 {
		t.Errorf("duplicate provider lines after second set:\n%s", out2)
	}
}

func TestSetEnvVarsRefusesKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aegis.env")
	_, err := SetEnvVars(path, map[string]string{"AEGIS_LLM_KEY": "nope"})
	if err == nil || !strings.Contains(err.Error(), "KEY") {
		t.Fatalf("expected refusal for key var, got: %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("file should not have been created for a refused write")
	}
}

func TestLoadEnvFile(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "aegis.env")
	os.WriteFile(path, []byte("# c\nAEGIS_PROVIDER=groq\nexport AEGIS_LLM_MODEL=\"m/x\"\n"), 0600)
	t.Setenv("AEGIS_ENV_FILE", path)

	LoadEnvFile()

	if got := os.Getenv("AEGIS_PROVIDER"); got != "groq" {
		t.Errorf("AEGIS_PROVIDER = %q, want groq", got)
	}
	if got := os.Getenv("AEGIS_LLM_MODEL"); got != "m/x" {
		t.Errorf("quoted value not unwrapped: %q", got)
	}
}

func TestListModelsOpenRouterShape(t *testing.T) {
	clearEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("missing auth header on models request")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "deepseek/deepseek-v4-flash", "pricing": map[string]string{"prompt": "0.000000098", "completion": "0.000000196"}},
				{"id": "openai/gpt-4o-mini"},
			},
		})
	}))
	defer srv.Close()

	res := &Resolved{
		ProviderName: "openrouter",
		ModelsURL:    srv.URL,
		Key:          "test-key",
		Auth:         "bearer",
	}
	models, err := ListModels(context.Background(), res)
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d", len(models))
	}
	if models[0].ID != "deepseek/deepseek-v4-flash" || models[0].PromptPrice == "" {
		t.Errorf("pricing not parsed: %+v", models[0])
	}
}

func TestListModelsOllamaShape(t *testing.T) {
	clearEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("auth=none must not send Authorization header")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{{"name": "llama3.1:8b"}},
		})
	}))
	defer srv.Close()

	res := &Resolved{ProviderName: "ollama", ModelsURL: srv.URL, Auth: "none"}
	models, err := ListModels(context.Background(), res)
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].ID != "llama3.1:8b" {
		t.Fatalf("ollama parse failed: %+v", models)
	}
}
