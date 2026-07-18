// Package provider resolves which LLM endpoint and models the daemon
// should use, from a user-editable providers.json plus environment
// variables. Keys always come from the environment and are never
// written anywhere by this package or the CLI.
package provider

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// DefaultProvider and DefaultModel are used when nothing is configured.
const (
	DefaultProvider = "openai"
	DefaultModel    = "gpt-4o"
)

//go:embed providers_fallback.json
var fallbackJSON []byte

// Preset is one named entry in providers.json.
type Preset struct {
	URL           string            `json:"url"`
	ModelsURL     string            `json:"models_url,omitempty"`
	KeyEnv        string            `json:"key_env,omitempty"`
	Auth          string            `json:"auth,omitempty"` // "bearer" (default) or "none"
	Headers       map[string]string `json:"headers,omitempty"`
	DefaultModel  string            `json:"default_model,omitempty"`
	CheapModel    string            `json:"cheap_model,omitempty"`
	FlagshipModel string            `json:"flagship_model,omitempty"`
	Comment       string            `json:"comment,omitempty"`
}

// Registry is the loaded set of presets and where they came from.
type Registry struct {
	Providers map[string]Preset
	Source    string // file path or "embedded fallback"
}

type registryFile struct {
	Providers map[string]Preset `json:"providers"`
}

// Load reads the first providers.json found, falling back to an embedded
// copy so the binary always works.
//
// Search order: $AEGIS_PROVIDERS_FILE, ./providers.json,
// /etc/aegis/providers.json, embedded fallback.
func Load() (*Registry, error) {
	candidates := []string{}
	if explicit := os.Getenv("AEGIS_PROVIDERS_FILE"); explicit != "" {
		candidates = []string{explicit}
	} else {
		candidates = []string{"providers.json", "/etc/aegis/providers.json"}
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var rf registryFile
		if err := json.Unmarshal(data, &rf); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}
		if len(rf.Providers) == 0 {
			return nil, fmt.Errorf("%s contains no providers", path)
		}
		return &Registry{Providers: rf.Providers, Source: path}, nil
	}

	var rf registryFile
	if err := json.Unmarshal(fallbackJSON, &rf); err != nil {
		return nil, fmt.Errorf("embedded providers_fallback.json is broken: %w", err)
	}
	return &Registry{Providers: rf.Providers, Source: "embedded fallback"}, nil
}

// Names returns the sorted preset names (for errors and `list`).
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.Providers))
	for name := range r.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Resolved is the final runtime configuration.
type Resolved struct {
	ProviderName  string
	URL           string
	Key           string
	KeySource     string   // name of the env var the key came from (never the value)
	KeyEnvsTried  []string // vars checked, in order (for the missing-key warning)
	CheapModel    string
	FlagshipModel string
	Headers       map[string]string
	ModelsURL     string
	Auth          string
}

// MaskedKey renders the key for display without revealing it.
func (r *Resolved) MaskedKey() string {
	if r.Key == "" {
		return "<not set>"
	}
	if len(r.Key) <= 8 {
		return "****"
	}
	return r.Key[:4] + "..." + "****"
}

// Resolve applies the documented precedence, per field:
//
//	explicit env vars  >  AEGIS_PROVIDER preset  >  shipped default
//
// AEGIS_LLM_MODEL sets both tiers; AEGIS_CHEAP_MODEL / AEGIS_FLAGSHIP_MODEL
// override their own tier only.
func (r *Registry) Resolve() (*Resolved, error) {
	name := os.Getenv("AEGIS_PROVIDER")
	if name == "" {
		name = DefaultProvider
	}

	preset, ok := r.Providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q (loaded from %s); valid names: %s",
			name, r.Source, strings.Join(r.Names(), ", "))
	}

	auth := preset.Auth
	if auth == "" {
		auth = "bearer"
	}

	url := firstNonEmpty(os.Getenv("AEGIS_LLM_URL"), preset.URL)
	if url == "" {
		return nil, fmt.Errorf("provider %q has no url in %s; set AEGIS_LLM_URL", name, r.Source)
	}

	llmModel := os.Getenv("AEGIS_LLM_MODEL")
	cheap := firstNonEmpty(os.Getenv("AEGIS_CHEAP_MODEL"), llmModel, preset.CheapModel, preset.DefaultModel, DefaultModel)
	flagship := firstNonEmpty(os.Getenv("AEGIS_FLAGSHIP_MODEL"), llmModel, preset.FlagshipModel, preset.DefaultModel, DefaultModel)

	res := &Resolved{
		ProviderName:  name,
		URL:           url,
		CheapModel:    cheap,
		FlagshipModel: flagship,
		Headers:       preset.Headers,
		ModelsURL:     preset.ModelsURL,
		Auth:          auth,
	}

	if auth == "none" {
		return res, nil
	}

	// Key lookup: the preset's declared var, then the generic ones.
	candidates := []string{}
	if preset.KeyEnv != "" {
		candidates = append(candidates, preset.KeyEnv)
	}
	for _, v := range []string{"AEGIS_LLM_KEY", "OPENAI_API_KEY"} {
		seen := false
		for _, c := range candidates {
			if c == v {
				seen = true
			}
		}
		if !seen {
			candidates = append(candidates, v)
		}
	}
	res.KeyEnvsTried = candidates
	for _, v := range candidates {
		if key := os.Getenv(v); key != "" {
			res.Key = key
			res.KeySource = v
			break
		}
	}
	return res, nil
}

// LoadEnvFile fills in missing env vars from the first config file found:
// $AEGIS_ENV_FILE, ./aegis.env, ./.env, /etc/aegis/aegis.env.
// Variables already present in the process environment always win.
// Required because sudo strips user exports before aegisd runs.
func LoadEnvFile() {
	candidates := []string{}
	if explicit := os.Getenv("AEGIS_ENV_FILE"); explicit != "" {
		candidates = []string{explicit}
	} else {
		candidates = []string{"aegis.env", ".env", "/etc/aegis/aegis.env"}
	}

	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		n := applyEnvFile(f)
		f.Close()
		fmt.Printf("Loaded %d config value(s) from %s\n", n, path)
		return
	}
}

func applyEnvFile(f *os.File) int {
	loaded := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err == nil {
			loaded++
		}
	}
	return loaded
}

// SetEnvVars updates (or appends) whitelisted variables in an env file,
// preserving comments and unrelated lines. Any variable containing "KEY"
// is refused: secrets are never written by tooling.
func SetEnvVars(path string, vars map[string]string) ([]string, error) {
	for k := range vars {
		if strings.Contains(strings.ToUpper(k), "KEY") {
			return nil, fmt.Errorf("refusing to write %s: keys must be set in the environment manually", k)
		}
	}

	var lines []string
	data, err := os.ReadFile(path)
	if err == nil {
		lines = strings.Split(string(data), "\n")
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	var changes []string
	remaining := map[string]string{}
	for k, v := range vars {
		remaining[k] = v
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		body := strings.TrimPrefix(trimmed, "export ")
		key, _, ok := strings.Cut(body, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		newVal, pending := remaining[key]
		if !pending {
			continue
		}
		old := trimmed
		lines[i] = key + "=" + newVal
		changes = append(changes, fmt.Sprintf("- %s\n+ %s", old, lines[i]))
		delete(remaining, key)
	}

	// Drop a trailing empty element from Split so we don't accumulate blank lines.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for k, v := range remaining {
		lines = append(lines, k+"="+v)
		changes = append(changes, fmt.Sprintf("+ %s=%s (new)", k, v))
	}

	out := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(out), 0600); err != nil {
		return nil, err
	}
	return changes, nil
}

// ModelInfo is one entry from a provider's models endpoint.
type ModelInfo struct {
	ID              string
	PromptPrice     string // OpenRouter only; empty elsewhere
	CompletionPrice string
}

// ListModels queries the provider's models endpoint. Handles both the
// OpenAI/OpenRouter shape ({data:[{id}]}) and the Ollama shape
// ({models:[{name}]}).
func ListModels(ctx context.Context, res *Resolved) ([]ModelInfo, error) {
	if res.ModelsURL == "" {
		return nil, fmt.Errorf("provider %q has no models_url configured", res.ProviderName)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, res.ModelsURL, nil)
	if err != nil {
		return nil, err
	}
	if res.Auth != "none" && res.Key != "" {
		req.Header.Set("Authorization", "Bearer "+res.Key)
	}
	for k, v := range res.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("models endpoint returned HTTP %d (check your key for %s)", resp.StatusCode, res.ProviderName)
	}

	var parsed struct {
		Data []struct {
			ID      string `json:"id"`
			Pricing *struct {
				Prompt     string `json:"prompt"`
				Completion string `json:"completion"`
			} `json:"pricing"`
		} `json:"data"`
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("could not decode models list: %w", err)
	}

	var out []ModelInfo
	for _, m := range parsed.Data {
		info := ModelInfo{ID: m.ID}
		if m.Pricing != nil {
			info.PromptPrice = m.Pricing.Prompt
			info.CompletionPrice = m.Pricing.Completion
		}
		out = append(out, info)
	}
	for _, m := range parsed.Models {
		out = append(out, ModelInfo{ID: m.Name})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("models endpoint returned an empty list")
	}
	return out, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
