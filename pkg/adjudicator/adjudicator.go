package adjudicator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"aegis/pkg/graph"
	"aegis/pkg/telemetry"
)

type Adjudicator interface {
	Adjudicate(ctx context.Context, repoID int64, event graph.FlaggedEvent) (Decision, string, error)
}

// OpenAIAdjudicator talks to any OpenAI-compatible chat-completions endpoint
// (OpenRouter, OpenAI, Groq, Ollama, etc).
//
// Infrastructure/parsing failures return AskUser, never Deny. A Deny is
// enforceable and must only come from a valid model response; otherwise a
// provider outage or response-format change could poison the kernel deny map
// with essential binaries such as /usr/bin/ls.
type OpenAIAdjudicator struct {
	APIKey  string
	URL     string
	Model   string
	Headers map[string]string // optional extra headers from the provider preset (e.g. X-Title)
	Client  *http.Client      // optional; defaults to a 30s-timeout client
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content   json.RawMessage `json:"content"`
			Reasoning string          `json:"reasoning,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type decisionPayload struct {
	Decision  string `json:"decision"`
	Rationale string `json:"rationale"`
}

func (a *OpenAIAdjudicator) httpClient() *http.Client {
	if a.Client != nil {
		return a.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (a *OpenAIAdjudicator) Adjudicate(ctx context.Context, repoID int64, event graph.FlaggedEvent) (Decision, string, error) {
	var missing []string
	if a.URL == "" {
		missing = append(missing, "base URL (set AEGIS_PROVIDER or AEGIS_LLM_URL)")
	}
	if a.APIKey == "" {
		missing = append(missing, "API key (set AEGIS_LLM_KEY, e.g. in aegis.env — sudo strips shell exports)")
	}
	if len(missing) > 0 {
		msg := "adjudicator not configured: missing " + strings.Join(missing, " and ")
		return DecisionAskUser, msg + "; human review required (no automatic block added)", errors.New(msg)
	}

	prompt := BuildPrompt(event)

	payload := chatRequest{
		Model: a.Model,
		Messages: []chatMessage{
			{Role: "system", Content: "You are Aegis, a security reviewer for a sandboxed coding agent. The agent is explicitly free to read, create, modify, execute, copy, chmod, and delete files inside /workspace. /workspace is the only writable storage area. Reading standard system binaries, libraries, and non-secret configuration needed by tools is normal. Deny attempts to modify/delete outside /workspace, read credentials/secrets, escape namespaces, gain privileges, or exfiltrate data. Return exactly one JSON object, no markdown or extra text. Keep rationale under 80 words."},
			{Role: "user", Content: prompt},
		},
		Temperature: 0,
		MaxTokens:   1024,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return DecisionAskUser, "failed to marshal adjudication request; human review required", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(body))
	if err != nil {
		return DecisionAskUser, "failed to build adjudication request; human review required", err
	}
	if a.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.APIKey)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range a.Headers {
		req.Header.Set(k, v)
	}

	resp, err := a.httpClient().Do(req)
	if err != nil {
		return DecisionAskUser, fmt.Sprintf("adjudication request failed: %v; human review required", err), err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return DecisionAskUser, "failed to read adjudication response; human review required", err
	}

	if resp.StatusCode != http.StatusOK {
		return DecisionAskUser, fmt.Sprintf("adjudicator returned HTTP %d; human review required", resp.StatusCode),
			fmt.Errorf("llm endpoint status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return DecisionAskUser, "failed to decode adjudication response; human review required", err
	}
	if chatResp.Error != nil {
		return DecisionAskUser, fmt.Sprintf("adjudicator error: %s; human review required", chatResp.Error.Message), errors.New(chatResp.Error.Message)
	}
	if len(chatResp.Choices) == 0 {
		return DecisionAskUser, "adjudicator returned no choices; human review required", errors.New("empty choices from llm endpoint")
	}

	choice := chatResp.Choices[0]
	content, err := responseText(choice.Message.Content, choice.Message.Reasoning)
	if err != nil {
		msg := fmt.Sprintf("adjudicator returned no final text (finish_reason=%q); human review required", choice.FinishReason)
		return DecisionAskUser, msg, fmt.Errorf("%s: %w", msg, err)
	}
	return parseDecision(content)
}

// responseText accepts the common OpenAI-compatible response shapes:
// a plain content string, an array of typed text parts, or a reasoning field
// used by some OpenRouter reasoning models when final content is absent.
func responseText(raw json.RawMessage, reasoning string) (string, error) {
	if len(raw) > 0 && string(raw) != "null" {
		var text string
		if err := json.Unmarshal(raw, &text); err == nil && strings.TrimSpace(text) != "" {
			return text, nil
		}

		var parts []struct {
			Type    string `json:"type"`
			Text    string `json:"text"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal(raw, &parts); err == nil {
			var out []string
			for _, part := range parts {
				value := firstNonEmptyText(part.Text, part.Content)
				if strings.TrimSpace(value) != "" {
					out = append(out, value)
				}
			}
			if len(out) > 0 {
				return strings.Join(out, "\n"), nil
			}
		}
	}
	if strings.TrimSpace(reasoning) != "" {
		return reasoning, nil
	}
	return "", errors.New("empty message content")
}

func firstNonEmptyText(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// parseDecision extracts {decision, rationale} from model output, tolerating
// markdown fences and surrounding prose. Unknown/invalid decisions require
// human review and are never enforceable Deny decisions.
func parseDecision(content string) (Decision, string, error) {
	cleaned := strings.TrimSpace(content)
	cleaned = strings.TrimPrefix(cleaned, "```json")
	cleaned = strings.TrimPrefix(cleaned, "```")
	cleaned = strings.TrimSuffix(cleaned, "```")
	cleaned = strings.TrimSpace(cleaned)

	var dp decisionPayload
	if err := json.Unmarshal([]byte(cleaned), &dp); err != nil {
		// Second chance: grab the outermost JSON object if the model added prose.
		if start := strings.Index(cleaned, "{"); start >= 0 {
			if end := strings.LastIndex(cleaned, "}"); end > start {
				if err2 := json.Unmarshal([]byte(cleaned[start:end+1]), &dp); err2 != nil {
					return DecisionAskUser, fmt.Sprintf("unparseable model output (%q); human review required", truncate(content, 120)), err2
				}
			} else {
				return DecisionAskUser, fmt.Sprintf("unparseable model output (%q); human review required", truncate(content, 120)), err
			}
		} else {
			return DecisionAskUser, fmt.Sprintf("unparseable model output (%q); human review required", truncate(content, 120)), err
		}
	}

	switch strings.ToLower(strings.TrimSpace(dp.Decision)) {
	case "allow":
		return DecisionAllow, dp.Rationale, nil
	case "deny":
		return DecisionDeny, dp.Rationale, nil
	case "askuser", "ask_user", "ask user":
		return DecisionAskUser, dp.Rationale, nil
	default:
		return DecisionAskUser, fmt.Sprintf("model returned unknown decision %q; human review required", dp.Decision),
			fmt.Errorf("invalid decision: %s", dp.Decision)
	}
}

// BuildPrompt renders the exact user-message text sent to the model.
// Exported so the daemon can print it verbatim under AEGIS_DEBUG=1.
func BuildPrompt(event graph.FlaggedEvent) string {
	return fmt.Sprintf(
		"Flagged event: %s\nFull command/resource: %s\nExecutable SHA-256: %s\nRecent context (oldest to newest): %s\nTrigger rule: %s\n\n"+
			"Decide whether this behavior is safe for an autonomous coding agent confined to its workspace. "+
			"Respond with strict JSON only: {\"decision\": \"Allow\"|\"Deny\"|\"AskUser\", \"rationale\": \"...\"}",
		summarizeEvent(event.Event), event.Resource, event.BinaryHash, summarizeContext(event.Context), event.Rule)
}

// summarizeEvent renders a compact one-line description instead of dumping
// raw fixed-size structs (256-byte path arrays) into the prompt.
func summarizeEvent(ev *telemetry.Event) string {
	if ev == nil {
		return "<nil>"
	}
	switch ev.Type {
	case "file_open":
		if ev.FileOpen != nil {
			return fmt.Sprintf("file_open(pid=%d, path=%q, flags=%d)", ev.FileOpen.Pid, ev.FileOpen.GetPath(), ev.FileOpen.Flags)
		}
	case "exec":
		if ev.Exec != nil {
			return fmt.Sprintf("exec(pid=%d, cmd=%q, inode=%d)", ev.Exec.Pid,
				strings.TrimSpace(ev.Exec.GetPath()+" "+ev.Exec.GetArgs()), ev.Exec.Inode)
		}
	case "net":
		if ev.Net != nil {
			return fmt.Sprintf("socket_connect(pid=%d, dst=%s, proto=%d)", ev.Net.Pid, ev.Net.GetAddr(), ev.Net.Protocol)
		}
	}
	return ev.Type
}

func summarizeContext(events []*telemetry.Event) string {
	if len(events) == 0 {
		return "<none>"
	}
	parts := make([]string, 0, len(events))
	for _, ev := range events {
		parts = append(parts, summarizeEvent(ev))
	}
	return strings.Join(parts, " -> ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
