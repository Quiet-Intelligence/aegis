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
// Fail-closed contract: every transport or parsing failure returns
// DecisionDeny alongside the error, so a misconfigured or unreachable
// adjudicator can never silently allow a flagged event.
type OpenAIAdjudicator struct {
	APIKey string
	URL    string
	Model  string
	Client *http.Client // optional; defaults to a 30s-timeout client
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
		Message chatMessage `json:"message"`
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
	if a.URL == "" || a.APIKey == "" {
		return DecisionDeny, "adjudicator not configured (set AEGIS_LLM_URL and AEGIS_LLM_KEY); failing closed", errors.New("adjudicator not configured")
	}

	prompt := BuildPrompt(event)

	payload := chatRequest{
		Model: a.Model,
		Messages: []chatMessage{
			{Role: "system", Content: "You are Aegis, a zero-trust agentic security boundary. You audit syscall sequences from a sandboxed AI agent. Answer with strict JSON only."},
			{Role: "user", Content: prompt},
		},
		Temperature: 0,
		MaxTokens:   300,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return DecisionDeny, "failed to marshal adjudication request; failing closed", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(body))
	if err != nil {
		return DecisionDeny, "failed to build adjudication request; failing closed", err
	}
	req.Header.Set("Authorization", "Bearer "+a.APIKey)
	req.Header.Set("Content-Type", "application/json")
	// OpenRouter attribution header; ignored by other providers.
	req.Header.Set("X-Title", "aegisd")

	resp, err := a.httpClient().Do(req)
	if err != nil {
		return DecisionDeny, fmt.Sprintf("adjudication request failed: %v; failing closed", err), err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return DecisionDeny, "failed to read adjudication response; failing closed", err
	}

	if resp.StatusCode != http.StatusOK {
		return DecisionDeny, fmt.Sprintf("adjudicator returned HTTP %d; failing closed", resp.StatusCode),
			fmt.Errorf("llm endpoint status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return DecisionDeny, "failed to decode adjudication response; failing closed", err
	}
	if chatResp.Error != nil {
		return DecisionDeny, fmt.Sprintf("adjudicator error: %s; failing closed", chatResp.Error.Message), errors.New(chatResp.Error.Message)
	}
	if len(chatResp.Choices) == 0 {
		return DecisionDeny, "adjudicator returned no choices; failing closed", errors.New("empty choices from llm endpoint")
	}

	return parseDecision(chatResp.Choices[0].Message.Content)
}

// parseDecision extracts {decision, rationale} from model output, tolerating
// markdown fences and surrounding prose. Unknown decisions fail closed.
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
					return DecisionDeny, fmt.Sprintf("unparseable model output (%q); failing closed", truncate(content, 120)), err2
				}
			} else {
				return DecisionDeny, fmt.Sprintf("unparseable model output (%q); failing closed", truncate(content, 120)), err
			}
		} else {
			return DecisionDeny, fmt.Sprintf("unparseable model output (%q); failing closed", truncate(content, 120)), err
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
		return DecisionDeny, fmt.Sprintf("model returned unknown decision %q; failing closed", dp.Decision),
			fmt.Errorf("invalid decision: %s", dp.Decision)
	}
}

// BuildPrompt renders the exact user-message text sent to the model.
// Exported so the daemon can print it verbatim under AEGIS_DEBUG=1.
func BuildPrompt(event graph.FlaggedEvent) string {
	return fmt.Sprintf(
		"Flagged event: %s\nRecent context (oldest to newest): %s\nTrigger rule: %s\n\n"+
			"Decide whether this behavior is safe for an autonomous coding agent confined to its workspace. "+
			"Respond with strict JSON only: {\"decision\": \"Allow\"|\"Deny\"|\"AskUser\", \"rationale\": \"...\"}",
		summarizeEvent(event.Event), summarizeContext(event.Context), event.Rule)
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
