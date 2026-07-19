package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"aegis/pkg/provider"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	_ "github.com/mattn/go-sqlite3"
)

var (
	logo = `
    ___    ______ ___________
   /   |  / ____// ____/  _/ ___/
  / /| | / __/  / / __ / / \__ \ 
 / ___ |/ /___ / /_/ // / ___/ / 
/_/  |_/_____/ \____/___//____/  
`
	logoColors = []string{
		"#00ADD8", "#00BCE4", "#00CBEF", "#00D9F9", "#00E7FF",
		"#00D9F9", "#00CBEF", "#00BCE4",
	}

	borderStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2).BorderForeground(lipgloss.Color("#2c3e50"))
	panelStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).BorderForeground(lipgloss.Color("#34495e"))
	
	denyStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff4757")).Bold(true)
	allowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#2ed573")).Bold(true)
	askStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffa502")).Bold(true)
	autoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#a4b0be"))
	
	dimStyle    = lipgloss.NewStyle().Faint(true).Foreground(lipgloss.Color("#747d8c"))
	labelStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#1e90ff")).Bold(true)
	valueStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff"))
	
	footerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#a4b0be")).PaddingTop(1)
)

type auditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id"`
	Event     struct {
		Type     string `json:"Type"`
		FileOpen *struct {
			Pid  uint32 `json:"Pid"`
			Path string `json:"Path"`
		} `json:"FileOpen"`
		Exec *struct {
			Pid  uint32 `json:"Pid"`
			Path string `json:"Path"`
			Args string `json:"Args"`
		} `json:"Exec"`
		Net *struct {
			Daddr uint32 `json:"Daddr"`
			Dport uint16 `json:"Dport"`
		} `json:"Net"`
	} `json:"event"`
	Rule       string `json:"rule"`
	Actor      string `json:"actor"`
	Resource   string `json:"resource"`
	BinaryHash string `json:"binary_sha256"`
	Decision   string `json:"decision"`
	Rationale  string `json:"rationale"`
}

func (e *auditEntry) resource() string {
	if e.Resource != "" {
		return e.Resource
	}
	switch e.Event.Type {
	case "file_open":
		if e.Event.FileOpen != nil {
			return e.Event.FileOpen.Path
		}
	case "exec":
		if e.Event.Exec != nil {
			return strings.TrimSpace(e.Event.Exec.Path + " " + e.Event.Exec.Args)
		}
	case "net":
		if e.Event.Net != nil {
			d := e.Event.Net.Daddr
			return fmt.Sprintf("%d.%d.%d.%d:%d", d>>24&0xFF, d>>16&0xFF, d>>8&0xFF, d&0xFF, e.Event.Net.Dport)
		}
	}
	return e.Event.Type
}

func (e *auditEntry) isAutoRecall() bool {
	return strings.HasPrefix(e.Rationale, "Auto-recalled")
}

type feedItem struct {
	entry auditEntry
}

type stats struct {
	vectors     int
	decisions   int
	autoRecalls int
	policies    []policyRow
	emaBaseline float64
	dbPresent   bool
}

type policyRow struct {
	ID         int
	MatchType  string
	MatchValue string
	Expires    time.Time
}

type model struct {
	feed        []feedItem
	stats       stats
	paused      bool
	auditOffset int64
	providerStr string
	scopeStr    string
	width       int
	height      int
	ticks       int
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func initialModel() model {
	return model{
		providerStr: providerString(),
		scopeStr:    scopeString(),
		ticks:       0,
	}
}

func providerString() string {
	registry, err := provider.Load()
	if err != nil {
		return "error (" + err.Error() + ")"
	}
	cfg, err := registry.Resolve()
	if err != nil {
		return "error (" + err.Error() + ")"
	}
	return fmt.Sprintf("%s (cheap=%s flagship=%s)", cfg.ProviderName, cfg.CheapModel, cfg.FlagshipModel)
}

func scopeString() string {
	if v, explicit := os.LookupEnv("AEGIS_CGROUP_ID"); explicit && strings.TrimSpace(v) != "" {
		if v == "0" {
			return "host-wide (audit-only)"
		}
		return "cgroup " + v
	}
	name := os.Getenv("AEGIS_CONTAINER_NAME")
	if name == "" {
		name = "aegis-agent-runtime"
	}
	out, err := exec.Command("docker", "inspect", "-f", "{{.Id}}", name).Output()
	if err != nil {
		return "waiting for " + name
	}
	cid := strings.TrimSpace(string(out))
	for _, p := range []string{
		fmt.Sprintf("/sys/fs/cgroup/system.slice/docker-%s.scope", cid),
		fmt.Sprintf("/sys/fs/cgroup/docker/%s", cid),
	} {
		if fi, err := os.Stat(p); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				return fmt.Sprintf("%s (cgroup %d)", name, st.Ino)
			}
		}
	}
	return "waiting for " + name
}

func (m *model) readNewAuditLines() {
	f, err := os.Open("audit.jsonl")
	if err != nil {
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return
	}
	if fi.Size() < m.auditOffset {
		m.auditOffset = 0
	}
	if fi.Size() == m.auditOffset {
		return
	}

	if _, err := f.Seek(m.auditOffset, 0); err != nil {
		return
	}
	buf := make([]byte, fi.Size()-m.auditOffset)
	n, _ := f.Read(buf)
	m.auditOffset += int64(n)

	for _, line := range strings.Split(string(buf[:n]), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e auditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		m.feed = append([]feedItem{{entry: e}}, m.feed...)
	}
	if len(m.feed) > 200 {
		m.feed = m.feed[:200]
	}
}

func (m *model) refreshStats() {
	s := stats{}
	db, err := sql.Open("sqlite3", "file:aegis.db?mode=ro")
	if err != nil {
		m.stats = s
		return
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		m.stats = s
		return
	}
	s.dbPresent = true

	db.QueryRow("SELECT COUNT(*) FROM embeddings").Scan(&s.vectors)
	db.QueryRow("SELECT COUNT(*) FROM flagged_events").Scan(&s.decisions)
	db.QueryRow("SELECT COUNT(*) FROM flagged_events WHERE decided_by = 'auto_recall'").Scan(&s.autoRecalls)
	db.QueryRow("SELECT ema_value FROM semantic_baseline WHERE feature_key = 'flagged_event_count' ORDER BY updated_at DESC LIMIT 1").Scan(&s.emaBaseline)

	rows, err := db.Query("SELECT id, match_type, match_value, expires_at FROM policy_entries WHERE revoked_at IS NULL ORDER BY id DESC LIMIT 8")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p policyRow
			if err := rows.Scan(&p.ID, &p.MatchType, &p.MatchValue, &p.Expires); err == nil {
				s.policies = append(s.policies, p)
			}
		}
	}
	m.stats = s
}

func (m model) Init() tea.Cmd { return tickCmd() }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "p":
			m.paused = !m.paused
		case "r":
			m.refreshStats()
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		m.ticks++
		if m.ticks%10 == 0 {
			if !m.paused {
				m.readNewAuditLines()
			}
			m.refreshStats()
			m.scopeStr = scopeString()
		}
		return m, tickCmd()
	}
	return m, nil
}

func decisionBadge(decision string, auto bool) string {
	tag := ""
	if auto {
		tag = autoStyle.Render("[AUTO]")
	}
	switch decision {
	case "Deny":
		return denyStyle.Render("[ DENY ]") + " " + tag
	case "Allow":
		return allowStyle.Render("[ ALLOW ]") + tag
	case "AskUser":
		return askStyle.Render("[ ASK ]") + "  " + tag
	default:
		return "[" + decision + "] " + tag
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func (m model) View() string {
	colorIdx := m.ticks % len(logoColors)
	logoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(logoColors[colorIdx])).Bold(true)
	
	logoView := logoStyle.Render(logo)
	
	statusView := "\n" +
		labelStyle.Render("STATUS:   ") + valueStyle.Render("[ONLINE]") + "\n" +
		labelStyle.Render("PROVIDER: ") + valueStyle.Render(m.providerStr) + "\n" +
		labelStyle.Render("SCOPE:    ") + valueStyle.Render(m.scopeStr)
		
	header := lipgloss.JoinHorizontal(lipgloss.Center, logoView, "    ", statusView)
	
	s := m.stats
	autoPct := 0.0
	if s.decisions > 0 {
		autoPct = 100 * float64(s.autoRecalls) / float64(s.decisions)
	}
	dbLine := fmt.Sprintf("%d (%.0f%% auto-recalled)", s.decisions, autoPct)
	if !s.dbPresent {
		dbLine = "waiting for daemon..."
	}
	
	metricsBar := lipgloss.JoinHorizontal(lipgloss.Top,
		panelStyle.Render(labelStyle.Render("Decisions: ")+valueStyle.Render(dbLine)),
		" ",
		panelStyle.Render(labelStyle.Render("Vectors Cached: ")+valueStyle.Render(fmt.Sprintf("%d", s.vectors))),
		" ",
		panelStyle.Render(labelStyle.Render("Baseline EMA: ")+valueStyle.Render(fmt.Sprintf("%.1f", s.emaBaseline))),
	)

	var feed strings.Builder
	if len(m.feed) == 0 {
		feed.WriteString(dimStyle.Render("Waiting for telemetry... (run aegisd and interact in the container)"))
	}
	
	availHeight := m.height - 20
	if availHeight < 5 {
		availHeight = 5
	}
	
	for i, item := range m.feed {
		if i >= availHeight {
			break
		}
		e := item.entry
		ts := e.Timestamp.Format("15:04:05")
		detail := e.Rationale
		if e.Actor != "" {
			detail = "by " + e.Actor + " | " + detail
		}
		
		feed.WriteString(fmt.Sprintf("%s %-15s %-6s %s\n      %s\n",
			dimStyle.Render(ts),
			decisionBadge(e.Decision, e.isAutoRecall()),
			e.Event.Type,
			truncate(e.resource(), 50),
			dimStyle.Render(truncate(detail, 80))))
	}
	
	feedTitle := "Live Adjudication Feed (audit.jsonl)"
	if m.paused {
		feedTitle += askStyle.Render(" [PAUSED]")
	}
	
	feedPanel := panelStyle.Copy().Width(m.width * 2 / 3).Render(
		lipgloss.NewStyle().Bold(true).Render(feedTitle) + "\n\n" + feed.String(),
	)
	
	var pol strings.Builder
	if len(s.policies) == 0 {
		pol.WriteString(dimStyle.Render("No active policies..."))
	}
	for _, p := range s.policies {
		pol.WriteString(fmt.Sprintf("#%d %s\n  %s\n  %s\n",
			p.ID, p.MatchType, truncate(p.MatchValue, 30), dimStyle.Render("exp: "+p.Expires.Format("01-02 15:04"))))
	}
	
	policyPanel := panelStyle.Copy().Width((m.width / 3) - 4).Render(
		lipgloss.NewStyle().Bold(true).Render("Active Kernel Policies") + "\n\n" + pol.String(),
	)
	
	body := lipgloss.JoinHorizontal(lipgloss.Top, feedPanel, "  ", policyPanel)
	
	footer := footerStyle.Render("[q] quit   [p] pause/resume feed   [r] force refresh")
	
	return lipgloss.JoinVertical(lipgloss.Left, header, "", metricsBar, "", body, footer)
}

func main() {
	provider.LoadEnvFile()
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("TUI error: %v\n", err)
		os.Exit(1)
	}
}
