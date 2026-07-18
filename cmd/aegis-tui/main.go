package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00ADD8")).MarginBottom(1)
	borderStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2).BorderForeground(lipgloss.Color("#2c3e50")).Width(60)
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#2ecc71"))
	alertStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c")).Bold(true)
	infoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#f1c40f"))
)

type model struct {
	events []string
	ticks  int
}

func initialModel() model {
	return model{
		events: []string{
			"[*] System Booted. eBPF hooks attached.",
			"[-] Listening for container telemetry...",
		},
		ticks: 0,
	}
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second*2, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Init() tea.Cmd {
	return tickCmd()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	case tickMsg:
		m.ticks++
		// Simulate live feed of Aegis
		if m.ticks == 2 {
			m.events = append([]string{alertStyle.Render("[!] Anomaly Detected: Repetitive .git traversal")}, m.events...)
		} else if m.ticks == 3 {
			m.events = append([]string{infoStyle.Render("[*] Cascade Proxy: Routed to Cheap LLM (Score: 4.5)")}, m.events...)
		} else if m.ticks == 4 {
			m.events = append([]string{alertStyle.Render("[!] BPF Block Signal Sent. (Process Denied)")}, m.events...)
		} else if m.ticks == 6 {
			m.events = append([]string{statusStyle.Render("[+] Bandit Proposes: AUTO_DECIDE_THRESHOLD -> 0.92")}, m.events...)
		}

		if len(m.events) > 8 {
			m.events = m.events[:8]
		}
		return m, tickCmd()
	}
	return m, nil
}

func (m model) View() string {
	s := titleStyle.Render("🛡️  Aegis Control Plane") + "\n"

	header := fmt.Sprintf("Status: %s | Hooks: 3 | Vectors: 5,234", statusStyle.Render("ONLINE"))
	s += header + "\n\n"

	eventsStr := strings.Join(m.events, "\n")
	s += borderStyle.Render("Live Telemetry & Adjudication Feed\n\n"+eventsStr) + "\n\n"

	s += lipgloss.NewStyle().Faint(true).Render("Press 'q' to exit")

	return lipgloss.Place(
		80, 24,
		lipgloss.Center, lipgloss.Center,
		s,
	)
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}
