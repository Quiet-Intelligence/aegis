package embed

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"strings"

	"aegis/pkg/graph"
)

type FeatureVector struct {
	SyscallClassSequence []string
	NormalizedPath       string
	AvgTimingNs          uint64
}

type Embedder interface {
	Embed(ctx context.Context, fv FeatureVector) ([]float32, error)
}

func BuildFeatureVector(flagged graph.FlaggedEvent) FeatureVector {
	var seq []string
	var totalTiming uint64
	var count uint64

	allEvents := append(flagged.Context, flagged.Event)
	for i, ev := range allEvents {
		seq = append(seq, ev.Type)
		if i > 0 {
			var currTime uint64
			if ev.Type == "file_open" && ev.FileOpen != nil {
				currTime = ev.FileOpen.TimestampNs
			} else if ev.Type == "exec" && ev.Exec != nil {
				currTime = ev.Exec.TimestampNs
			}
			totalTiming += currTime
			count++
		}
	}

	avgTiming := uint64(0)
	if count > 0 {
		avgTiming = totalTiming / count
	}

	resource := ""
	if flagged.Event.Type == "file_open" && flagged.Event.FileOpen != nil {
		resource = flagged.Event.FileOpen.GetPath()
	} else if flagged.Event.Type == "exec" && flagged.Event.Exec != nil {
		resource = flagged.Event.Exec.GetPath()
	}

	dir := filepath.Dir(resource)
	ext := filepath.Ext(resource)
	normalized := fmt.Sprintf("%s/*%s", dir, ext)

	return FeatureVector{
		SyscallClassSequence: seq,
		NormalizedPath:       normalized,
		AvgTimingNs:          avgTiming,
	}
}

type MockEmbedder struct{}

func (m *MockEmbedder) Embed(ctx context.Context, fv FeatureVector) ([]float32, error) {
	vec := []float32{float32(len(fv.SyscallClassSequence)), float32(len(fv.NormalizedPath)), float32(fv.AvgTimingNs)}
	return vec, nil
}

// HeuristicDims is the fixed width of HeuristicEmbedder's output.
const HeuristicDims = 16

// HeuristicEmbedder produces a deterministic, bounded (0..1) feature vector
// so cosine similarity actually discriminates behavior shapes. The old
// MockEmbedder emitted raw nanosecond timestamps (~1e18) which dominated
// every dot product and collapsed all similarities to ~1.0 — meaning ANY
// event auto-recalled the first cached decision. Every dimension here is
// deliberately scale-free.
//
// Layout:
//
//	0-2: syscall class mix (file/exec/net ratios)
//	3  : sequence length (capped)
//	4  : outside-workspace
//	5  : sensitive location (/etc, /root, /proc, dotfiles...)
//	6  : credential/secret flavored (shadow, passwd, .ssh, tokens...)
//	7  : runtime-loader flavored (ld.so, *.so, locale, gconv...)
//	8  : path depth (capped)
//	9  : has file extension
//	10 : timing bucket (log-scaled, low influence)
//	11-15: reserved (zero)
type HeuristicEmbedder struct{}

func (h *HeuristicEmbedder) Embed(ctx context.Context, fv FeatureVector) ([]float32, error) {
	vec := make([]float32, HeuristicDims)

	total := float32(len(fv.SyscallClassSequence))
	if total == 0 {
		total = 1
	}
	var nFile, nExec, nNet float32
	for _, class := range fv.SyscallClassSequence {
		switch class {
		case "file_open":
			nFile++
		case "exec":
			nExec++
		case "net":
			nNet++
		}
	}
	vec[0] = nFile / total
	vec[1] = nExec / total
	vec[2] = nNet / total
	vec[3] = total / 10
	if vec[3] > 1 {
		vec[3] = 1
	}

	p := fv.NormalizedPath // shape: "/dir/*ext"

	if !strings.HasPrefix(p, "/workspace/") {
		vec[4] = 1
	}
	if hasAnyPrefix(p, "/etc/", "/root/", "/proc/", "/sys/", "/dev/") || strings.Contains(p, "/.") {
		vec[5] = 1
	}
	if containsAny(p, "shadow", "passwd", ".ssh", "id_rsa", ".git/config", "token", "secret", "credential", ".aws", ".gnupg") {
		vec[6] = 1
	}
	if containsAny(p, "ld.so", ".so", "/lib/", "locale", "gconv", "ld-musl") {
		vec[7] = 1
	}

	dir := p
	if idx := strings.Index(dir, "/*"); idx >= 0 {
		dir = dir[:idx]
	}
	vec[8] = float32(strings.Count(dir, "/")) / 8
	if vec[8] > 1 {
		vec[8] = 1
	}

	if ext := filepath.Ext(p); ext != "" && ext != "." {
		vec[9] = 1
	}

	if fv.AvgTimingNs > 0 {
		vec[10] = float32(math.Log10(float64(fv.AvgTimingNs))) / 20
	}

	return vec, nil
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, pre := range prefixes {
		if strings.HasPrefix(s, pre) {
			return true
		}
	}
	return false
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
