package embed

import (
	"context"
	"fmt"
	"path/filepath"

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
