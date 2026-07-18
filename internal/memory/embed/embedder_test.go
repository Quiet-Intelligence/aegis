package embed

import (
	"context"
	"math"
	"testing"
)

func cosine(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

func libLoadVector() FeatureVector {
	return FeatureVector{
		SyscallClassSequence: []string{"exec", "file_open", "file_open"},
		NormalizedPath:       "/etc/*.cache",
		AvgTimingNs:          1750000000000000000,
	}
}

func shadowReadVector() FeatureVector {
	return FeatureVector{
		SyscallClassSequence: []string{"exec", "file_open"},
		NormalizedPath:       "/etc/*",
		AvgTimingNs:          1750000000000000000,
	}
}

func TestHeuristic_IdenticalShapesRecall(t *testing.T) {
	h := &HeuristicEmbedder{}
	a, err := h.Embed(context.Background(), libLoadVector())
	if err != nil {
		t.Fatal(err)
	}
	// Same shape, wildly different timestamp — must still be ~identical.
	other := libLoadVector()
	other.AvgTimingNs = 900000000000000000
	b, err := h.Embed(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	if sim := cosine(a, b); sim < 0.98 {
		t.Fatalf("same shape with different timing should recall (sim=%.3f)", sim)
	}
}

func TestHeuristic_DifferentShapesDoNotRecall(t *testing.T) {
	h := &HeuristicEmbedder{}
	lib, _ := h.Embed(context.Background(), libLoadVector())
	shadow, _ := h.Embed(context.Background(), shadowReadVector())

	if sim := cosine(lib, shadow); sim > 0.95 {
		t.Fatalf("library load must not recall a shadow read (sim=%.3f)", sim)
	}
}

func TestHeuristic_BoundedAndDeterministic(t *testing.T) {
	h := &HeuristicEmbedder{}
	fv := shadowReadVector()
	a, _ := h.Embed(context.Background(), fv)
	b, _ := h.Embed(context.Background(), fv)

	if len(a) != HeuristicDims {
		t.Fatalf("expected %d dims, got %d", HeuristicDims, len(a))
	}
	for i := range a {
		if a[i] < 0 || a[i] > 1 {
			t.Fatalf("dim %d out of bounds: %f", i, a[i])
		}
		if a[i] != b[i] {
			t.Fatalf("dim %d not deterministic: %f vs %f", i, a[i], b[i])
		}
	}
}
