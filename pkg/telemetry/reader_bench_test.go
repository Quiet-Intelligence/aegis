package telemetry

import (
	"testing"
)

func BenchmarkEventAlloc_NoPool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ev := &Event{Type: "file_open"}
		_ = ev
	}
}

func BenchmarkEventAlloc_Pool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ev := GetEvent()
		ev.Type = "file_open"
		PutEvent(ev)
	}
}
