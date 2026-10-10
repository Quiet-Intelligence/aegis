package telemetry

import "testing"

// Allocation behaviour of the hot-path helpers. The eBPF record decoders reinterpret the ring-buffer bytes in place.
func BenchmarkDecodeFileOpen(b *testing.B) {
	rec := make([]byte, 512)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = decodeFileOpen(rec)
	}
}

func BenchmarkEventPoolGetPut(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e := GetEvent()
		PutEvent(e)
	}
}

func BenchmarkFileOpenGetPath(b *testing.B) {
	ev := &FileOpenEvent{}
	copy(ev.Path[:], "/workspace/src/some/deep/path/main.c")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ev.GetPath()
	}
}
