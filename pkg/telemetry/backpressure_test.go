package telemetry

import (
	"testing"
	"time"
)

func TestBackpressure_FailClosed(t *testing.T) {
	chConfig := ChannelConfig{
		CriticalChan:    make(chan *Event, 1),
		TelemetryChan:   make(chan *Event, 1),
		CriticalTimeout: 10 * time.Millisecond,
	}

	ev1 := &Event{Type: "file_open"}
	chConfig.CriticalChan <- ev1

	start := time.Now()
	
	ev2 := &Event{Type: "file_open"}
	select {
	case chConfig.CriticalChan <- ev2:
		t.Fatal("Expected channel to block and timeout")
	case <-time.After(chConfig.CriticalTimeout):
		if time.Since(start) < chConfig.CriticalTimeout {
			t.Fatal("Timeout fired too early")
		}
	}
}

func TestBackpressure_FailOpen(t *testing.T) {
	chConfig := ChannelConfig{
		CriticalChan:    make(chan *Event, 1),
		TelemetryChan:   make(chan *Event, 1),
		CriticalTimeout: 10 * time.Millisecond,
	}

	ev1 := &Event{Type: "net"}
	chConfig.TelemetryChan <- ev1

	ev2 := &Event{Type: "net"}
	select {
	case chConfig.TelemetryChan <- ev2:
		t.Fatal("Expected channel to drop without blocking")
	default:
		// Passed - dropped immediately
	}
}
