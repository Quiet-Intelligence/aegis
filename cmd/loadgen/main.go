package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"sync"
	"time"

	"aegis/pkg/telemetry"
)

type LoadResult struct {
	TotalEvents int           `json:"total_events"`
	Duration    time.Duration `json:"duration_ms"`
	EventsSec   float64       `json:"events_per_sec"`
	Drops       int           `json:"drop_count"`
	P50         time.Duration `json:"p50_latency_ms"`
	P95         time.Duration `json:"p95_latency_ms"`
	P99         time.Duration `json:"p99_latency_ms"`
}

func main() {
	rate := flag.Int("rate", 1000, "events per second")
	duration := flag.Duration("duration", 2*time.Second, "duration of load test")
	flag.Parse()

	eventChan := make(chan *telemetry.Event, 500)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range eventChan {
			time.Sleep(5 * time.Microsecond) // Slow consumer
		}
	}()

	start := time.Now()
	ticker := time.NewTicker(time.Second / time.Duration(*rate))
	timer := time.NewTimer(*duration)

	drops := 0
	total := 0
	var latencies []time.Duration

loop:
	for {
		select {
		case <-timer.C:
			break loop
		case t := <-ticker.C:
			ev := telemetry.GetEvent()
			ev.Type = "file_open"
			
			select {
			case eventChan <- ev:
				latencies = append(latencies, time.Since(t))
				total++
			default:
				drops++
				telemetry.PutEvent(ev)
			}
		}
	}

	ticker.Stop()
	close(eventChan)
	wg.Wait()

	elapsed := time.Since(start)

	p50 := time.Duration(0)
	p95 := time.Duration(0)
	p99 := time.Duration(0)
	if len(latencies) > 0 {
		p50 = latencies[len(latencies)/2]
		p95 = latencies[int(float64(len(latencies))*0.95)]
		p99 = latencies[int(float64(len(latencies))*0.99)]
	}

	res := LoadResult{
		TotalEvents: total,
		Duration:    elapsed,
		EventsSec:   float64(total) / elapsed.Seconds(),
		Drops:       drops,
		P50:         p50,
		P95:         p95,
		P99:         p99,
	}

	fmt.Printf("Load Test Complete\n")
	fmt.Printf("Sustained Rate: %.2f events/sec\n", res.EventsSec)
	fmt.Printf("Drops: %d\n", res.Drops)
	fmt.Printf("p50: %v, p95: %v, p99: %v\n", res.P50, res.P95, res.P99)

	b, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(b))
}
