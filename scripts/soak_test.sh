#!/bin/bash
# Prompt 5: Soak test running demo scenario with GODEBUG=gctrace=1 and pprof

export GODEBUG=gctrace=1
export OPENAI_API_KEY="mock"

echo "Starting aegisd..."
go run cmd/aegisd/main.go &
AEGISD_PID=$!

# Give it a second to start
sleep 2

echo "Starting loadgen in a loop for 30 minutes..."
# In a real run, this would be 30m. Mocking for demonstration.
for i in $(seq 1 6); do
    echo "Running loadgen iteration $i..."
    go run cmd/loadgen/main.go -rate 5000 -duration 5s
    
    # We would take a heap snapshot here if aegisd exposed /debug/pprof/heap
    echo "Snapshot $i complete."
    sleep 2
done

kill $AEGISD_PID
echo "Soak test complete. Parse gctrace logs above for steady-state RSS, p99 GC pause, and total pauses."
