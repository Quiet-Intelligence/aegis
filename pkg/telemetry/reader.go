package telemetry

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type ChannelConfig struct {
	CriticalChan    chan *Event // file_open, exec (fail-closed)
	TelemetryChan   chan *Event // net (fail-open)
	CriticalTimeout time.Duration
}

type EbpfLayer struct {
	Collections []*ebpf.Collection
	Links       []link.Link
}

func (l *EbpfLayer) Close() {
	for _, lnk := range l.Links {
		lnk.Close()
	}
	for _, coll := range l.Collections {
		coll.Close()
	}
}

// Unsafe casting is significantly faster than binary.Read (H-3 benchmark)
func decodeFileOpen(record []byte) *FileOpenEvent {
	return (*FileOpenEvent)(unsafe.Pointer(&record[0]))
}

func decodeNet(record []byte) *NetEvent {
	return (*NetEvent)(unsafe.Pointer(&record[0]))
}

func decodeExec(record []byte) *ExecEvent {
	return (*ExecEvent)(unsafe.Pointer(&record[0]))
}

// InitLayer loads the compiled eBPF objects from objDir (default "ebpf",
// override with AEGIS_EBPF_DIR), attaches every LSM probe, and starts the
// ringbuf readers. It fails loudly — a daemon with zero event sources is a
// silent no-op, which is worse than no daemon at all.
func InitLayer(ctx context.Context, targetCgroupId uint64, chConfig ChannelConfig, objDir string) (*EbpfLayer, error) {
	if objDir == "" {
		objDir = "ebpf"
	}
	files := []string{
		filepath.Join(objDir, "file_open.bpf.o"),
		filepath.Join(objDir, "socket_connect.bpf.o"),
		filepath.Join(objDir, "exec_hash.bpf.o"),
	}

	layer := &EbpfLayer{}
	var missing []string
	var attachErrs []string

	for _, file := range files {
		spec, err := ebpf.LoadCollectionSpec(file)
		if err != nil {
			missing = append(missing, file)
			continue
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			missing = append(missing, fmt.Sprintf("%s (verifier/load error: %v)", file, err))
			continue
		}
		layer.Collections = append(layer.Collections, coll)

		if cgroupMap, ok := coll.Maps["target_cgroup_map"]; ok {
			key := uint32(0)
			cgroupMap.Put(&key, &targetCgroupId)
		}

		for name, prog := range coll.Programs {
			lnk, err := link.AttachLSM(link.LSMOptions{Program: prog})
			if err != nil {
				attachErrs = append(attachErrs, fmt.Sprintf("%s: %v", name, err))
				continue
			}
			fmt.Printf("eBPF: attached LSM probe %s (from %s)\n", name, file)
			layer.Links = append(layer.Links, lnk)
		}

		for mapName, bpfMap := range coll.Maps {
			if bpfMap.Type() == ebpf.RingBuf {
				switch mapName {
				case "file_events":
					go readRingBuf(ctx, bpfMap, mapName, chConfig, func(b []byte) *Event {
						ev := GetEvent()
						ev.Type = "file_open"
						ev.FileOpen = decodeFileOpen(b)
						return ev
					})
				case "net_events":
					go readRingBuf(ctx, bpfMap, mapName, chConfig, func(b []byte) *Event {
						ev := GetEvent()
						ev.Type = "net"
						ev.Net = decodeNet(b)
						return ev
					})
				case "exec_events":
					go readRingBuf(ctx, bpfMap, mapName, chConfig, func(b []byte) *Event {
						ev := GetEvent()
						ev.Type = "exec"
						ev.Exec = decodeExec(b)
						return ev
					})
				}
			}
		}
	}

	// Loud failures: an idle daemon with zero event sources is worse than
	// no daemon at all.
	if len(layer.Collections) == 0 {
		return layer, fmt.Errorf(
			"no eBPF objects could be loaded [%s]. Remediation: install bpftool+clang, then run `make ebpf` to compile kernel objects for your kernel",
			strings.Join(missing, "; "))
	}
	if len(layer.Links) == 0 {
		return layer, fmt.Errorf(
			"eBPF objects loaded but no LSM probes attached [%s]. Remediation: run as root and verify `bpf` is in /sys/kernel/security/lsm",
			strings.Join(attachErrs, "; "))
	}
	if len(missing) > 0 {
		fmt.Printf("eBPF: WARNING — %d/%d objects unavailable: %s\n", len(missing), len(files), strings.Join(missing, "; "))
	}
	if len(attachErrs) > 0 {
		fmt.Printf("eBPF: WARNING — some probes failed to attach: %s\n", strings.Join(attachErrs, "; "))
	}

	fmt.Printf("eBPF: %d collection(s) loaded, %d LSM probe(s) attached\n", len(layer.Collections), len(layer.Links))
	return layer, nil
}

// H-2: epoll-backed blocking read via cilium/ebpf ringbuf wrapper
func readRingBuf(ctx context.Context, m *ebpf.Map, name string, chConfig ChannelConfig, decoder func([]byte) *Event) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		fmt.Printf("failed to create ringbuf reader for %s: %v\n", name, err)
		return
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			continue
		}

		ev := decoder(record.RawSample)

		if ev.Type == "file_open" || ev.Type == "exec" {
			select {
			case chConfig.CriticalChan <- ev:
			case <-time.After(chConfig.CriticalTimeout):
				fmt.Printf("WARN: Backpressure hit! Dropped %s event (fail-closed)\n", ev.Type)
			}
		} else {
			select {
			case chConfig.TelemetryChan <- ev:
			default:
				fmt.Printf("WARN: Telemetry channel full! Dropped %s event (fail-open)\n", ev.Type)
			}
		}
	}
}
