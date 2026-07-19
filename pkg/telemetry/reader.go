package telemetry

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
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

// DisabledCgroupID is a sentinel no real cgroup can have. Loading probes
// with this value keeps them attached but silent while aegisd waits for the
// agent container to appear. Target 0 remains explicit host-wide mode.
const DisabledCgroupID = ^uint64(0)

// SetTargetCgroup updates every loaded probe without detaching it, allowing
// aegisd to follow a container across stop/recreate cycles.
func (l *EbpfLayer) SetTargetCgroup(id uint64) error {
	key := uint32(0)
	for _, coll := range l.Collections {
		m, ok := coll.Maps["target_cgroup_map"]
		if !ok {
			continue
		}
		if err := m.Put(&key, &id); err != nil {
			return fmt.Errorf("update target_cgroup_map: %w", err)
		}
	}
	return nil
}

func (l *EbpfLayer) Map(name string) *ebpf.Map {
	for _, coll := range l.Collections {
		if m, ok := coll.Maps[name]; ok {
			return m
		}
	}
	return nil
}

func (l *EbpfLayer) SetExecGateEnabled(enabled bool) error {
	m := l.Map("exec_gate_enabled_map")
	if m == nil {
		return fmt.Errorf("exec_gate_enabled_map not found")
	}
	key := uint32(0)
	value := uint32(0)
	if enabled {
		value = 1
	}
	return m.Put(&key, &value)
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
	permDenied := false

	for _, file := range files {
		spec, err := ebpf.LoadCollectionSpec(file)
		if err != nil {
			missing = append(missing, file)
			continue
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			if errors.Is(err, syscall.EPERM) {
				permDenied = true
			}
			missing = append(missing, fmt.Sprintf("%s (verifier/load error: %v)", file, err))
			continue
		}
		layer.Collections = append(layer.Collections, coll)

		if cgroupMap, ok := coll.Maps["target_cgroup_map"]; ok {
			key := uint32(0)
			cgroupMap.Put(&key, &targetCgroupId)
		}

		for name, prog := range coll.Programs {
			var lnk link.Link
			var err error
			switch prog.Type() {
			case ebpf.LSM:
				lnk, err = link.AttachLSM(link.LSMOptions{Program: prog})
			case ebpf.TracePoint:
				if name != "aegis_exec" {
					attachErrs = append(attachErrs, fmt.Sprintf("%s: unsupported tracepoint program", name))
					continue
				}
				lnk, err = link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
			default:
				attachErrs = append(attachErrs, fmt.Sprintf("%s: unsupported program type %s", name, prog.Type()))
				continue
			}
			if err != nil {
				attachErrs = append(attachErrs, fmt.Sprintf("%s: %v", name, err))
				continue
			}
			fmt.Printf("eBPF: attached %s probe %s (from %s)\n", prog.Type(), name, file)
			layer.Links = append(layer.Links, lnk)
		}

		for mapName, bpfMap := range coll.Maps {
			if bpfMap.Type() == ebpf.RingBuf {
				switch mapName {
				case "file_events":
					go readRingBuf(ctx, bpfMap, mapName, chConfig, func(b []byte) *Event {
						ev := GetEvent()
						ev.FileOpen = decodeFileOpen(b)
						if ev.FileOpen.Flags == -1 {
							ev.Type = "path_unlink"
						} else if ev.FileOpen.Flags == -2 {
							ev.Type = "path_rmdir"
						} else {
							ev.Type = "file_open"
						}
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
		if permDenied {
			return layer, fmt.Errorf(
				"permission denied loading eBPF programs — aegisd must run as root (sudo ./bin/aegisd); CAP_BPF/CAP_SYS_ADMIN is required to create maps and attach LSM probes")
		}
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

		if ev.Type == "file_open" || ev.Type == "path_unlink" || ev.Type == "path_rmdir" || ev.Type == "exec" {
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
