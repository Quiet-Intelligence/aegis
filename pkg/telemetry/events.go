package telemetry

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
)

const MaxPathLen = 256

// H-3: Fixed-size flat structs mapped directly from eBPF

type FileOpenEvent struct {
	Pid         uint32
	CgroupId    uint64
	TimestampNs uint64
	Flags       int32
	Path        [MaxPathLen]byte
}

func (e *FileOpenEvent) GetPath() string {
	idx := bytes.IndexByte(e.Path[:], 0)
	if idx == -1 {
		return string(e.Path[:])
	}
	return string(e.Path[:idx])
}

type NetEvent struct {
	Pid         uint32
	CgroupId    uint64
	TimestampNs uint64
	Daddr       uint32
	Dport       uint16
	Protocol    uint16
}

// GetAddr renders the network-byte-order destination as dotted:port.
func (e *NetEvent) GetAddr() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d",
		e.Daddr>>24&0xFF, e.Daddr>>16&0xFF, e.Daddr>>8&0xFF, e.Daddr&0xFF, e.Dport)
}

type ExecEvent struct {
	Pid         uint32
	Argc        uint32
	CgroupId    uint64
	TimestampNs uint64
	Inode       uint64
	Path        [MaxPathLen]byte
	Args        [MaxPathLen]byte
}

func (e *ExecEvent) GetPath() string {
	idx := bytes.IndexByte(e.Path[:], 0)
	if idx == -1 {
		return string(e.Path[:])
	}
	return string(e.Path[:idx])
}

// GetArgs reconstructs the command line from the NUL-separated argv
// capture, keeping only the first Argc tokens (the rest of the kernel
// page holds envp, which we don't want in prompts or logs).
func (e *ExecEvent) GetArgs() string {
	if e.Argc == 0 {
		return ""
	}
	parts := bytes.Split(e.Args[:], []byte{0})
	out := make([]string, 0, e.Argc)
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		out = append(out, string(p))
		if uint32(len(out)) >= e.Argc {
			break
		}
	}
	return strings.Join(out, " ")
}

type Event struct {
	Type     string
	FileOpen *FileOpenEvent
	Net      *NetEvent
	Exec     *ExecEvent
}

var eventPool = sync.Pool{
	New: func() interface{} {
		return new(Event)
	},
}

func GetEvent() *Event {
	return eventPool.Get().(*Event)
}

func PutEvent(e *Event) {
	e.Type = ""
	e.FileOpen = nil
	e.Net = nil
	e.Exec = nil
	eventPool.Put(e)
}
