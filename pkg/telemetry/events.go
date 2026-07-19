package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

const MaxPathLen = 256
const MaxArgCount = 8
const MaxArgLen = 128

const MaxFilenameLen = 64

// H-3: Fixed-size flat structs mapped directly from eBPF

type FileOpenEvent struct {
	Pid         uint32
	CgroupId    uint64
	TimestampNs uint64
	Flags       int32
	Path        [MaxPathLen]byte
	Filename    [MaxFilenameLen]byte
}

func (e *FileOpenEvent) GetPath() string {
	dirIdx := bytes.IndexByte(e.Path[:], 0)
	dir := ""
	if dirIdx == -1 {
		dir = string(e.Path[:])
	} else {
		dir = string(e.Path[:dirIdx])
	}

	fileIdx := bytes.IndexByte(e.Filename[:], 0)
	filename := ""
	if fileIdx == -1 {
		filename = string(e.Filename[:])
	} else {
		filename = string(e.Filename[:fileIdx])
	}

	if filename == "" {
		return dir
	}
	if strings.HasSuffix(dir, "/") {
		return dir + filename
	}
	return dir + "/" + filename
}

func (e *FileOpenEvent) MarshalJSON() ([]byte, error) {
	type Alias FileOpenEvent
	return json.Marshal(&struct {
		*Alias
		PathString string `json:"Path"`
	}{
		Alias:      (*Alias)(e),
		PathString: e.GetPath(),
	})
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
	Args        [MaxArgCount][MaxArgLen]byte
}

func (e *ExecEvent) GetPath() string {
	idx := bytes.IndexByte(e.Path[:], 0)
	if idx == -1 {
		return string(e.Path[:])
	}
	return string(e.Path[:idx])
}

// GetArgs reconstructs the command arguments from the NUL-separated
// argv capture, SKIPPING argv[0] (the binary itself, already shown by
// GetPath) and stopping before envp. This keeps busybox-style invocations
// readable too: /usr/bin/busybox + "rm" instead of a duplicated name.
func (e *ExecEvent) GetArgs() string {
	if e.Argc <= 1 {
		return ""
	}
	out := make([]string, 0, e.Argc-1)
	limit := e.Argc
	if limit > MaxArgCount {
		limit = MaxArgCount
	}
	for i := uint32(0); i < limit; i++ {
		slot := e.Args[i][:]
		end := bytes.IndexByte(slot, 0)
		if end < 0 {
			end = len(slot)
		}
		if i == 0 {
			continue // argv[0]
		}
		if end > 0 {
			out = append(out, string(slot[:end]))
		}
	}
	return strings.Join(out, " ")
}

func (e *ExecEvent) MarshalJSON() ([]byte, error) {
	type Alias ExecEvent
	return json.Marshal(&struct {
		*Alias
		PathString string `json:"Path"`
		ArgsString string `json:"Args,omitempty"`
	}{
		Alias:      (*Alias)(e),
		PathString: e.GetPath(),
		ArgsString: e.GetArgs(),
	})
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
