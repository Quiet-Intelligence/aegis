package telemetry

import (
	"bytes"
	"encoding/json"
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

type ExecEvent struct {
	Pid         uint32
	CgroupId    uint64
	TimestampNs uint64
	Inode       uint64
	MtimeNs     uint64
	Path        [MaxPathLen]byte
}

func (e *ExecEvent) GetPath() string {
	idx := bytes.IndexByte(e.Path[:], 0)
	if idx == -1 {
		return string(e.Path[:])
	}
	return string(e.Path[:idx])
}

func (e *ExecEvent) MarshalJSON() ([]byte, error) {
	type Alias ExecEvent
	return json.Marshal(&struct {
		*Alias
		PathString string `json:"Path"`
	}{
		Alias:      (*Alias)(e),
		PathString: e.GetPath(),
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

