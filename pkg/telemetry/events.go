package telemetry

import (
	"bytes"
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

type Event struct {
	Type     string
	FileOpen *FileOpenEvent
	Net      *NetEvent
	Exec     *ExecEvent
}
