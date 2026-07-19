package control

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"aegis/pkg/policy"
)

type SocketCommand struct {
	Cmd string `json:"cmd"`
	ID  int64  `json:"id,omitempty"`
}

type SocketResponse struct {
	Ok      bool   `json:"ok"`
	Revoked string `json:"revoked,omitempty"`
	Error   string `json:"error,omitempty"`
}

type ControlSocket struct {
	path     string
	listener net.Listener
	enforcer *policy.Enforcer
}

func NewControlSocket(path string, enforcer *policy.Enforcer) *ControlSocket {
	return &ControlSocket{
		path:     path,
		enforcer: enforcer,
	}
}

func (c *ControlSocket) Start() error {
	_ = os.Remove(c.path)
	l, err := net.Listen("unix", c.path)
	if err != nil {
		return err
	}
	if err := os.Chmod(c.path, 0600); err != nil {
		l.Close()
		return err
	}
	c.listener = l

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go c.handle(conn)
		}
	}()
	return nil
}

func (c *ControlSocket) Stop() {
	if c.listener != nil {
		c.listener.Close()
	}
	_ = os.Remove(c.path)
}

func (c *ControlSocket) handle(conn net.Conn) {
	defer conn.Close()
	var cmd SocketCommand
	if err := json.NewDecoder(conn).Decode(&cmd); err != nil {
		c.reply(conn, SocketResponse{Ok: false, Error: "invalid JSON"})
		return
	}

	switch cmd.Cmd {
	case "revoke":
		if c.enforcer == nil {
			c.reply(conn, SocketResponse{Ok: false, Error: "no enforcer"})
			return
		}
		val, err := c.enforcer.Revoke(cmd.ID)
		if err != nil {
			c.reply(conn, SocketResponse{Ok: false, Error: err.Error()})
		} else {
			c.reply(conn, SocketResponse{Ok: true, Revoked: val})
		}
	default:
		c.reply(conn, SocketResponse{Ok: false, Error: fmt.Sprintf("unknown cmd: %s", cmd.Cmd)})
	}
}

func (c *ControlSocket) reply(conn net.Conn, resp SocketResponse) {
	json.NewEncoder(conn).Encode(resp)
}
