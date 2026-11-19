//go:build windows

package ipc

import (
	"encoding/json"
	"errors"
	"io"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"peanut/internal/proto"
)

const (
	pipeName       = `\\.\pipe\peanut`
	pipeSDDL       = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
	maxConnections = 16
	maxRequestSize = 1 << 20
	connDeadline   = 90 * time.Second
	firstInstance  = 0x00080000
)

var ErrServiceDown = errors.New("peanut service is not running")

type conn struct{ h windows.Handle }

func (c *conn) Read(p []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(c.h, p, &n, nil)
	if n > 0 {
		return int(n), nil
	}
	if err == nil || errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
		return 0, io.EOF
	}
	return 0, err
}

func (c *conn) Write(p []byte) (int, error) {
	var n uint32
	err := windows.WriteFile(c.h, p, &n, nil)
	return int(n), err
}

func Serve(handle func(proto.Request) proto.Response) error {
	name, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	slots := make(chan struct{}, maxConnections)
	first := true
	for {
		mode := uint32(windows.PIPE_ACCESS_DUPLEX)
		if first {
			mode |= firstInstance
		}
		h, err := windows.CreateNamedPipe(name, mode,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
			windows.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, &sa)
		if err != nil {
			if first {
				return err
			}
			time.Sleep(time.Second)
			continue
		}
		first = false
		err = windows.ConnectNamedPipe(h, nil)
		if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			windows.CloseHandle(h)
			continue
		}
		slots <- struct{}{}
		go func() {
			defer func() { <-slots }()
			serveConn(h, handle)
		}()
	}
}

func serveConn(h windows.Handle, handle func(proto.Request) proto.Response) {
	watchdog := time.AfterFunc(connDeadline, func() {
		windows.CancelIoEx(h, nil)
		windows.DisconnectNamedPipe(h)
	})
	defer func() {
		watchdog.Stop()
		windows.DisconnectNamedPipe(h)
		windows.CloseHandle(h)
	}()
	c := &conn{h}
	var req proto.Request
	if err := json.NewDecoder(io.LimitReader(c, maxRequestSize)).Decode(&req); err != nil {
		return
	}
	if err := json.NewEncoder(c).Encode(handle(req)); err != nil {
		return
	}
	windows.FlushFileBuffers(h)
}

func Call(req proto.Request) (proto.Response, error) {
	name, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return proto.Response{}, err
	}
	var h windows.Handle
	for attempt := 0; ; attempt++ {
		h, err = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			break
		}
		if errors.Is(err, windows.ERROR_PIPE_BUSY) && attempt < 30 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return proto.Response{}, ErrServiceDown
		}
		return proto.Response{}, err
	}
	c := &conn{h}
	defer windows.CloseHandle(h)
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return proto.Response{}, err
	}
	var resp proto.Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return proto.Response{}, err
	}
	return resp, nil
}
