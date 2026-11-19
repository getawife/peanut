//go:build windows

package cli

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func launchedByDoubleClick() bool {
	var pids [2]uint32
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}
