//go:build windows

package guard

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"peanut/internal/policy"
)

const (
	sweepInterval = 250 * time.Millisecond
	maxAncestry   = 16
)

type Policy interface {
	Enforcement() (active bool, allowed []string)
}

type process struct {
	pid, ppid, session uint32
	name, path         string
}

type pathKey struct {
	pid  uint32
	name string
}

func Run(p Policy, stop <-chan struct{}, logger *log.Logger) {
	self, _ := os.Executable()
	winDir, _ := windows.GetWindowsDirectory()
	s := &sweeper{
		self:   strings.ToLower(self),
		winDir: strings.ToLower(winDir) + `\`,
		paths:  map[pathKey]string{},
		logger: logger,
	}
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			active, allowed := p.Enforcement()
			if active {
				s.sweep(allowed)
			}
		}
	}
}

type sweeper struct {
	self, winDir string
	paths        map[pathKey]string
	logger       *log.Logger
}

func (s *sweeper) sweep(allowedPaths []string) {
	procs := s.snapshot()
	allowed := make(map[string]bool, len(allowedPaths))
	for _, p := range allowedPaths {
		allowed[strings.ToLower(filepath.Clean(p))] = true
	}
	for _, pr := range procs {
		if s.shouldClose(pr, procs, allowed) {
			terminate(pr.pid)
			s.logger.Printf("closed %s (pid %d)", pr.name, pr.pid)
		}
	}
}

func (s *sweeper) shouldClose(pr process, procs map[uint32]process, allowed map[string]bool) bool {
	if pr.session == 0 || pr.path == "" || pr.path == s.self {
		return false
	}
	if allowed[pr.path] {
		return false
	}
	switch {
	case policy.IsAlwaysClosed(pr.name):
		return true
	case policy.IsConsoleHost(pr.name):
		return false
	case policy.IsShell(pr.name):
		return descendsFromAllowed(pr, procs, allowed)
	case descendsFromAllowed(pr, procs, allowed):
		return false
	}
	return !strings.HasPrefix(pr.path, s.winDir)
}

func descendsFromAllowed(pr process, procs map[uint32]process, allowed map[string]bool) bool {
	cur := pr
	for i := 0; i < maxAncestry; i++ {
		parent, ok := procs[cur.ppid]
		if !ok || parent.pid == cur.pid {
			return false
		}
		if allowed[parent.path] {
			return true
		}
		cur = parent
	}
	return false
}

func (s *sweeper) snapshot() map[uint32]process {
	procs := map[uint32]process{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return procs
	}
	defer windows.CloseHandle(snap)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	live := map[pathKey]bool{}
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		name := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		var session uint32
		if windows.ProcessIdToSessionId(entry.ProcessID, &session) != nil {
			continue
		}
		key := pathKey{entry.ProcessID, name}
		live[key] = true
		path, cached := s.paths[key]
		if !cached {
			path = imagePath(entry.ProcessID)
			s.paths[key] = path
		}
		procs[entry.ProcessID] = process{
			pid: entry.ProcessID, ppid: entry.ParentProcessID, session: session,
			name: name, path: path,
		}
	}
	for key := range s.paths {
		if !live[key] {
			delete(s.paths, key)
		}
	}
	return procs
}

func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) != nil {
		return ""
	}
	return strings.ToLower(windows.UTF16ToString(buf[:size]))
}

func terminate(pid uint32) {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	windows.TerminateProcess(h, 1)
}
