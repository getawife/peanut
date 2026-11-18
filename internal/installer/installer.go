//go:build windows

package installer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	winsvc "golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"peanut/internal/svc"
)

const (
	envKey      = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	safeBootFmt = `SYSTEM\CurrentControlSet\Control\SafeBoot\%s\` + svc.Name
	stopTimeout = 20 * time.Second
)

var ErrLocked = errors.New("peanut is locked, unlock it first")

func InstallDir() string { return filepath.Join(os.Getenv("ProgramFiles"), "peanut") }

func ExePath() string { return filepath.Join(InstallDir(), "peanut.exe") }

func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

func Relaunch(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	return windows.ShellExecute(0, verb, file, params, nil, windows.SW_SHOWNORMAL)
}

func Install() error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	existing, openErr := m.OpenService(svc.Name)
	installed := openErr == nil
	if installed {
		err := stopAndWait(existing)
		existing.Close()
		if err != nil {
			return err
		}
	}
	if err := os.MkdirAll(InstallDir(), 0o755); err != nil {
		return err
	}
	if err := copyFile(src, ExePath()); err != nil {
		return err
	}
	if !installed {
		if err := createService(m); err != nil {
			return err
		}
	}
	for _, kind := range []string{"Minimal", "Network"} {
		if err := registerSafeBoot(kind); err != nil {
			return err
		}
	}
	if err := addToPath(InstallDir()); err != nil {
		return err
	}
	s, err := m.OpenService(svc.Name)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start("service")
}

func createService(m *mgr.Mgr) error {
	s, err := m.CreateService(svc.Name, ExePath(), mgr.Config{
		DisplayName: "Peanut",
		Description: "Peanut focus lock. Closes apps that are not on your allowed list while locked.",
		StartType:   mgr.StartAutomatic,
	}, "service")
	if err != nil {
		return err
	}
	defer s.Close()
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}
	if err := s.SetRecoveryActions(actions, 86400); err != nil {
		return err
	}
	return s.SetRecoveryActionsOnNonCrashFailures(true)
}

func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(svc.Name)
	if err == nil {
		if err := stopAndWait(s); err != nil {
			s.Close()
			return err
		}
		if err := s.Delete(); err != nil {
			s.Close()
			return err
		}
		s.Close()
	}
	for _, kind := range []string{"Minimal", "Network"} {
		registry.DeleteKey(registry.LOCAL_MACHINE, fmt.Sprintf(safeBootFmt, kind))
	}
	removeFromPath(InstallDir())
	os.RemoveAll(svc.DataDir())
	if exe, err := windows.UTF16PtrFromString(ExePath()); err == nil {
		windows.MoveFileEx(exe, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
	return nil
}

func stopAndWait(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == winsvc.Stopped {
		return nil
	}
	if _, err := s.Control(winsvc.Stop); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
			return ErrLocked
		}
		return err
	}
	deadline := time.Now().Add(stopTimeout)
	for time.Now().Before(deadline) {
		status, err = s.Query()
		if err != nil {
			return err
		}
		if status.State == winsvc.Stopped {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("timed out waiting for peanut to stop")
}

func registerSafeBoot(kind string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, fmt.Sprintf(safeBootFmt, kind), registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("", "Service")
}

func addToPath(dir string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	current, _, err := k.GetStringValue("Path")
	if err != nil {
		return err
	}
	for _, entry := range strings.Split(current, ";") {
		if strings.EqualFold(strings.TrimSpace(entry), dir) {
			return nil
		}
	}
	if err := k.SetExpandStringValue("Path", strings.TrimRight(current, ";")+";"+dir); err != nil {
		return err
	}
	broadcastEnvChange()
	return nil
}

func removeFromPath(dir string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	current, _, err := k.GetStringValue("Path")
	if err != nil {
		return
	}
	var kept []string
	for _, entry := range strings.Split(current, ";") {
		if !strings.EqualFold(strings.TrimSpace(entry), dir) {
			kept = append(kept, entry)
		}
	}
	k.SetExpandStringValue("Path", strings.Join(kept, ";"))
	broadcastEnvChange()
}

func broadcastEnvChange() {
	proc := windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")
	env, _ := windows.UTF16PtrFromString("Environment")
	const hwndBroadcast, wmSettingChange, abortIfHung = 0xFFFF, 0x001A, 0x0002
	proc.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)), abortIfHung, 5000, 0)
}

func copyFile(src, dst string) error {
	if strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
