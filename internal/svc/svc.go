//go:build windows

package svc

import (
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	winsvc "golang.org/x/sys/windows/svc"

	"peanut/internal/engine"
	"peanut/internal/guard"
	"peanut/internal/ipc"
	"peanut/internal/store"
)

const (
	Name        = "peanut"
	dataDirSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	maxLogBytes = 1 << 20

	systemFull = "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
	readers    = "(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
	adminFull  = "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
	adminRead  = "(A;;CCLCSWLOCRRC;;;BA)"
)

func DataDir() string { return filepath.Join(os.Getenv("ProgramData"), "peanut") }

func Main() int {
	dir := DataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 1
	}
	hardenDir(dir)
	logger := openLog(dir)
	eng, err := engine.New(store.Store{Dir: dir}, engine.DefaultOptions())
	if err != nil {
		logger.Printf("cannot load state: %v", err)
		return 1
	}
	h := &handler{eng: eng, logger: logger, changes: make(chan bool, 4)}
	eng.OnLock = func(locked bool) {
		if err := applyServiceDACL(locked); err != nil {
			logger.Printf("service permissions: %v", err)
		}
		select {
		case h.changes <- locked:
		default:
		}
	}
	if err := winsvc.Run(Name, h); err != nil {
		logger.Printf("service run: %v", err)
		return 1
	}
	return 0
}

type handler struct {
	eng     *engine.Engine
	logger  *log.Logger
	changes chan bool
}

func accepted(locked bool) winsvc.Accepted {
	if locked {
		return winsvc.AcceptShutdown
	}
	return winsvc.AcceptStop | winsvc.AcceptShutdown
}

func (h *handler) Execute(_ []string, requests <-chan winsvc.ChangeRequest, status chan<- winsvc.Status) (bool, uint32) {
	status <- winsvc.Status{State: winsvc.StartPending}
	stop := make(chan struct{})
	go guard.Run(h.eng, stop, h.logger)
	go func() {
		if err := ipc.Serve(h.eng.Handle); err != nil {
			h.logger.Printf("pipe server: %v", err)
		}
	}()
	locked := h.eng.Locked()
	if err := applyServiceDACL(locked); err != nil {
		h.logger.Printf("service permissions: %v", err)
	}
	status <- winsvc.Status{State: winsvc.Running, Accepts: accepted(locked)}
	for {
		select {
		case l := <-h.changes:
			status <- winsvc.Status{State: winsvc.Running, Accepts: accepted(l)}
		case req := <-requests:
			switch req.Cmd {
			case winsvc.Interrogate:
				status <- req.CurrentStatus
			case winsvc.Stop, winsvc.Shutdown:
				close(stop)
				status <- winsvc.Status{State: winsvc.StopPending}
				return false, 0
			}
		}
	}
}

func applyServiceDACL(locked bool) error {
	sddl := "D:" + systemFull + adminFull + readers
	if locked {
		sddl = "D:" + systemFull + adminRead + readers
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)
	name, err := windows.UTF16PtrFromString(Name)
	if err != nil {
		return err
	}
	svcHandle, err := windows.OpenService(scm, name, windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(svcHandle)
	return windows.SetSecurityInfo(svcHandle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func hardenDir(dir string) {
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return
	}
	windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func openLog(dir string) *log.Logger {
	path := filepath.Join(dir, "service.log")
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if info, err := os.Stat(path); err == nil && info.Size() > maxLogBytes {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return log.New(os.Stderr, "peanut ", log.LstdFlags)
	}
	return log.New(f, "", log.LstdFlags)
}
