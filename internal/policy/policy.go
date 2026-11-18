package policy

import "strings"

var shells = set("cmd.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe", "wsl.exe", "bash.exe")

var consoleHosts = set("conhost.exe", "windowsterminal.exe", "openconsole.exe", "wt.exe")

var alwaysClosed = set(
	"taskmgr.exe", "regedit.exe", "mmc.exe", "msconfig.exe", "perfmon.exe", "resmon.exe",
	"procexp.exe", "procexp64.exe", "processhacker.exe", "notepad.exe", "mspaint.exe",
	"wordpad.exe", "write.exe", "mstsc.exe", "control.exe", "systemsettings.exe",
	"snippingtool.exe", "screenclippinghost.exe", "wscript.exe", "cscript.exe", "mshta.exe",
	"calc.exe", "charmap.exe", "quickassist.exe", "osk.exe", "magnify.exe", "cleanmgr.exe",
	"eventvwr.exe", "services.exe", "compmgmt.exe", "msinfo32.exe", "dxdiag.exe",
)

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

func norm(name string) string { return strings.ToLower(name) }

func IsShell(name string) bool { return shells[norm(name)] }

func IsConsoleHost(name string) bool { return consoleHosts[norm(name)] }

func IsAlwaysClosed(name string) bool { return alwaysClosed[norm(name)] }

func CanAllow(name string) bool {
	n := norm(name)
	return !shells[n] && !consoleHosts[n] && !alwaysClosed[n] && n != "explorer.exe"
}
