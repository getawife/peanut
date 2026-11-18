//go:build windows

package apps

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

const createNoWindow = 0x08000000

type Match struct {
	Name     string
	Shortcut string
}

func startMenuRoots() []string {
	return []string{
		filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs`),
		filepath.Join(os.Getenv("AppData"), `Microsoft\Windows\Start Menu\Programs`),
	}
}

func Search(query string) []Match {
	query = strings.ToLower(strings.TrimSpace(query))
	seen := map[string]bool{}
	var all []Match
	for _, root := range startMenuRoots() {
		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".lnk") {
				return nil
			}
			name := strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))
			key := strings.ToLower(name)
			if seen[key] || strings.Contains(key, "uninstall") {
				return nil
			}
			seen[key] = true
			all = append(all, Match{Name: name, Shortcut: path})
			return nil
		})
	}
	var hits []Match
	for _, m := range all {
		if strings.Contains(strings.ToLower(m.Name), query) {
			hits = append(hits, m)
		}
	}
	if len(hits) == 0 {
		for _, m := range all {
			if subsequence(query, strings.ToLower(m.Name)) {
				hits = append(hits, m)
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Name < hits[j].Name })
	if len(hits) > 10 {
		hits = hits[:10]
	}
	return hits
}

func subsequence(needle, haystack string) bool {
	if needle == "" {
		return false
	}
	i := 0
	for _, r := range haystack {
		if i < len(needle) && rune(needle[i]) == r {
			i++
		}
	}
	return i == len(needle)
}

func Resolve(shortcut string) (string, error) {
	script := "(New-Object -ComObject WScript.Shell).CreateShortcut('" + strings.ReplaceAll(shortcut, "'", "''") + "').TargetPath"
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	target := strings.TrimSpace(string(out))
	if !strings.EqualFold(filepath.Ext(target), ".exe") {
		return "", errors.New("shortcut does not point to a program")
	}
	return target, nil
}

func Launch(path string) error {
	file, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	dir, err := windows.UTF16PtrFromString(filepath.Dir(path))
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, nil, file, nil, dir, windows.SW_SHOWNORMAL)
}
