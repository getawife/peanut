
package main

import (
	"os"

	winsvc "golang.org/x/sys/windows/svc"

	"peanut/internal/cli"
	"peanut/internal/svc"
)

func main() {
	if isService, err := winsvc.IsWindowsService(); err == nil && isService {
		os.Exit(svc.Main())
	}
	os.Exit(cli.Run(os.Args[1:]))
}
