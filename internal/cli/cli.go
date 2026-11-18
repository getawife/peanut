//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"peanut/internal/apps"
	"peanut/internal/installer"
	"peanut/internal/ipc"
	"peanut/internal/proto"
	"peanut/internal/ui"
)

const minPassword = 6

type command struct {
	name, summary string
	run           func(args []string) int
}

var commands []command

func init() {
	commands = []command{
		{"help", "Show this list", help},
		{"lock", "Lock the computer so only allowed apps work", lock},
		{"unlock", "Unlock it (asks for your password)", unlock},
		{"allow_apps", "Add an app to the allowed list", allowApps},
		{"remove_apps", "Remove an app from the allowed list", removeApps},
		{"open", "Open one of your allowed apps", open},
		{"reset_password", "Change your password", resetPassword},
		{"force_unlock", "Forgot your password? Unlocks after a wait", forceUnlock},
		{"status", "See what is going on right now", status},
		{"install", "Install Peanut as a Windows service", install},
		{"uninstall", "Remove Peanut from this computer", uninstall},
	}
}

var aliases = map[string]string{"allow": "allow_apps", "remove": "remove_apps", "-h": "help", "--help": "help", "/?": "help"}

func Run(args []string) (code int) {
	ui.Init()
	pause := len(args) > 0 && args[len(args)-1] == "--pause"
	if pause {
		args = args[:len(args)-1]
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("\n  Peanut crashed: %v\n", r)
			code = 1
		}
		if pause {
			ui.Ask("  Press Enter to close. ")
		}
	}()
	return dispatch(args)
}

func dispatch(args []string) int {
	if len(args) == 0 {
		return help(nil)
	}
	name := strings.ReplaceAll(strings.ToLower(args[0]), "-", "_")
	if alias, ok := aliases[strings.ToLower(args[0])]; ok {
		name = alias
	}
	for _, c := range commands {
		if c.name == name {
			return c.run(args[1:])
		}
	}
	ui.Say(ui.Oops, fmt.Sprintf("I don't know the command '%s'.", args[0]), "Try  peanut help")
	return 1
}

func call(req proto.Request) (proto.Response, bool) {
	resp, err := ipc.Call(req)
	if errors.Is(err, ipc.ErrServiceDown) {
		ui.Say(ui.Oops, "The Peanut service isn't running.", "Run  peanut install  to set it up.")
		return resp, false
	}
	if err != nil {
		ui.Say(ui.Oops, "I couldn't talk to the Peanut service.", err.Error())
		return resp, false
	}
	return resp, true
}

func ready() (*proto.Status, bool) {
	resp, ok := call(proto.Request{Cmd: proto.CmdStatus})
	if !ok {
		return nil, false
	}
	if !resp.Status.Configured {
		if !runSetup() {
			return nil, false
		}
		resp, ok = call(proto.Request{Cmd: proto.CmdStatus})
		if !ok {
			return nil, false
		}
	}
	return resp.Status, true
}

func runSetup() bool {
	ui.Say(ui.Happy, "Hi, I'm Peanut, your focus cat.", "Let's get you set up. It takes a minute.")
	name, err := ui.Ask("  What's your name? ")
	if err != nil || name == "" {
		return false
	}
	pw, ok := newPassword()
	if !ok {
		return false
	}
	resp, ok := call(proto.Request{Cmd: proto.CmdSetup, Name: name, Password: pw})
	if !ok {
		return false
	}
	if !resp.OK {
		return explain(resp)
	}
	ui.Say(ui.Happy, fmt.Sprintf("All set, %s!", name), "Type  peanut help  to see what I can do.")
	return true
}

func newPassword() (string, bool) {
	for {
		first, err := ui.Secret(fmt.Sprintf("  Choose a password (at least %d characters): ", minPassword))
		if err != nil {
			return "", false
		}
		if len(first) < minPassword {
			ui.Plain("That one is too short. Try again.")
			continue
		}
		second, err := ui.Secret("  Type it again: ")
		if err != nil {
			return "", false
		}
		if first != second {
			ui.Plain("Those didn't match. Try again.")
			continue
		}
		return first, true
	}
}

func authenticate() (string, bool) {
	pw, err := ui.Secret("  Password: ")
	if err != nil {
		return "", false
	}
	resp, ok := call(proto.Request{Cmd: proto.CmdCheck, Password: pw})
	if !ok {
		return "", false
	}
	if !resp.OK {
		explain(resp)
		return "", false
	}
	return pw, true
}

func explain(resp proto.Response) bool {
	st := resp.Status
	switch resp.Code {
	case proto.CodeBadPassword:
		lines := []string{"That password is wrong."}
		if st != nil && st.CooldownLeft > 0 {
			lines = append(lines, "Too many tries. Wait "+duration(st.CooldownLeft)+" before the next one.")
		} else if st != nil && st.AttemptsLeft > 0 {
			lines = append(lines, fmt.Sprintf("%d tries left before a cool-down.", st.AttemptsLeft))
		}
		ui.Say(ui.Oops, lines...)
	case proto.CodeCooldown:
		ui.Say(ui.Oops, "Too many wrong tries.", "Try again in "+duration(st.CooldownLeft)+".")
	case proto.CodeForced:
		ui.Say(ui.Oops, "You used force_unlock, so locking is switched off.", "Run  peanut reset_password  to set a new password first.")
	case proto.CodeAlreadyLocked:
		ui.Say(ui.Sleepy, "Already locked. Zzz...")
	case proto.CodeNotLocked:
		ui.Say(ui.Happy, "You're not locked, so there's nothing to do.")
	case proto.CodeLocked:
		ui.Say(ui.Oops, "Peanut is locked.", "Unlock it first.")
	case proto.CodeInvalidApp:
		ui.Say(ui.Oops, "That doesn't look like a program I can allow.", "Try the full path to its .exe file.")
	case proto.CodeBlockedApp:
		ui.Say(ui.Oops, "That app can't be allowed.", "It could be used to get around the lock.")
	case proto.CodeDuplicate:
		ui.Say(ui.Happy, "That app is already on the list.")
	case proto.CodeNotFound:
		ui.Say(ui.Oops, "I couldn't find that app on the list.")
	case proto.CodeWeakPassword:
		ui.Say(ui.Oops, fmt.Sprintf("Passwords need at least %d characters.", minPassword))
	case proto.CodeEmptyName:
		ui.Say(ui.Oops, "I need a name to call you.")
	case proto.CodeAlreadyConfigured:
		ui.Say(ui.Happy, "Peanut is already set up.")
	case proto.CodeStorage:
		ui.Say(ui.Oops, "I couldn't save that. Check the disk and try again.")
	default:
		ui.Say(ui.Oops, "Something went wrong ("+resp.Code+").")
	}
	return false
}

func duration(seconds int) string {
	d := time.Duration(seconds) * time.Second
	if d >= time.Minute {
		return fmt.Sprintf("%d min %02d sec", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%d sec", seconds)
}

func exit(ok bool) int {
	if ok {
		return 0
	}
	return 1
}

func help(_ []string) int {
	ui.Say(ui.Happy, "Here's what I can do:")
	for _, c := range commands {
		fmt.Printf("  %-24s%s\n", "peanut "+c.name, c.summary)
	}
	fmt.Println()
	return 0
}

func status(_ []string) int {
	st, ok := ready()
	if !ok {
		return 1
	}
	if st.Locked {
		lines := []string{"Locked.", fmt.Sprintf("Allowed apps: %d", st.Apps)}
		if st.GraceLeft > 0 {
			lines = append(lines, "Other apps close in "+duration(st.GraceLeft)+".")
		}
		if st.ForceLeft > 0 {
			lines = append(lines, "Force unlock in "+duration(st.ForceLeft)+".")
		}
		ui.Say(ui.Sleepy, lines...)
		return 0
	}
	lines := []string{"Unlocked.", fmt.Sprintf("Allowed apps: %d", st.Apps)}
	if st.Forced {
		lines = append(lines, "Locking is off until you run  peanut reset_password.")
	}
	ui.Say(ui.Happy, lines...)
	return 0
}

func lock(_ []string) int {
	st, ok := ready()
	if !ok {
		return 1
	}
	if st.Apps == 0 {
		ui.Say(ui.Curious, "No apps are allowed yet,", "so only the terminal will work while locked.")
		if !ui.Confirm("Lock anyway?") {
			return 0
		}
	}
	resp, ok := call(proto.Request{Cmd: proto.CmdLock})
	if !ok {
		return 1
	}
	if !resp.OK {
		return exit(explain(resp))
	}
	ui.Say(ui.Sleepy,
		"Locked.",
		fmt.Sprintf("Other apps close in %d seconds, so save your work now.", resp.Wait),
		"Use  peanut open  to start an allowed app.",
		"Use  peanut unlock  when you're done.")
	return 0
}

func unlock(_ []string) int {
	st, ok := ready()
	if !ok {
		return 1
	}
	if !st.Locked {
		return exit(explain(proto.Response{Code: proto.CodeNotLocked}))
	}
	pw, ok := authenticate()
	if !ok {
		return 1
	}
	resp, ok := call(proto.Request{Cmd: proto.CmdUnlock, Password: pw})
	if !ok {
		return 1
	}
	if !resp.OK {
		return exit(explain(resp))
	}
	ui.Say(ui.Happy, fmt.Sprintf("Welcome back, %s! You're free.", st.Name))
	return 0
}

func allowApps(args []string) int {
	if _, ok := ready(); !ok {
		return 1
	}
	pw, ok := authenticate()
	if !ok {
		return 1
	}
	query := strings.Join(args, " ")
	if query == "" {
		var err error
		if query, err = ui.Ask("  Which app? (for example chrome, word, spotify): "); err != nil || query == "" {
			return 0
		}
	}
	app, ok := chooseApp(query)
	if !ok {
		return 1
	}
	resp, ok := call(proto.Request{Cmd: proto.CmdAppsAdd, Password: pw, App: &app})
	if !ok {
		return 1
	}
	if !resp.OK {
		return exit(explain(resp))
	}
	ui.Say(ui.Happy, "Added "+app.Name+"!")
	return 0
}

func chooseApp(query string) (proto.App, bool) {
	matches := apps.Search(query)
	if len(matches) == 0 {
		ui.Say(ui.Curious, "I couldn't find that in your Start Menu.", "Paste the full path to the program's .exe file.")
		path, err := ui.Ask("  Path: ")
		path = strings.Trim(path, `"`)
		if err != nil || path == "" {
			return proto.App{}, false
		}
		return proto.App{Path: path}, true
	}
	ui.Say(ui.Curious, "Here's what I found:")
	for i, m := range matches {
		ui.Plain("%d. %s", i+1, m.Name)
	}
	fmt.Println()
	i, ok := ui.Pick("Pick a number: ", len(matches))
	if !ok {
		return proto.App{}, false
	}
	target, err := apps.Resolve(matches[i].Shortcut)
	if err != nil {
		ui.Say(ui.Oops, "I couldn't work out which program "+matches[i].Name+" starts.", "Try again with the path to its .exe file.")
		return proto.App{}, false
	}
	return proto.App{Name: matches[i].Name, Path: target}, true
}

func listApps() ([]proto.App, bool) {
	resp, ok := call(proto.Request{Cmd: proto.CmdAppsList})
	if !ok {
		return nil, false
	}
	if len(resp.Apps) == 0 {
		ui.Say(ui.Curious, "No apps are allowed yet.", "Add one with  peanut allow_apps")
		return nil, false
	}
	return resp.Apps, true
}

func removeApps(_ []string) int {
	if _, ok := ready(); !ok {
		return 1
	}
	list, ok := listApps()
	if !ok {
		return 0
	}
	pw, ok := authenticate()
	if !ok {
		return 1
	}
	ui.Say(ui.Curious, "Which one should go?")
	for i, a := range list {
		ui.Plain("%d. %s", i+1, a.Name)
	}
	fmt.Println()
	i, ok := ui.Pick("Pick a number: ", len(list))
	if !ok {
		return 0
	}
	resp, ok := call(proto.Request{Cmd: proto.CmdAppsRemove, Password: pw, App: &list[i]})
	if !ok {
		return 1
	}
	if !resp.OK {
		return exit(explain(resp))
	}
	ui.Say(ui.Happy, "Removed "+list[i].Name+".")
	return 0
}

func open(args []string) int {
	if _, ok := ready(); !ok {
		return 1
	}
	list, ok := listApps()
	if !ok {
		return 0
	}
	query := strings.ToLower(strings.Join(args, " "))
	var matches []proto.App
	for _, a := range list {
		if query == "" || strings.Contains(strings.ToLower(a.Name), query) {
			matches = append(matches, a)
		}
	}
	if len(matches) == 0 {
		ui.Say(ui.Curious, "Nothing on your list matches '"+query+"'.")
		return 1
	}
	if len(matches) > 1 {
		ui.Say(ui.Curious, "Which one?")
		for i, a := range matches {
			ui.Plain("%d. %s", i+1, a.Name)
		}
		fmt.Println()
		i, ok := ui.Pick("Pick a number: ", len(matches))
		if !ok {
			return 0
		}
		matches = matches[i : i+1]
	}
	if err := apps.Launch(matches[0].Path); err != nil {
		ui.Say(ui.Oops, "I couldn't open "+matches[0].Name+".", err.Error())
		return 1
	}
	ui.Say(ui.Happy, "Opening "+matches[0].Name+"...")
	return 0
}

func resetPassword(_ []string) int {
	st, ok := ready()
	if !ok {
		return 1
	}
	var old string
	if st.Forced {
		ui.Say(ui.Curious, "You used force_unlock, so I won't ask for the old password.", "Let's pick a new one.")
	} else if old, ok = authenticate(); !ok {
		return 1
	}
	pw, ok := newPassword()
	if !ok {
		return 1
	}
	resp, ok := call(proto.Request{Cmd: proto.CmdReset, Password: old, NewPassword: pw})
	if !ok {
		return 1
	}
	if !resp.OK {
		return exit(explain(resp))
	}
	ui.Say(ui.Happy, "Password changed.", "Locking is available again.")
	return 0
}

func forceUnlock(_ []string) int {
	st, ok := ready()
	if !ok {
		return 1
	}
	if !st.Locked {
		return exit(explain(proto.Response{Code: proto.CodeNotLocked}))
	}
	if st.ForceLeft == 0 {
		ui.Say(ui.Curious,
			"Forgot your password? I can unlock you, but you have to wait.",
			"After that, locking stays off until you set a new password",
			"with  peanut reset_password.")
		answer, err := ui.Ask("  Type FORCE to start the timer: ")
		if err != nil || answer != "FORCE" {
			ui.Plain("Cancelled.")
			return 0
		}
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	for {
		resp, ok := call(proto.Request{Cmd: proto.CmdForce})
		if !ok {
			return 1
		}
		if resp.OK && resp.Code == proto.CodeOK {
			ui.Say(ui.Happy, "Force-unlocked.", "Run  peanut reset_password  to turn locking back on.")
			return 0
		}
		if !resp.OK {
			return exit(explain(resp))
		}
		if !countdown(resp.Wait, interrupt) {
			ui.Plain("Stopped. The timer keeps running. Run  peanut force_unlock  again later.")
			return 0
		}
	}
}

func countdown(seconds int, interrupt <-chan os.Signal) bool {
	end := time.Now().Add(time.Duration(seconds) * time.Second)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for time.Now().Before(end) {
		left := int(time.Until(end).Round(time.Second).Seconds())
		fmt.Printf("\r  Unlocking in %s  (Ctrl+C to stop watching)   ", duration(max(left, 0)))
		select {
		case <-interrupt:
			fmt.Println()
			return false
		case <-tick.C:
		}
	}
	fmt.Println()
	return true
}

func install(_ []string) int {
	if !installer.Elevated() {
		ui.Say(ui.Curious, "Peanut needs administrator rights to install.", "Windows will ask for permission in a moment.")
		if err := installer.Relaunch("install", "--pause"); err != nil {
			ui.Say(ui.Oops, "I couldn't ask for permission.", err.Error())
			return 1
		}
		return 0
	}
	if err := installer.Install(); err != nil {
		ui.Say(ui.Oops, "The install didn't finish.", err.Error())
		return 1
	}
	for i := 0; i < 25; i++ {
		if _, ok := ipcStatus(); ok {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	ui.Say(ui.Happy, "Peanut is installed and running.", "Open a new terminal window to use the  peanut  command.")
	if _, ok := ready(); !ok {
		return 1
	}
	return 0
}

func ipcStatus() (proto.Response, bool) {
	resp, err := ipc.Call(proto.Request{Cmd: proto.CmdStatus})
	return resp, err == nil
}

func uninstall(_ []string) int {
	if !installer.Elevated() {
		ui.Say(ui.Curious, "Removing Peanut needs administrator rights.", "Windows will ask for permission in a moment.")
		if err := installer.Relaunch("uninstall", "--pause"); err != nil {
			ui.Say(ui.Oops, "I couldn't ask for permission.", err.Error())
			return 1
		}
		return 0
	}
	if resp, ok := ipcStatus(); ok && resp.Status.Configured {
		pw, err := ui.Secret("  Password: ")
		if err != nil {
			return 1
		}
		auth, ok := call(proto.Request{Cmd: proto.CmdAuthorizeUninstall, Password: pw})
		if !ok {
			return 1
		}
		if !auth.OK {
			return exit(explain(auth))
		}
	}
	if err := installer.Uninstall(); err != nil {
		ui.Say(ui.Oops, "I couldn't finish removing Peanut.", err.Error())
		return 1
	}
	ui.Say(ui.Sleepy, "Peanut is gone. Bye for now!")
	return 0
}
