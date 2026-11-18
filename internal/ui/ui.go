//go:build windows

package ui

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

type Face int

const (
	Happy Face = iota
	Sleepy
	Oops
	Curious
)

var faces = map[Face]string{Happy: "^.^", Sleepy: "-.-", Oops: ">.<", Curious: "o.o"}

var rainbow = []int{196, 208, 226, 46, 33, 129}

var (
	ErrCancelled = errors.New("cancelled")
	stdin        = bufio.NewReader(os.Stdin)
	colorOn      bool
)

const (
	trailWidth = 8
	artWidth   = 14
)

func Init() {
	out := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if windows.GetConsoleMode(out, &mode) == nil {
		if windows.SetConsoleMode(out, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil {
			colorOn = os.Getenv("NO_COLOR") == ""
		}
	}
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleOutputCP")
	proc.Call(65001)
}

func paint(code int, s string) string {
	if !colorOn {
		return s
	}
	return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", code, s)
}

func trail(row int) string {
	var b strings.Builder
	for i := 0; i < trailWidth; i++ {
		b.WriteString(paint(rainbow[(i+row)%len(rainbow)], "█"))
	}
	return b.String()
}

func sparkles() string {
	return "   " + paint(226, "✦") + "      " + paint(51, "·") + "    " + paint(201, "✧") + "     " + paint(226, "·") + "       " + paint(51, "✦")
}

func Say(face Face, lines ...string) {
	art := []string{
		"_,------,",
		"_|   /\\_/\\",
		"^|__( " + faces[face] + " )",
		"  \"\"  \"\"",
	}
	fmt.Println()
	fmt.Println(sparkles())
	rows := max(len(art), len(lines))
	for i := 0; i < rows; i++ {
		left := strings.Repeat(" ", trailWidth)
		piece := ""
		if i < 3 {
			left = trail(i)
		}
		if i < len(art) {
			piece = art[i]
		}
		text := ""
		if i < len(lines) {
			text = lines[i]
		}
		if i >= len(art) {
			left = strings.Repeat(" ", trailWidth)
		}
		fmt.Printf(" %s%-*s %s\n", left, artWidth, piece, text)
	}
	fmt.Println()
}

func Plain(format string, a ...any) { fmt.Printf("  "+format+"\n", a...) }

func Ask(prompt string) (string, error) {
	fmt.Print(prompt)
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", ErrCancelled
	}
	return strings.TrimSpace(line), nil
}

func Confirm(prompt string) bool {
	answer, err := Ask("  " + prompt + " (y/n) ")
	return err == nil && strings.EqualFold(answer, "y")
}

func Pick(prompt string, n int) (int, bool) {
	answer, err := Ask("  " + prompt)
	if err != nil {
		return 0, false
	}
	i, err := strconv.Atoi(answer)
	if err != nil || i < 1 || i > n {
		return 0, false
	}
	return i - 1, true
}

func Secret(prompt string) (string, error) {
	fmt.Print(prompt)
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		line, err := stdin.ReadString('\n')
		if err != nil && line == "" {
			return "", ErrCancelled
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	raw := mode &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT)
	if err := windows.SetConsoleMode(h, raw); err != nil {
		return "", err
	}
	defer windows.SetConsoleMode(h, mode)
	var pw []rune
	for {
		r, _, err := stdin.ReadRune()
		if err != nil {
			return "", ErrCancelled
		}
		switch {
		case r == '\r' || r == '\n':
			fmt.Println()
			return string(pw), nil
		case r == 3:
			fmt.Println()
			return "", ErrCancelled
		case r == 8 || r == 127:
			if len(pw) > 0 {
				pw = pw[:len(pw)-1]
				fmt.Print("\b \b")
			}
		case r >= 32:
			pw = append(pw, r)
			fmt.Print("*")
		}
	}
}
