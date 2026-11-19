package engine

import (
	"testing"
	"time"

	"peanut/internal/proto"
	"peanut/internal/secret"
	"peanut/internal/store"
)

func secretHash(pw string, salt []byte) []byte { return secret.Hash(pw, salt, 100) }

type memory struct{ st *store.State }

func (m *memory) Load() (*store.State, error) { return m.st, nil }
func (m *memory) Save(s *store.State) error {
	c := *s
	m.st = &c
	return nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newEngine(t *testing.T) (*Engine, *clock) {
	t.Helper()
	c := &clock{t: time.Unix(1_000_000, 0)}
	e, err := New(&memory{}, Options{
		ForceWait: 5 * time.Minute, Grace: 20 * time.Second, MinPassword: 6,
		Iterations: 100, Now: c.now, Exists: func(string) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdSetup, Name: "Huzaifa", Password: "secret1", Question: "First pet?", Answer: "Mochi"}); !r.OK {
		t.Fatalf("setup failed: %s", r.Code)
	}
	return e, c
}

func TestSetupRules(t *testing.T) {
	e, _ := newEngine(t)
	if r := e.Handle(proto.Request{Cmd: proto.CmdSetup, Name: "x", Password: "secret1", Question: "q", Answer: "abc"}); r.Code != proto.CodeAlreadyConfigured {
		t.Fatalf("setup twice: %q", r.Code)
	}
	fresh, _ := New(&memory{}, DefaultOptions())
	if r := fresh.Handle(proto.Request{Cmd: proto.CmdSetup, Name: "x", Password: "abc", Question: "q", Answer: "abc"}); r.Code != proto.CodeWeakPassword {
		t.Fatalf("weak password accepted: %q", r.Code)
	}
	if r := fresh.Handle(proto.Request{Cmd: proto.CmdLock}); r.Code != proto.CodeNotConfigured {
		t.Fatalf("lock before setup: %q", r.Code)
	}
}

func TestLockUnlockAndGrace(t *testing.T) {
	e, c := newEngine(t)
	if r := e.Handle(proto.Request{Cmd: proto.CmdLock}); !r.OK || r.Wait != 20 {
		t.Fatalf("lock: %+v", r)
	}
	if active, _ := e.Enforcement(); active {
		t.Fatal("enforcement active during grace")
	}
	c.t = c.t.Add(21 * time.Second)
	if active, _ := e.Enforcement(); !active {
		t.Fatal("enforcement inactive after grace")
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdUnlock, Password: "wrong!"}); r.Code != proto.CodeBadPassword {
		t.Fatalf("wrong password: %q", r.Code)
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdUnlock, Password: "secret1"}); !r.OK {
		t.Fatalf("unlock: %q", r.Code)
	}
}

func TestCooldownAfterFailures(t *testing.T) {
	e, c := newEngine(t)
	for i := 0; i < maxFails; i++ {
		e.Handle(proto.Request{Cmd: proto.CmdCheck, Password: "nope!!"})
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdCheck, Password: "secret1"}); r.Code != proto.CodeCooldown {
		t.Fatalf("correct password during cooldown: %q", r.Code)
	}
	c.t = c.t.Add(31 * time.Second)
	if r := e.Handle(proto.Request{Cmd: proto.CmdCheck, Password: "secret1"}); !r.OK {
		t.Fatalf("after cooldown: %q", r.Code)
	}
}

func TestForceUnlockFlow(t *testing.T) {
	e, c := newEngine(t)
	e.Handle(proto.Request{Cmd: proto.CmdLock})
	if r := e.Handle(proto.Request{Cmd: proto.CmdForce, Answer: "wrong"}); r.Code != proto.CodeBadAnswer {
		t.Fatalf("force without answer: %q", r.Code)
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdForce, Answer: "  MOCHI "}); r.Code != proto.CodeForceStarted || r.Wait != 300 {
		t.Fatalf("start: %+v", r)
	}
	c.t = c.t.Add(2 * time.Minute)
	if r := e.Handle(proto.Request{Cmd: proto.CmdForce, Answer: "mochi"}); r.Code != proto.CodeForceWaiting || r.Wait != 180 {
		t.Fatalf("waiting: %+v", r)
	}
	c.t = c.t.Add(4 * time.Minute)
	if r := e.Handle(proto.Request{Cmd: proto.CmdForce, Answer: "mochi"}); !r.OK || r.Code != "" {
		t.Fatalf("finish: %+v", r)
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdLock}); r.Code != proto.CodeForced {
		t.Fatalf("lock after force: %q", r.Code)
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdReset, NewPassword: "another1"}); r.Code != proto.CodeBadAnswer {
		t.Fatalf("reset after force without answer: %q", r.Code)
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdReset, Answer: "mochi", NewPassword: "another1"}); !r.OK {
		t.Fatalf("reset with answer: %q", r.Code)
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdLock}); !r.OK {
		t.Fatalf("lock after reset: %q", r.Code)
	}
}

func TestResetNeedsOldPassword(t *testing.T) {
	e, _ := newEngine(t)
	if r := e.Handle(proto.Request{Cmd: proto.CmdReset, Password: "bad!!!", NewPassword: "another1"}); r.Code != proto.CodeBadPassword {
		t.Fatalf("reset with wrong password: %q", r.Code)
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdReset, Password: "secret1", NewPassword: "another1"}); !r.OK {
		t.Fatalf("reset: %q", r.Code)
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdCheck, Password: "another1"}); !r.OK {
		t.Fatal("new password rejected")
	}
}

func TestAppRules(t *testing.T) {
	e, _ := newEngine(t)
	add := func(path string) string {
		return e.Handle(proto.Request{Cmd: proto.CmdAppsAdd, Password: "secret1", App: &proto.App{Path: path}}).Code
	}
	if code := add(`/apps/chrome.exe`); code != "" {
		t.Fatalf("add: %q", code)
	}
	if code := add(`/apps/chrome.exe`); code != proto.CodeDuplicate {
		t.Fatalf("duplicate: %q", code)
	}
	if code := add(`/apps/cmd.exe`); code != proto.CodeBlockedApp {
		t.Fatalf("shell allowed: %q", code)
	}
	if code := add(`/apps/readme.txt`); code != proto.CodeInvalidApp {
		t.Fatalf("non-exe allowed: %q", code)
	}
	r := e.Handle(proto.Request{Cmd: proto.CmdAppsRemove, Password: "secret1", App: &proto.App{Path: `/apps/chrome.exe`}})
	if !r.OK {
		t.Fatalf("remove: %q", r.Code)
	}
}

func TestUninstallNeedsUnlock(t *testing.T) {
	e, _ := newEngine(t)
	e.Handle(proto.Request{Cmd: proto.CmdLock})
	if r := e.Handle(proto.Request{Cmd: proto.CmdAuthorizeUninstall, Password: "secret1"}); r.Code != proto.CodeLocked {
		t.Fatalf("uninstall while locked: %q", r.Code)
	}
}

func TestResetWithAnswerOnlyWhenUnlocked(t *testing.T) {
	e, _ := newEngine(t)
	if r := e.Handle(proto.Request{Cmd: proto.CmdReset, Answer: "mochi", NewPassword: "another1"}); !r.OK {
		t.Fatalf("reset by answer while unlocked: %q", r.Code)
	}
	e.Handle(proto.Request{Cmd: proto.CmdLock})
	if r := e.Handle(proto.Request{Cmd: proto.CmdReset, Answer: "mochi", NewPassword: "third123"}); r.Code != proto.CodeLocked {
		t.Fatalf("reset by answer while locked: %q", r.Code)
	}
}

func TestWrongAnswersTriggerCooldown(t *testing.T) {
	e, _ := newEngine(t)
	for i := 0; i < maxFails; i++ {
		e.Handle(proto.Request{Cmd: proto.CmdCheckAnswer, Answer: "nope"})
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdCheckAnswer, Answer: "mochi"}); r.Code != proto.CodeCooldown {
		t.Fatalf("answer during cooldown: %q", r.Code)
	}
}

func TestSetQuestionNeedsPassword(t *testing.T) {
	e, _ := newEngine(t)
	if r := e.Handle(proto.Request{Cmd: proto.CmdSetQuestion, Password: "bad!!!", Question: "q?", Answer: "blue"}); r.Code != proto.CodeBadPassword {
		t.Fatalf("set question with wrong password: %q", r.Code)
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdSetQuestion, Password: "secret1", Question: "Color?", Answer: "Blue"}); !r.OK {
		t.Fatalf("set question: %q", r.Code)
	}
	if r := e.Handle(proto.Request{Cmd: proto.CmdCheckAnswer, Answer: "blue"}); !r.OK {
		t.Fatalf("new answer rejected: %q", r.Code)
	}
}

func TestLegacyAccountWithoutQuestion(t *testing.T) {
	m := &memory{st: &store.State{Configured: true, Name: "Old"}}
	e, _ := New(m, Options{ForceWait: time.Minute, Grace: time.Second, MinPassword: 6, Iterations: 100, Now: time.Now, Exists: func(string) bool { return true }})
	e.st.Salt = []byte("salt-salt-salt-1")
	e.st.Iterations = 100
	e.st.Hash = secretHash("secret1", e.st.Salt)
	e.Handle(proto.Request{Cmd: proto.CmdLock})
	if r := e.Handle(proto.Request{Cmd: proto.CmdForce}); r.Code != proto.CodeForceStarted {
		t.Fatalf("legacy force: %q", r.Code)
	}
}
