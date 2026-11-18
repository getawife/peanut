package engine

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"peanut/internal/policy"
	"peanut/internal/proto"
	"peanut/internal/secret"
	"peanut/internal/store"
)

const maxFails = 5

type Persister interface {
	Load() (*store.State, error)
	Save(*store.State) error
}

type Options struct {
	ForceWait   time.Duration
	Grace       time.Duration
	MinPassword int
	Iterations  int
	Now         func() time.Time
	Exists      func(string) bool
}

func DefaultOptions() Options {
	return Options{
		ForceWait:   5 * time.Minute,
		Grace:       20 * time.Second,
		MinPassword: 6,
		Iterations:  secret.DefaultIterations,
		Now:         time.Now,
		Exists: func(p string) bool {
			info, err := os.Stat(p)
			return err == nil && !info.IsDir()
		},
	}
}

type Engine struct {
	mu     sync.Mutex
	st     *store.State
	store  Persister
	opt    Options
	OnLock func(locked bool)
}

func New(p Persister, opt Options) (*Engine, error) {
	st, err := p.Load()
	if err != nil {
		return nil, err
	}
	if st == nil {
		st = &store.State{}
	}
	return &Engine{store: p, st: st, opt: opt}, nil
}

func (e *Engine) Locked() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.st.Locked
}

func (e *Engine) Enforcement() (bool, []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.st.Locked || e.opt.Now().Before(e.st.LockedAt.Add(e.opt.Grace)) {
		return false, nil
	}
	paths := make([]string, 0, len(e.st.Apps))
	for _, a := range e.st.Apps {
		paths = append(paths, a.Path)
	}
	return true, paths
}

func (e *Engine) Handle(req proto.Request) proto.Response {
	e.mu.Lock()
	before := e.st.Locked
	resp := e.dispatch(req)
	after := e.st.Locked
	e.mu.Unlock()
	if before != after && e.OnLock != nil {
		e.OnLock(after)
	}
	return resp
}

func (e *Engine) dispatch(req proto.Request) proto.Response {
	switch req.Cmd {
	case proto.CmdStatus:
		return e.ok()
	case proto.CmdSetup:
		return e.setup(req)
	}
	if !e.st.Configured {
		return e.fail(proto.CodeNotConfigured)
	}
	switch req.Cmd {
	case proto.CmdLock:
		return e.lock()
	case proto.CmdUnlock:
		return e.unlock(req)
	case proto.CmdCheck:
		if code := e.authenticate(req.Password); code != "" {
			return e.fail(code)
		}
		return e.ok()
	case proto.CmdAppsList:
		resp := e.ok()
		resp.Apps = append([]proto.App(nil), e.st.Apps...)
		return resp
	case proto.CmdAppsAdd:
		return e.addApp(req)
	case proto.CmdAppsRemove:
		return e.removeApp(req)
	case proto.CmdReset:
		return e.reset(req)
	case proto.CmdForce:
		return e.force()
	case proto.CmdAuthorizeUninstall:
		if e.st.Locked {
			return e.fail(proto.CodeLocked)
		}
		if code := e.authenticate(req.Password); code != "" {
			return e.fail(code)
		}
		return e.ok()
	}
	return e.fail(proto.CodeUnknownCommand)
}

func (e *Engine) setup(req proto.Request) proto.Response {
	if e.st.Configured {
		return e.fail(proto.CodeAlreadyConfigured)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return e.fail(proto.CodeEmptyName)
	}
	if len(req.Password) < e.opt.MinPassword {
		return e.fail(proto.CodeWeakPassword)
	}
	e.setPassword(req.Password)
	e.st.Name = name
	e.st.Configured = true
	if err := e.save(); err != nil {
		e.st.Configured = false
		return e.fail(proto.CodeStorage)
	}
	return e.ok()
}

func (e *Engine) lock() proto.Response {
	if e.st.Forced {
		return e.fail(proto.CodeForced)
	}
	if e.st.Locked {
		return e.fail(proto.CodeAlreadyLocked)
	}
	e.st.Locked = true
	e.st.LockedAt = e.opt.Now()
	e.st.ForceAt = time.Time{}
	if err := e.save(); err != nil {
		e.st.Locked = false
		return e.fail(proto.CodeStorage)
	}
	resp := e.ok()
	resp.Wait = int(e.opt.Grace.Seconds())
	return resp
}

func (e *Engine) unlock(req proto.Request) proto.Response {
	if !e.st.Locked {
		return e.fail(proto.CodeNotLocked)
	}
	if code := e.authenticate(req.Password); code != "" {
		return e.fail(code)
	}
	e.st.Locked = false
	e.st.ForceAt = time.Time{}
	if err := e.save(); err != nil {
		e.st.Locked = true
		return e.fail(proto.CodeStorage)
	}
	return e.ok()
}

func (e *Engine) addApp(req proto.Request) proto.Response {
	if code := e.authenticate(req.Password); code != "" {
		return e.fail(code)
	}
	if req.App == nil {
		return e.fail(proto.CodeInvalidApp)
	}
	app, code := e.validateApp(*req.App)
	if code != "" {
		return e.fail(code)
	}
	for _, a := range e.st.Apps {
		if strings.EqualFold(a.Path, app.Path) {
			return e.fail(proto.CodeDuplicate)
		}
	}
	e.st.Apps = append(e.st.Apps, app)
	if err := e.save(); err != nil {
		e.st.Apps = e.st.Apps[:len(e.st.Apps)-1]
		return e.fail(proto.CodeStorage)
	}
	return e.ok()
}

func (e *Engine) validateApp(a proto.App) (proto.App, string) {
	path := filepath.Clean(a.Path)
	base := filepath.Base(path)
	if !strings.HasSuffix(strings.ToLower(base), ".exe") || !e.opt.Exists(path) {
		return a, proto.CodeInvalidApp
	}
	if !policy.CanAllow(base) {
		return a, proto.CodeBlockedApp
	}
	a.Path = path
	if strings.TrimSpace(a.Name) == "" {
		a.Name = strings.TrimSuffix(base, filepath.Ext(base))
	}
	return a, ""
}

func (e *Engine) removeApp(req proto.Request) proto.Response {
	if code := e.authenticate(req.Password); code != "" {
		return e.fail(code)
	}
	if req.App == nil {
		return e.fail(proto.CodeNotFound)
	}
	target := filepath.Clean(req.App.Path)
	for i, a := range e.st.Apps {
		if strings.EqualFold(a.Path, target) {
			old := e.st.Apps
			e.st.Apps = append(append([]proto.App(nil), old[:i]...), old[i+1:]...)
			if err := e.save(); err != nil {
				e.st.Apps = old
				return e.fail(proto.CodeStorage)
			}
			return e.ok()
		}
	}
	return e.fail(proto.CodeNotFound)
}

func (e *Engine) reset(req proto.Request) proto.Response {
	if !e.st.Forced {
		if code := e.authenticate(req.Password); code != "" {
			return e.fail(code)
		}
	}
	if len(req.NewPassword) < e.opt.MinPassword {
		return e.fail(proto.CodeWeakPassword)
	}
	e.setPassword(req.NewPassword)
	e.st.Forced = false
	e.st.Fails = 0
	e.st.CooldownUntil = time.Time{}
	e.st.ForceAt = time.Time{}
	if err := e.save(); err != nil {
		return e.fail(proto.CodeStorage)
	}
	return e.ok()
}

func (e *Engine) force() proto.Response {
	if !e.st.Locked {
		return e.fail(proto.CodeNotLocked)
	}
	now := e.opt.Now()
	if e.st.ForceAt.IsZero() {
		e.st.ForceAt = now.Add(e.opt.ForceWait)
		if err := e.save(); err != nil {
			e.st.ForceAt = time.Time{}
			return e.fail(proto.CodeStorage)
		}
		resp := e.ok()
		resp.Code = proto.CodeForceStarted
		resp.Wait = seconds(e.st.ForceAt.Sub(now))
		return resp
	}
	if now.Before(e.st.ForceAt) {
		resp := e.ok()
		resp.Code = proto.CodeForceWaiting
		resp.Wait = seconds(e.st.ForceAt.Sub(now))
		return resp
	}
	e.st.Locked = false
	e.st.Forced = true
	e.st.ForceAt = time.Time{}
	if err := e.save(); err != nil {
		e.st.Locked = true
		e.st.Forced = false
		return e.fail(proto.CodeStorage)
	}
	return e.ok()
}

func (e *Engine) authenticate(password string) string {
	now := e.opt.Now()
	if now.Before(e.st.CooldownUntil) {
		return proto.CodeCooldown
	}
	if secret.Verify(password, e.st.Salt, e.st.Hash, e.st.Iterations) {
		if e.st.Fails != 0 || !e.st.CooldownUntil.IsZero() {
			e.st.Fails = 0
			e.st.CooldownUntil = time.Time{}
			_ = e.save()
		}
		return ""
	}
	e.st.Fails++
	if e.st.Fails >= maxFails {
		shift := min(e.st.Fails-maxFails, 7)
		e.st.CooldownUntil = now.Add(30 * time.Second << shift)
	}
	_ = e.save()
	return proto.CodeBadPassword
}

func (e *Engine) setPassword(password string) {
	e.st.Salt = secret.NewSalt()
	e.st.Iterations = e.opt.Iterations
	e.st.Hash = secret.Hash(password, e.st.Salt, e.st.Iterations)
}

func (e *Engine) save() error { return e.store.Save(e.st) }

func (e *Engine) status() *proto.Status {
	now := e.opt.Now()
	st := &proto.Status{
		Configured: e.st.Configured,
		Name:       e.st.Name,
		Locked:     e.st.Locked,
		Forced:     e.st.Forced,
		Apps:       len(e.st.Apps),
	}
	if e.st.Locked {
		st.GraceLeft = max(seconds(e.st.LockedAt.Add(e.opt.Grace).Sub(now)), 0)
	}
	if !e.st.ForceAt.IsZero() {
		st.ForceLeft = max(seconds(e.st.ForceAt.Sub(now)), 0)
	}
	if now.Before(e.st.CooldownUntil) {
		st.CooldownLeft = seconds(e.st.CooldownUntil.Sub(now))
	}
	if e.st.Fails < maxFails {
		st.AttemptsLeft = maxFails - e.st.Fails
	}
	return st
}

func (e *Engine) ok() proto.Response {
	return proto.Response{OK: true, Status: e.status()}
}

func (e *Engine) fail(code string) proto.Response {
	return proto.Response{Code: code, Status: e.status()}
}

func seconds(d time.Duration) int {
	return int((d + time.Second - 1) / time.Second)
}
