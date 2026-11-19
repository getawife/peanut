package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Repo                = "getawife/peanut"
	exeAsset            = "peanut.exe"
	sigAsset            = "peanut.exe.sig"
	checkInterval       = 6 * time.Hour
	firstCheck          = 2 * time.Minute
	requestTimeout      = 60 * time.Second
	maxExeSize          = 64 << 20
	maxJSONSize         = 1 << 20
	maxRollbackAttempts = 3
	HealthyAfter        = 30 * time.Second
)

const (
	ResultDisabled = "disabled"
	ResultCurrent  = "current"
	ResultReady    = "ready"
	ResultApplying = "applying"
	ResultFailed   = "failed"
)

type Result struct {
	Code    string
	Version string
}

type Config struct {
	Current   string
	DataDir   string
	Exe       string
	APIURL    string
	PublicKey ed25519.PublicKey
	Enabled   func() bool
	Idle      func() bool
	Restart   func()
	Logger    *log.Logger
	AllowURL  func(*url.URL) bool
}

type Updater struct {
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	poke   chan struct{}
}

type release struct {
	Tag    string  `json:"tag_name"`
	Assets []asset `json:"assets"`
}

type asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

func New(cfg Config) *Updater {
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.github.com/repos/" + Repo + "/releases/latest"
	}
	if cfg.AllowURL == nil {
		cfg.AllowURL = allowGitHub
	}
	u := &Updater{cfg: cfg, poke: make(chan struct{}, 1)}
	u.client = &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 || !cfg.AllowURL(req.URL) {
				return errors.New("redirect not allowed")
			}
			return nil
		},
	}
	return u
}

func allowGitHub(u *url.URL) bool {
	if u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "github.com" || strings.HasSuffix(host, ".github.com") || strings.HasSuffix(host, ".githubusercontent.com")
}

func (u *Updater) Loop(stop <-chan struct{}) {
	timer := time.NewTimer(firstCheck)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-u.poke:
			u.applyStaged()
		case <-timer.C:
			if u.cfg.Enabled() {
				u.Check()
			}
			timer.Reset(checkInterval)
		}
	}
}

func (u *Updater) Poke() {
	select {
	case u.poke <- struct{}{}:
	default:
	}
}

func (u *Updater) Check() Result {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cfg.PublicKey == nil || u.cfg.Current == "dev" {
		return Result{Code: ResultDisabled}
	}
	rel, err := u.latest()
	if err != nil {
		u.cfg.Logger.Printf("update check: %v", err)
		return Result{Code: ResultFailed}
	}
	if !Newer(u.cfg.Current, rel.Tag) {
		return Result{Code: ResultCurrent, Version: u.cfg.Current}
	}
	if err := u.stage(rel); err != nil {
		u.cfg.Logger.Printf("update download: %v", err)
		return Result{Code: ResultFailed, Version: rel.Tag}
	}
	return u.applyLocked(rel.Tag)
}

func (u *Updater) applyStaged() {
	u.mu.Lock()
	defer u.mu.Unlock()
	tag := u.stagedVersion()
	if tag == "" || !Newer(u.cfg.Current, tag) || !u.cfg.Enabled() {
		return
	}
	u.applyLocked(tag)
}

func (u *Updater) applyLocked(tag string) Result {
	if !u.cfg.Idle() {
		return Result{Code: ResultReady, Version: tag}
	}
	if err := u.swap(); err != nil {
		u.cfg.Logger.Printf("update apply: %v", err)
		return Result{Code: ResultFailed, Version: tag}
	}
	u.cfg.Logger.Printf("updated to %s, restarting", tag)
	u.cfg.Restart()
	return Result{Code: ResultApplying, Version: tag}
}

func (u *Updater) latest() (release, error) {
	var rel release
	body, err := u.get(u.cfg.APIURL, maxJSONSize)
	if err != nil {
		return rel, err
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return rel, err
	}
	return rel, nil
}

func (u *Updater) get(rawURL string, limit int64) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || !u.cfg.AllowURL(parsed) {
		return nil, fmt.Errorf("address not allowed: %s", rawURL)
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "peanut-updater")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", rawURL, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("download is too large")
	}
	return data, nil
}

func (r release) find(name string) string {
	for _, a := range r.Assets {
		if a.Name == name {
			return a.URL
		}
	}
	return ""
}

func (u *Updater) stageDir() string { return filepath.Join(u.cfg.DataDir, "update") }

func (u *Updater) stagedVersion() string {
	data, err := os.ReadFile(filepath.Join(u.stageDir(), "version.txt"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (u *Updater) stage(rel release) error {
	if u.stagedVersion() == rel.Tag && u.stagedVerified() {
		return nil
	}
	exeURL, sigURL := rel.find(exeAsset), rel.find(sigAsset)
	if exeURL == "" || sigURL == "" {
		return errors.New("release is missing the exe or its signature")
	}
	exe, err := u.get(exeURL, maxExeSize)
	if err != nil {
		return err
	}
	sig, err := u.get(sigURL, maxJSONSize)
	if err != nil {
		return err
	}
	if err := Verify(u.cfg.PublicKey, exe, sig); err != nil {
		return err
	}
	dir := u.stageDir()
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
	}{{exeAsset, exe}, {sigAsset, sig}, {"version.txt", []byte(rel.Tag)}}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (u *Updater) stagedVerified() bool {
	exe, sig, err := u.readStaged()
	return err == nil && Verify(u.cfg.PublicKey, exe, sig) == nil
}

func (u *Updater) readStaged() ([]byte, []byte, error) {
	exe, err := os.ReadFile(filepath.Join(u.stageDir(), exeAsset))
	if err != nil {
		return nil, nil, err
	}
	sig, err := os.ReadFile(filepath.Join(u.stageDir(), sigAsset))
	if err != nil {
		return nil, nil, err
	}
	return exe, sig, nil
}

func (u *Updater) swap() error {
	exe, sig, err := u.readStaged()
	if err != nil {
		return err
	}
	if err := Verify(u.cfg.PublicKey, exe, sig); err != nil {
		return err
	}
	next, old := u.cfg.Exe+".new", u.cfg.Exe+".old"
	if err := os.WriteFile(next, exe, 0o755); err != nil {
		return err
	}
	written, err := os.ReadFile(next)
	if err != nil || !bytes.Equal(written, exe) {
		os.Remove(next)
		return errors.New("staged file did not copy correctly")
	}
	os.Remove(old)
	if err := os.Rename(u.cfg.Exe, old); err != nil {
		os.Remove(next)
		return err
	}
	if err := os.Rename(next, u.cfg.Exe); err != nil {
		os.Rename(old, u.cfg.Exe)
		return err
	}
	if err := u.writeMarker(0); err != nil {
		return err
	}
	os.RemoveAll(u.stageDir())
	return nil
}

type marker struct {
	Attempts int `json:"attempts"`
}

func (u *Updater) markerPath() string { return filepath.Join(u.cfg.DataDir, "update-pending.json") }

func (u *Updater) writeMarker(attempts int) error {
	data, err := json.Marshal(marker{Attempts: attempts})
	if err != nil {
		return err
	}
	return os.WriteFile(u.markerPath(), data, 0o600)
}

func (u *Updater) BeginStart() bool {
	data, err := os.ReadFile(u.markerPath())
	if err != nil {
		return false
	}
	var m marker
	json.Unmarshal(data, &m)
	m.Attempts++
	if m.Attempts <= maxRollbackAttempts {
		u.writeMarker(m.Attempts)
		return false
	}
	os.Remove(u.markerPath())
	old, bad := u.cfg.Exe+".old", u.cfg.Exe+".bad"
	if _, err := os.Stat(old); err != nil {
		return false
	}
	os.Remove(bad)
	if err := os.Rename(u.cfg.Exe, bad); err != nil {
		return false
	}
	if err := os.Rename(old, u.cfg.Exe); err != nil {
		os.Rename(bad, u.cfg.Exe)
		return false
	}
	u.cfg.Logger.Printf("new version kept failing to start, restored the previous one")
	return true
}

func (u *Updater) MarkHealthy() { os.Remove(u.markerPath()) }

func Verify(key ed25519.PublicKey, data, sigBase64 []byte) error {
	if key == nil {
		return errors.New("no public key configured")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigBase64)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("signature is malformed")
	}
	if !ed25519.Verify(key, data, sig) {
		return errors.New("signature does not match")
	}
	return nil
}

func Newer(current, candidate string) bool {
	cur, ok := parseVersion(current)
	if !ok {
		return false
	}
	next, ok := parseVersion(candidate)
	if !ok {
		return false
	}
	for i := range cur {
		if next[i] != cur[i] {
			return next[i] > cur[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}