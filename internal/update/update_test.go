package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		cur, next string
		want      bool
	}{
		{"v0.1.0", "v0.1.1", true},
		{"v0.1.9", "v0.2.0", true},
		{"v0.2.0", "v0.1.9", false},
		{"v0.1.1", "v0.1.1", false},
		{"dev", "v0.1.1", false},
		{"v0.1.0", "v0.1.1-beta", false},
		{"v1.0.0", "v0.9.9", false},
	}
	for _, c := range cases {
		if got := Newer(c.cur, c.next); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.cur, c.next, got)
		}
	}
}

func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte("exe bytes")
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)))
	if err := Verify(pub, data, sig); err != nil {
		t.Fatal(err)
	}
	if Verify(pub, []byte("tampered"), sig) == nil {
		t.Fatal("tampered data accepted")
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if Verify(otherPub, data, sig) == nil {
		t.Fatal("wrong key accepted")
	}
	if Verify(pub, data, []byte("not base64!")) == nil {
		t.Fatal("malformed signature accepted")
	}
}

func fixture(t *testing.T, tag string, signWith ed25519.PrivateKey, exe []byte) (*httptest.Server, string) {
	t.Helper()
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(signWith, exe))
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			json.NewEncoder(w).Encode(release{Tag: tag, Assets: []asset{
				{Name: exeAsset, URL: srv.URL + "/exe"},
				{Name: sigAsset, URL: srv.URL + "/sig"},
			}})
		case "/exe":
			w.Write(exe)
		case "/sig":
			io.WriteString(w, sig)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/latest"
}

func newUpdater(t *testing.T, pub ed25519.PublicKey, api string, idle bool) (*Updater, string, *bool) {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "peanut.exe")
	os.WriteFile(exe, []byte("old build"), 0o755)
	restarted := false
	u := New(Config{
		Current: "v0.1.0", DataDir: dir, Exe: exe, APIURL: api, PublicKey: pub,
		Enabled:  func() bool { return true },
		Idle:     func() bool { return idle },
		Restart:  func() { restarted = true },
		Logger:   log.New(io.Discard, "", 0),
		AllowURL: func(*url.URL) bool { return true },
	})
	return u, exe, &restarted
}

func TestUpdateAppliesSignedBuild(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, api := fixture(t, "v0.1.1", priv, []byte("new build"))
	u, exe, restarted := newUpdater(t, pub, api, true)
	if res := u.Check(); res.Code != ResultApplying || res.Version != "v0.1.1" {
		t.Fatalf("result: %+v", res)
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "new build" || !*restarted {
		t.Fatalf("exe %q restarted %v", got, *restarted)
	}
	if old, _ := os.ReadFile(exe + ".old"); string(old) != "old build" {
		t.Fatal("previous build not kept")
	}
}

func TestUpdateRejectsWrongSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	_, api := fixture(t, "v0.1.1", attacker, []byte("evil build"))
	u, exe, restarted := newUpdater(t, pub, api, true)
	if res := u.Check(); res.Code != ResultFailed {
		t.Fatalf("result: %+v", res)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old build" || *restarted {
		t.Fatal("unsigned build was installed")
	}
}

func TestUpdateWaitsWhileLocked(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, api := fixture(t, "v0.1.1", priv, []byte("new build"))
	u, exe, restarted := newUpdater(t, pub, api, false)
	if res := u.Check(); res.Code != ResultReady {
		t.Fatalf("result: %+v", res)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old build" || *restarted {
		t.Fatal("applied while locked")
	}
	u.cfg.Idle = func() bool { return true }
	u.applyStaged()
	if got, _ := os.ReadFile(exe); string(got) != "new build" || !*restarted {
		t.Fatal("staged update not applied after unlock")
	}
}

func TestIgnoresOlderAndDevBuilds(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, api := fixture(t, "v0.0.9", priv, []byte("older"))
	u, _, _ := newUpdater(t, pub, api, true)
	if res := u.Check(); res.Code != ResultCurrent {
		t.Fatalf("downgrade result: %+v", res)
	}
	u.cfg.Current = "dev"
	if res := u.Check(); res.Code != ResultDisabled {
		t.Fatalf("dev result: %+v", res)
	}
}

func TestRollbackAfterRepeatedFailedStarts(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, api := fixture(t, "v0.1.1", priv, []byte("new build"))
	u, exe, _ := newUpdater(t, pub, api, true)
	u.Check()
	for i := 0; i < maxRollbackAttempts; i++ {
		if u.BeginStart() {
			t.Fatalf("rolled back too early on start %d", i+1)
		}
	}
	if !u.BeginStart() {
		t.Fatal("did not roll back")
	}
	if got, _ := os.ReadFile(exe); string(got) != "old build" {
		t.Fatalf("exe after rollback: %q", got)
	}
}

func TestHealthyStartClearsMarker(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, api := fixture(t, "v0.1.1", priv, []byte("new build"))
	u, _, _ := newUpdater(t, pub, api, true)
	u.Check()
	u.BeginStart()
	u.MarkHealthy()
	if u.BeginStart() {
		t.Fatal("rolled back after a healthy start")
	}
}