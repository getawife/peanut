package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"peanut/internal/proto"
)

type State struct {
	Configured    bool        `json:"configured"`
	Name          string      `json:"name"`
	Salt          []byte      `json:"salt"`
	Hash          []byte      `json:"hash"`
	Iterations    int         `json:"iterations"`
	Question      string      `json:"question"`
	AnswerSalt    []byte      `json:"answer_salt"`
	AnswerHash    []byte      `json:"answer_hash"`
	AnswerIter    int         `json:"answer_iter"`
	Locked        bool        `json:"locked"`
	LockedAt      time.Time   `json:"locked_at"`
	Forced        bool        `json:"forced"`
	Fails         int         `json:"fails"`
	CooldownUntil time.Time   `json:"cooldown_until"`
	ForceAt       time.Time   `json:"force_at"`
	Apps          []proto.App `json:"apps"`
}

type Store struct{ Dir string }

func (s Store) primary() string { return filepath.Join(s.Dir, "state.json") }
func (s Store) backup() string  { return filepath.Join(s.Dir, "state.bak") }

func (s Store) Load() (*State, error) {
	var lastErr error
	found := false
	for _, path := range []string{s.primary(), s.backup()} {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		found = true
		if err != nil {
			lastErr = err
			continue
		}
		var st State
		if err := json.Unmarshal(data, &st); err != nil {
			lastErr = err
			continue
		}
		return &st, nil
	}
	if found {
		return nil, fmt.Errorf("state files unreadable: %w", lastErr)
	}
	return nil, nil
}

func (s Store) Save(st *State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	for _, path := range []string{s.backup(), s.primary()} {
		if err := writeAtomic(path, data); err != nil {
			return err
		}
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
