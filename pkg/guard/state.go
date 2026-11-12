package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type stateEntry struct {
	IP   string    `json:"ip"`
	When time.Time `json:"when"`
}

type stateFile struct {
	mu   sync.Mutex
	path string
}

func newStateFile(path string) *stateFile {
	return &stateFile{path: path}
}

func (s *stateFile) load() ([]stateEntry, error) {
	var entries []stateEntry
	if err := s.loadJSON(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *stateFile) loadJSON(value any) error {
	if s == nil || s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("invalid state json: %w", err)
	}
	return nil
}

func (s *stateFile) saveEntries(entries []stateEntry) error {
	return s.saveJSON(entries)
}

func (s *stateFile) saveJSON(value any) error {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
