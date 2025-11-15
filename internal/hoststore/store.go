package hoststore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MKlolbullen/rustygo/internal/model"
)

// Store persists HostRecord JSON files under:
//
//   <root>/hosts/<engagement>/<hostname>.json
//
type Store struct {
	root string
}

func New(root string) *Store {
	return &Store{root: root}
}

func (s *Store) engagementDir(eng string) string {
	safe := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(eng)), string(os.PathSeparator), "_")
	if safe == "" {
		safe = "default"
	}
	return filepath.Join(s.root, "hosts", safe)
}

func (s *Store) hostFile(eng, hostname string) string {
	dir := s.engagementDir(eng)
	safeHost := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(hostname)), string(os.PathSeparator), "_")
	if safeHost == "" {
		safeHost = "unknown"
	}
	return filepath.Join(dir, safeHost+".json")
}

// Save writes a HostRecord to disk. If an existing record is present, it
// preserves FirstSeen.
func (s *Store) Save(rec *model.HostRecord) error {
	if rec == nil || rec.Profile == nil {
		return fmt.Errorf("record/profile is nil")
	}
	if rec.Profile.Hostname == "" {
		return fmt.Errorf("profile.hostname is required")
	}

	if rec.Engagement == "" {
		rec.Engagement = rec.Profile.Domain
	}
	if rec.Engagement == "" {
		rec.Engagement = "default"
	}

	dir := s.engagementDir(rec.Engagement)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	path := s.hostFile(rec.Engagement, rec.Profile.Hostname)

	// Preserve FirstSeen if we already have a record.
	if old, err := s.Load(rec.Engagement, rec.Profile.Hostname); err == nil && old != nil {
		rec.FirstSeen = old.FirstSeen
		if rec.LastUpdated.IsZero() {
			rec.LastUpdated = old.LastUpdated
		}
	} else {
		if rec.FirstSeen.IsZero() {
			rec.FirstSeen = rec.LastUpdated
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(rec)
}

func (s *Store) Load(engagement, hostname string) (*model.HostRecord, error) {
	path := s.hostFile(engagement, hostname)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rec model.HostRecord
	if err := json.NewDecoder(f).Decode(&rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// List returns all HostRecords for an engagement. If none exist, returns an
// empty slice, not nil.
func (s *Store) List(engagement string) ([]*model.HostRecord, error) {
	dir := s.engagementDir(engagement)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*model.HostRecord{}, nil
		}
		return nil, err
	}

	out := make([]*model.HostRecord, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fpath := filepath.Join(dir, e.Name())
		f, err := os.Open(fpath)
		if err != nil {
			continue
		}
		var rec model.HostRecord
		if err := json.NewDecoder(f).Decode(&rec); err == nil {
			out = append(out, &rec)
		}
		f.Close()
	}
	return out, nil
}
