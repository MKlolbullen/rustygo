package credstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MKlolbullen/rustygo/internal/model"
)

// Store persists Credential JSON files under:
//
//   <root>/credentials/<engagement>/<id>.json
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
	return filepath.Join(s.root, "credentials", safe)
}

func (s *Store) credFile(eng, id string) string {
	dir := s.engagementDir(eng)
	return filepath.Join(dir, id+".json")
}

// Save writes a Credential to disk. If ID is empty, one is generated.
// If FirstSeen/LastUpdated are zero, they are set to now.
func (s *Store) Save(c *model.Credential) error {
	if c == nil {
		return fmt.Errorf("credential is nil")
	}
	if strings.TrimSpace(c.Account) == "" {
		return fmt.Errorf("credential.account is required")
	}
	if strings.TrimSpace(c.Engagement) == "" {
		c.Engagement = "default"
	}

	if c.ID == "" {
		c.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	now := time.Now().UTC()
	if c.FirstSeen.IsZero() {
		c.FirstSeen = now
	}
	if c.LastUpdated.IsZero() {
		c.LastUpdated = now
	}

	dir := s.engagementDir(c.Engagement)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := s.credFile(c.Engagement, c.ID)

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(c)
}

// List returns all credentials for an engagement. If engagement is empty,
// it uses "default".
func (s *Store) List(engagement string) ([]*model.Credential, error) {
	if strings.TrimSpace(engagement) == "" {
		engagement = "default"
	}
	dir := s.engagementDir(engagement)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*model.Credential{}, nil
		}
		return nil, err
	}

	out := make([]*model.Credential, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		var c model.Credential
		if err := json.NewDecoder(f).Decode(&c); err == nil {
			out = append(out, &c)
		}
		f.Close()
	}
	return out, nil
}
