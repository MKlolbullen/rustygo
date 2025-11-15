package sessionstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MKlolbullen/rustygo/internal/model"
)

// Store persists Session JSON files under:
//
//   <root>/sessions/<engagement>/<id>.json
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
	return filepath.Join(s.root, "sessions", safe)
}

func (s *Store) sessionFile(eng, id string) string {
	dir := s.engagementDir(eng)
	return filepath.Join(dir, id+".json")
}

// Save writes a Session to disk. If ID is empty, one is generated.
// If FirstSeen/LastSeen are zero, they are set to now.
func (s *Store) Save(sess *model.Session) error {
	if sess == nil {
		return fmt.Errorf("session is nil")
	}
	if strings.TrimSpace(sess.User) == "" || strings.TrimSpace(sess.Host) == "" {
		return fmt.Errorf("session.user and session.host are required")
	}
	if strings.TrimSpace(sess.Engagement) == "" {
		sess.Engagement = "default"
	}

	if sess.ID == "" {
		sess.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	now := time.Now().UTC()
	if sess.FirstSeen.IsZero() {
		sess.FirstSeen = now
	}
	if sess.LastSeen.IsZero() {
		sess.LastSeen = now
	}

	dir := s.engagementDir(sess.Engagement)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := s.sessionFile(sess.Engagement, sess.ID)

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(sess)
}

// List returns all sessions for an engagement. If engagement is empty,
// it uses "default".
func (s *Store) List(engagement string) ([]*model.Session, error) {
	if strings.TrimSpace(engagement) == "" {
		engagement = "default"
	}
	dir := s.engagementDir(engagement)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*model.Session{}, nil
		}
		return nil, err
	}

	out := make([]*model.Session, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		var sess model.Session
		if err := json.NewDecoder(f).Decode(&sess); err == nil {
			out = append(out, &sess)
		}
		f.Close()
	}
	return out, nil
}
