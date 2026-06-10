// Package shortcuts persists named one-click shell commands for the WebSSH
// console. A shortcut is just a label plus the command text typed at the prompt
// when it runs. They live in a single JSON file on the machine, alongside the
// passkey store and TLS material, so they survive restarts and are shared by
// every browser that signs in over the tunnel.
//
// The console lists them, lets you add/edit/delete them, and "runs" one by
// opening a fresh terminal tab that types the command at the prompt — see
// web/console.js (the management UI) and web/app.js (the ?run= auto-typer).
// This package owns only storage + validation and the HTTP handlers behind the
// passkey gate; it never executes anything itself.
package shortcuts

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	maxName    = 200  // generous label cap
	maxCommand = 8192 // a command may be a small multi-line script
	maxItems   = 200  // backstop so the file cannot grow without bound
)

// Shortcut is a single stored command: a human label and the shell text typed
// at the prompt when it is run. ID is server-minted and stable across edits.
type Shortcut struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Command string `json:"command"`
}

// ValidationError marks a client-correctable problem (missing/oversized fields,
// limit exceeded) so the HTTP layer can answer 400 rather than 500.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalid(msg string) error { return &ValidationError{msg} }

// Store is the persistent collection of shortcuts, guarded by a mutex and
// mirrored to a JSON file on every change.
type Store struct {
	path  string
	mu    sync.Mutex
	items []Shortcut
}

// New loads the shortcuts file at path (treating a missing file as an empty
// set) and returns a ready Store. A malformed file is surfaced as an error
// rather than silently discarded, so a typo never wipes saved commands.
func New(path string) (*Store, error) {
	s := &Store{path: path, items: []Shortcut{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var items []Shortcut
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	if items != nil {
		s.items = items
	}
	return s, nil
}

// save writes the current items to disk. Callers hold s.mu.
func (s *Store) save() error {
	data, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

// List returns a copy of the stored shortcuts in insertion order.
func (s *Store) List() []Shortcut {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Shortcut, len(s.items))
	copy(out, s.items)
	return out
}

// normalize trims and validates the user-supplied fields, returning a cleaned
// copy or a ValidationError describing what is wrong. The command keeps its
// internal whitespace (it may be a multi-line script) but loses surrounding
// blank lines and spaces.
func normalize(sc Shortcut) (Shortcut, error) {
	sc.Name = strings.TrimSpace(sc.Name)
	sc.Command = strings.TrimSpace(sc.Command)
	switch {
	case sc.Name == "":
		return sc, invalid("name is required")
	case sc.Command == "":
		return sc, invalid("command is required")
	case len(sc.Name) > maxName:
		return sc, invalid("name is too long")
	case len(sc.Command) > maxCommand:
		return sc, invalid("command is too long")
	}
	return sc, nil
}

// Upsert validates sc and either updates the existing shortcut with the same ID
// or, when the ID is empty or unknown, appends a new one with a freshly minted
// ID. It returns the stored shortcut (including its ID) and persists the change.
// IDs are always server-controlled, so a caller-supplied ID that matches nothing
// is ignored rather than honored.
func (s *Store) Upsert(sc Shortcut) (Shortcut, error) {
	clean, err := normalize(sc)
	if err != nil {
		return Shortcut{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if clean.ID != "" {
		for i := range s.items {
			if s.items[i].ID == clean.ID {
				prev := s.items[i]
				s.items[i].Name, s.items[i].Command = clean.Name, clean.Command
				if err := s.save(); err != nil {
					s.items[i] = prev // keep memory and disk in step
					return Shortcut{}, err
				}
				return s.items[i], nil
			}
		}
	}

	if len(s.items) >= maxItems {
		return Shortcut{}, invalid("too many shortcuts")
	}
	clean.ID = newID()
	s.items = append(s.items, clean)
	if err := s.save(); err != nil {
		s.items = s.items[:len(s.items)-1] // roll back the append
		return Shortcut{}, err
	}
	return clean, nil
}

// Delete removes the shortcut with the given ID, persisting the change, and
// reports whether one was found.
func (s *Store) Delete(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i := range s.items {
		if s.items[i].ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return false, nil
	}
	old := s.items
	next := make([]Shortcut, 0, len(s.items)-1)
	next = append(next, s.items[:idx]...)
	next = append(next, s.items[idx+1:]...)
	s.items = next
	if err := s.save(); err != nil {
		s.items = old // restore on write failure
		return false, err
	}
	return true, nil
}

// newID returns a short, unguessable, URL-safe identifier for a shortcut.
func newID() string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- HTTP handlers (mounted behind the passkey gate in package webssh) ---

// Handle serves /api/shortcuts: GET lists every shortcut, POST creates or
// updates one from a JSON body ({id?, name, command}).
func (s *Store) Handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"shortcuts": s.List()})
	case http.MethodPost:
		var sc Shortcut
		if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		saved, err := s.Upsert(sc)
		if err != nil {
			writeUpsertError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"shortcut": saved})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleDelete removes the shortcut named in the JSON body ({"id":"…"}) on
// /api/shortcuts/delete.
func (s *Store) HandleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "missing shortcut id", http.StatusBadRequest)
		return
	}
	deleted, err := s.Delete(req.ID)
	if err != nil {
		http.Error(w, "failed to save shortcuts", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": deleted})
}

// writeUpsertError maps a bad field/limit (client's fault) to 400 and a disk
// write failure (server's fault) to 500.
func writeUpsertError(w http.ResponseWriter, err error) {
	var ve *ValidationError
	if errors.As(err, &ve) {
		http.Error(w, ve.Error(), http.StatusBadRequest)
		return
	}
	http.Error(w, "failed to save shortcut", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
