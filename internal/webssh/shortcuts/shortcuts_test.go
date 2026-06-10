package shortcuts

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUpsertPersistsAndReloads covers the core round trip: a created shortcut
// gets a server-minted ID, lands on disk, and survives a reload by a fresh
// Store. Editing it by ID then mutates in place rather than appending.
func TestUpsertPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shortcuts.json")
	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	saved, err := s.Upsert(Shortcut{Name: "  Git pull  ", Command: "  git pull  "})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if saved.ID == "" {
		t.Fatal("expected a minted ID")
	}
	if saved.Name != "Git pull" || saved.Command != "git pull" {
		t.Errorf("fields not trimmed: %+v", saved)
	}

	// A second Store loading the same file must see the persisted shortcut.
	reloaded, err := New(path)
	if err != nil {
		t.Fatalf("reload New: %v", err)
	}
	got := reloaded.List()
	if len(got) != 1 || got[0] != saved {
		t.Fatalf("reloaded = %+v, want [%+v]", got, saved)
	}

	// Editing by ID updates in place and keeps the same ID.
	edited, err := reloaded.Upsert(Shortcut{ID: saved.ID, Name: "Pull", Command: "git pull --rebase"})
	if err != nil {
		t.Fatalf("edit Upsert: %v", err)
	}
	if edited.ID != saved.ID {
		t.Errorf("edit changed ID: %q -> %q", saved.ID, edited.ID)
	}
	if list := reloaded.List(); len(list) != 1 || list[0].Command != "git pull --rebase" {
		t.Errorf("edit did not update in place: %+v", list)
	}
}

func TestDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shortcuts.json")
	s, _ := New(path)
	a, _ := s.Upsert(Shortcut{Name: "a", Command: "echo a"})
	b, _ := s.Upsert(Shortcut{Name: "b", Command: "echo b"})

	if ok, err := s.Delete(a.ID); err != nil || !ok {
		t.Fatalf("Delete(a) = %v, %v; want true, nil", ok, err)
	}
	if ok, _ := s.Delete("nope"); ok {
		t.Error("Delete(unknown) = true, want false")
	}
	list := s.List()
	if len(list) != 1 || list[0].ID != b.ID {
		t.Fatalf("after delete list = %+v, want only b", list)
	}

	// The deletion must be durable.
	reloaded, _ := New(path)
	if list := reloaded.List(); len(list) != 1 || list[0].ID != b.ID {
		t.Errorf("delete not persisted: %+v", list)
	}
}

func TestUpsertValidation(t *testing.T) {
	s, _ := New(filepath.Join(t.TempDir(), "shortcuts.json"))
	cases := []struct {
		name string
		in   Shortcut
	}{
		{"empty name", Shortcut{Name: "   ", Command: "ls"}},
		{"empty command", Shortcut{Name: "ls", Command: "  "}},
		{"name too long", Shortcut{Name: strings.Repeat("x", maxName+1), Command: "ls"}},
		{"command too long", Shortcut{Name: "big", Command: strings.Repeat("x", maxCommand+1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Upsert(tc.in)
			var ve *ValidationError
			if err == nil || !asValidation(err, &ve) {
				t.Fatalf("Upsert(%+v) err = %v, want ValidationError", tc.in, err)
			}
		})
	}
	if got := s.List(); len(got) != 0 {
		t.Errorf("invalid upserts were stored: %+v", got)
	}
}

func TestNewRejectsMalformedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shortcuts.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Error("New on malformed file = nil error, want failure (do not discard saved data)")
	}
}

// TestHTTP exercises the handler surface end to end: list, create, the minted
// shortcut showing up in a follow-up list, a validation 400, and delete.
func TestHTTP(t *testing.T) {
	s, _ := New(filepath.Join(t.TempDir(), "shortcuts.json"))

	// Create.
	rec := httptest.NewRecorder()
	s.Handle(rec, jsonReq(t, http.MethodPost, `{"name":"List","command":"ls -la"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		Shortcut Shortcut `json:"shortcut"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.Shortcut.ID == "" {
		t.Fatal("create did not return an ID")
	}

	// List shows it.
	rec = httptest.NewRecorder()
	s.Handle(rec, httptest.NewRequest(http.MethodGet, "/api/shortcuts", nil))
	var listed struct {
		Shortcuts []Shortcut `json:"shortcuts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Shortcuts) != 1 || listed.Shortcuts[0].ID != created.Shortcut.ID {
		t.Fatalf("list = %+v, want the created shortcut", listed.Shortcuts)
	}

	// A bad create is a 400, not a 500.
	rec = httptest.NewRecorder()
	s.Handle(rec, jsonReq(t, http.MethodPost, `{"name":"","command":"x"}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid create status = %d, want 400", rec.Code)
	}

	// Delete it.
	rec = httptest.NewRecorder()
	s.HandleDelete(rec, jsonReq(t, http.MethodPost, `{"id":"`+created.Shortcut.ID+`"}`))
	var del struct {
		Deleted bool `json:"deleted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &del); err != nil {
		t.Fatalf("decode delete: %v", err)
	}
	if !del.Deleted {
		t.Error("delete reported deleted=false")
	}
}

func jsonReq(t *testing.T, method, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, "/api/shortcuts", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// asValidation is errors.As specialized for *ValidationError, kept tiny so the
// test reads cleanly.
func asValidation(err error, target **ValidationError) bool {
	for err != nil {
		if ve, ok := err.(*ValidationError); ok {
			*target = ve
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
