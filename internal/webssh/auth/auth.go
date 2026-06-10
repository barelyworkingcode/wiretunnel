// Package auth implements passkey (WebAuthn) enrollment and sign-in, plus the
// server-side session that gates the terminal websocket. State is a single
// user record (possibly holding several passkeys) persisted as JSON.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	flowCookie    = "webssh_flow"
	sessionCookie = "webssh_session"
	flowTTL       = 5 * time.Minute
	sessionTTL    = 12 * time.Hour
)

// User is the single account this server protects. It satisfies
// webauthn.User. Multiple passkeys (e.g. several devices) attach to it.
type User struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	DisplayName string                `json:"displayName"`
	Creds       []webauthn.Credential `json:"credentials"`
}

func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *User) WebAuthnIcon() string                       { return "" }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Creds }

type flow struct {
	session *webauthn.SessionData
	user    *User
	expires time.Time
}

// Manager owns the credential store and the in-memory session state.
type Manager struct {
	wa        *webauthn.WebAuthn
	storePath string
	secure    bool // mark cookies Secure (server is serving HTTPS)

	mu       sync.Mutex
	user     *User // nil until first enrollment
	flows    map[string]*flow
	sessions map[string]time.Time
}

// New constructs a Manager, loading any previously enrolled passkey. secure
// marks issued cookies Secure (set when the server is serving HTTPS).
func New(rpID string, origins []string, storePath string, secure bool) (*Manager, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "WebSSH",
		RPID:          rpID,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, err
	}
	m := &Manager{
		wa:        wa,
		storePath: storePath,
		secure:    secure,
		flows:     make(map[string]*flow),
		sessions:  make(map[string]time.Time),
	}
	m.load()
	return m, nil
}

func (m *Manager) load() {
	data, err := os.ReadFile(m.storePath)
	if err != nil {
		return
	}
	var u User
	if json.Unmarshal(data, &u) == nil && len(u.ID) > 0 {
		m.user = &u
	}
}

func (m *Manager) save() error {
	if m.user == nil {
		return nil
	}
	data, err := json.MarshalIndent(m.user, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.storePath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(m.storePath, data, 0o600)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func token() string {
	return base64.RawURLEncoding.EncodeToString(randBytes(32))
}

// --- session helpers ---

func (m *Manager) authenticated(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.sessions[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(m.sessions, c.Value)
		return false
	}
	return true
}

func (m *Manager) startSession(w http.ResponseWriter) {
	t := token()
	m.mu.Lock()
	// Opportunistically evict expired sessions so the map cannot grow unbounded
	// across logins (entries are otherwise only pruned when re-presented).
	now := time.Now()
	for k, exp := range m.sessions {
		if now.After(exp) {
			delete(m.sessions, k)
		}
	}
	m.sessions[t] = now.Add(sessionTTL)
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    t,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func (m *Manager) setFlow(w http.ResponseWriter, f *flow) {
	id := token()
	f.expires = time.Now().Add(flowTTL)
	m.mu.Lock()
	// Opportunistically evict expired flows so the map cannot grow unbounded.
	now := time.Now()
	for k, v := range m.flows {
		if now.After(v.expires) {
			delete(m.flows, k)
		}
	}
	m.flows[id] = f
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(flowTTL.Seconds()),
	})
}

func (m *Manager) takeFlow(r *http.Request) *flow {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.flows[c.Value]
	delete(m.flows, c.Value)
	if f == nil || time.Now().After(f.expires) {
		return nil
	}
	return f
}

// --- HTTP handlers ---

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Status reports whether a passkey is enrolled and whether the caller holds a
// valid session, so the page knows which prompt to show.
func (m *Manager) Status(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	enrolled := m.user != nil
	m.mu.Unlock()
	writeJSON(w, map[string]bool{
		"enrolled":      enrolled,
		"authenticated": m.authenticated(r),
	})
}

// RegisterBegin starts passkey enrollment. It is allowed when no passkey
// exists yet (first visit) or when an already-enrolled user is signed in and
// wants to add another device.
func (m *Manager) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	enrolled := m.user != nil
	u := m.user
	m.mu.Unlock()

	if enrolled && !m.authenticated(r) {
		http.Error(w, "already enrolled; sign in required", http.StatusForbidden)
		return
	}
	if u == nil {
		u = &User{ID: randBytes(16), Name: "user", DisplayName: "WebSSH User"}
	}

	options, session, err := m.wa.BeginRegistration(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	m.setFlow(w, &flow{session: session, user: u})
	writeJSON(w, options)
}

// RegisterFinish verifies the attestation, persists the new passkey, and signs
// the caller in.
func (m *Manager) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	f := m.takeFlow(r)
	if f == nil {
		http.Error(w, "no registration in progress", http.StatusBadRequest)
		return
	}
	cred, err := m.wa.FinishRegistration(f.user, *f.session, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	f.user.Creds = append(f.user.Creds, *cred)
	m.user = f.user
	err = m.save()
	m.mu.Unlock()
	if err != nil {
		http.Error(w, "failed to persist credential", http.StatusInternalServerError)
		return
	}
	m.startSession(w)
	writeJSON(w, map[string]bool{"ok": true})
}

// LoginBegin starts a passkey assertion for the enrolled user.
func (m *Manager) LoginBegin(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	u := m.user
	m.mu.Unlock()
	if u == nil {
		http.Error(w, "no passkey enrolled", http.StatusBadRequest)
		return
	}
	options, session, err := m.wa.BeginLogin(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	m.setFlow(w, &flow{session: session, user: u})
	writeJSON(w, options)
}

// LoginFinish verifies the assertion, updates the credential sign counter, and
// starts a session.
func (m *Manager) LoginFinish(w http.ResponseWriter, r *http.Request) {
	f := m.takeFlow(r)
	if f == nil {
		http.Error(w, "no sign-in in progress", http.StatusBadRequest)
		return
	}
	cred, err := m.wa.FinishLogin(f.user, *f.session, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	// Persist the updated sign counter to detect cloned authenticators.
	for i := range f.user.Creds {
		if string(f.user.Creds[i].ID) == string(cred.ID) {
			f.user.Creds[i] = *cred
			break
		}
	}
	_ = m.save()
	m.mu.Unlock()
	m.startSession(w)
	writeJSON(w, map[string]bool{"ok": true})
}

// Logout clears the caller's session.
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		m.mu.Lock()
		delete(m.sessions, c.Value)
		m.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		MaxAge:   -1,
	})
	writeJSON(w, map[string]bool{"ok": true})
}

// Require wraps a handler so it only runs for authenticated callers.
func (m *Manager) Require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !m.authenticated(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
