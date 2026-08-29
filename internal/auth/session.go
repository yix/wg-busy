package auth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

const (
	// SessionCookieName is the name of the HTTP session cookie.
	SessionCookieName = "wg_busy_session"
	// SessionDuration is how long a session remains valid.
	SessionDuration = 7 * 24 * time.Hour
	// ChallengeTTL is how long a WebAuthn challenge remains valid.
	ChallengeTTL = 5 * time.Minute
)

// Session represents an active authenticated session.
type Session struct {
	CreatedAt time.Time
	ExpiresAt time.Time
}

// SessionManager manages active user sessions and session cookies.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]Session),
	}
}

// CreateSession generates a new session token, records it, and sets the cookie on w.
func (sm *SessionManager) CreateSession(w http.ResponseWriter) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)

	now := time.Now().UTC()
	session := Session{
		CreatedAt: now,
		ExpiresAt: now.Add(SessionDuration),
	}

	sm.mu.Lock()
	sm.sessions[token] = session
	sm.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  session.ExpiresAt,
		MaxAge:   int(SessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return token
}

// ValidateSession returns true if the request contains a valid, unexpired session cookie.
func (sm *SessionManager) ValidateSession(r *http.Request) bool {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	sm.mu.RLock()
	session, exists := sm.sessions[cookie.Value]
	sm.mu.RUnlock()

	if !exists {
		return false
	}

	if time.Now().UTC().After(session.ExpiresAt) {
		sm.mu.Lock()
		delete(sm.sessions, cookie.Value)
		sm.mu.Unlock()
		return false
	}

	return true
}

// ClearSession clears the session cookie and revokes the session.
func (sm *SessionManager) ClearSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		sm.mu.Lock()
		delete(sm.sessions, cookie.Value)
		sm.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ChallengeStore manages temporary WebAuthn ceremony challenges.
type ChallengeStore struct {
	mu         sync.RWMutex
	challenges map[string]time.Time
}

// NewChallengeStore creates a new ChallengeStore.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{
		challenges: make(map[string]time.Time),
	}
}

// GenerateChallenge creates, saves, and returns a new random base64url challenge string.
func (cs *ChallengeStore) GenerateChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	challenge := base64.RawURLEncoding.EncodeToString(b)

	cs.mu.Lock()
	// Periodic prune of expired challenges
	now := time.Now().UTC()
	for k, exp := range cs.challenges {
		if now.After(exp) {
			delete(cs.challenges, k)
		}
	}
	cs.challenges[challenge] = now.Add(ChallengeTTL)
	cs.mu.Unlock()

	return challenge, nil
}

// VerifyAndConsume checks if challenge exists and is valid, and consumes it.
func (cs *ChallengeStore) VerifyAndConsume(challenge string) bool {
	if challenge == "" {
		return false
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	exp, exists := cs.challenges[challenge]
	if !exists {
		return false
	}

	delete(cs.challenges, challenge)
	return time.Now().UTC().Before(exp)
}
