package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/yix/wg-busy/internal/auth"
	"github.com/yix/wg-busy/internal/models"
)

type authStatusResponse struct {
	RequirePasskey bool `json:"requirePasskey"`
	HasPasskeys    bool `json:"hasPasskeys"`
	PasskeyCount   int  `json:"passkeyCount"`
	Authenticated  bool `json:"authenticated"`
}

// GetAuthStatus handles GET /api/auth/status.
func (h *handler) GetAuthStatus(w http.ResponseWriter, r *http.Request) {
	var resp authStatusResponse
	h.store.Read(func(cfg *models.AppConfig) {
		resp.RequirePasskey = cfg.Server.RequirePasskey
		resp.PasskeyCount = len(cfg.Server.Passkeys)
		resp.HasPasskeys = resp.PasskeyCount > 0
	})

	resp.Authenticated = h.sessions.ValidateSession(r)
	if !resp.RequirePasskey || !resp.HasPasskeys {
		// If auth is not enforced, consider session naturally authenticated
		resp.Authenticated = true
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

// getRPID extracts the relying party hostname from r.Host.
func getRPID(r *http.Request) string {
	host := r.Host
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(host)
		if err == nil {
			host = h
		}
	}
	if host == "" {
		return "localhost"
	}
	return host
}

// BeginLogin handles POST /api/auth/login/begin.
func (h *handler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	var passkeys []models.Passkey
	h.store.Read(func(cfg *models.AppConfig) {
		passkeys = append([]models.Passkey(nil), cfg.Server.Passkeys...)
	})

	if len(passkeys) == 0 {
		http.Error(w, "no passkeys registered", http.StatusBadRequest)
		return
	}

	rpID := getRPID(r)
	opts, err := h.webauthn.BeginLogin(rpID, passkeys)
	if err != nil {
		http.Error(w, fmt.Sprintf("initiating login: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(opts)
}

// FinishLogin handles POST /api/auth/login/finish.
func (h *handler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	var req auth.AuthenticationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request payload", http.StatusBadRequest)
		return
	}

	var passkeys []models.Passkey
	h.store.Read(func(cfg *models.AppConfig) {
		passkeys = append([]models.Passkey(nil), cfg.Server.Passkeys...)
	})

	updatedPasskey, err := h.webauthn.FinishLogin(passkeys, req)
	if err != nil {
		logRejected(r, err)
		http.Error(w, fmt.Sprintf("authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Update passkey signCount & lastUsedAt in configuration
	_ = h.store.Write(func(cfg *models.AppConfig) error {
		for i := range cfg.Server.Passkeys {
			if cfg.Server.Passkeys[i].ID == updatedPasskey.ID {
				cfg.Server.Passkeys[i].SignCount = updatedPasskey.SignCount
				cfg.Server.Passkeys[i].LastUsedAt = updatedPasskey.LastUsedAt
				break
			}
		}
		return nil
	})

	// Create authenticated session
	h.sessions.CreateSession(w)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Authenticated successfully",
	})
}

// Logout handles POST /api/auth/logout.
func (h *handler) Logout(w http.ResponseWriter, r *http.Request) {
	h.sessions.ClearSession(w, r)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

// BeginPasskeyRegistration handles POST /api/auth/passkeys/begin.
func (h *handler) BeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	var requirePasskey bool
	var hasPasskeys bool
	h.store.Read(func(cfg *models.AppConfig) {
		requirePasskey = cfg.Server.RequirePasskey
		hasPasskeys = len(cfg.Server.Passkeys) > 0
	})

	// If passkey auth is required and passkeys exist, user must be logged in to add more
	if requirePasskey && hasPasskeys && !h.sessions.ValidateSession(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rpID := getRPID(r)
	opts, err := h.webauthn.BeginRegistration(rpID, "WG Busy")
	if err != nil {
		http.Error(w, fmt.Sprintf("initiating passkey registration: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(opts)
}

// FinishPasskeyRegistration handles POST /api/auth/passkeys/finish.
func (h *handler) FinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	var requirePasskey bool
	var hasPasskeys bool
	h.store.Read(func(cfg *models.AppConfig) {
		requirePasskey = cfg.Server.RequirePasskey
		hasPasskeys = len(cfg.Server.Passkeys) > 0
	})

	if requirePasskey && hasPasskeys && !h.sessions.ValidateSession(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req auth.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request payload", http.StatusBadRequest)
		return
	}

	passkey, err := h.webauthn.FinishRegistration(req)
	if err != nil {
		logRejected(r, err)
		http.Error(w, fmt.Sprintf("passkey registration failed: %v", err), http.StatusBadRequest)
		return
	}

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		// Check for duplicate ID
		for _, existing := range cfg.Server.Passkeys {
			if existing.ID == passkey.ID {
				return fmt.Errorf("passkey is already registered")
			}
		}
		cfg.Server.Passkeys = append(cfg.Server.Passkeys, *passkey)
		return nil
	})

	if writeErr != nil {
		if _, isApply := applyError(writeErr); !isApply {
			logRejected(r, writeErr)
			http.Error(w, fmt.Sprintf("saving passkey: %v", writeErr), http.StatusInternalServerError)
			return
		}
	}

	// If this was added, establish authenticated session for the current user
	h.sessions.CreateSession(w)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"passkey": passkey,
	})
}

// DeletePasskey handles DELETE /api/auth/passkeys/{id}.
func (h *handler) DeletePasskey(w http.ResponseWriter, r *http.Request) {
	var requirePasskey bool
	var hasPasskeys bool
	h.store.Read(func(cfg *models.AppConfig) {
		requirePasskey = cfg.Server.RequirePasskey
		hasPasskeys = len(cfg.Server.Passkeys) > 0
	})

	if requirePasskey && hasPasskeys && !h.sessions.ValidateSession(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing passkey ID", http.StatusBadRequest)
		return
	}

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		var filtered []models.Passkey
		found := false
		for _, p := range cfg.Server.Passkeys {
			if p.ID == id {
				found = true
				continue
			}
			filtered = append(filtered, p)
		}
		if !found {
			return fmt.Errorf("passkey not found")
		}
		cfg.Server.Passkeys = filtered
		// If no passkeys remain, disable requirePasskey to prevent lockout
		if len(cfg.Server.Passkeys) == 0 {
			cfg.Server.RequirePasskey = false
		}
		return nil
	})

	if writeErr != nil {
		if _, isApply := applyError(writeErr); !isApply {
			logRejected(r, writeErr)
			http.Error(w, writeErr.Error(), http.StatusNotFound)
			return
		}
	}

	// If requested via HTMX from server tab, return updated server config tab
	if r.Header.Get("HX-Request") == "true" {
		h.GetServerConfig(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}
