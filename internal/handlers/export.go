package handlers

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/routing"
	"github.com/yix/wg-busy/internal/wireguard"
)

// DownloadClientConfig handles GET /api/peers/{id}/config.
func (h *handler) DownloadClientConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var content string
	var filename string
	var genErr error

	h.store.Read(func(cfg *models.AppConfig) {
		peer := models.FindPeerByID(cfg.Peers, id)
		if peer == nil {
			genErr = fmt.Errorf("peer not found")
			return
		}

		content, genErr = wireguard.RenderClientConfig(cfg.Server, *peer)
		if genErr != nil {
			return
		}

		// Sanitize name for filename.
		name := strings.ReplaceAll(peer.Name, " ", "-")
		name = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				return r
			}
			return -1
		}, name)
		if name == "" {
			name = peer.ID
		}
		filename = name + ".conf"
	})

	if genErr != nil {
		http.Error(w, genErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Write([]byte(content))
}

// DownloadServerConfig handles GET /api/server/config.
func (h *handler) DownloadServerConfig(w http.ResponseWriter, r *http.Request) {
	var content string
	var genErr error

	h.store.Read(func(cfg *models.AppConfig) {
		postUpCmds := routing.GeneratePostUpCommands(*cfg)
		postDownCmds := routing.GeneratePostDownCommands(*cfg)
		content, genErr = wireguard.RenderServerConfig(*cfg, postUpCmds, postDownCmds)
	})

	if genErr != nil {
		http.Error(w, genErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="wg0.conf"`)
	w.Write([]byte(content))
}

// ApplyConfig handles POST /api/server/apply.
func (h *handler) ApplyConfig(w http.ResponseWriter, r *http.Request) {
	// wg0.conf is already on disk (written on every save).
	// Just restart the interface.
	cmd := exec.Command("sh", "-c", "wg-quick down wg0 2>/dev/null; wg-quick up wg0")
	output, err := cmd.CombinedOutput()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err != nil {
		msg := fmt.Sprintf("Failed to apply config: %v\n%s", err, string(output))
		templates.ExecuteTemplate(w, "toast-error", msg)
		return
	}

	// Reset uptime tracking on successful restart.
	if h.stats != nil {
		h.stats.SetStartedAt(time.Now())
	}

	templates.ExecuteTemplate(w, "toast-success", "WireGuard configuration applied successfully.")
}
