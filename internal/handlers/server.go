package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/yix/wg-busy/internal/models"
)

// serverFormData is the template data for the server config form.
type serverFormData struct {
	Server           models.ServerConfig
	Success          string
	Error            string
	ValidationErrors models.ValidationErrors
}

// GetServerConfig returns the server settings form HTML fragment.
func (h *handler) GetServerConfig(w http.ResponseWriter, r *http.Request) {
	var data serverFormData
	h.store.Read(func(cfg *models.AppConfig) {
		data.Server = cfg.Server
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "server-config", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// UpdateServerConfig handles PUT /server.
func (h *handler) UpdateServerConfig(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	port, _ := strconv.ParseUint(r.FormValue("listenPort"), 10, 16)
	mtu, _ := strconv.ParseUint(r.FormValue("mtu"), 10, 16)

	var data serverFormData

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		cfg.Server.ListenPort = uint16(port)
		cfg.Server.Address = strings.TrimSpace(r.FormValue("address"))
		cfg.Server.Endpoint = strings.TrimSpace(r.FormValue("endpoint"))
		cfg.Server.DNS = strings.TrimSpace(r.FormValue("dns"))
		cfg.Server.MTU = uint16(mtu)
		cfg.Server.Table = strings.TrimSpace(r.FormValue("table"))
		cfg.Server.FwMark = strings.TrimSpace(r.FormValue("fwMark"))
		cfg.Server.PreUp = r.FormValue("preUp")
		cfg.Server.PostUp = r.FormValue("postUp")
		cfg.Server.PreDown = r.FormValue("preDown")
		cfg.Server.PostDown = r.FormValue("postDown")
		cfg.Server.SaveConfig = r.FormValue("saveConfig") == "on"

		if errs := cfg.Server.Validate(); len(errs) > 0 {
			return errs
		}

		data.Server = cfg.Server
		return nil
	})

	if writeErr != nil {
		if ve, ok := writeErr.(models.ValidationErrors); ok {
			data.ValidationErrors = ve
			h.store.Read(func(cfg *models.AppConfig) {
				data.Server = cfg.Server
			})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = templates.ExecuteTemplate(w, "server-config", data)
			return
		}
		data.Error = writeErr.Error()
		h.store.Read(func(cfg *models.AppConfig) {
			data.Server = cfg.Server
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = templates.ExecuteTemplate(w, "server-config", data)
		return
	}

	data.Success = "Configuration saved successfully."
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = templates.ExecuteTemplate(w, "server-config", data)
}
