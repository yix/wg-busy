package handlers

import (
	"fmt"
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

// GetServerConfig returns the server settings data.
func (h *handler) GetServerConfig(w http.ResponseWriter, r *http.Request) {
	var data serverFormData
	h.store.Read(func(cfg *models.AppConfig) {
		data.Server = cfg.Server
	})

	writePageJSON(w, http.StatusOK, "server-config", data, nil)
}

// UpdateServerConfig handles PUT /server.
func (h *handler) UpdateServerConfig(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writePageError(w, http.StatusBadRequest, fmt.Errorf("bad request"))
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
		// Capture what was submitted before validating: the store rolls its copy
		// back on error, and the form has to show the user their own input.
		data.Server = cfg.Server

		if errs := cfg.Server.Validate(); len(errs) > 0 {
			return errs
		}

		return nil
	})

	if writeErr != nil {
		logRejected(r, writeErr)
		if ve, ok := writeErr.(models.ValidationErrors); ok {
			data.ValidationErrors = ve
			writePageJSON(w, http.StatusUnprocessableEntity, "server-config", data, nil)
			return
		} else if _, ok := applyError(writeErr); ok {
			data.Error = writeErr.Error()
		} else {
			data.Error = writeErr.Error()
			writePageJSON(w, http.StatusInternalServerError, "server-config", data, nil)
			return
		}
		writePageJSON(w, http.StatusOK, "server-config", data, nil)
		return
	}

	data.Success = "Configuration saved successfully."
	writePageJSON(w, http.StatusOK, "server-config", data, nil)
}
