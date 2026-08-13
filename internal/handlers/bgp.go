package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yix/wg-busy/internal/bgp"
	"github.com/yix/wg-busy/internal/models"
)

// bgpTabData is the template data for the BGP tab: live session stats plus the
// configured standalone (non-WireGuard) BGP peers.
type bgpTabData struct {
	*models.BGPStats
	CustomPeers bgpCustomPeersData
}

// GetBGPStatsTab renders the HTML partial for the BGP statistics.
func (h *handler) GetBGPStatsTab(w http.ResponseWriter, r *http.Request) {
	data := bgpTabData{BGPStats: bgp.GetBGPStats()}
	h.store.Read(func(cfg *models.AppConfig) {
		data.CustomPeers.Peers = cfg.BGPPeers
	})
	if err := templates.ExecuteTemplate(w, "bgp-stats", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// bgpPeerFormData is the template data for the custom BGP peer create/edit form.
type bgpPeerFormData struct {
	IsNew bool
	// Defaults renders a blank form with default values checked, mirroring the
	// WireGuard peer form's behavior.
	Defaults         bool
	Peer             models.BGPPeer
	Error            string
	ValidationErrors models.ValidationErrors
}

// GetBGPPeerForm returns the custom BGP peer create or edit form dialog.
func (h *handler) GetBGPPeerForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	isNew := id == ""

	data := bgpPeerFormData{IsNew: isNew, Defaults: isNew}

	if !isNew {
		h.store.Read(func(cfg *models.AppConfig) {
			if p := models.FindBGPPeerByID(cfg.BGPPeers, id); p != nil {
				data.Peer = *p
			}
		})
		if data.Peer.ID == "" {
			http.Error(w, "BGP peer not found", http.StatusNotFound)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "bgp-peer-form", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// CreateBGPPeer handles POST /bgp/peers.
func (h *handler) CreateBGPPeer(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	id, err := newPeerID()
	if err != nil {
		http.Error(w, fmt.Sprintf("ID generation failed: %v", err), http.StatusInternalServerError)
		return
	}

	_, bgpConnect, bgpPeerIP, bgpPeerPort, bgpPeerASN, bgpRouteFilters, bgpExportFilters := parsePeerBGPForm(r)

	now := time.Now().UTC()
	peer := models.BGPPeer{
		ID:            id,
		Name:          strings.TrimSpace(r.FormValue("name")),
		Enabled:       r.FormValue("enabled") == "on",
		Connect:       bgpConnect,
		PeerIP:        bgpPeerIP,
		PeerPort:      bgpPeerPort,
		PeerASN:       bgpPeerASN,
		RouteFilters:  bgpRouteFilters,
		ExportFilters: bgpExportFilters,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		if errs := peer.Validate(); len(errs) > 0 {
			return errs
		}
		cfg.BGPPeers = append(cfg.BGPPeers, peer)
		return nil
	})

	if writeErr != nil {
		logRejected(r, writeErr)
		if renderApplyWarning(w, writeErr) {
			h.listBGPPeersOOB(w, r)
			return
		}
		h.renderBGPPeerFormError(w, bgpPeerFormData{IsNew: true, Peer: peer}, writeErr)
		return
	}

	h.listBGPPeersOOB(w, r)
}

// UpdateBGPPeer handles PUT /bgp/peers/{id}.
func (h *handler) UpdateBGPPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	_, bgpConnect, bgpPeerIP, bgpPeerPort, bgpPeerASN, bgpRouteFilters, bgpExportFilters := parsePeerBGPForm(r)

	var submitted models.BGPPeer

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		p := models.FindBGPPeerByID(cfg.BGPPeers, id)
		if p == nil {
			return fmt.Errorf("BGP peer not found")
		}

		p.Name = strings.TrimSpace(r.FormValue("name"))
		p.Enabled = r.FormValue("enabled") == "on"
		p.Connect = bgpConnect
		p.PeerIP = bgpPeerIP
		p.PeerPort = bgpPeerPort
		p.PeerASN = bgpPeerASN
		p.RouteFilters = bgpRouteFilters
		p.ExportFilters = bgpExportFilters
		p.UpdatedAt = time.Now().UTC()

		if errs := p.Validate(); len(errs) > 0 {
			submitted = *p
			return errs
		}

		submitted = *p
		return nil
	})

	if writeErr != nil {
		logRejected(r, writeErr)
		if renderApplyWarning(w, writeErr) {
			h.listBGPPeersOOB(w, r)
			return
		}
		if _, ok := writeErr.(models.ValidationErrors); !ok {
			http.Error(w, writeErr.Error(), http.StatusInternalServerError)
			return
		}
		h.renderBGPPeerFormError(w, bgpPeerFormData{Peer: submitted}, writeErr)
		return
	}

	h.listBGPPeersOOB(w, r)
}

// DeleteBGPPeer handles DELETE /bgp/peers/{id}.
func (h *handler) DeleteBGPPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	err := h.store.Write(func(cfg *models.AppConfig) error {
		idx := -1
		for i, p := range cfg.BGPPeers {
			if p.ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			return fmt.Errorf("BGP peer not found")
		}
		cfg.BGPPeers = append(cfg.BGPPeers[:idx], cfg.BGPPeers[idx+1:]...)
		return nil
	})

	if err != nil {
		if !renderApplyWarning(w, err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	h.GetBGPStatsTab(w, r)
}

// renderBGPPeerFormError re-renders the form with the rejected input still in it.
func (h *handler) renderBGPPeerFormError(w http.ResponseWriter, data bgpPeerFormData, writeErr error) {
	if ve, ok := writeErr.(models.ValidationErrors); ok {
		data.ValidationErrors = ve
	} else {
		data.Error = writeErr.Error()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = templates.ExecuteTemplate(w, "bgp-peer-form", data)
}

func (h *handler) listBGPPeersOOB(w http.ResponseWriter, r *http.Request) {
	var peers []models.BGPPeer
	h.store.Read(func(cfg *models.AppConfig) {
		peers = cfg.BGPPeers
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "bgp-custom-peers", bgpCustomPeersData{Peers: peers, OOB: true}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// bgpCustomPeersData is the template data for the custom BGP peers list section.
type bgpCustomPeersData struct {
	Peers []models.BGPPeer
	OOB   bool
}
