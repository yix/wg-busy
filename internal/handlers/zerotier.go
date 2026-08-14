package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wgstats"
	"github.com/yix/wg-busy/internal/zerotier"
)

// ztNetworkRow is one joined network with its interface counters, for the template.
type ztNetworkRow struct {
	zerotier.NetworkStats
	Rx   string
	Tx   string
	RxPS string
	TxPS string
}

// ztPeerRow is one ZeroTier peer. ZeroTier reports no per-peer byte counters.
type ztPeerRow struct {
	zerotier.Peer
	LatencyText string
	PathText    string
}

// zerotierData is the template data for the ZeroTier tab.
type zerotierData struct {
	Config   models.ZeroTierConfig
	Port     uint16
	Snapshot zerotier.Snapshot
	Networks []ztNetworkRow
	Peers    []ztPeerRow
	// Addresses are this node's own ZeroTier IPs across all joined networks.
	Addresses []string
	// Pending are networks in the config the daemon has not joined, so a network
	// that never took effect is visible instead of just missing from the list.
	Pending          []models.ZeroTierNetwork
	Success          string
	Error            string
	ValidationErrors models.ValidationErrors
	Revision         uint64
}

func (h *handler) buildZeroTierData() zerotierData {
	var data zerotierData
	h.store.Read(func(cfg *models.AppConfig) {
		data.Config = cfg.ZeroTier
	})
	data.Port = data.Config.ZeroTierPort()

	if h.zt == nil {
		return data
	}

	snap, revision := h.zt.SnapshotVersion()
	data.Revision = revision
	data.Snapshot = snap

	for _, n := range snap.Networks {
		row := ztNetworkRow{
			NetworkStats: n,
			Rx:           wgstats.FormatBytes(n.Rx),
			Tx:           wgstats.FormatBytes(n.Tx),
		}
		if n.HasRate {
			row.RxPS = wgstats.FormatBytesPerSec(n.RxPS)
			row.TxPS = wgstats.FormatBytesPerSec(n.TxPS)
		}
		data.Networks = append(data.Networks, row)
		data.Addresses = append(data.Addresses, n.AssignedAddresses...)
	}

	// Configured networks the daemon does not report back: the join never took
	// effect (service degraded, still starting, or the ID does not exist).
	for _, want := range data.Config.Networks {
		joined := false
		for _, n := range snap.Networks {
			if strings.EqualFold(n.ID, want.ID) {
				joined = true
				break
			}
		}
		if !joined {
			data.Pending = append(data.Pending, want)
		}
	}

	for _, p := range snap.Peers {
		row := ztPeerRow{Peer: p, LatencyText: "—"}
		if p.Latency >= 0 {
			row.LatencyText = fmt.Sprintf("%d ms", p.Latency)
		}
		var paths []string
		for _, path := range p.Paths {
			if path.Active && !path.Expired {
				label := path.Address
				if path.Preferred {
					label += " (preferred)"
				}
				paths = append(paths, label)
			}
		}
		if len(paths) == 0 {
			row.PathText = "relayed"
		} else {
			row.PathText = strings.Join(paths, ", ")
		}
		data.Peers = append(data.Peers, row)
	}

	return data
}

// GetZeroTierTab handles GET /zerotier.
func (h *handler) GetZeroTierTab(w http.ResponseWriter, r *http.Request) {
	data := h.buildZeroTierData()
	writePageJSON(w, http.StatusOK, "zerotier-tab", data, nil)
}

// GetZeroTierStatus waits for a changed cached snapshot. A timed-out request
// returns no duplicate payload and tells htmx to open the next long poll.
func (h *handler) GetZeroTierStatus(w http.ResponseWriter, r *http.Request) {
	if h.zt != nil && r.URL.Query().Has("since") {
		revision, err := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		if err != nil {
			writePageError(w, http.StatusBadRequest, fmt.Errorf("invalid ZeroTier revision"))
			return
		}
		if !h.zt.WaitForChange(r.Context(), revision, 25*time.Second) {
			w.Header().Set("HX-Trigger", "zerotier-repoll")
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	data := h.buildZeroTierData()
	writePageJSON(w, http.StatusOK, "zerotier-status", data, nil)
}

// UpdateZeroTier handles PUT /zerotier — service and routing settings.
func (h *handler) UpdateZeroTier(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writePageError(w, http.StatusBadRequest, fmt.Errorf("bad request"))
		return
	}

	port, _ := strconv.ParseUint(r.FormValue("ztPort"), 10, 16)
	enabled := r.FormValue("ztEnabled") == "on"

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		cfg.ZeroTier.Enabled = enabled
		cfg.ZeroTier.Port = uint16(port)
		cfg.ZeroTier.DisableMasquerade = r.FormValue("ztMasquerade") != "on"
		cfg.ZeroTier.ExcludeAdvertisedRoutesFromMasquerade = r.FormValue("ztExcludeAdvertisedRoutesFromMasquerade") == "on"
		if errs := cfg.ZeroTier.Validate(); len(errs) > 0 {
			return errs
		}
		return nil
	})

	h.respondZeroTier(w, r, writeErr, "ZeroTier settings saved.")
}

// JoinZeroTierNetwork handles POST /zerotier/networks.
func (h *handler) JoinZeroTierNetwork(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writePageError(w, http.StatusBadRequest, fmt.Errorf("bad request"))
		return
	}

	network := models.ZeroTierNetwork{
		ID:           strings.ToLower(strings.TrimSpace(r.FormValue("networkID"))),
		Name:         strings.TrimSpace(r.FormValue("networkName")),
		AllowManaged: r.FormValue("allowManaged") == "on",
		AllowGlobal:  r.FormValue("allowGlobal") == "on",
		AllowDefault: r.FormValue("allowDefault") == "on",
		AllowDNS:     r.FormValue("allowDNS") == "on",
	}

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		if existing := models.FindZeroTierNetwork(cfg.ZeroTier.Networks, network.ID); existing != nil {
			*existing = network
		} else {
			cfg.ZeroTier.Networks = append(cfg.ZeroTier.Networks, network)
		}
		if errs := cfg.ZeroTier.Validate(); len(errs) > 0 {
			return errs
		}
		return nil
	})

	h.respondZeroTier(w, r, writeErr, fmt.Sprintf("Joining network %s.", network.ID))
}

// LeaveZeroTierNetwork handles DELETE /zerotier/networks/{id}.
func (h *handler) LeaveZeroTierNetwork(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		for i, n := range cfg.ZeroTier.Networks {
			if strings.EqualFold(n.ID, id) {
				cfg.ZeroTier.Networks = append(cfg.ZeroTier.Networks[:i], cfg.ZeroTier.Networks[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("network %s is not configured", id)
	})

	h.respondZeroTier(w, r, writeErr, fmt.Sprintf("Leaving network %s.", id))
}

// RestartZeroTier handles POST /api/zerotier/restart.
func (h *handler) RestartZeroTier(w http.ResponseWriter, r *http.Request) {
	if h.zt == nil {
		toast := toastData{Kind: "error", Message: "ZeroTier supervisor is not available."}
		writePageJSON(w, http.StatusOK, "empty", struct{}{}, &toast)
		return
	}
	if err := h.zt.Restart(); err != nil {
		logRejected(r, err)
		toast := toastData{Kind: "error", Message: fmt.Sprintf("Restart failed: %v", err)}
		writePageJSON(w, http.StatusOK, "empty", struct{}{}, &toast)
		return
	}
	toast := toastData{Kind: "success", Message: "ZeroTier service restarting."}
	writePageJSON(w, http.StatusOK, "empty", struct{}{}, &toast)
}

// respondZeroTier re-renders the tab, reporting validation errors the same way
// the peer and server forms do.
func (h *handler) respondZeroTier(w http.ResponseWriter, r *http.Request, writeErr error, success string) {
	data := h.buildZeroTierData()
	if writeErr != nil {
		logRejected(r, writeErr)
		if ve, ok := writeErr.(models.ValidationErrors); ok {
			data.ValidationErrors = ve
			writePageJSON(w, http.StatusUnprocessableEntity, "zerotier-tab", data, nil)
			return
		} else if _, ok := applyError(writeErr); ok {
			data.Error = writeErr.Error()
		} else {
			data.Error = writeErr.Error()
			writePageJSON(w, http.StatusInternalServerError, "zerotier-tab", data, nil)
			return
		}
		writePageJSON(w, http.StatusOK, "zerotier-tab", data, nil)
		return
	}

	// The supervisor applies the change on its next tick; give it one so the
	// re-rendered tab already reflects reality rather than the previous state.
	time.Sleep(reconcileGrace)

	data = h.buildZeroTierData()
	data.Success = success
	writePageJSON(w, http.StatusOK, "zerotier-tab", data, nil)
}

// reconcileGrace is how long a save waits for the supervisor to pick the change up.
// ponytail: a sleep, not a completion signal — the tab's long poll refreshes
// when the supervisor snapshot changes; this only makes the immediate response look right.
const reconcileGrace = 300 * time.Millisecond
