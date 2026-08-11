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
	Config           models.ZeroTierConfig
	Port             uint16
	Snapshot         zerotier.Snapshot
	Networks         []ztNetworkRow
	Peers            []ztPeerRow
	Uptime           string
	Success          string
	Error            string
	ValidationErrors models.ValidationErrors
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

	snap := h.zt.Snapshot()
	data.Snapshot = snap
	if snap.Running {
		data.Uptime = wgstats.FormatDuration(snap.Uptime)
	}

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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "zerotier-tab", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// GetZeroTierStatus handles GET /zerotier/status — the fragment htmx polls.
func (h *handler) GetZeroTierStatus(w http.ResponseWriter, r *http.Request) {
	data := h.buildZeroTierData()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "zerotier-status", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// UpdateZeroTier handles PUT /zerotier — the on/off toggle and port.
func (h *handler) UpdateZeroTier(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	port, _ := strconv.ParseUint(r.FormValue("ztPort"), 10, 16)
	enabled := r.FormValue("ztEnabled") == "on"

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		cfg.ZeroTier.Enabled = enabled
		cfg.ZeroTier.Port = uint16(port)
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
		http.Error(w, "Bad request", http.StatusBadRequest)
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if h.zt == nil {
		_ = templates.ExecuteTemplate(w, "toast-error", "ZeroTier supervisor is not available.")
		return
	}
	if err := h.zt.Restart(); err != nil {
		logRejected(r, err)
		_ = templates.ExecuteTemplate(w, "toast-error", fmt.Sprintf("Restart failed: %v", err))
		return
	}
	_ = templates.ExecuteTemplate(w, "toast-success", "ZeroTier service restarting.")
}

// respondZeroTier re-renders the tab, reporting validation errors the same way
// the peer and server forms do.
func (h *handler) respondZeroTier(w http.ResponseWriter, r *http.Request, writeErr error, success string) {
	data := h.buildZeroTierData()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if writeErr != nil {
		logRejected(r, writeErr)
		if ve, ok := writeErr.(models.ValidationErrors); ok {
			data.ValidationErrors = ve
			w.WriteHeader(http.StatusUnprocessableEntity)
		} else {
			data.Error = writeErr.Error()
			w.WriteHeader(http.StatusUnprocessableEntity)
		}
		_ = templates.ExecuteTemplate(w, "zerotier-tab", data)
		return
	}

	// The supervisor applies the change on its next tick; give it one so the
	// re-rendered tab already reflects reality rather than the previous state.
	time.Sleep(reconcileGrace)

	data = h.buildZeroTierData()
	data.Success = success
	_ = templates.ExecuteTemplate(w, "zerotier-tab", data)
}

// reconcileGrace is how long a save waits for the supervisor to pick the change up.
// ponytail: a sleep, not a completion signal — the tab re-polls every 2s anyway,
// this only makes the immediate response look right.
const reconcileGrace = 300 * time.Millisecond
