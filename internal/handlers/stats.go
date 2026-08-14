package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/yix/wg-busy/internal/bgp"
	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wgstats"
	"github.com/yix/wg-busy/internal/wireguard"
)

// statsBarData is the template data for the stats bar and its OOB peer rows.
type statsBarData struct {
	IsUp         bool
	Uptime       string
	TotalRx      string
	TotalTx      string
	CurrentRxPS  string
	CurrentTxPS  string
	SparklineSVG string
	Peers        []peerLiveData   `json:",omitempty"`
	BGPStats     *models.BGPStats `json:",omitempty"`
}

// peerLiveData is deliberately smaller than peerRowData: the two-second peers
// refresh must not resend keys, routing policy, and other form-only settings.
type peerLiveData struct {
	ID           string
	AllowedIPs   string
	CreatedAt    time.Time
	TransferRx   string
	TransferTx   string
	CurrentRxPS  string
	CurrentTxPS  string
	LastSeen     string
	LastSeenAt   string
	SparklineSVG string
	HasStats     bool
}

// GetCombinedStats returns the title stats plus only the live data needed by
// the active tab. Peer and BGP updates are rendered as out-of-band swaps.
func (h *handler) GetCombinedStats(w http.ResponseWriter, r *http.Request) {
	var data statsBarData
	switch r.URL.Query().Get("kind") {
	case "bgp":
		data.BGPStats = bgp.GetBGPStats()
	case "server", "zerotier":
		// These tabs need only the interface summary in the title.
	default:
		// Keep peers as the default for the initial page and old clients.
		for _, row := range h.buildPeersListData().Peers {
			data.Peers = append(data.Peers, peerLiveData{
				ID: row.ID, AllowedIPs: row.AllowedIPs, CreatedAt: row.CreatedAt,
				TransferRx: row.TransferRx, TransferTx: row.TransferTx,
				CurrentRxPS: row.CurrentRxPS, CurrentTxPS: row.CurrentTxPS,
				LastSeen: row.LastSeen, LastSeenAt: row.LastSeenAt,
				SparklineSVG: row.SparklineSVG, HasStats: row.HasStats,
			})
		}
	}

	if h.stats != nil {
		iface := h.stats.GetInterfaceStats()
		data.IsUp = h.stats.IsUp()
		data.Uptime = wgstats.FormatDuration(h.stats.Uptime())
		data.TotalRx = wgstats.FormatBytes(iface.TotalRx)
		data.TotalTx = wgstats.FormatBytes(iface.TotalTx)
		data.CurrentRxPS = wgstats.FormatBytesPerSec(iface.CurrentRxPS)
		data.CurrentTxPS = wgstats.FormatBytesPerSec(iface.CurrentTxPS)
		data.SparklineSVG = wgstats.RenderSparklineSVG(h.stats.GetHistory(), 120, 24)
	}

	writePageJSON(w, http.StatusOK, "stats-bar", data, nil)
}

// QRCode handles GET /api/peers/{id}/qr.
func (h *handler) QRCode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var content string
	var genErr error

	h.store.Read(func(cfg *models.AppConfig) {
		peer := models.FindPeerByID(cfg.Peers, id)
		if peer == nil {
			genErr = fmt.Errorf("peer not found")
			return
		}

		content, genErr = wireguard.RenderClientConfig(cfg.Server, *peer)
	})

	if genErr != nil {
		http.Error(w, genErr.Error(), http.StatusInternalServerError)
		return
	}

	qr, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		http.Error(w, fmt.Sprintf("QR generation failed: %v", err), http.StatusInternalServerError)
		return
	}

	png, err := qr.PNG(256)
	if err != nil {
		http.Error(w, fmt.Sprintf("QR PNG failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(png)
}

// QRCodeModal handles GET /peers/{id}/qr — returns an HTML dialog with the QR code image.
func (h *handler) QRCodeModal(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var peerName string

	h.store.Read(func(cfg *models.AppConfig) {
		peer := models.FindPeerByID(cfg.Peers, id)
		if peer != nil {
			peerName = peer.Name
		}
	})

	if peerName == "" {
		writePageError(w, http.StatusNotFound, fmt.Errorf("peer not found"))
		return
	}

	data := struct {
		ID   string
		Name string
	}{ID: id, Name: peerName}

	writePageJSON(w, http.StatusOK, "qr-modal", data, nil)
}
