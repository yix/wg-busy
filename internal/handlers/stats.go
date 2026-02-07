package handlers

import (
	"fmt"
	"net/http"

	"github.com/skip2/go-qrcode"

	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wgstats"
	"github.com/yix/wg-busy/internal/wireguard"
)

// statsBarData is the template data for the stats bar fragment.
type statsBarData struct {
	IsUp         bool
	Uptime       string
	TotalRx      string
	TotalTx      string
	CurrentRx    string
	CurrentTx    string
	SparklineSVG string
}

// GetStatsBar returns the stats bar HTML fragment.
func (h *handler) GetStatsBar(w http.ResponseWriter, r *http.Request) {
	var data statsBarData

	if h.stats != nil {
		data.IsUp = h.stats.IsUp()
		data.Uptime = wgstats.FormatDuration(h.stats.Uptime())
		iface := h.stats.GetInterfaceStats()
		data.TotalRx = wgstats.FormatBytes(iface.TotalRx)
		data.TotalTx = wgstats.FormatBytes(iface.TotalTx)
		data.CurrentRx = wgstats.FormatBytesPerSec(iface.CurrentRxPS)
		data.CurrentTx = wgstats.FormatBytesPerSec(iface.CurrentTxPS)
		data.SparklineSVG = wgstats.RenderSparklineSVG(h.stats.GetHistory(), 120, 24)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "stats-bar", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
	w.Write(png)
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
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}

	data := struct {
		ID   string
		Name string
	}{ID: id, Name: peerName}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "qr-modal", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
