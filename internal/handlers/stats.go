package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/skip2/go-qrcode"

	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wgstats"
	"github.com/yix/wg-busy/internal/wireguard"
)

// ServerStatsJSON represents the server part of the JSON response.
type ServerStatsJSON struct {
	IsUp         bool   `json:"isUp"`
	Uptime       string `json:"uptime"`
	TotalRx      string `json:"totalRx"`
	TotalTx      string `json:"totalTx"`
	SparklineSVG string `json:"sparklineSVG"`
}

// PeerStatsJSON represents a peer's stats in the JSON response.
type PeerStatsJSON struct {
	ID           string `json:"id"`
	AllowedIPs   string `json:"allowedIPs"`
	HasStats     bool   `json:"hasStats"`
	TransferRx   string `json:"transferRx"`
	TransferTx   string `json:"transferTx"`
	Handshake    string `json:"handshake"`
	CreatedAt    string `json:"createdAt"`
	SparklineSVG string `json:"sparklineSVG"`
}

// StatsResponse is the top-level JSON response.
type StatsResponse struct {
	Server ServerStatsJSON `json:"server"`
	Peers  []PeerStatsJSON `json:"peers"`
}

// GetCombinedStats returns stats as JSON for client-side rendering.
func (h *handler) GetCombinedStats(w http.ResponseWriter, r *http.Request) {
	var resp StatsResponse

	// Server stats
	if h.stats != nil {
		resp.Server.IsUp = h.stats.IsUp()
		resp.Server.Uptime = wgstats.FormatDuration(h.stats.Uptime())
		iface := h.stats.GetInterfaceStats()
		resp.Server.TotalRx = wgstats.FormatBytes(iface.TotalRx)
		resp.Server.TotalTx = wgstats.FormatBytes(iface.TotalTx)
		resp.Server.SparklineSVG = wgstats.RenderSparklineSVG(h.stats.GetHistory(), 120, 24)
	}

	// Peer stats
	peerList := h.buildPeersListData()
	for _, p := range peerList.Peers {
		ps := PeerStatsJSON{
			ID:         p.Peer.ID,
			AllowedIPs: p.Peer.AllowedIPs,
			CreatedAt:  p.Peer.CreatedAt.Format("2006-01-02"),
		}
		if p.HasStats {
			ps.HasStats = true
			ps.TransferRx = p.TransferRx
			ps.TransferTx = p.TransferTx
			ps.Handshake = p.Handshake
			ps.SparklineSVG = p.SparklineSVG
		}
		resp.Peers = append(resp.Peers, ps)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
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
