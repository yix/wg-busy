package handlers

import (
	"io/fs"
	"net/http"

	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/wgstats"
)

type handler struct {
	store *config.Store
	stats *wgstats.Collector
}

// NewRouter creates the HTTP mux with all routes registered.
func NewRouter(store *config.Store, webFS fs.FS, stats *wgstats.Collector) *http.ServeMux {
	h := &handler{store: store, stats: stats}

	mux := http.NewServeMux()

	// Static files (index.html).
	mux.Handle("GET /", http.FileServerFS(webFS))

	// Stats bar fragment.
	mux.HandleFunc("GET /stats", h.GetStatsBar)

	// Peer fragment endpoints.
	mux.HandleFunc("GET /peers", h.ListPeers)
	mux.HandleFunc("GET /peers/new", h.GetPeerForm)
	mux.HandleFunc("GET /peers/{id}/edit", h.GetPeerForm)
	mux.HandleFunc("POST /peers", h.CreatePeer)
	mux.HandleFunc("PUT /peers/{id}", h.UpdatePeer)
	mux.HandleFunc("DELETE /peers/{id}", h.DeletePeer)
	mux.HandleFunc("PUT /peers/{id}/toggle", h.TogglePeer)
	mux.HandleFunc("GET /peers/stats", h.GetPeersStats)

	// QR code modal (HTML dialog).
	mux.HandleFunc("GET /peers/{id}/qr", h.QRCodeModal)

	// Server config fragment endpoints.
	mux.HandleFunc("GET /server", h.GetServerConfig)
	mux.HandleFunc("PUT /server", h.UpdateServerConfig)

	// API endpoints.
	mux.HandleFunc("GET /api/peers/{id}/config", h.DownloadClientConfig)
	mux.HandleFunc("GET /api/peers/{id}/qr", h.QRCode)
	mux.HandleFunc("GET /api/server/config", h.DownloadServerConfig)
	mux.HandleFunc("POST /api/server/apply", h.ApplyConfig)
	mux.HandleFunc("POST /api/peers/{id}/regenerate-keys", h.RegeneratePeerKeys)

	return mux
}
