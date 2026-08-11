package handlers

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/wgstats"
	"github.com/yix/wg-busy/internal/zerotier"
)

type handler struct {
	store *config.Store
	stats *wgstats.Collector
	zt    *zerotier.Supervisor
}

// logRejected records why a user action was rejected. The middleware logs that a
// request failed; this logs what was wrong with it.
func logRejected(r *http.Request, err error) {
	log.Printf("rejected %s %s from %s: %v", r.Method, r.URL.Path, r.RemoteAddr, err)
}

// statusRecorder captures the response status, and the body of plain-text error
// responses (everything http.Error writes), so the middleware can log both.
type statusRecorder struct {
	http.ResponseWriter
	status int
	detail string
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	// ponytail: only http.Error bodies are text/plain; HTML error responses carry
	// their detail via logRejected instead, so we don't log whole rendered forms.
	if s.status >= 400 && s.detail == "" && strings.HasPrefix(s.Header().Get("Content-Type"), "text/plain") {
		s.detail = strings.TrimSpace(string(b))
	}
	return s.ResponseWriter.Write(b)
}

// logErrors logs every request that ends in a 4xx or 5xx, so no failed user
// action is invisible in the app log.
func logErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.status >= 400 {
			msg := fmt.Sprintf("%d %s %s from %s", rec.status, r.Method, r.URL.Path, r.RemoteAddr)
			if rec.detail != "" {
				msg += ": " + rec.detail
			}
			log.Print(msg)
		}
	})
}

// NewRouter creates the HTTP mux with all routes registered.
func NewRouter(store *config.Store, webFS fs.FS, stats *wgstats.Collector, zt *zerotier.Supervisor) http.Handler {
	h := &handler{store: store, stats: stats, zt: zt}

	mux := http.NewServeMux()

	// Static files (index.html).
	mux.Handle("GET /", http.FileServerFS(webFS))

	// Stats bar fragment (includes OOB peer stats).
	mux.HandleFunc("GET /stats", h.GetCombinedStats)

	// Peer fragment endpoints.
	mux.HandleFunc("GET /peers", h.ListPeers)
	mux.HandleFunc("GET /peers/new", h.GetPeerForm)
	mux.HandleFunc("GET /peers/{id}/edit", h.GetPeerForm)
	mux.HandleFunc("POST /peers", h.CreatePeer)
	mux.HandleFunc("PUT /peers/{id}", h.UpdatePeer)
	mux.HandleFunc("DELETE /peers/{id}", h.DeletePeer)
	mux.HandleFunc("PUT /peers/{id}/toggle", h.TogglePeer)

	// QR code modal (HTML dialog).
	mux.HandleFunc("GET /peers/{id}/qr", h.QRCodeModal)

	// Server config fragment endpoints.
	mux.HandleFunc("GET /server", h.GetServerConfig)
	mux.HandleFunc("PUT /server", h.UpdateServerConfig)

	// BGP stats fragment.
	mux.HandleFunc("GET /bgp/stats", h.GetBGPStatsTab)

	// ZeroTier fragment endpoints.
	mux.HandleFunc("GET /zerotier", h.GetZeroTierTab)
	mux.HandleFunc("GET /zerotier/status", h.GetZeroTierStatus)
	mux.HandleFunc("PUT /zerotier", h.UpdateZeroTier)
	mux.HandleFunc("POST /zerotier/networks", h.JoinZeroTierNetwork)
	mux.HandleFunc("DELETE /zerotier/networks/{id}", h.LeaveZeroTierNetwork)

	// API endpoints.
	mux.HandleFunc("GET /api/peers/{id}/config", h.DownloadClientConfig)
	mux.HandleFunc("GET /api/peers/{id}/qr", h.QRCode)
	mux.HandleFunc("GET /api/server/config", h.DownloadServerConfig)
	mux.HandleFunc("POST /api/server/apply", h.ApplyConfig)
	mux.HandleFunc("POST /api/peers/{id}/regenerate-keys", h.RegeneratePeerKeys)
	mux.HandleFunc("POST /api/zerotier/restart", h.RestartZeroTier)

	return logErrors(mux)
}
