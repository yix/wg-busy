package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wgstats"
	"github.com/yix/wg-busy/internal/zerotier"
)

func applyError(err error) (*config.ApplyError, bool) {
	var result *config.ApplyError
	ok := errors.As(err, &result)
	return result, ok
}

func applyWarning(err error) (toastData, bool) {
	if _, ok := applyError(err); !ok {
		return toastData{}, false
	}
	return toastData{Kind: "error", Message: err.Error()}, true
}

type toastData struct {
	Kind    string
	Message string
}

type pageResponse struct {
	Template string
	Data     any
	Toast    *toastData `json:",omitempty"`
}

func writePageJSON(w http.ResponseWriter, status int, templateName string, data any, toast *toastData) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(pageResponse{Template: templateName, Data: data, Toast: toast})
}

func writePageError(w http.ResponseWriter, status int, err error) {
	writePageJSON(w, status, "empty", struct{ Error string }{Error: err.Error()}, nil)
}

type handler struct {
	store *config.Store
	stats *wgstats.Collector
	zt    *zerotier.Supervisor
}

// ztGatewayNets returns the ZeroTier on-link networks, or nil when ZeroTier is
// not running. It reads only the supervisor's cached snapshot, so it is safe to
// call while the config store lock is held.
func (h *handler) ztGatewayNets() []models.GatewayNet {
	if h.zt == nil {
		return nil
	}
	return h.zt.GatewayNets()
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
	if s.status >= 400 && s.detail == "" {
		contentType := s.Header().Get("Content-Type")
		if strings.HasPrefix(contentType, "text/plain") {
			s.detail = strings.TrimSpace(string(b))
		} else if strings.HasPrefix(contentType, "application/json") {
			var response struct {
				Data struct{ Error string }
			}
			if json.Unmarshal(b, &response) == nil {
				s.detail = response.Data.Error
			}
		}
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
func NewRouter(store *config.Store, webFS fs.FS, stats *wgstats.Collector, zt *zerotier.Supervisor, version string) http.Handler {
	h := &handler{store: store, stats: stats, zt: zt}

	mux := http.NewServeMux()

	// Static files (index.html).
	mux.Handle("GET /", http.FileServerFS(webFS))
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writePageJSON(w, http.StatusOK, "version", struct{ Version string }{Version: version}, nil)
	})

	// Stats bar fragment (includes active-tab OOB stats selected by ?kind=).
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

	// BGP tab; live data is refreshed through the active-tab /stats request.
	mux.HandleFunc("GET /bgp/stats", h.GetBGPStatsTab)

	// Custom (non-WireGuard) BGP peer fragment endpoints.
	mux.HandleFunc("GET /bgp/peers/new", h.GetBGPPeerForm)
	mux.HandleFunc("GET /bgp/peers/{id}/edit", h.GetBGPPeerForm)
	mux.HandleFunc("POST /bgp/peers", h.CreateBGPPeer)
	mux.HandleFunc("PUT /bgp/peers/{id}", h.UpdateBGPPeer)
	mux.HandleFunc("DELETE /bgp/peers/{id}", h.DeleteBGPPeer)

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
