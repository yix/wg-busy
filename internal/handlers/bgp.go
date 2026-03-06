package handlers

import (
	"net/http"

	"github.com/yix/wg-busy/internal/bgp"
)

// GetBGPStatsTab renders the HTML partial for the BGP statistics.
func (h *handler) GetBGPStatsTab(w http.ResponseWriter, r *http.Request) {
	stats := bgp.GetBGPStats()
	if err := templates.ExecuteTemplate(w, "bgp-stats", stats); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
