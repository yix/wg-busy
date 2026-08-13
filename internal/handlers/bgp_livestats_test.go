package handlers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yix/wg-busy/internal/models"
)

// TestBGPLiveStatsRouteKeysAreStableAcrossPolls verifies the data the
// bgp-live-stats fragment relies on to survive the 2s poll: each route table
// carries a data-route-key derived only from the peer IP and direction (never
// from render order), and a "Show All" button is tagged with the class the
// restore JS looks for. If either drifts, an open route panel folds itself
// shut on the next poll.
func TestBGPLiveStatsRouteKeysAreStableAcrossPolls(t *testing.T) {
	routes := make([]models.BGPRoute, 12)
	for i := range routes {
		routes[i] = models.BGPRoute{Prefix: "10.0.0.0/24", NextHop: "10.0.0.1", Status: "Accepted"}
	}
	stats := &models.BGPStats{
		Running: true,
		Peers: []models.BGPPeerStats{
			{IP: "192.0.2.1", State: "Established", Routes: routes, AdvertisedRoutes: routes},
		},
	}

	render := func() string {
		var buf bytes.Buffer
		if err := templates.ExecuteTemplate(&buf, "bgp-live-stats", stats); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}

	first := render()
	second := render()

	for _, key := range []string{
		`data-route-key="192.0.2.1-received"`,
		`data-route-key="192.0.2.1-advertised"`,
	} {
		if !strings.Contains(first, key) {
			t.Fatalf("missing %s in rendered output", key)
		}
	}
	if strings.Count(first, "show-all-btn") != 2 {
		t.Fatalf("expected 2 show-all-btn buttons (received + advertised), got %d", strings.Count(first, "show-all-btn"))
	}
	if first != second {
		t.Fatal("identical stats rendered different HTML across polls — route keys or ordering are not stable")
	}
}
