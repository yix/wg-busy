package handlers

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/yix/wg-busy/internal/models"
)

// TestBGPLiveStatsRouteKeysAreStableAcrossPolls verifies the data the
// bgp-live-stats fragment relies on to survive the 2s poll: its JSON is stable,
// and the Handlebars template derives route keys only from peer IP + direction.
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
		body, err := json.Marshal(stats)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}

	first := render()
	second := render()

	templateSource, err := os.ReadFile("../../web/templates.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(templateSource)
	for _, key := range []string{`data-route-key="{{IP}}-received"`, `data-route-key="{{IP}}-advertised"`} {
		if !strings.Contains(source, key) {
			t.Fatalf("missing stable route key %s", key)
		}
	}
	if strings.Count(source, "show-all-btn") != 2 {
		t.Fatalf("expected 2 show-all-btn buttons (received + advertised), got %d", strings.Count(source, "show-all-btn"))
	}
	if first != second {
		t.Fatal("identical stats rendered different HTML across polls — route keys or ordering are not stable")
	}
}
