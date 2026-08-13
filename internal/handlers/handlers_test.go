package handlers

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wgstats"
)

func TestRenderApplyWarningKeepsPersistedMutationOnSuccessPath(t *testing.T) {
	recorder := httptest.NewRecorder()
	err := &config.ApplyError{Err: errors.New("wg syncconf failed")}
	if !renderApplyWarning(recorder, err) {
		t.Fatal("ApplyError was not recognized")
	}
	if recorder.Code != 200 {
		t.Fatalf("status = %d, want 200 so htmx renders the persisted state", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "configuration saved but live apply failed") || !strings.Contains(body, `hx-swap-oob="beforeend:#toast-container"`) {
		t.Fatalf("warning response does not distinguish persistence from apply failure: %s", body)
	}
	if renderApplyWarning(httptest.NewRecorder(), errors.New("not persisted")) {
		t.Fatal("ordinary error was treated as a persisted mutation")
	}
}

func TestNewDualRolePeerGetsDistinctRoutingTables(t *testing.T) {
	peer := models.Peer{IsExitNode: true, PolicyRoutes: []string{"10.5.5.0/24 via 10.0.0.2"}}
	assignNewPeerRoutingTables(&peer, nil)
	if peer.RoutingTableID == 0 || peer.PolicyRoutingTableID == 0 {
		t.Fatalf("table IDs = exit %d, policy %d", peer.RoutingTableID, peer.PolicyRoutingTableID)
	}
	if peer.RoutingTableID == peer.PolicyRoutingTableID {
		t.Fatalf("dual-role peer reused table %d", peer.RoutingTableID)
	}
}

func TestPeerLastSeenUsesNewestTimestampAndExactHoverText(t *testing.T) {
	persisted := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	observed := persisted.Add(time.Hour)
	h := &handler{stats: wgstats.NewCollector()}
	row := h.buildPeerRow(
		models.Peer{PublicKey: "peer-key", AllowedIPs: "10.0.0.2/32", LastSeen: persisted},
		"",
		wgstats.PeerStats{PublicKey: "peer-key", LatestHandshake: observed},
	)

	var rendered strings.Builder
	if err := templates.ExecuteTemplate(&rendered, "peer-stats", row); err != nil {
		t.Fatal(err)
	}
	exact := observed.Format(time.RFC3339)
	body := rendered.String()
	if !strings.Contains(body, `datetime="`+exact+`" title="`+exact+`"`) || !strings.Contains(body, "last seen") {
		t.Fatalf("last-seen timestamp missing from peer row: %s", body)
	}
}

func TestVersionEndpointReturnsBuildVersion(t *testing.T) {
	router := NewRouter(nil, fstest.MapFS{"index.html": {Data: []byte("ok")}}, nil, nil, "v0.0.1")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest("GET", "/version", nil))

	if got := recorder.Body.String(); got != "v0.0.1" {
		t.Fatalf("version response = %q, want v0.0.1", got)
	}
}
