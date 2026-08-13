package handlers

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wgstats"
)

func TestRenderApplyWarningKeepsPersistedMutationOnSuccessPath(t *testing.T) {
	err := &config.ApplyError{Err: errors.New("wg syncconf failed")}
	toast, ok := applyWarning(err)
	if !ok {
		t.Fatal("ApplyError was not recognized")
	}
	if toast.Kind != "error" || !strings.Contains(toast.Message, "configuration saved but live apply failed") {
		t.Fatalf("warning does not distinguish persistence from apply failure: %#v", toast)
	}
	if _, ok := applyWarning(errors.New("not persisted")); ok {
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

	exact := observed.Format(time.RFC3339)
	if row.LastSeenAt != exact || row.LastSeen == "" {
		t.Fatalf("last-seen data = %q (%q), want exact timestamp %q", row.LastSeen, row.LastSeenAt, exact)
	}
	templateSource, err := os.ReadFile("../../web/templates.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(templateSource), `datetime="{{LastSeenAt}}" title="{{LastSeenAt}}"`) {
		t.Fatal("peer-stats Handlebars template does not expose the exact timestamp")
	}
}

func TestVersionEndpointReturnsBuildVersion(t *testing.T) {
	router := NewRouter(nil, fstest.MapFS{"index.html": {Data: []byte("ok")}}, nil, nil, "v0.0.1")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest("GET", "/version", nil))

	var response struct {
		Template string
		Data     struct{ Version string }
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Template != "version" || response.Data.Version != "v0.0.1" {
		t.Fatalf("version response = %#v", response)
	}
}

func TestCustomBGPPeerFormIncludesRedistributeConnectedSetting(t *testing.T) {
	data := bgpPeerFormData{Peer: models.BGPPeer{
		RedistributeConnected:     true,
		MaxReceivedPrefixLength:   24,
		MaxAdvertisedPrefixLength: 25,
	}}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{`"RedistributeConnected":true`, `"MaxReceivedPrefixLength":24`, `"MaxAdvertisedPrefixLength":25`} {
		if !strings.Contains(string(encoded), value) {
			t.Fatalf("custom BGP peer JSON is missing %s: %s", value, encoded)
		}
	}

	templateSource, err := os.ReadFile("../../web/templates.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(templateSource)
	for _, name := range []string{"bgpRedistributeConnected", "bgpMaxReceivedPrefixLength", "bgpMaxAdvertisedPrefixLength"} {
		if strings.Count(body, `name="`+name+`"`) < 2 {
			t.Fatalf("both BGP peer forms must contain %s", name)
		}
	}
}

func TestParseMaxPrefixLengthPreservesInvalidInputForValidation(t *testing.T) {
	for input, want := range map[string]uint16{"": 0, "0": 0, "24": 24, "129": 129, "invalid": 129, "70000": 129} {
		if got := parseMaxPrefixLength(input); got != want {
			t.Errorf("parseMaxPrefixLength(%q) = %d, want %d", input, got, want)
		}
	}
}
