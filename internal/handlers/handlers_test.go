package handlers

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wgstats"
	"github.com/yix/wg-busy/internal/zerotier"
)

func TestRenderApplyWarningKeepsPersistedMutationOnSuccessPath(t *testing.T) {
	err := &config.ApplyError{Err: errors.New("wg syncconf failed")}
	toast, ok := applyWarning(err)
	if !ok {
		t.Fatal("ApplyError was not recognized")
	}
	if toast.Kind != "error" || !strings.Contains(toast.Message, "configuration saved, but live apply did not complete") {
		t.Fatalf("warning does not distinguish persistence from apply failure: %#v", toast)
	}
	if _, ok := applyWarning(errors.New("not persisted")); ok {
		t.Fatal("ordinary error was treated as a persisted mutation")
	}
}

func TestServerAndBGPFormsUpdateOnlyTheirOwnSettings(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.yaml"
	if err := os.WriteFile(configPath, []byte(`server:
  privateKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  listenPort: 51820
  address: 10.0.0.1/24
  bgpEnabled: true
  bgpListenAddress: 10.0.0.1
  bgpListenPort: 179
  bgpAsn: 64512
`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(configPath, dir+"/wg0.conf")
	if err != nil {
		t.Fatal(err)
	}
	h := &handler{store: store}

	serverRequest := httptest.NewRequest("PUT", "/server", strings.NewReader("listenPort=51821&address=10.0.0.1%2F24"))
	serverRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.UpdateServerConfig(httptest.NewRecorder(), serverRequest)

	store.Read(func(cfg *models.AppConfig) {
		if !cfg.Server.BGPEnabled || cfg.Server.BGPASN != 64512 || cfg.Server.BGPListenAddress != "10.0.0.1" || cfg.Server.BGPListenPort != 179 {
			t.Errorf("server form changed BGP settings: %#v", cfg.Server)
		}
	})

	bgpRequest := httptest.NewRequest("PUT", "/bgp/server", strings.NewReader("bgpEnabled=on&bgpAsn=65001&bgpListenAddress=10.0.0.2&bgpListenPort=1179"))
	bgpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.UpdateBGPServerConfig(httptest.NewRecorder(), bgpRequest)

	store.Read(func(cfg *models.AppConfig) {
		if cfg.Server.ListenPort != 51821 || cfg.Server.Address != "10.0.0.1/24" {
			t.Errorf("BGP form changed WireGuard settings: %#v", cfg.Server)
		}
		if !cfg.Server.BGPEnabled || cfg.Server.BGPASN != 65001 || cfg.Server.BGPListenAddress != "10.0.0.2" || cfg.Server.BGPListenPort != 1179 {
			t.Errorf("BGP settings were not updated: %#v", cfg.Server)
		}
	})
}

func TestBGPServerConfigurationLivesInBGPTab(t *testing.T) {
	templateSource, err := os.ReadFile("../../web/templates.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(templateSource)
	serverStart := strings.Index(source, `id="server-config-template"`)
	bgpStart := strings.Index(source, `id="bgp-tab-template"`)
	if serverStart < 0 || bgpStart < 0 {
		t.Fatal("server or BGP template not found")
	}
	serverEnd := strings.Index(source[serverStart:], "</script>")
	bgpEnd := strings.Index(source[bgpStart:], "</script>")
	if serverEnd < 0 || bgpEnd < 0 {
		t.Fatal("server or BGP template is not closed")
	}
	serverTemplate := source[serverStart : serverStart+serverEnd]
	bgpTemplate := source[bgpStart : bgpStart+bgpEnd]
	if strings.Contains(serverTemplate, "BGP Server Configuration") || strings.Contains(serverTemplate, `name="bgpEnabled"`) {
		t.Fatal("BGP server controls remain in the Server tab")
	}
	if !strings.Contains(bgpTemplate, "BGP Server Configuration") || !strings.Contains(bgpTemplate, `hx-put="bgp/server"`) {
		t.Fatal("BGP tab does not contain the BGP server form")
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

func TestPeerRowShowsBGPBadgeWhenEnabled(t *testing.T) {
	templateSource, err := os.ReadFile("../../web/templates.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(templateSource), `{{#if Peer.BGPEnabled}}<span class="badge badge-via" title="BGP enabled">BGP</span>{{/if}}`) {
		t.Fatal("peer-row Handlebars template does not conditionally render the BGP badge")
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

func TestRouterCompressesJSONWhenGzipIsAccepted(t *testing.T) {
	router := NewRouter(nil, fstest.MapFS{"index.html": {Data: []byte("ok")}}, nil, nil, "v0.0.1")
	request := httptest.NewRequest("GET", "/version", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := recorder.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
	reader, err := gzip.NewReader(recorder.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"Version":"v0.0.1"`) {
		t.Fatalf("decoded response = %s", body)
	}
}

func TestRouterHonorsDisabledGzipAndEmptyResponses(t *testing.T) {
	handler := gzipResponses(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/empty":
			w.WriteHeader(http.StatusNoContent)
			return
		case "/image":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("png"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	for _, test := range []struct{ path, acceptEncoding string }{
		{path: "/json", acceptEncoding: "gzip;q=0, *;q=1"},
		{path: "/empty", acceptEncoding: "gzip"},
		{path: "/image", acceptEncoding: "gzip"},
	} {
		request := httptest.NewRequest("GET", test.path, nil)
		request.Header.Set("Accept-Encoding", test.acceptEncoding)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if got := recorder.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("%s Content-Encoding = %q, want empty", test.path, got)
		}
	}
}

func TestStatsPollingPausesWhilePageIsHidden(t *testing.T) {
	source, err := os.ReadFile("../../web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	for _, trigger := range []string{
		`every 2s [document.visibilityState === 'visible']`,
		`visibilitychange from:document [document.visibilityState === 'visible']`,
	} {
		if !strings.Contains(body, trigger) {
			t.Fatalf("stats trigger is missing %q", trigger)
		}
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

func TestStatsRequestIncludesOnlyActiveScreenData(t *testing.T) {
	tests := []struct {
		kind    string
		present string
		absent  []string
	}{
		{kind: "server", present: `"Data"`, absent: []string{`"Peers"`, `"BGPStats"`}},
		{kind: "zerotier", present: `"Data"`, absent: []string{`"Peers"`, `"BGPStats"`}},
		{kind: "bgp", present: `"BGPStats"`, absent: []string{`"Peers"`}},
	}
	for _, test := range tests {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/stats?kind="+test.kind, nil)
		(&handler{}).GetCombinedStats(recorder, request)
		body := recorder.Body.String()
		if !strings.Contains(body, test.present) {
			t.Fatalf("%s stats response lacks %s: %s", test.kind, test.present, body)
		}
		for _, absent := range test.absent {
			if strings.Contains(body, absent) {
				t.Fatalf("%s stats response unexpectedly contains %s: %s", test.kind, absent, body)
			}
		}
	}
}

func TestZeroTierOnlineMockMatchesHandlebarsFieldNames(t *testing.T) {
	mock := zerotierData{Snapshot: zerotier.Snapshot{Status: &zerotier.Status{
		Address: "8056c2e21c", Online: true, Version: "1.14.2", TCPFallbackActive: true,
	}}}
	encoded, err := json.Marshal(mock)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{`"address":"8056c2e21c"`, `"online":true`, `"version":"1.14.2"`, `"tcpFallbackActive":true`} {
		if !strings.Contains(string(encoded), value) {
			t.Fatalf("mock status JSON is missing %s: %s", value, encoded)
		}
	}

	templateSource, err := os.ReadFile("../../web/templates.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(templateSource)
	for _, expression := range []string{
		`{{#if Snapshot.Status.online}}`,
		`{{Snapshot.Status.address}}`,
		`{{Snapshot.Status.version}}`,
		`{{#if Snapshot.Status.tcpFallbackActive}}`,
	} {
		if !strings.Contains(source, expression) {
			t.Fatalf("ZeroTier template does not render mocked JSON field %s", expression)
		}
	}
}

func TestZeroTierLongPollReturnsNoDuplicatePayloadWhenCanceled(t *testing.T) {
	h := &handler{zt: zerotier.New(t.TempDir())}
	request := httptest.NewRequest("GET", "/zerotier/status?since=0", nil)
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	request = request.WithContext(ctx)
	recorder := httptest.NewRecorder()

	h.GetZeroTierStatus(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("unchanged long poll returned duplicate payload: %s", recorder.Body.String())
	}
	if got := recorder.Header().Get("HX-Trigger"); got != "zerotier-repoll" {
		t.Fatalf("HX-Trigger = %q, want zerotier-repoll", got)
	}
}
