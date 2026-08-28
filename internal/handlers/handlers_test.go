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
	"github.com/yix/wg-busy/internal/wireguard"
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

func TestPeerRowDisplaysPersistedTrafficCountersWhenLiveStatsUnavailable(t *testing.T) {
	h := &handler{}
	row := h.buildPeerRow(
		models.Peer{
			PublicKey:  "peer-key",
			AllowedIPs: "10.0.0.2/32",
			TransferRx: 1024 * 1024 * 5, // 5 MB
			TransferTx: 1024 * 1024 * 2, // 2 MB
		},
		"",
		wgstats.PeerStats{},
	)

	if row.TransferRx != "5.0 MB" || row.TransferTx != "2.0 MB" {
		t.Fatalf("row transfer rx=%q, tx=%q, want 5.0 MB, 2.0 MB", row.TransferRx, row.TransferTx)
	}
}

func TestRegeneratePeerKeysResetsTrafficCounters(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.yaml"
	if err := os.WriteFile(configPath, []byte(`server:
  privateKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  listenPort: 51820
  address: 10.0.0.1/24
peers:
  - id: peer-1
    name: Alice
    publicKey: KEYALICE=
    allowedIPs: 10.0.0.2/32
    transferRx: 5000
    transferTx: 6000
    lastSeen: 2026-08-13T12:00:00Z
`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(configPath, dir+"/wg0.conf")
	if err != nil {
		t.Fatal(err)
	}
	collector := wgstats.NewCollector()
	collector.SetPeerBases(map[string]wgstats.PeerTrafficBase{
		"KEYALICE=": {Rx: 5000, Tx: 6000},
	})
	h := &handler{store: store, stats: collector}

	req := httptest.NewRequest("POST", "/api/peers/peer-1/regenerate-keys", nil)
	req.SetPathValue("id", "peer-1")
	rec := httptest.NewRecorder()
	h.RegeneratePeerKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("regenerate keys status = %d, want 200", rec.Code)
	}

	store.Read(func(cfg *models.AppConfig) {
		p := models.FindPeerByID(cfg.Peers, "peer-1")
		if p == nil {
			t.Fatal("peer not found")
		}
		if p.TransferRx != 0 || p.TransferTx != 0 || !p.LastSeen.IsZero() {
			t.Fatalf("traffic counters and lastSeen not reset: Rx:%d, Tx:%d, LastSeen:%v", p.TransferRx, p.TransferTx, p.LastSeen)
		}
		if p.PublicKey == "KEYALICE=" {
			t.Fatal("public key was not regenerated")
		}
	})
}

func TestPeerStatsLayoutPreventsSparklineWrapping(t *testing.T) {
	templateSource, err := os.ReadFile("../../web/templates.html")
	if err != nil {
		t.Fatal(err)
	}
	templateBody := string(templateSource)
	for _, required := range []string{
		`id="peer-stats-{{Peer.ID}}" class="peer-stats"`,
		`id="peer-stats-{{ID}}" class="peer-stats" hx-swap-oob="true"`,
		`<span class="peer-stats-text">`,
		`<span class="peer-sparkline">{{{SparklineSVG}}}</span>`,
	} {
		if !strings.Contains(templateBody, required) {
			t.Fatalf("templates.html is missing sparkline wrap protection markup: %q", required)
		}
	}

	cssSource, err := os.ReadFile("../../web/index.css")
	if err != nil {
		t.Fatal(err)
	}
	cssBody := string(cssSource)
	for _, required := range []string{
		".peer-stats",
		".peer-stats-text",
		".peer-sparkline",
		"white-space: nowrap",
		"flex-shrink: 0",
	} {
		if !strings.Contains(cssBody, required) {
			t.Fatalf("index.css is missing sparkline wrap protection rule: %q", required)
		}
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

func TestActivityPausesWhenPageUnfocusedOrHidden(t *testing.T) {
	source, err := os.ReadFile("../../web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	for _, required := range []string{
		"isPageActive",
		"document.visibilityState === 'visible'",
		"document.hasFocus",
		"window.addEventListener('focus'",
		"window.addEventListener('blur'",
		"document.addEventListener('visibilitychange'",
		"window.addEventListener('pageshow'",
		"window.addEventListener('pagehide'",
		"page-unfocused",
		"stopStatsPolling",
		"startStatsPolling",
		"htmx:beforeRequest",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("index.html is missing energy conservation requirement %q", required)
		}
	}

	cssSource, err := os.ReadFile("../../web/index.css")
	if err != nil {
		t.Fatal(err)
	}
	cssBody := string(cssSource)
	if !strings.Contains(cssBody, "html.page-unfocused") || !strings.Contains(cssBody, "animation-play-state: paused") {
		t.Fatal("index.css missing animation-play-state paused rule for html.page-unfocused")
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
		if !strings.Contains(body, `name="`+name+`"`) {
			t.Fatalf("BGP peer form must contain %s", name)
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

func TestShowWGStatusHandler(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.yaml"
	if err := os.WriteFile(configPath, []byte(`server:
  privateKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  listenPort: 51820
  address: 10.0.0.1/24
peers:
  - id: peer-1
    name: Alice
    publicKey: KEYALICE=
    allowedIPs: 10.0.0.2/32
`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(configPath, dir+"/wg0.conf")
	if err != nil {
		t.Fatal(err)
	}

	restore := wireguard.SetRunCommandForTesting(func(name string, args []string, _ []byte) ([]byte, error) {
		return []byte("interface: wg0\n  public key: SERVERKEY=\n\npeer: KEYALICE=\n  endpoint: 1.2.3.4:51820\n"), nil
	})
	t.Cleanup(restore)

	router := NewRouter(store, fstest.MapFS{"index.html": {Data: []byte("ok")}}, nil, nil, "v0.0.1")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest("GET", "/server/show", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	var resp struct {
		Template string
		Data     struct {
			Output string
			Error  string
		}
	}
	if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp.Template != "wg-show-modal" {
		t.Fatalf("Template = %q, want wg-show-modal", resp.Template)
	}
	if resp.Data.Error != "" {
		t.Fatalf("unexpected error = %q", resp.Data.Error)
	}
	want := "interface: wg0\n  public key: SERVERKEY=\n\n# Alice\npeer: KEYALICE=\n  endpoint: 1.2.3.4:51820\n"
	if resp.Data.Output != want {
		t.Fatalf("Output = %q, want %q", resp.Data.Output, want)
	}
}

func TestServerTabIncludesWGShowButton(t *testing.T) {
	templateSource, err := os.ReadFile("../../web/templates.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(templateSource)

	serverStart := strings.Index(source, `id="server-config-template"`)
	if serverStart < 0 {
		t.Fatal("server-config-template not found")
	}
	serverEnd := strings.Index(source[serverStart:], "</script>")
	if serverEnd < 0 {
		t.Fatal("server-config-template not closed")
	}
	serverTemplate := source[serverStart : serverStart+serverEnd]

	// Must contain the button targeting modal-container with hx-get="server/show"
	buttonHTML := `<button class="btn btn-outline secondary" hx-get="server/show" hx-target="#modal-container" hx-swap="innerHTML">wg show</button>`
	if !strings.Contains(serverTemplate, buttonHTML) {
		t.Fatalf("server-config-template does not contain expected wg show button: %s", serverTemplate)
	}

	// Must be placed to the left of the "Apply Config" button
	btnIdx := strings.Index(serverTemplate, `hx-get="server/show"`)
	applyIdx := strings.Index(serverTemplate, `Apply Config`)
	if btnIdx < 0 || applyIdx < 0 || btnIdx >= applyIdx {
		t.Fatalf("wg show button is not to the left of Apply Config (btnIdx=%d, applyIdx=%d)", btnIdx, applyIdx)
	}
}

func TestWGShowModalTemplate(t *testing.T) {
	templateSource, err := os.ReadFile("../../web/templates.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(templateSource)

	modalStart := strings.Index(source, `id="wg-show-modal-template"`)
	if modalStart < 0 {
		t.Fatal("wg-show-modal-template not found in templates.html")
	}
	modalEnd := strings.Index(source[modalStart:], "</script>")
	if modalEnd < 0 {
		t.Fatal("wg-show-modal-template not closed")
	}
	modalTemplate := source[modalStart : modalStart+modalEnd]

	for _, required := range []string{
		"<dialog>",
		"closeModal()",
		"{{#if Error}}",
		"{{Output}}",
	} {
		if !strings.Contains(modalTemplate, required) {
			t.Fatalf("wg-show-modal-template is missing required element: %q", required)
		}
	}
}

