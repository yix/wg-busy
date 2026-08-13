package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yix/wg-busy/internal/ipam"
	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/routing"
	"github.com/yix/wg-busy/internal/wgstats"
	"github.com/yix/wg-busy/internal/wireguard"
)

// peerRowData is the template data for a single peer row.
type peerRowData struct {
	Peer         models.Peer
	ExitNodeName string
	Endpoint     string
	TransferRx   string
	TransferTx   string
	CurrentRxPS  string
	CurrentTxPS  string
	LastSeen     string
	LastSeenAt   string
	SparklineSVG string
	HasStats     bool
}

// peersListData is the template data for the peers list.
type peersListData struct {
	Peers []peerRowData
	OOB   bool
}

// peerFormData is the template data for the peer create/edit form.
type peerFormData struct {
	IsNew bool
	// Defaults renders a blank form with default values checked. It is off when
	// re-rendering after an error, so the user's own input is preserved.
	Defaults  bool
	Peer      models.Peer
	ExitNodes []models.Peer
	// Gateways are the subnets a policy route gateway may point into, shown as a
	// hint on the form: the WireGuard subnet and any joined ZeroTier networks.
	Gateways         []models.GatewayNet
	Error            string
	ValidationErrors models.ValidationErrors
}

func (h *handler) buildPeersListData() peersListData {
	var data peersListData
	var cfg *models.AppConfig
	h.store.Read(func(c *models.AppConfig) {
		cfg = c
	})

	// Fetch peer stats if available.
	var allPeerStats map[string]wgstats.PeerStats
	if h.stats != nil {
		allPeerStats = h.stats.GetAllPeerStats()
	}

	exitNodeNames := make(map[string]string)
	for _, p := range cfg.Peers {
		if p.IsExitNode {
			exitNodeNames[p.ID] = p.Name
		}
	}

	for _, p := range cfg.Peers {
		row := h.buildPeerRow(p, exitNodeNames[p.ExitNodeID], allPeerStats[p.PublicKey])
		data.Peers = append(data.Peers, row)
	}
	return data
}

func (h *handler) buildPeerRow(peer models.Peer, exitNodeName string, stats wgstats.PeerStats) peerRowData {
	row := peerRowData{Peer: peer, ExitNodeName: exitNodeName}
	lastSeen := peer.LastSeen
	if stats.PublicKey != "" {
		row.HasStats = true
		row.Endpoint = stats.Endpoint
		row.TransferRx = wgstats.FormatBytes(stats.TransferRx)
		row.TransferTx = wgstats.FormatBytes(stats.TransferTx)
		row.CurrentRxPS = wgstats.FormatBytesPerSec(stats.CurrentRxPS)
		row.CurrentTxPS = wgstats.FormatBytesPerSec(stats.CurrentTxPS)
		row.SparklineSVG = wgstats.RenderSparklineSVG(h.stats.GetPeerHistory(peer.PublicKey), 80, 16)
		if stats.LatestHandshake.After(lastSeen) {
			lastSeen = stats.LatestHandshake
		}
	}
	row.LastSeen = wgstats.FormatHandshake(lastSeen)
	if !lastSeen.IsZero() {
		row.LastSeenAt = lastSeen.UTC().Format(time.RFC3339)
	}
	return row
}

// ListPeers returns the peers list HTML fragment.
func (h *handler) ListPeers(w http.ResponseWriter, r *http.Request) {
	data := h.buildPeersListData()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "peers-list", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// GetPeerForm returns the peer create or edit form dialog.
func (h *handler) GetPeerForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	isNew := id == ""

	data := peerFormData{IsNew: isNew, Defaults: isNew}

	h.store.Read(func(cfg *models.AppConfig) {
		if !isNew {
			p := models.FindPeerByID(cfg.Peers, id)
			if p != nil {
				data.Peer = *p
			}
		}
		data.ExitNodes = models.ExitNodePeers(cfg.Peers)
		data.Gateways = models.GatewayNets(cfg.Server.Address, h.ztGatewayNets())
	})

	if !isNew && data.Peer.ID == "" {
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "peer-form", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// CreatePeer handles POST /peers.
func (h *handler) CreatePeer(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Generate keys.
	privKey, pubKey, err := wireguard.GenerateKeyPair()
	if err != nil {
		http.Error(w, fmt.Sprintf("Key generation failed: %v", err), http.StatusInternalServerError)
		return
	}

	var psk string
	if r.FormValue("presharedKey") == "on" {
		psk, err = wireguard.GeneratePresharedKey()
		if err != nil {
			http.Error(w, fmt.Sprintf("PSK generation failed: %v", err), http.StatusInternalServerError)
			return
		}
	}

	keepalive, _ := strconv.ParseUint(r.FormValue("persistentKeepalive"), 10, 16)
	isExitNode := r.FormValue("isExitNode") == "on"
	exitNodeID := r.FormValue("exitNodeID")
	if isExitNode {
		exitNodeID = ""
	}

	exitNodeAllowAll := r.FormValue("exitNodeAllowAll") == "on"
	exitNodeRoutes := parseRouteList(r.FormValue("exitNodeRoutes"))
	advertisedRoutes := parseRouteList(r.FormValue("advertisedRoutes"))
	policyRoutes := parseRouteList(r.FormValue("policyRoutes"))

	bgpEnabled, bgpConnect, bgpRedistributeConnected, bgpMaxReceivedPrefixLength, bgpMaxAdvertisedPrefixLength, bgpPeerIP, bgpPeerPort, bgpPeerASN, bgpRouteFilters, bgpExportFilters := parsePeerBGPForm(r)

	id, err := newPeerID()
	if err != nil {
		http.Error(w, fmt.Sprintf("ID generation failed: %v", err), http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	peer := models.Peer{
		ID:                           id,
		Name:                         strings.TrimSpace(r.FormValue("name")),
		PrivateKey:                   privKey,
		PublicKey:                    pubKey,
		PresharedKey:                 psk,
		AllowedIPs:                   strings.TrimSpace(r.FormValue("allowedIPs")),
		Endpoint:                     strings.TrimSpace(r.FormValue("endpoint")),
		PersistentKeepalive:          uint16(keepalive),
		DNS:                          strings.TrimSpace(r.FormValue("dns")),
		ClientAllowedIPs:             strings.TrimSpace(r.FormValue("clientAllowedIPs")),
		IsExitNode:                   isExitNode,
		ExitNodeID:                   exitNodeID,
		ExitNodeAllowAll:             exitNodeAllowAll,
		ExitNodeRoutes:               exitNodeRoutes,
		AdvertisedRoutes:             advertisedRoutes,
		PolicyRoutes:                 policyRoutes,
		StrictPolicyRouting:          r.FormValue("strictPolicyRouting") == "on",
		BGPEnabled:                   bgpEnabled,
		BGPConnect:                   bgpConnect,
		BGPRedistributeConnected:     bgpRedistributeConnected,
		BGPMaxReceivedPrefixLength:   bgpMaxReceivedPrefixLength,
		BGPMaxAdvertisedPrefixLength: bgpMaxAdvertisedPrefixLength,
		BGPPeerIP:                    bgpPeerIP,
		BGPPeerPort:                  bgpPeerPort,
		BGPPeerASN:                   bgpPeerASN,
		BGPRouteFilters:              bgpRouteFilters,
		BGPExportFilters:             bgpExportFilters,
		Enabled:                      r.FormValue("enabled") == "on",
		CreatedAt:                    now,
		UpdatedAt:                    now,
	}

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		// Auto-assign IP if empty.
		if peer.AllowedIPs == "" {
			usedIPs := make([]string, len(cfg.Peers))
			for i, p := range cfg.Peers {
				usedIPs[i] = p.AllowedIPs
			}
			ip, err := ipam.NextAvailableIP(cfg.Server.Address, usedIPs)
			if err != nil {
				return fmt.Errorf("auto-assign IP: %w", err)
			}
			peer.AllowedIPs = ip
		}

		assignNewPeerRoutingTables(&peer, cfg.Peers)

		// Validate.
		if errs := peer.Validate(models.GatewayNets(cfg.Server.Address, h.ztGatewayNets())); len(errs) > 0 {
			return errs
		}

		cfg.Peers = append(cfg.Peers, peer)
		return nil
	})

	if writeErr != nil {
		logRejected(r, writeErr)
		if renderApplyWarning(w, writeErr) {
			h.listPeersOOB(w, r)
			return
		}
		h.renderPeerFormError(w, peerFormData{IsNew: true, Peer: peer}, writeErr)
		return
	}

	// Success: return full peers list with OOB swap to close modal.
	// We return an empty string (200 OK) for the form target (#modal-container), which clears the modal.
	// The OOB swap updates the peers list in the background.
	h.listPeersOOB(w, r)
}

func assignNewPeerRoutingTables(peer *models.Peer, existing []models.Peer) {
	if peer.IsExitNode {
		peer.RoutingTableID = routing.AssignRoutingTableID(existing)
	}
	if len(peer.PolicyRoutes) > 0 {
		reserved := append(append([]models.Peer(nil), existing...), *peer)
		peer.PolicyRoutingTableID = routing.AssignRoutingTableID(reserved)
	}
}

// UpdatePeer handles PUT /peers/{id}.
func (h *handler) UpdatePeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	keepalive, _ := strconv.ParseUint(r.FormValue("persistentKeepalive"), 10, 16)
	isExitNode := r.FormValue("isExitNode") == "on"
	exitNodeID := r.FormValue("exitNodeID")
	if isExitNode {
		exitNodeID = ""
	}

	exitNodeAllowAll := r.FormValue("exitNodeAllowAll") == "on"
	exitNodeRoutes := parseRouteList(r.FormValue("exitNodeRoutes"))
	advertisedRoutes := parseRouteList(r.FormValue("advertisedRoutes"))
	policyRoutes := parseRouteList(r.FormValue("policyRoutes"))

	bgpEnabled, bgpConnect, bgpRedistributeConnected, bgpMaxReceivedPrefixLength, bgpMaxAdvertisedPrefixLength, bgpPeerIP, bgpPeerPort, bgpPeerASN, bgpRouteFilters, bgpExportFilters := parsePeerBGPForm(r)

	// Holds what the user submitted, so a rejected edit can be shown back to them
	// (the store rolls its own copy back on error).
	var submitted models.Peer

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		p := models.FindPeerByID(cfg.Peers, id)
		if p == nil {
			return fmt.Errorf("peer not found")
		}

		wasExitNode := p.IsExitNode

		p.Name = strings.TrimSpace(r.FormValue("name"))
		p.AllowedIPs = strings.TrimSpace(r.FormValue("allowedIPs"))
		p.Endpoint = strings.TrimSpace(r.FormValue("endpoint"))
		p.PersistentKeepalive = uint16(keepalive)
		p.DNS = strings.TrimSpace(r.FormValue("dns"))
		p.ClientAllowedIPs = strings.TrimSpace(r.FormValue("clientAllowedIPs"))
		p.IsExitNode = isExitNode
		p.ExitNodeID = exitNodeID
		p.ExitNodeAllowAll = exitNodeAllowAll
		p.ExitNodeRoutes = exitNodeRoutes
		p.AdvertisedRoutes = advertisedRoutes
		p.PolicyRoutes = policyRoutes
		p.StrictPolicyRouting = r.FormValue("strictPolicyRouting") == "on"
		p.BGPEnabled = bgpEnabled
		p.BGPConnect = bgpConnect
		p.BGPRedistributeConnected = bgpRedistributeConnected
		p.BGPMaxReceivedPrefixLength = bgpMaxReceivedPrefixLength
		p.BGPMaxAdvertisedPrefixLength = bgpMaxAdvertisedPrefixLength
		p.BGPPeerIP = bgpPeerIP
		p.BGPPeerPort = bgpPeerPort
		p.BGPPeerASN = bgpPeerASN
		p.BGPRouteFilters = bgpRouteFilters
		p.BGPExportFilters = bgpExportFilters
		p.Enabled = r.FormValue("enabled") == "on"
		p.UpdatedAt = time.Now().UTC()

		// Handle exit node transitions.
		if isExitNode && p.RoutingTableID == 0 {
			p.RoutingTableID = routing.AssignRoutingTableID(cfg.Peers)
		}
		if !isExitNode {
			p.RoutingTableID = 0
		}

		// Handle policy routes transitions.
		if len(policyRoutes) > 0 && p.PolicyRoutingTableID == 0 {
			p.PolicyRoutingTableID = routing.AssignRoutingTableID(cfg.Peers)
		}
		if len(policyRoutes) == 0 {
			p.PolicyRoutingTableID = 0
		}

		// If this peer was an exit node and no longer is, cascade clear.
		if wasExitNode && !isExitNode {
			models.CascadeClearExitNode(cfg.Peers, id)
		}

		if errs := p.Validate(models.GatewayNets(cfg.Server.Address, h.ztGatewayNets())); len(errs) > 0 {
			submitted = *p
			return errs
		}

		submitted = *p
		return nil
	})

	if writeErr != nil {
		logRejected(r, writeErr)
		if renderApplyWarning(w, writeErr) {
			h.listPeersOOB(w, r)
			return
		}
		if _, ok := writeErr.(models.ValidationErrors); !ok {
			http.Error(w, writeErr.Error(), http.StatusInternalServerError)
			return
		}
		h.renderPeerFormError(w, peerFormData{Peer: submitted}, writeErr)
		return
	}

	h.listPeersOOB(w, r)
}

// DeletePeer handles DELETE /peers/{id}.
func (h *handler) DeletePeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	err := h.store.Write(func(cfg *models.AppConfig) error {
		idx := -1
		for i, p := range cfg.Peers {
			if p.ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			return fmt.Errorf("peer not found")
		}

		// Cascade clear if this was an exit node.
		if cfg.Peers[idx].IsExitNode {
			models.CascadeClearExitNode(cfg.Peers, id)
		}

		cfg.Peers = append(cfg.Peers[:idx], cfg.Peers[idx+1:]...)
		return nil
	})

	if err != nil {
		if !renderApplyWarning(w, err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Return full peers list so the UI updates.
	h.ListPeers(w, r)
}

// TogglePeer handles PUT /peers/{id}/toggle.
func (h *handler) TogglePeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var peer models.Peer
	err := h.store.Write(func(cfg *models.AppConfig) error {
		p := models.FindPeerByID(cfg.Peers, id)
		if p == nil {
			return fmt.Errorf("peer not found")
		}

		p.Enabled = !p.Enabled
		p.UpdatedAt = time.Now().UTC()

		// If disabling an exit node, cascade clear.
		if !p.Enabled && p.IsExitNode {
			models.CascadeClearExitNode(cfg.Peers, id)
		}

		peer = *p
		return nil
	})

	if err != nil {
		if !renderApplyWarning(w, err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	exitNodeName := ""
	if peer.ExitNodeID != "" {
		h.store.Read(func(cfg *models.AppConfig) {
			en := models.FindPeerByID(cfg.Peers, peer.ExitNodeID)
			if en != nil {
				exitNodeName = en.Name
			}
		})
	}

	var stats wgstats.PeerStats
	if h.stats != nil {
		if ps := h.stats.GetPeerStats(peer.PublicKey); ps != nil {
			stats = *ps
		}
	}
	data := h.buildPeerRow(peer, exitNodeName, stats)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "peer-row", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// RegeneratePeerKeys handles POST /api/peers/{id}/regenerate-keys.
func (h *handler) RegeneratePeerKeys(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	err := h.store.Write(func(cfg *models.AppConfig) error {
		p := models.FindPeerByID(cfg.Peers, id)
		if p == nil {
			return fmt.Errorf("peer not found")
		}

		privKey, pubKey, err := wireguard.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("key generation: %w", err)
		}

		p.PrivateKey = privKey
		p.PublicKey = pubKey
		p.LastSeen = time.Time{}
		p.UpdatedAt = time.Now().UTC()
		return nil
	})

	if err != nil {
		if !renderApplyWarning(w, err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Return the edit form with updated data.
	h.GetPeerForm(w, r)
}

// renderPeerFormError re-renders the form with the rejected input still in it.
// Validation errors are listed per field; anything else is shown as one message.
func (h *handler) renderPeerFormError(w http.ResponseWriter, data peerFormData, writeErr error) {
	if ve, ok := writeErr.(models.ValidationErrors); ok {
		data.ValidationErrors = ve
	} else {
		data.Error = writeErr.Error()
	}
	h.store.Read(func(cfg *models.AppConfig) {
		data.ExitNodes = models.ExitNodePeers(cfg.Peers)
		data.Gateways = models.GatewayNets(cfg.Server.Address, h.ztGatewayNets())
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = templates.ExecuteTemplate(w, "peer-form", data)
}

// newPeerID returns a random opaque ID for a new peer.
func newPeerID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// parseRouteList splits a routes textarea into entries. Browsers submit CRLF,
// and the fields accept commas as well as newlines — but never spaces: a policy
// route is "CIDR via IP".
func parseRouteList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (h *handler) listPeersOOB(w http.ResponseWriter, r *http.Request) {
	data := h.buildPeersListData()
	data.OOB = true
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "peers-list", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func parsePeerBGPForm(r *http.Request) (bgpEnabled, bgpConnect, bgpRedistributeConnected bool, bgpMaxReceivedPrefixLength, bgpMaxAdvertisedPrefixLength uint16, bgpPeerIP string, bgpPeerPort uint16, bgpPeerASN uint32, bgpRouteFilters, bgpExportFilters []models.RouteFilter) {
	bgpEnabled = r.FormValue("bgpEnabled") == "on"
	bgpConnect = r.FormValue("bgpConnect") == "on"
	bgpRedistributeConnected = r.FormValue("bgpRedistributeConnected") == "on"
	bgpMaxReceivedPrefixLength = parseMaxPrefixLength(r.FormValue("bgpMaxReceivedPrefixLength"))
	bgpMaxAdvertisedPrefixLength = parseMaxPrefixLength(r.FormValue("bgpMaxAdvertisedPrefixLength"))
	bgpPeerIP = strings.TrimSpace(r.FormValue("bgpPeerIP"))

	port, _ := strconv.ParseUint(r.FormValue("bgpPeerPort"), 10, 16)
	if bgpEnabled && port == 0 {
		port = 179
	}
	bgpPeerPort = uint16(port)

	asn, _ := strconv.ParseUint(r.FormValue("bgpPeerAsn"), 10, 32)
	if bgpEnabled && asn == 0 {
		asn = 64512
	}
	bgpPeerASN = uint32(asn)

	bgpRouteFilters = parseRouteFilterForm(r, "filterPrefix[]", "filterMatcher[]", "filterAction[]")
	bgpExportFilters = parseRouteFilterForm(r, "exportFilterPrefix[]", "exportFilterMatcher[]", "exportFilterAction[]")

	return
}

func parseMaxPrefixLength(value string) uint16 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	length, err := strconv.ParseUint(value, 10, 16)
	if err != nil || length > 128 {
		return 129 // Preserve an invalid value so model validation rejects the form.
	}
	return uint16(length)
}

// parseRouteFilterForm reads a route-filter row list from a submitted form,
// shared by the import (received) and export (advertised) filter sections on
// both the WireGuard peer form and the custom BGP peer form.
func parseRouteFilterForm(r *http.Request, prefixField, matcherField, actionField string) []models.RouteFilter {
	var filters []models.RouteFilter
	prefixes := r.Form[prefixField]
	matchers := r.Form[matcherField]
	actions := r.Form[actionField]

	for i := 0; i < len(prefixes); i++ {
		pfx := strings.TrimSpace(prefixes[i])
		if pfx == "" {
			continue
		}
		matcher := "exact"
		if i < len(matchers) {
			matcher = strings.TrimSpace(matchers[i])
		}
		action := "accept"
		if i < len(actions) {
			action = strings.TrimSpace(actions[i])
		}

		filters = append(filters, models.RouteFilter{
			Prefix:  pfx,
			Matcher: matcher,
			Action:  action,
		})
	}

	return filters
}
