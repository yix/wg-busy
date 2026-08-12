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
	Handshake    string
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
		row := peerRowData{Peer: p}
		if p.ExitNodeID != "" {
			row.ExitNodeName = exitNodeNames[p.ExitNodeID]
		}

		// Attach stats by public key.
		if allPeerStats != nil {
			if ps, ok := allPeerStats[p.PublicKey]; ok {
				row.HasStats = true
				row.Endpoint = ps.Endpoint
				row.TransferRx = wgstats.FormatBytes(ps.TransferRx)
				row.TransferTx = wgstats.FormatBytes(ps.TransferTx)
				row.CurrentRxPS = wgstats.FormatBytesPerSec(ps.CurrentRxPS)
				row.CurrentTxPS = wgstats.FormatBytesPerSec(ps.CurrentTxPS)
				row.Handshake = wgstats.FormatHandshake(ps.LatestHandshake)
				if h.stats != nil {
					row.SparklineSVG = wgstats.RenderSparklineSVG(h.stats.GetPeerHistory(p.PublicKey), 80, 16)
				}
			}
		}

		data.Peers = append(data.Peers, row)
	}
	return data
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

	bgpEnabled, bgpConnect, bgpPeerIP, bgpPeerPort, bgpPeerASN, bgpRouteFilters := parsePeerBGPForm(r)

	id, err := newPeerID()
	if err != nil {
		http.Error(w, fmt.Sprintf("ID generation failed: %v", err), http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	peer := models.Peer{
		ID:                  id,
		Name:                strings.TrimSpace(r.FormValue("name")),
		PrivateKey:          privKey,
		PublicKey:           pubKey,
		PresharedKey:        psk,
		AllowedIPs:          strings.TrimSpace(r.FormValue("allowedIPs")),
		Endpoint:            strings.TrimSpace(r.FormValue("endpoint")),
		PersistentKeepalive: uint16(keepalive),
		DNS:                 strings.TrimSpace(r.FormValue("dns")),
		ClientAllowedIPs:    strings.TrimSpace(r.FormValue("clientAllowedIPs")),
		IsExitNode:          isExitNode,
		ExitNodeID:          exitNodeID,
		ExitNodeAllowAll:    exitNodeAllowAll,
		ExitNodeRoutes:      exitNodeRoutes,
		AdvertisedRoutes:    advertisedRoutes,
		PolicyRoutes:        policyRoutes,
		StrictPolicyRouting: r.FormValue("strictPolicyRouting") == "on",
		BGPEnabled:          bgpEnabled,
		BGPConnect:          bgpConnect,
		BGPPeerIP:           bgpPeerIP,
		BGPPeerPort:         bgpPeerPort,
		BGPPeerASN:          bgpPeerASN,
		BGPRouteFilters:     bgpRouteFilters,
		Enabled:             r.FormValue("enabled") == "on",
		CreatedAt:           now,
		UpdatedAt:           now,
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

		// Auto-assign routing table ID if exit node.
		if peer.IsExitNode {
			peer.RoutingTableID = routing.AssignRoutingTableID(cfg.Peers)
		}

		// Auto-assign policy routing table ID if policy routes exist.
		if len(peer.PolicyRoutes) > 0 {
			peer.PolicyRoutingTableID = routing.AssignRoutingTableID(cfg.Peers)
		}

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

	bgpEnabled, bgpConnect, bgpPeerIP, bgpPeerPort, bgpPeerASN, bgpRouteFilters := parsePeerBGPForm(r)

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
		p.BGPPeerIP = bgpPeerIP
		p.BGPPeerPort = bgpPeerPort
		p.BGPPeerASN = bgpPeerASN
		p.BGPRouteFilters = bgpRouteFilters
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

	data := peerRowData{Peer: peer, ExitNodeName: exitNodeName}

	// Attach stats if available.
	if h.stats != nil {
		if ps := h.stats.GetPeerStats(peer.PublicKey); ps != nil {
			data.HasStats = true
			data.Endpoint = ps.Endpoint
			data.TransferRx = wgstats.FormatBytes(ps.TransferRx)
			data.TransferTx = wgstats.FormatBytes(ps.TransferTx)
			data.Handshake = wgstats.FormatHandshake(ps.LatestHandshake)
			data.SparklineSVG = wgstats.RenderSparklineSVG(h.stats.GetPeerHistory(peer.PublicKey), 80, 16)
		}
	}

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

func parsePeerBGPForm(r *http.Request) (bool, bool, string, uint16, uint32, []models.RouteFilter) {
	bgpEnabled := r.FormValue("bgpEnabled") == "on"
	bgpConnect := r.FormValue("bgpConnect") == "on"
	bgpPeerIP := strings.TrimSpace(r.FormValue("bgpPeerIP"))

	bgpPeerPort, _ := strconv.ParseUint(r.FormValue("bgpPeerPort"), 10, 16)
	if bgpEnabled && bgpPeerPort == 0 {
		bgpPeerPort = 179
	}

	bgpPeerASN, _ := strconv.ParseUint(r.FormValue("bgpPeerAsn"), 10, 32)
	if bgpEnabled && bgpPeerASN == 0 {
		bgpPeerASN = 64512
	}

	var bgpRouteFilters []models.RouteFilter
	prefixes := r.Form["filterPrefix[]"]
	matchers := r.Form["filterMatcher[]"]
	actions := r.Form["filterAction[]"]

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

		bgpRouteFilters = append(bgpRouteFilters, models.RouteFilter{
			Prefix:  pfx,
			Matcher: matcher,
			Action:  action,
		})
	}

	return bgpEnabled, bgpConnect, bgpPeerIP, uint16(bgpPeerPort), uint32(bgpPeerASN), bgpRouteFilters
}
