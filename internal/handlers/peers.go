package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

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
	TransferRx   string
	TransferTx   string
	Handshake    string
	SparklineSVG string
	HasStats     bool
}

// peersListData is the template data for the peers list.
type peersListData struct {
	Peers []peerRowData
}

// peerFormData is the template data for the peer create/edit form.
type peerFormData struct {
	IsNew            bool
	Peer             models.Peer
	ExitNodes        []models.Peer
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
				row.TransferRx = wgstats.FormatBytes(ps.TransferRx)
				row.TransferTx = wgstats.FormatBytes(ps.TransferTx)
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

	data := peerFormData{IsNew: isNew}

	h.store.Read(func(cfg *models.AppConfig) {
		if !isNew {
			p := models.FindPeerByID(cfg.Peers, id)
			if p != nil {
				data.Peer = *p
			}
		}
		data.ExitNodes = models.ExitNodePeers(cfg.Peers)
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

	now := time.Now().UTC()
	peer := models.Peer{
		ID:                  uuid.New().String(),
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

		// Validate.
		if errs := peer.Validate(); len(errs) > 0 {
			return errs
		}

		cfg.Peers = append(cfg.Peers, peer)
		return nil
	})

	if writeErr != nil {
		if ve, ok := writeErr.(models.ValidationErrors); ok {
			data := peerFormData{
				IsNew:            true,
				Peer:             peer,
				ValidationErrors: ve,
			}
			h.store.Read(func(cfg *models.AppConfig) {
				data.ExitNodes = models.ExitNodePeers(cfg.Peers)
			})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnprocessableEntity)
			templates.ExecuteTemplate(w, "peer-form", data)
			return
		}
		data := peerFormData{IsNew: true, Peer: peer, Error: writeErr.Error()}
		h.store.Read(func(cfg *models.AppConfig) {
			data.ExitNodes = models.ExitNodePeers(cfg.Peers)
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnprocessableEntity)
		templates.ExecuteTemplate(w, "peer-form", data)
		return
	}

	// Success: return full peers list.
	h.ListPeers(w, r)
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
		p.Enabled = r.FormValue("enabled") == "on"
		p.UpdatedAt = time.Now().UTC()

		// Handle exit node transitions.
		if isExitNode && p.RoutingTableID == 0 {
			p.RoutingTableID = routing.AssignRoutingTableID(cfg.Peers)
		}
		if !isExitNode {
			p.RoutingTableID = 0
		}

		// If this peer was an exit node and no longer is, cascade clear.
		if wasExitNode && !isExitNode {
			models.CascadeClearExitNode(cfg.Peers, id)
		}

		if errs := p.Validate(); len(errs) > 0 {
			return errs
		}

		return nil
	})

	if writeErr != nil {
		if ve, ok := writeErr.(models.ValidationErrors); ok {
			data := peerFormData{ValidationErrors: ve}
			h.store.Read(func(cfg *models.AppConfig) {
				p := models.FindPeerByID(cfg.Peers, id)
				if p != nil {
					data.Peer = *p
				}
				data.ExitNodes = models.ExitNodePeers(cfg.Peers)
			})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnprocessableEntity)
			templates.ExecuteTemplate(w, "peer-form", data)
			return
		}
		http.Error(w, writeErr.Error(), http.StatusInternalServerError)
		return
	}

	h.ListPeers(w, r)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the edit form with updated data.
	h.GetPeerForm(w, r)
}

// GetPeersStats handles GET /peers/stats.
func (h *handler) GetPeersStats(w http.ResponseWriter, r *http.Request) {
	data := h.buildPeersListData()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	for _, peerRow := range data.Peers {
		if err := templates.ExecuteTemplate(w, "peer-stats-oob", peerRow); err != nil {
			// Log error but continue trying to render others?
			// Since we've already started writing to the response, we can't really error out cleanly.
			// Ideally we buffer, but for now direct write is okay.
			fmt.Printf("Error rendering peer stats for %s: %v\n", peerRow.Peer.ID, err)
		}
	}
}
