package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yix/wg-busy/internal/bgp"
	"github.com/yix/wg-busy/internal/models"
)

// bgpTabData is the template data for the BGP tab: live session stats plus the
// configured standalone (non-WireGuard) BGP peers.
type bgpTabData struct {
	BGPServer        bgpServerConfigData
	BGPStats         *models.BGPStats
	CustomPeers      bgpCustomPeersData
	Success          string
	Error            string
	ValidationErrors models.ValidationErrors
}

type bgpServerConfigData struct {
	Enabled       bool
	ASN           uint32
	ListenAddress string
	ListenPort    uint16
}

// GetBGPStatsTab returns the BGP statistics data.
func (h *handler) GetBGPStatsTab(w http.ResponseWriter, r *http.Request) {
	writePageJSON(w, http.StatusOK, "bgp-tab", h.buildBGPTabData(), nil)
}

func (h *handler) buildBGPTabData() bgpTabData {
	data := bgpTabData{BGPStats: bgp.GetBGPStats()}
	h.store.Read(func(cfg *models.AppConfig) {
		data.BGPServer = bgpServerConfigData{
			Enabled:       cfg.Server.BGPEnabled,
			ASN:           cfg.Server.BGPASN,
			ListenAddress: cfg.Server.BGPListenAddress,
			ListenPort:    cfg.Server.BGPListenPort,
		}
		data.CustomPeers.Peers = cfg.BGPPeers
	})
	return data
}

// UpdateBGPServerConfig updates only the global BGP listener settings.
func (h *handler) UpdateBGPServerConfig(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writePageError(w, http.StatusBadRequest, fmt.Errorf("bad request"))
		return
	}

	port, _ := strconv.ParseUint(r.FormValue("bgpListenPort"), 10, 16)
	asn, _ := strconv.ParseUint(r.FormValue("bgpAsn"), 10, 32)
	submitted := bgpServerConfigData{
		Enabled:       r.FormValue("bgpEnabled") == "on",
		ASN:           uint32(asn),
		ListenAddress: strings.TrimSpace(r.FormValue("bgpListenAddress")),
		ListenPort:    uint16(port),
	}

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		cfg.Server.BGPEnabled = submitted.Enabled
		cfg.Server.BGPASN = submitted.ASN
		cfg.Server.BGPListenAddress = submitted.ListenAddress
		cfg.Server.BGPListenPort = submitted.ListenPort
		return nil
	})

	data := h.buildBGPTabData()
	if writeErr != nil {
		logRejected(r, writeErr)
		if ve, ok := writeErr.(models.ValidationErrors); ok {
			data.BGPServer = submitted
			data.ValidationErrors = ve
			writePageJSON(w, http.StatusUnprocessableEntity, "bgp-tab", data, nil)
			return
		}
		if warning, ok := applyWarning(writeErr); ok {
			writePageJSON(w, http.StatusOK, "bgp-tab", data, &warning)
			return
		}
		data.Error = writeErr.Error()
		writePageJSON(w, http.StatusInternalServerError, "bgp-tab", data, nil)
		return
	}

	data.Success = "BGP server configuration saved successfully."
	writePageJSON(w, http.StatusOK, "bgp-tab", data, nil)
}

// bgpPeerFormData is the template data for the custom BGP peer create/edit form.
type bgpPeerFormData struct {
	IsNew bool
	// Defaults renders a blank form with default values checked, mirroring the
	// WireGuard peer form's behavior.
	Defaults         bool
	Peer             models.BGPPeer
	Error            string
	ValidationErrors models.ValidationErrors
}

// GetBGPPeerForm returns the custom BGP peer create or edit form dialog.
func (h *handler) GetBGPPeerForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	isNew := id == ""

	data := bgpPeerFormData{IsNew: isNew, Defaults: isNew}

	if !isNew {
		h.store.Read(func(cfg *models.AppConfig) {
			if p := models.FindBGPPeerByID(cfg.BGPPeers, id); p != nil {
				data.Peer = *p
			}
		})
		if data.Peer.ID == "" {
			writePageError(w, http.StatusNotFound, fmt.Errorf("BGP peer not found"))
			return
		}
	}

	writePageJSON(w, http.StatusOK, "bgp-peer-form", data, nil)
}

// CreateBGPPeer handles POST /bgp/peers.
func (h *handler) CreateBGPPeer(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writePageError(w, http.StatusBadRequest, fmt.Errorf("bad request"))
		return
	}

	id, err := newPeerID()
	if err != nil {
		writePageError(w, http.StatusInternalServerError, fmt.Errorf("ID generation failed: %w", err))
		return
	}

	bgpConnect, bgpRedistributeConnected, bgpMaxReceivedPrefixLength, bgpMaxAdvertisedPrefixLength, bgpPeerIP, bgpPeerPort, bgpPeerASN, bgpRouteFilters, bgpExportFilters := parseBGPPeerForm(r)

	now := time.Now().UTC()
	peer := models.BGPPeer{
		ID:                        id,
		Name:                      strings.TrimSpace(r.FormValue("name")),
		Enabled:                   r.FormValue("enabled") == "on",
		Connect:                   bgpConnect,
		RedistributeConnected:     bgpRedistributeConnected,
		MaxReceivedPrefixLength:   bgpMaxReceivedPrefixLength,
		MaxAdvertisedPrefixLength: bgpMaxAdvertisedPrefixLength,
		PeerIP:                    bgpPeerIP,
		PeerPort:                  bgpPeerPort,
		PeerASN:                   bgpPeerASN,
		RouteFilters:              bgpRouteFilters,
		ExportFilters:             bgpExportFilters,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		if errs := peer.Validate(); len(errs) > 0 {
			return errs
		}
		cfg.BGPPeers = append(cfg.BGPPeers, peer)
		return nil
	})

	if writeErr != nil {
		logRejected(r, writeErr)
		if warning, ok := applyWarning(writeErr); ok {
			h.listBGPPeersOOB(w, r, &warning)
			return
		}
		h.renderBGPPeerFormError(w, bgpPeerFormData{IsNew: true, Peer: peer}, writeErr)
		return
	}

	h.listBGPPeersOOB(w, r, nil)
}

// UpdateBGPPeer handles PUT /bgp/peers/{id}.
func (h *handler) UpdateBGPPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		writePageError(w, http.StatusBadRequest, fmt.Errorf("bad request"))
		return
	}

	bgpConnect, bgpRedistributeConnected, bgpMaxReceivedPrefixLength, bgpMaxAdvertisedPrefixLength, bgpPeerIP, bgpPeerPort, bgpPeerASN, bgpRouteFilters, bgpExportFilters := parseBGPPeerForm(r)

	var submitted models.BGPPeer

	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		p := models.FindBGPPeerByID(cfg.BGPPeers, id)
		if p == nil {
			return fmt.Errorf("BGP peer not found")
		}

		p.Name = strings.TrimSpace(r.FormValue("name"))
		p.Enabled = r.FormValue("enabled") == "on"
		p.Connect = bgpConnect
		p.RedistributeConnected = bgpRedistributeConnected
		p.MaxReceivedPrefixLength = bgpMaxReceivedPrefixLength
		p.MaxAdvertisedPrefixLength = bgpMaxAdvertisedPrefixLength
		p.PeerIP = bgpPeerIP
		p.PeerPort = bgpPeerPort
		p.PeerASN = bgpPeerASN
		p.RouteFilters = bgpRouteFilters
		p.ExportFilters = bgpExportFilters
		p.UpdatedAt = time.Now().UTC()

		if errs := p.Validate(); len(errs) > 0 {
			submitted = *p
			return errs
		}

		submitted = *p
		return nil
	})

	if writeErr != nil {
		logRejected(r, writeErr)
		if warning, ok := applyWarning(writeErr); ok {
			h.listBGPPeersOOB(w, r, &warning)
			return
		}
		if _, ok := writeErr.(models.ValidationErrors); !ok {
			writePageError(w, http.StatusInternalServerError, writeErr)
			return
		}
		h.renderBGPPeerFormError(w, bgpPeerFormData{Peer: submitted}, writeErr)
		return
	}

	h.listBGPPeersOOB(w, r, nil)
}

// DeleteBGPPeer handles DELETE /bgp/peers/{id}.
func (h *handler) DeleteBGPPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	err := h.store.Write(func(cfg *models.AppConfig) error {
		idx := -1
		for i, p := range cfg.BGPPeers {
			if p.ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			return fmt.Errorf("BGP peer not found")
		}
		cfg.BGPPeers = append(cfg.BGPPeers[:idx], cfg.BGPPeers[idx+1:]...)
		return nil
	})

	var warning *toastData
	if err != nil {
		if value, ok := applyWarning(err); ok {
			warning = &value
		} else {
			writePageError(w, http.StatusInternalServerError, err)
			return
		}
	}

	writePageJSON(w, http.StatusOK, "bgp-tab", h.buildBGPTabData(), warning)
}

// renderBGPPeerFormError re-renders the form with the rejected input still in it.
func (h *handler) renderBGPPeerFormError(w http.ResponseWriter, data bgpPeerFormData, writeErr error) {
	if ve, ok := writeErr.(models.ValidationErrors); ok {
		data.ValidationErrors = ve
	} else {
		data.Error = writeErr.Error()
	}
	writePageJSON(w, http.StatusUnprocessableEntity, "bgp-peer-form", data, nil)
}

func (h *handler) listBGPPeersOOB(w http.ResponseWriter, r *http.Request, warning *toastData) {
	var peers []models.BGPPeer
	h.store.Read(func(cfg *models.AppConfig) {
		peers = cfg.BGPPeers
	})
	writePageJSON(w, http.StatusOK, "bgp-custom-peers", bgpCustomPeersData{Peers: peers, OOB: true}, warning)
}

// bgpCustomPeersData is the template data for the custom BGP peers list section.
type bgpCustomPeersData struct {
	Peers []models.BGPPeer
	OOB   bool
}

func parseBGPPeerForm(r *http.Request) (connect, redistributeConnected bool, maxReceivedPrefixLength, maxAdvertisedPrefixLength uint16, peerIP string, peerPort uint16, peerASN uint32, routeFilters, exportFilters []models.RouteFilter) {
	connect = r.FormValue("connect") == "on" || r.FormValue("bgpConnect") == "on"
	redistributeConnected = r.FormValue("redistributeConnected") == "on" || r.FormValue("bgpRedistributeConnected") == "on"
	maxReceivedPrefixLength = parseMaxPrefixLength(r.FormValue("maxReceivedPrefixLength"))
	if maxReceivedPrefixLength == 0 {
		maxReceivedPrefixLength = parseMaxPrefixLength(r.FormValue("bgpMaxReceivedPrefixLength"))
	}
	maxAdvertisedPrefixLength = parseMaxPrefixLength(r.FormValue("maxAdvertisedPrefixLength"))
	if maxAdvertisedPrefixLength == 0 {
		maxAdvertisedPrefixLength = parseMaxPrefixLength(r.FormValue("bgpMaxAdvertisedPrefixLength"))
	}
	peerIP = strings.TrimSpace(r.FormValue("peerIP"))
	if peerIP == "" {
		peerIP = strings.TrimSpace(r.FormValue("bgpPeerIP"))
	}

	portVal := r.FormValue("peerPort")
	if portVal == "" {
		portVal = r.FormValue("bgpPeerPort")
	}
	port, _ := strconv.ParseUint(portVal, 10, 16)
	if port == 0 {
		port = 179
	}
	peerPort = uint16(port)

	asnVal := r.FormValue("peerAsn")
	if asnVal == "" {
		asnVal = r.FormValue("bgpPeerAsn")
	}
	asn, _ := strconv.ParseUint(asnVal, 10, 32)
	if asn == 0 {
		asn = 64512
	}
	peerASN = uint32(asn)

	routeFilters = parseRouteFilterForm(r, "filterPrefix[]", "filterMatcher[]", "filterAction[]")
	exportFilters = parseRouteFilterForm(r, "exportFilterPrefix[]", "exportFilterMatcher[]", "exportFilterAction[]")

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

