package models

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AppConfig is the top-level structure persisted to YAML.
type AppConfig struct {
	Server ServerConfig `yaml:"server"`
	Peers  []Peer       `yaml:"peers"`
}

// ServerConfig represents the [Interface] section of wg0.conf.
type ServerConfig struct {
	PrivateKey string `yaml:"privateKey"`
	ListenPort uint16 `yaml:"listenPort"`
	Address    string `yaml:"address"`
	Endpoint   string `yaml:"endpoint,omitempty"`
	DNS        string `yaml:"dns,omitempty"`
	MTU        uint16 `yaml:"mtu,omitempty"`
	Table      string `yaml:"table,omitempty"`
	FwMark     string `yaml:"fwMark,omitempty"`
	PreUp      string `yaml:"preUp,omitempty"`
	PostUp     string `yaml:"postUp,omitempty"`
	PreDown    string `yaml:"preDown,omitempty"`
	PostDown   string `yaml:"postDown,omitempty"`
	SaveConfig bool   `yaml:"saveConfig,omitempty"`
}

// Peer represents a WireGuard peer (client).
type Peer struct {
	ID                  string    `yaml:"id"`
	Name                string    `yaml:"name"`
	PrivateKey          string    `yaml:"privateKey"`
	PublicKey           string    `yaml:"publicKey"`
	PresharedKey        string    `yaml:"presharedKey,omitempty"`
	AllowedIPs          string    `yaml:"allowedIPs"`
	Endpoint            string    `yaml:"endpoint,omitempty"`
	PersistentKeepalive uint16    `yaml:"persistentKeepalive,omitempty"`
	DNS                 string    `yaml:"dns,omitempty"`
	ClientAllowedIPs    string    `yaml:"clientAllowedIPs,omitempty"`
	IsExitNode          bool      `yaml:"isExitNode,omitempty"`
	ExitNodeID          string    `yaml:"exitNodeID,omitempty"`
	RoutingTableID      uint      `yaml:"routingTableID,omitempty"`
	Enabled             bool      `yaml:"enabled"`
	CreatedAt           time.Time `yaml:"createdAt"`
	UpdatedAt           time.Time `yaml:"updatedAt"`
}

// ValidationError represents a single field validation error.
type ValidationError struct {
	Field   string
	Message string
}

// ValidationErrors collects multiple validation errors.
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	msgs := make([]string, len(ve))
	for i, e := range ve {
		msgs[i] = fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return strings.Join(msgs, "; ")
}

// HasField returns true if there is an error for the given field.
func (ve ValidationErrors) HasField(field string) bool {
	for _, e := range ve {
		if e.Field == field {
			return true
		}
	}
	return false
}

// Validate checks all fields on ServerConfig and returns all errors found.
func (s *ServerConfig) Validate() ValidationErrors {
	var errs ValidationErrors

	if s.PrivateKey == "" {
		errs = append(errs, ValidationError{Field: "privateKey", Message: "required"})
	} else if !isValidBase64Key(s.PrivateKey) {
		errs = append(errs, ValidationError{Field: "privateKey", Message: "must be a 44-character base64 key"})
	}

	if s.ListenPort == 0 {
		errs = append(errs, ValidationError{Field: "listenPort", Message: "required and must be > 0"})
	}

	if s.Address == "" {
		errs = append(errs, ValidationError{Field: "address", Message: "required"})
	} else if !isValidCIDRList(s.Address) {
		errs = append(errs, ValidationError{Field: "address", Message: "must be valid CIDR (e.g. 10.0.0.1/24)"})
	}

	if s.Endpoint != "" && !isValidEndpoint(s.Endpoint) {
		errs = append(errs, ValidationError{Field: "endpoint", Message: "must be host:port"})
	}

	if s.DNS != "" && !isValidDNSList(s.DNS) {
		errs = append(errs, ValidationError{Field: "dns", Message: "must be comma-separated IPs or hostnames"})
	}

	if s.MTU != 0 && s.MTU < 1280 {
		errs = append(errs, ValidationError{Field: "mtu", Message: "must be 1280-65535"})
	}

	if s.Table != "" && !isValidTable(s.Table) {
		errs = append(errs, ValidationError{Field: "table", Message: "must be 'off', 'auto', or a numeric value"})
	}

	if s.FwMark != "" && !isValidFwMark(s.FwMark) {
		errs = append(errs, ValidationError{Field: "fwMark", Message: "must be a number, hex (0x...), or 'off'"})
	}

	if len(s.PreUp) > 4096 {
		errs = append(errs, ValidationError{Field: "preUp", Message: "maximum 4096 characters"})
	}
	if len(s.PostUp) > 4096 {
		errs = append(errs, ValidationError{Field: "postUp", Message: "maximum 4096 characters"})
	}
	if len(s.PreDown) > 4096 {
		errs = append(errs, ValidationError{Field: "preDown", Message: "maximum 4096 characters"})
	}
	if len(s.PostDown) > 4096 {
		errs = append(errs, ValidationError{Field: "postDown", Message: "maximum 4096 characters"})
	}

	return errs
}

var nameRegexp = regexp.MustCompile(`^[a-zA-Z0-9 _.\-]+$`)

// Validate checks all fields on Peer and returns all errors found.
func (p *Peer) Validate() ValidationErrors {
	var errs ValidationErrors

	if strings.TrimSpace(p.Name) == "" {
		errs = append(errs, ValidationError{Field: "name", Message: "required"})
	} else if len(p.Name) > 64 {
		errs = append(errs, ValidationError{Field: "name", Message: "maximum 64 characters"})
	} else if !nameRegexp.MatchString(p.Name) {
		errs = append(errs, ValidationError{Field: "name", Message: "only letters, numbers, spaces, dashes, dots, underscores"})
	}

	if p.PrivateKey == "" {
		errs = append(errs, ValidationError{Field: "privateKey", Message: "required"})
	} else if !isValidBase64Key(p.PrivateKey) {
		errs = append(errs, ValidationError{Field: "privateKey", Message: "must be a 44-character base64 key"})
	}

	if p.PublicKey == "" {
		errs = append(errs, ValidationError{Field: "publicKey", Message: "required"})
	} else if !isValidBase64Key(p.PublicKey) {
		errs = append(errs, ValidationError{Field: "publicKey", Message: "must be a 44-character base64 key"})
	}

	if p.PresharedKey != "" && !isValidBase64Key(p.PresharedKey) {
		errs = append(errs, ValidationError{Field: "presharedKey", Message: "must be a 44-character base64 key"})
	}

	if p.AllowedIPs == "" {
		errs = append(errs, ValidationError{Field: "allowedIPs", Message: "required"})
	} else if !isValidCIDRList(p.AllowedIPs) {
		errs = append(errs, ValidationError{Field: "allowedIPs", Message: "must be comma-separated CIDRs"})
	}

	if p.Endpoint != "" && !isValidEndpoint(p.Endpoint) {
		errs = append(errs, ValidationError{Field: "endpoint", Message: "must be host:port"})
	}

	if p.ClientAllowedIPs != "" && !isValidCIDRList(p.ClientAllowedIPs) {
		errs = append(errs, ValidationError{Field: "clientAllowedIPs", Message: "must be comma-separated CIDRs"})
	}

	if p.DNS != "" && !isValidDNSList(p.DNS) {
		errs = append(errs, ValidationError{Field: "dns", Message: "must be comma-separated IPs or hostnames"})
	}

	if p.IsExitNode && p.ExitNodeID != "" {
		errs = append(errs, ValidationError{Field: "exitNodeID", Message: "a peer cannot be both an exit node and use an exit node"})
	}

	return errs
}

// ValidateExitNodeRefs validates exit node references against the full peer list.
// This is called separately since it requires cross-peer validation.
func ValidateExitNodeRefs(peers []Peer) ValidationErrors {
	var errs ValidationErrors

	exitNodes := make(map[string]bool)
	for _, p := range peers {
		if p.IsExitNode && p.Enabled {
			exitNodes[p.ID] = true
		}
	}

	for _, p := range peers {
		if p.ExitNodeID != "" {
			if !exitNodes[p.ExitNodeID] {
				errs = append(errs, ValidationError{
					Field:   fmt.Sprintf("peers[%s].exitNodeID", p.ID),
					Message: fmt.Sprintf("references non-existent or disabled exit node %q", p.ExitNodeID),
				})
			}
		}
	}

	return errs
}

// CascadeClearExitNode removes all references to the given exit node peer ID.
func CascadeClearExitNode(peers []Peer, exitNodeID string) {
	for i := range peers {
		if peers[i].ExitNodeID == exitNodeID {
			peers[i].ExitNodeID = ""
		}
	}
}

// FindPeerByID returns a pointer to the peer with the given ID, or nil.
func FindPeerByID(peers []Peer, id string) *Peer {
	for i := range peers {
		if peers[i].ID == id {
			return &peers[i]
		}
	}
	return nil
}

// ExitNodePeers returns all enabled peers marked as exit nodes.
func ExitNodePeers(peers []Peer) []Peer {
	var result []Peer
	for _, p := range peers {
		if p.IsExitNode && p.Enabled {
			result = append(result, p)
		}
	}
	return result
}

// --- Validation helpers ---

func isValidBase64Key(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 44 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func isValidCIDRList(s string) bool {
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		_, _, err := net.ParseCIDR(part)
		if err != nil {
			return false
		}
	}
	return true
}

var hostnameRegexp = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$`)

func isValidDNSList(s string) bool {
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		if net.ParseIP(part) != nil {
			continue
		}
		if hostnameRegexp.MatchString(part) {
			continue
		}
		return false
	}
	return true
}

func isValidEndpoint(s string) bool {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port >= 1 && port <= 65535
}

func isValidTable(s string) bool {
	if s == "off" || s == "auto" {
		return true
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0
}

func isValidFwMark(s string) bool {
	if s == "off" {
		return true
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		_, err := strconv.ParseUint(s[2:], 16, 32)
		return err == nil
	}
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

// FirstIP extracts the IP (without mask) from a CIDR string.
// Returns empty string if invalid.
func FirstIP(cidr string) string {
	cidr = strings.TrimSpace(strings.Split(cidr, ",")[0])
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	return ip.String()
}
