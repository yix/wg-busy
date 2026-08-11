// Package zerotier runs and manages the local ZeroTier One client.
package zerotier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yix/wg-busy/internal/models"
)

// Status is the subset of GET /status we display.
type Status struct {
	Address           string `json:"address"`
	Online            bool   `json:"online"`
	Version           string `json:"version"`
	TCPFallbackActive bool   `json:"tcpFallbackActive"`
	Clock             int64  `json:"clock"`
}

// Route is a managed route pushed by a network.
type Route struct {
	Target string `json:"target"`
	Via    string `json:"via"`
	Metric int    `json:"metric"`
}

// DNS is the DNS configuration pushed by a network.
type DNS struct {
	Domain  string   `json:"domain"`
	Servers []string `json:"servers"`
}

// Network is the subset of GET /network we display.
type Network struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Status            string   `json:"status"`
	Type              string   `json:"type"`
	MAC               string   `json:"mac"`
	MTU               int      `json:"mtu"`
	Bridge            bool     `json:"bridge"`
	BroadcastEnabled  bool     `json:"broadcastEnabled"`
	NetconfRevision   int      `json:"netconfRevision"`
	PortDeviceName    string   `json:"portDeviceName"`
	PortError         int      `json:"portError"`
	AssignedAddresses []string `json:"assignedAddresses"`
	Routes            []Route  `json:"routes"`
	DNS               DNS      `json:"dns"`
	AllowManaged      bool     `json:"allowManaged"`
	AllowGlobal       bool     `json:"allowGlobal"`
	AllowDefault      bool     `json:"allowDefault"`
	AllowDNS          bool     `json:"allowDNS"`
}

// Path is one physical path to a peer.
type Path struct {
	Address     string `json:"address"`
	LastSend    int64  `json:"lastSend"`
	LastReceive int64  `json:"lastReceive"`
	Active      bool   `json:"active"`
	Expired     bool   `json:"expired"`
	Preferred   bool   `json:"preferred"`
}

// Peer is the subset of GET /peer we display. ZeroTier reports no byte counters
// per peer, so traffic is only available per network interface.
type Peer struct {
	Address string `json:"address"`
	Version string `json:"version"`
	Role    string `json:"role"`
	Latency int    `json:"latency"`
	Paths   []Path `json:"paths"`
}

// Client talks to the ZeroTier One local control API on 127.0.0.1.
type Client struct {
	homeDir string
	port    uint16
	token   string
	http    *http.Client
}

// NewClient returns a client for the service with the given home directory and port.
func NewClient(homeDir string, port uint16) *Client {
	return &Client{
		homeDir: homeDir,
		port:    port,
		// Short timeout: a wedged daemon must not stall the supervisor's tick.
		http: &http.Client{Timeout: 2 * time.Second},
	}
}

// authToken reads authtoken.secret, which the service writes on first start.
func (c *Client) authToken() (string, error) {
	if c.token != "" {
		return c.token, nil
	}
	data, err := os.ReadFile(filepath.Join(c.homeDir, "authtoken.secret"))
	if err != nil {
		return "", fmt.Errorf("reading authtoken.secret: %w", err)
	}
	c.token = strings.TrimSpace(string(data))
	if c.token == "" {
		return "", fmt.Errorf("authtoken.secret is empty")
	}
	return c.token, nil
}

func (c *Client) do(method, path string, body, out any) error {
	token, err := c.authToken()
	if err != nil {
		return err
	}

	var reqBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		reqBody = bytes.NewReader(encoded)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d%s", c.port, path)
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-ZT1-Auth", token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(detail)))
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding %s response: %w", path, err)
	}
	return nil
}

// Status returns the local node's status.
func (c *Client) Status() (*Status, error) {
	var s Status
	if err := c.do(http.MethodGet, "/status", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Networks returns all networks the node has joined.
func (c *Client) Networks() ([]Network, error) {
	var n []Network
	if err := c.do(http.MethodGet, "/network", nil, &n); err != nil {
		return nil, err
	}
	return n, nil
}

// Peers returns all peers the node knows about.
func (c *Client) Peers() ([]Peer, error) {
	var p []Peer
	if err := c.do(http.MethodGet, "/peer", nil, &p); err != nil {
		return nil, err
	}
	return p, nil
}

// Join joins a network, or updates its settings if already joined — POST is
// idempotent, which is what lets a flag change take effect without a rejoin.
func (c *Client) Join(n models.ZeroTierNetwork) error {
	body := map[string]bool{
		"allowManaged": n.AllowManaged,
		"allowGlobal":  n.AllowGlobal,
		"allowDefault": n.AllowDefault,
		"allowDNS":     n.AllowDNS,
	}
	return c.do(http.MethodPost, "/network/"+strings.ToLower(n.ID), body, nil)
}

// Leave leaves a network.
func (c *Client) Leave(id string) error {
	return c.do(http.MethodDelete, "/network/"+strings.ToLower(id), nil, nil)
}
