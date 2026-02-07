package wgstats

import (
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// PollInterval is how often we poll wg show.
	PollInterval = 2 * time.Second

	// HistorySize is the number of data points kept in the ring buffer (~2min at 2s).
	HistorySize = 60
)

// InterfaceStats holds aggregate stats for the wg interface.
type InterfaceStats struct {
	TotalRx     int64   // cumulative bytes received (sum of all peers)
	TotalTx     int64   // cumulative bytes sent
	CurrentRxPS float64 // bytes per second receive
	CurrentTxPS float64 // bytes per second transmit
}

// PeerStats holds stats for a single peer.
type PeerStats struct {
	PublicKey       string
	Endpoint        string
	LatestHandshake time.Time
	TransferRx      int64
	TransferTx      int64
	CurrentRxPS     float64
	CurrentTxPS     float64
}

// HistoryPoint is a single bandwidth sample.
type HistoryPoint struct {
	Time time.Time
	RxPS float64
	TxPS float64
}

// Collector polls wg show and collects stats.
type Collector struct {
	mu          sync.RWMutex
	startedAt   time.Time
	iface       InterfaceStats
	peers       map[string]*PeerStats    // keyed by public key
	history     []HistoryPoint           // ring buffer
	peerHistory map[string][]HistoryPoint // per-peer ring buffer
	prevRx      int64
	prevTx      int64
	prevPeerRx  map[string]int64
	prevPeerTx  map[string]int64
	prevTime    time.Time
	isUp        bool
	stopCh      chan struct{}
}

// NewCollector creates a new stats collector.
func NewCollector() *Collector {
	return &Collector{
		peers:       make(map[string]*PeerStats),
		peerHistory: make(map[string][]HistoryPoint),
		prevPeerRx:  make(map[string]int64),
		prevPeerTx:  make(map[string]int64),
		stopCh:      make(chan struct{}),
	}
}

// Start begins background polling. Call with startedAt set to when wg was brought up.
func (c *Collector) Start(startedAt time.Time) {
	c.mu.Lock()
	c.startedAt = startedAt
	c.mu.Unlock()

	go c.pollLoop()
}

// Stop halts the background polling goroutine.
func (c *Collector) Stop() {
	close(c.stopCh)
}

// SetStartedAt updates the WireGuard start time (e.g., after apply/restart).
func (c *Collector) SetStartedAt(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.startedAt = t
}

// IsUp returns whether WireGuard interface is responding.
func (c *Collector) IsUp() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isUp
}

// GetInterfaceStats returns a snapshot of the interface stats.
func (c *Collector) GetInterfaceStats() InterfaceStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.iface
}

// GetPeerStats returns stats for a specific peer by public key.
func (c *Collector) GetPeerStats(publicKey string) *PeerStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if ps, ok := c.peers[publicKey]; ok {
		cp := *ps
		return &cp
	}
	return nil
}

// GetAllPeerStats returns a copy of all peer stats.
func (c *Collector) GetAllPeerStats() map[string]PeerStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[string]PeerStats, len(c.peers))
	for k, v := range c.peers {
		result[k] = *v
	}
	return result
}

// GetHistory returns a copy of the interface bandwidth history.
func (c *Collector) GetHistory() []HistoryPoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]HistoryPoint, len(c.history))
	copy(result, c.history)
	return result
}

// GetPeerHistory returns a copy of a specific peer's bandwidth history.
func (c *Collector) GetPeerHistory(publicKey string) []HistoryPoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h, ok := c.peerHistory[publicKey]
	if !ok {
		return nil
	}
	result := make([]HistoryPoint, len(h))
	copy(result, h)
	return result
}

// Uptime returns the duration since WireGuard was started.
func (c *Collector) Uptime() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.startedAt.IsZero() {
		return 0
	}
	return time.Since(c.startedAt)
}

func (c *Collector) pollLoop() {
	ticker := time.NewTicker(PollInterval)
	defer ticker.Stop()

	// Do an initial poll immediately.
	c.poll()

	for {
		select {
		case <-ticker.C:
			c.poll()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Collector) poll() {
	output, err := exec.Command("wg", "show", "wg0", "dump").Output()
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if err != nil {
		c.isUp = false
		return
	}

	c.isUp = true
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 1 {
		return
	}

	// First line is the interface. Skip it (we derive stats from peers).
	// Parse peer lines.
	var totalRx, totalTx int64
	seenPeers := make(map[string]bool)

	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}

		pubKey := fields[0]
		endpoint := fields[2]
		handshakeUnix, _ := strconv.ParseInt(fields[4], 10, 64)
		rx, _ := strconv.ParseInt(fields[5], 10, 64)
		tx, _ := strconv.ParseInt(fields[6], 10, 64)

		totalRx += rx
		totalTx += tx
		seenPeers[pubKey] = true

		var handshake time.Time
		if handshakeUnix > 0 {
			handshake = time.Unix(handshakeUnix, 0)
		}

		// Compute per-peer bandwidth.
		var peerRxPS, peerTxPS float64
		if !c.prevTime.IsZero() {
			dt := now.Sub(c.prevTime).Seconds()
			if dt > 0 {
				prevRx, ok1 := c.prevPeerRx[pubKey]
				prevTx, ok2 := c.prevPeerTx[pubKey]
				if ok1 && ok2 && rx >= prevRx && tx >= prevTx {
					peerRxPS = float64(rx-prevRx) / dt
					peerTxPS = float64(tx-prevTx) / dt
				}
			}
		}

		c.peers[pubKey] = &PeerStats{
			PublicKey:       pubKey,
			Endpoint:        endpoint,
			LatestHandshake: handshake,
			TransferRx:      rx,
			TransferTx:      tx,
			CurrentRxPS:     peerRxPS,
			CurrentTxPS:     peerTxPS,
		}

		c.prevPeerRx[pubKey] = rx
		c.prevPeerTx[pubKey] = tx

		// Update per-peer history.
		ph := c.peerHistory[pubKey]
		ph = append(ph, HistoryPoint{Time: now, RxPS: peerRxPS, TxPS: peerTxPS})
		if len(ph) > HistorySize {
			ph = ph[len(ph)-HistorySize:]
		}
		c.peerHistory[pubKey] = ph
	}

	// Clean up peers that are no longer in the dump.
	for pubKey := range c.peers {
		if !seenPeers[pubKey] {
			delete(c.peers, pubKey)
			delete(c.prevPeerRx, pubKey)
			delete(c.prevPeerTx, pubKey)
			delete(c.peerHistory, pubKey)
		}
	}

	// Compute aggregate bandwidth.
	var rxPS, txPS float64
	if !c.prevTime.IsZero() {
		dt := now.Sub(c.prevTime).Seconds()
		if dt > 0 && totalRx >= c.prevRx && totalTx >= c.prevTx {
			rxPS = float64(totalRx-c.prevRx) / dt
			txPS = float64(totalTx-c.prevTx) / dt
		}
	}

	c.iface = InterfaceStats{
		TotalRx:     totalRx,
		TotalTx:     totalTx,
		CurrentRxPS: rxPS,
		CurrentTxPS: txPS,
	}

	c.prevRx = totalRx
	c.prevTx = totalTx
	c.prevTime = now

	// Update aggregate history.
	c.history = append(c.history, HistoryPoint{Time: now, RxPS: rxPS, TxPS: txPS})
	if len(c.history) > HistorySize {
		c.history = c.history[len(c.history)-HistorySize:]
	}
}

// RenderSparklineSVG renders an inline SVG sparkline from history data.
// width and height are in pixels.
func RenderSparklineSVG(history []HistoryPoint, width, height int) string {
	if len(history) < 2 {
		return fmt.Sprintf(`<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg"></svg>`, width, height)
	}

	// Find max value for Y scaling.
	maxVal := 0.0
	for _, h := range history {
		if h.RxPS > maxVal {
			maxVal = h.RxPS
		}
		if h.TxPS > maxVal {
			maxVal = h.TxPS
		}
	}
	if maxVal == 0 {
		maxVal = 1 // avoid division by zero
	}

	n := len(history)
	fW := float64(width)
	fH := float64(height)

	// Build polyline points.
	rxPoints := make([]string, n)
	txPoints := make([]string, n)
	for i, h := range history {
		x := fW * float64(i) / float64(n-1)
		yRx := fH - (fH * h.RxPS / maxVal)
		yTx := fH - (fH * h.TxPS / maxVal)
		// Clamp to bounds.
		yRx = math.Max(0, math.Min(fH, yRx))
		yTx = math.Max(0, math.Min(fH, yTx))
		rxPoints[i] = fmt.Sprintf("%.1f,%.1f", x, yRx)
		txPoints[i] = fmt.Sprintf("%.1f,%.1f", x, yTx)
	}

	return fmt.Sprintf(
		`<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg" class="sparkline">`+
			`<polyline points="%s" fill="none" stroke="#4a9eff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>`+
			`<polyline points="%s" fill="none" stroke="#48bb78" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>`+
			`</svg>`,
		width, height,
		strings.Join(rxPoints, " "),
		strings.Join(txPoints, " "),
	)
}

// FormatBytes formats bytes into a human-readable string.
func FormatBytes(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.1f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// FormatBytesPerSec formats bytes/sec into a human-readable rate string.
func FormatBytesPerSec(bps float64) string {
	return FormatBytes(int64(bps)) + "/s"
}

// FormatDuration formats a duration into a human-readable string.
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if hours >= 24 {
		days := hours / 24
		hours = hours % 24
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

// FormatHandshake formats a handshake time as a relative string.
func FormatHandshake(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
