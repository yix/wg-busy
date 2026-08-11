package zerotier

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yix/wg-busy/internal/models"
)

const (
	// PollInterval is how often the supervisor reconciles and samples counters.
	PollInterval = 2 * time.Second

	// restartBackoff is the minimum gap between start attempts, so a binary that
	// exits immediately doesn't get respawned every tick.
	restartBackoff = 15 * time.Second
)

// NetworkStats is a joined network plus the traffic counters of its interface.
type NetworkStats struct {
	Network
	// Configured is the peer's local label from config.yaml.
	Label   string
	Rx      int64
	Tx      int64
	RxPS    float64
	TxPS    float64
	HasRate bool
}

// Snapshot is what the UI renders. Err is the last reconcile/poll error, if any.
type Snapshot struct {
	Enabled  bool
	Running  bool
	Status   *Status
	Networks []NetworkStats
	Peers    []Peer
	Err      string
	Uptime   time.Duration
}

type counter struct {
	rx, tx int64
	at     time.Time
}

// Supervisor keeps the ZeroTier One service in sync with the desired config.
//
// Configure only records intent; all process control and HTTP work happens on
// the supervisor's own goroutine, so a slow or wedged daemon can never block a
// config save (which holds the config store's write lock).
type Supervisor struct {
	homeDir string

	// onGatewaysChanged fires when the set of ZeroTier on-link networks changes,
	// so wg0.conf can be re-rendered: policy routes pointing at a ZeroTier
	// gateway need its interface name, which only exists once a network is up.
	// Called without the supervisor lock held.
	onGatewaysChanged func()
	gatewaySig        string

	mu       sync.Mutex
	desired  models.ZeroTierConfig
	gen      uint64 // bumped by Configure
	appliedG uint64 // generation the network reconcile last completed for

	cmd         *exec.Cmd
	exited      bool  // set by the reaper goroutine; guarded by mu, never read from cmd
	exitErr     error //nolint:unused // logged when the service dies
	client      *Client
	runningPort uint16
	startedAt   time.Time
	lastStart   time.Time

	snap  Snapshot
	prev  map[string]counter // interface name -> previous sample
	stop  chan struct{}
	once  sync.Once
	waitG sync.WaitGroup
}

// New returns a supervisor for a ZeroTier home directory.
func New(homeDir string) *Supervisor {
	return &Supervisor{
		homeDir: homeDir,
		prev:    make(map[string]counter),
		stop:    make(chan struct{}),
	}
}

// OnGatewaysChanged registers a callback fired when the ZeroTier on-link
// networks change, so dependent configuration can be re-rendered.
func (s *Supervisor) OnGatewaysChanged(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onGatewaysChanged = fn
}

// notifyGatewayChange calls the callback when the gateway set changed. It must
// be called without the lock held: the callback re-enters the config store,
// which takes its own lock before calling back into this supervisor.
func (s *Supervisor) notifyGatewayChange(nets []models.GatewayNet) {
	sig := make([]string, 0, len(nets))
	for _, n := range nets {
		sig = append(sig, n.Device+"="+n.CIDR)
	}
	sort.Strings(sig)
	joined := strings.Join(sig, ",")

	s.mu.Lock()
	changed := joined != s.gatewaySig
	s.gatewaySig = joined
	fn := s.onGatewaysChanged
	s.mu.Unlock()

	if changed && fn != nil {
		log.Printf("[ZT] on-link networks changed (%s), re-rendering wg0.conf", joined)
		fn()
	}
}

// Configure records the desired state. It never blocks on the service.
func (s *Supervisor) Configure(cfg *models.AppConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.desired = cfg.ZeroTier
	s.gen++
}

// setSnapshot stores the observed state, logging errors only when they change so
// a persistent failure doesn't fill the log at one line every tick.
func (s *Supervisor) setSnapshot(snap Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.Err != s.snap.Err {
		switch {
		case snap.Err != "":
			log.Printf("[ZT] %s", snap.Err)
		case snap.Enabled:
			log.Printf("[ZT] recovered")
		}
	}
	s.snap = snap
}

// Snapshot returns the latest observed state for rendering.
func (s *Supervisor) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.snap
	snap.Networks = append([]NetworkStats(nil), s.snap.Networks...)
	snap.Peers = append([]Peer(nil), s.snap.Peers...)
	return snap
}

// Start begins the reconcile loop.
func (s *Supervisor) Start() {
	s.waitG.Add(1)
	go func() {
		defer s.waitG.Done()
		ticker := time.NewTicker(PollInterval)
		defer ticker.Stop()

		s.tick()
		for {
			select {
			case <-ticker.C:
				s.tick()
			case <-s.stop:
				s.mu.Lock()
				s.stopService()
				s.mu.Unlock()
				return
			}
		}
	}()
}

// Stop halts the loop and shuts the service down.
func (s *Supervisor) Stop() {
	s.once.Do(func() { close(s.stop) })
	s.waitG.Wait()
}

// Restart stops the service; the next tick starts it again with current config.
func (s *Supervisor) Restart() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.desired.Enabled {
		return fmt.Errorf("ZeroTier is disabled")
	}
	s.stopService()
	s.lastStart = time.Time{} // skip the backoff for an explicit restart
	s.appliedG = 0            // force a network reconcile once it is back up
	return nil
}

func (s *Supervisor) tick() {
	s.mu.Lock()
	desired := s.desired
	gen := s.gen
	s.mu.Unlock()

	if !desired.Enabled {
		s.mu.Lock()
		s.stopService()
		s.mu.Unlock()
		s.setSnapshot(Snapshot{})
		return
	}

	if err := s.ensureRunning(desired); err != nil {
		s.setSnapshot(Snapshot{Enabled: true, Err: err.Error()})
		return
	}

	s.mu.Lock()
	client := s.client
	needsReconcile := s.appliedG != gen
	startedAt := s.startedAt
	s.mu.Unlock()

	if client == nil {
		s.setSnapshot(Snapshot{Enabled: true, Err: "ZeroTier control API is not available yet"})
		return
	}

	snap := Snapshot{Enabled: true, Running: true, Uptime: time.Since(startedAt)}

	status, err := client.Status()
	if err != nil {
		// Normal for the first seconds after start, before the control plane is up.
		snap.Err = err.Error()
		s.setSnapshot(snap)
		return
	}
	snap.Status = status

	if needsReconcile {
		if err := s.reconcileNetworks(client, desired); err != nil {
			snap.Err = err.Error()
		} else {
			s.mu.Lock()
			s.appliedG = gen
			s.mu.Unlock()
		}
	}

	networks, err := client.Networks()
	if err != nil {
		snap.Err = err.Error()
	}
	snap.Networks = s.withCounters(networks, desired)

	peers, err := client.Peers()
	if err != nil && snap.Err == "" {
		snap.Err = err.Error()
	}
	snap.Peers = peers

	s.setSnapshot(snap)
	s.notifyGatewayChange(gatewayNets(snap.Networks))
}

// ensureRunning starts the service if needed, or restarts it if the port changed.
func (s *Supervisor) ensureRunning(desired models.ZeroTierConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	port := desired.ZeroTierPort()

	if s.cmd != nil {
		if s.exited {
			log.Printf("[ZT] service exited: %v", s.exitErr)
			s.clearProcess()
		} else if s.runningPort != port {
			log.Printf("[ZT] port changed %d -> %d, restarting service", s.runningPort, port)
			s.stopService()
			s.appliedG = 0
		}
	}

	if s.cmd != nil {
		return nil
	}

	if time.Since(s.lastStart) < restartBackoff {
		return fmt.Errorf("ZeroTier service is not running; retrying shortly")
	}

	if err := os.MkdirAll(s.homeDir, 0700); err != nil {
		return fmt.Errorf("creating ZeroTier home %s: %w", s.homeDir, err)
	}

	cmd := exec.Command("zerotier-one", "-p"+strconv.Itoa(int(port)), s.homeDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	s.lastStart = time.Now()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting zerotier-one: %w", err)
	}
	log.Printf("[ZT] started zerotier-one (pid %d) port %d home %s", cmd.Process.Pid, port, s.homeDir)

	// Reap the child so a crash is visible to the next tick.
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.cmd == cmd {
			s.exited = true
			s.exitErr = err
		}
	}()

	s.cmd = cmd
	s.exited = false
	s.runningPort = port
	s.startedAt = time.Now()
	s.client = NewClient(s.homeDir, port)
	s.appliedG = 0
	return nil
}

// stopService terminates the service. Callers must hold s.mu.
func (s *Supervisor) stopService() {
	if s.cmd == nil {
		return
	}
	if s.cmd.Process != nil && !s.exited {
		log.Printf("[ZT] stopping zerotier-one (pid %d)", s.cmd.Process.Pid)
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
	}
	// ponytail: no wait-then-kill escalation — zerotier-one exits promptly on
	// SIGTERM and the reaper goroutine collects it. Add a timed Kill if a stuck
	// daemon ever blocks a port change.
	s.clearProcess()
}

func (s *Supervisor) clearProcess() {
	s.cmd = nil
	s.exited = false
	s.client = nil
	s.runningPort = 0
	s.startedAt = time.Time{}
}

// reconcileNetworks joins every configured network and leaves the rest.
func (s *Supervisor) reconcileNetworks(client *Client, desired models.ZeroTierConfig) error {
	joined, err := client.Networks()
	if err != nil {
		return err
	}

	wanted := make(map[string]bool, len(desired.Networks))
	for _, n := range desired.Networks {
		wanted[strings.ToLower(n.ID)] = true
		// POST every time, not just for new IDs: it is join-or-update, and this is
		// how a changed allow* flag reaches the service.
		if err := client.Join(n); err != nil {
			return fmt.Errorf("joining %s: %w", n.ID, err)
		}
	}

	for _, n := range joined {
		if !wanted[strings.ToLower(n.ID)] {
			log.Printf("[ZT] leaving network %s (no longer in config)", n.ID)
			if err := client.Leave(n.ID); err != nil {
				return fmt.Errorf("leaving %s: %w", n.ID, err)
			}
		}
	}
	return nil
}

// withCounters attaches interface traffic counters and config labels to networks.
func (s *Supervisor) withCounters(networks []Network, desired models.ZeroTierConfig) []NetworkStats {
	now := time.Now()
	out := make([]NetworkStats, 0, len(networks))

	s.mu.Lock()
	defer s.mu.Unlock()

	seen := make(map[string]bool, len(networks))
	for _, n := range networks {
		ns := NetworkStats{Network: n}
		if cfg := models.FindZeroTierNetwork(desired.Networks, n.ID); cfg != nil {
			ns.Label = cfg.Name
		}

		if dev := n.PortDeviceName; dev != "" {
			seen[dev] = true
			rx, tx, err := InterfaceCounters(dev)
			if err == nil {
				ns.Rx, ns.Tx = rx, tx
				if prev, ok := s.prev[dev]; ok {
					if dt := now.Sub(prev.at).Seconds(); dt > 0 && rx >= prev.rx && tx >= prev.tx {
						ns.RxPS = float64(rx-prev.rx) / dt
						ns.TxPS = float64(tx-prev.tx) / dt
						ns.HasRate = true
					}
				}
				s.prev[dev] = counter{rx: rx, tx: tx, at: now}
			}
		}
		out = append(out, ns)
	}

	for dev := range s.prev {
		if !seen[dev] {
			delete(s.prev, dev)
		}
	}
	return out
}

// GatewayNets returns the on-link networks reachable over ZeroTier interfaces,
// so policy routes can use a ZeroTier peer's IP as their gateway.
func (s *Supervisor) GatewayNets() []models.GatewayNet {
	return gatewayNets(s.Snapshot().Networks)
}

func gatewayNets(networks []NetworkStats) []models.GatewayNet {
	var nets []models.GatewayNet
	for _, n := range networks {
		if n.PortDeviceName == "" {
			continue
		}
		for _, addr := range n.AssignedAddresses {
			nets = append(nets, models.GatewayNet{Device: n.PortDeviceName, CIDR: addr})
		}
	}
	return nets
}

// InterfaceCounters reads an interface's byte counters from sysfs. ZeroTier's API
// exposes no traffic data, so this is where the numbers come from.
func InterfaceCounters(dev string) (rx, tx int64, err error) {
	read := func(name string) (int64, error) {
		data, err := os.ReadFile(filepath.Join("/sys/class/net", dev, "statistics", name))
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	}
	if rx, err = read("rx_bytes"); err != nil {
		return 0, 0, err
	}
	if tx, err = read("tx_bytes"); err != nil {
		return 0, 0, err
	}
	return rx, tx, nil
}
