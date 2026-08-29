package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yix/wg-busy/internal/bgp"
	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/routing"
	"github.com/yix/wg-busy/internal/wireguard"
)

var (
	reloadWireGuard = wireguard.ReloadWGConfig
	configureBGP    = bgp.Configure
)

// PeerStatsSnapshot holds the latest observed stats for a peer.
type PeerStatsSnapshot struct {
	LastSeen   time.Time
	TransferRx int64
	TransferTx int64
}

// Store holds the in-memory config and manages persistence to YAML + wg0.conf.
type Store struct {
	mu           sync.RWMutex
	configPath   string
	wgConfigPath string
	config       models.AppConfig
	routingState models.AppConfig
	routingNets  []models.GatewayNet
	routingBGP   map[string][]string
	statsDirty   bool
	// wgRestartPending stays set until wg-quick has successfully rebuilt the
	// interface. syncconf cannot apply wg-quick-owned server fields.
	wgRestartPending bool
	wgAppliedServer  models.ServerConfig
	wgHasApplied     bool

	// onChange is notified after a successful write. It must not block: it runs
	// while the write lock is held, so anything slow (process control, HTTP)
	// belongs on the receiver's own goroutine.
	onChange func(*models.AppConfig)

	// ztGateways reports the ZeroTier subnets policy routes may use as gateways.
	// Called while the store lock is held, so it must only read cached state.
	ztGateways func() []models.GatewayNet
	// bgpAdvertised reports the prefixes in each peer's live Adj-RIB-Out.
	// Called while the store lock is held, so the provider must not call back
	// into the store.
	bgpAdvertised func() map[string][]string
}

// ApplyError means persistence succeeded but one or more live services did not
// converge. Callers must not retry the mutation as though it had been rejected.
type ApplyError struct{ Err error }

func (e *ApplyError) Error() string {
	return "configuration saved, but live apply did not complete: " + e.Err.Error()
}
func (e *ApplyError) Unwrap() error { return e.Err }

// SetZeroTierGateways registers the provider of ZeroTier on-link networks used
// when rendering policy routes into wg0.conf.
func (s *Store) SetZeroTierGateways(fn func() []models.GatewayNet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ztGateways = fn
}

// SetBGPAdvertisedRoutes registers the live per-peer Adj-RIB-Out provider used
// to build ZeroTier masquerade bypass rules.
func (s *Store) SetBGPAdvertisedRoutes(fn func() map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bgpAdvertised = fn
}

// gatewayNets returns every network a policy route gateway may point into.
// Callers must hold the lock.
func (s *Store) gatewayNets() []models.GatewayNet {
	var zt []models.GatewayNet
	if s.ztGateways != nil {
		zt = s.ztGateways()
	}
	return models.GatewayNets(s.config.Server.Address, zt)
}

// advertisedRoutes returns an independent live Adj-RIB-Out snapshot.
// Callers must hold the store lock.
func (s *Store) advertisedRoutes() map[string][]string {
	if s.bgpAdvertised == nil {
		return nil
	}
	return cloneAdvertisedRoutes(s.bgpAdvertised())
}

func cloneAdvertisedRoutes(routes map[string][]string) map[string][]string {
	clone := make(map[string][]string, len(routes))
	for peer, prefixes := range routes {
		clone[peer] = append([]string(nil), prefixes...)
	}
	return clone
}

// OnChange registers a callback invoked with the new config after every successful write.
func (s *Store) OnChange(fn func(*models.AppConfig)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = fn
}

// Load reads the YAML config file, or initializes defaults if it doesn't exist.
func Load(configPath, wgConfigPath string) (*Store, error) {
	s := &Store{
		configPath:   configPath,
		wgConfigPath: wgConfigPath,
	}

	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		s.config = models.AppConfig{
			Server: models.ServerConfig{
				ListenPort: 51820,
				Address:    "10.0.0.1/24",
				DNS:        "1.1.1.1,8.8.8.8",
				Table:      "off",
				PostUp:     "iptables -A POSTROUTING -t nat -o eth0 -j MASQUERADE",
				PostDown:   "iptables -D POSTROUTING -t nat -o eth0 -j MASQUERADE",
			},
			Peers: []models.Peer{},
		}
		s.routingState = s.config.Clone()
		s.wgRestartPending = true
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, &s.config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	s.routingState = s.config.Clone()
	s.wgRestartPending = true

	return s, nil
}

// Read executes fn with an independent snapshot of the current config. Callers
// may safely retain it after the callback returns.
func (s *Store) Read(fn func(cfg *models.AppConfig)) {
	s.mu.RLock()
	snapshot := s.config.Clone()
	s.mu.RUnlock()
	fn(&snapshot)
}

// IsPeerRoutingApplied reports whether the peer's routing and strict policy state
// in the kernel matches the current desired configuration.
func (s *Store) IsPeerRoutingApplied(peerID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.wgRestartPending {
		return false
	}
	desired := models.FindPeerByID(s.config.Peers, peerID)
	if desired == nil {
		return false
	}
	applied := models.FindPeerByID(s.routingState.Peers, peerID)
	if applied == nil {
		return false
	}
	return desired.Enabled == applied.Enabled &&
		desired.StrictPolicyRouting == applied.StrictPolicyRouting &&
		desired.ExitNodeID == applied.ExitNodeID &&
		desired.RoutingTableID == applied.RoutingTableID &&
		desired.PolicyRoutingTableID == applied.PolicyRoutingTableID &&
		slices.Equal(desired.PolicyRoutes, applied.PolicyRoutes) &&
		slices.Equal(desired.ExitNodeRoutes, applied.ExitNodeRoutes) &&
		desired.AllowedIPs == applied.AllowedIPs
}

// PeerRoutingAppliedMap returns a map of peer ID to whether its routing state
// has been successfully reconciled to the kernel.
func (s *Store) PeerRoutingAppliedMap() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]bool, len(s.config.Peers))
	if s.wgRestartPending {
		for _, p := range s.config.Peers {
			result[p.ID] = false
		}
		return result
	}
	for _, desired := range s.config.Peers {
		applied := models.FindPeerByID(s.routingState.Peers, desired.ID)
		if applied == nil {
			result[desired.ID] = false
			continue
		}
		result[desired.ID] = desired.Enabled == applied.Enabled &&
			desired.StrictPolicyRouting == applied.StrictPolicyRouting &&
			desired.ExitNodeID == applied.ExitNodeID &&
			desired.RoutingTableID == applied.RoutingTableID &&
			desired.PolicyRoutingTableID == applied.PolicyRoutingTableID &&
			slices.Equal(desired.PolicyRoutes, applied.PolicyRoutes) &&
			slices.Equal(desired.ExitNodeRoutes, applied.ExitNodeRoutes) &&
			desired.AllowedIPs == applied.AllowedIPs
	}
	return result
}

// RecordPeerStats updates in-memory peer last seen times and traffic counters
// without writing to disk immediately. It marks the store dirty so the background
// persister can save the changes periodically.
func (s *Store) RecordPeerStats(stats map[string]PeerStatsSnapshot) {
	if len(stats) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.config.Peers {
		peer := &s.config.Peers[i]
		stat, ok := stats[peer.PublicKey]
		if !ok {
			continue
		}
		if !stat.LastSeen.IsZero() && stat.LastSeen.After(peer.LastSeen) {
			peer.LastSeen = stat.LastSeen.UTC()
			s.statsDirty = true
		}
		if stat.TransferRx != peer.TransferRx || stat.TransferTx != peer.TransferTx {
			peer.TransferRx = stat.TransferRx
			peer.TransferTx = stat.TransferTx
			s.statsDirty = true
		}
	}
}

// SaveStats writes dirty in-memory stats to config.yaml if changes occurred.
func (s *Store) SaveStats() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.statsDirty {
		return nil
	}

	if err := s.saveYAML(); err != nil {
		return err
	}
	s.statsDirty = false
	return nil
}

// StartStatsPersister starts a background goroutine that periodically saves
// accumulated peer stats (lastSeen, transfer counters) to disk. It returns a
// stop function that flushes pending stats and stops the background ticker.
func (s *Store) StartStatsPersister(interval time.Duration) func() {
	ticker := time.NewTicker(interval)
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})

	go func() {
		defer close(doneCh)
		for {
			select {
			case <-ticker.C:
				if err := s.SaveStats(); err != nil {
					log.Printf("saving peer stats: %v", err)
				}
			case <-stopCh:
				ticker.Stop()
				return
			}
		}
	}()

	return func() {
		close(stopCh)
		<-doneCh
		if err := s.SaveStats(); err != nil {
			log.Printf("flushing peer stats on shutdown: %v", err)
		}
	}
}

// RecordPeerLastSeen persists newer WireGuard handshake times without
// reapplying configuration: last-seen data does not change wg0.conf.
func (s *Store) RecordPeerLastSeen(seen map[string]time.Time) error {
	if len(seen) == 0 {
		return nil
	}
	snapshots := make(map[string]PeerStatsSnapshot, len(seen))
	for k, v := range seen {
		snapshots[k] = PeerStatsSnapshot{LastSeen: v}
	}
	s.RecordPeerStats(snapshots)
	return s.SaveStats()
}

// Write executes fn with a write lock, then saves YAML and renders wg0.conf.
func (s *Store) Write(fn func(cfg *models.AppConfig) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Mutations may edit nested slice elements in place, so rollback needs an
	// independent snapshot rather than a shallow struct copy.
	backup := s.config.Clone()
	backupRestartPending := s.wgRestartPending

	if err := fn(&s.config); err != nil {
		s.config = backup
		return err
	}
	var restartErr error
	if s.wgHasApplied {
		restartErr = wireguard.ServerRestartReason(s.wgAppliedServer, s.config.Server)
		s.wgRestartPending = restartErr != nil
	} else if restartErr = wireguard.ServerRestartReason(backup.Server, s.config.Server); restartErr != nil {
		s.wgRestartPending = true
	}
	if errs := models.ValidateConfig(s.config); len(errs) > 0 {
		s.config = backup
		s.wgRestartPending = backupRestartPending
		return errs
	}

	if err := s.saveYAML(); err != nil {
		s.config = backup
		s.wgRestartPending = backupRestartPending
		return fmt.Errorf("saving config: %w", err)
	}
	s.statsDirty = false

	if err := s.renderWGConfig(); err != nil {
		s.config = backup
		s.wgRestartPending = backupRestartPending
		if rollbackErr := s.saveYAML(); rollbackErr != nil {
			return errors.Join(fmt.Errorf("rendering wg config: %w", err), fmt.Errorf("restoring YAML config: %w", rollbackErr))
		}
		return fmt.Errorf("rendering wg config: %w", err)
	}

	currentNets := s.gatewayNets()
	currentBGP := s.advertisedRoutes()
	var applyErrs []error
	running, reloadErr := reloadWireGuard(s.wgConfigPath)
	if reloadErr != nil {
		applyErrs = append(applyErrs, reloadErr)
	} else if !running {
		applyErrs = append(applyErrs, wireguard.ErrInterfaceDown)
	} else if s.wgRestartPending {
		if restartErr == nil {
			restartErr = wireguard.ErrRestartNeeded
		}
		applyErrs = append(applyErrs, restartErr)
	} else {
		if err := routing.Reconcile(s.routingState, s.routingNets, s.routingBGP, s.config, currentNets, currentBGP); err != nil {
			applyErrs = append(applyErrs, err)
		} else {
			s.routingState = s.config.Clone()
			s.routingNets = append([]models.GatewayNet(nil), currentNets...)
			s.routingBGP = cloneAdvertisedRoutes(currentBGP)
		}
	}
	// Disabling BGP never depends on wg0 and must stop an existing runtime even
	// while WireGuard is down or waiting for a full restart.
	if !s.config.Server.BGPEnabled || (running && reloadErr == nil && !s.wgRestartPending) {
		if err := configureBGP(&s.config); err != nil {
			applyErrs = append(applyErrs, fmt.Errorf("configuring BGP: %w", err))
		}
	}

	// After persistence, so a failure here can never trigger the rollback above.
	if s.onChange != nil {
		s.onChange(&s.config)
	}

	if len(applyErrs) > 0 {
		return &ApplyError{Err: errors.Join(applyErrs...)}
	}
	return nil
}

// ReapplyBGP retries the desired BGP state after a WireGuard restart.
func (s *Store) ReapplyBGP() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.wgRestartPending && s.config.Server.BGPEnabled {
		return wireguard.ErrRestartNeeded
	}
	return configureBGP(&s.config)
}

// ReapplyRouting re-renders wg0.conf and converges the live routing state to it.
// Called when a ZeroTier network comes up after wg0, whose routes and NAT rule
// would otherwise sit uninstalled until the next manual apply.
func (s *Store) ReapplyRouting() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wgRestartPending {
		return wireguard.ErrRestartNeeded
	}

	if err := s.renderWGConfig(); err != nil {
		return err
	}
	nets := s.gatewayNets()
	advertised := s.advertisedRoutes()
	if err := routing.Reconcile(s.routingState, s.routingNets, s.routingBGP, s.config, nets, advertised); err != nil {
		return err
	}
	s.routingState = s.config.Clone()
	s.routingNets = append([]models.GatewayNet(nil), nets...)
	s.routingBGP = cloneAdvertisedRoutes(advertised)
	return nil
}

// RenderWGConfig writes the current source-of-truth YAML state to wg0.conf
// without attempting to touch the live interface. Startup uses this before
// invoking wg-quick.
func (s *Store) RenderWGConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if errs := models.ValidateConfig(s.config); len(errs) > 0 {
		return errs
	}
	return s.renderWGConfig()
}

// WGConfigPath returns the file used for every wg-quick operation.
func (s *Store) WGConfigPath() string { return s.wgConfigPath }

// MarkWireGuardRestarted records that wg-quick successfully installed the
// complete current configuration, including fields syncconf cannot apply.
func (s *Store) MarkWireGuardRestarted() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wgRestartPending = false
	s.wgAppliedServer = s.config.Server
	s.wgHasApplied = true
	s.routingState = s.config.Clone()
	s.routingNets = append([]models.GatewayNet(nil), s.gatewayNets()...)
	s.routingBGP = s.advertisedRoutes()
}

func (s *Store) saveYAML() error {
	data, err := yaml.Marshal(&s.config)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	dir := filepath.Dir(s.configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	tmpPath := s.configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("writing temp config: %w", err)
	}
	if err := os.Rename(tmpPath, s.configPath); err != nil {
		return fmt.Errorf("renaming config: %w", err)
	}
	return nil
}

func (s *Store) renderWGConfig() error {
	gateways := s.gatewayNets()
	advertised := s.advertisedRoutes()
	postUpCmds := routing.GeneratePostUpCommandsWithBGP(s.config, gateways, advertised)
	postDownCmds := routing.GeneratePostDownCommandsWithBGP(s.config, gateways, advertised)

	content, err := wireguard.RenderServerConfig(s.config, postUpCmds, postDownCmds)
	if err != nil {
		return fmt.Errorf("rendering server config: %w", err)
	}

	dir := filepath.Dir(s.wgConfigPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating wg config dir: %w", err)
	}

	tmpPath := s.wgConfigPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("writing temp wg config: %w", err)
	}
	if err := os.Rename(tmpPath, s.wgConfigPath); err != nil {
		return fmt.Errorf("renaming wg config: %w", err)
	}
	return nil
}
