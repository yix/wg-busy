package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wireguard"
	"gopkg.in/yaml.v3"
)

func TestWriteRollsBackNestedZeroTierMutation(t *testing.T) {
	dir := t.TempDir()
	s := &Store{
		configPath:   filepath.Join(dir, "config.yaml"),
		wgConfigPath: filepath.Join(dir, "wg0.conf"),
		config: models.AppConfig{
			ZeroTier: models.ZeroTierConfig{Networks: []models.ZeroTierNetwork{{ID: "8056c2e21c000001", Name: "old"}}},
		},
	}
	wantErr := errors.New("rejected")
	err := s.Write(func(cfg *models.AppConfig) error {
		cfg.ZeroTier.Networks[0].Name = "rejected"
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Write error = %v, want %v", err, wantErr)
	}
	if got := s.config.ZeroTier.Networks[0].Name; got != "old" {
		t.Fatalf("network name after rollback = %q, want old", got)
	}
}

func TestWriteRestoresYAMLWhenWGRenderFails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	s := &Store{
		configPath:   configPath,
		wgConfigPath: filepath.Join(dir, "wg0.conf"),
		config:       validStoreConfig(),
	}
	s.config.Server.DNS = "1.1.1.1"
	s.MarkWireGuardRestarted()
	if err := s.saveYAML(); err != nil {
		t.Fatal(err)
	}
	s.wgConfigPath = dir // renaming a file over this directory must fail
	if err := s.Write(func(cfg *models.AppConfig) error {
		cfg.Server.DNS = "8.8.8.8"
		return nil
	}); err == nil {
		t.Fatal("Write succeeded despite wg0.conf render failure")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted models.AppConfig
	if err := yaml.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Server.DNS != "1.1.1.1" || s.config.Server.DNS != "1.1.1.1" {
		t.Fatalf("rollback = disk %q memory %q, want 1.1.1.1", persisted.Server.DNS, s.config.Server.DNS)
	}
}

func TestWriteRejectsInvalidExitNodeReferenceBeforeSaving(t *testing.T) {
	dir := t.TempDir()
	s := &Store{
		configPath:   filepath.Join(dir, "config.yaml"),
		wgConfigPath: filepath.Join(dir, "wg0.conf"),
		config:       validStoreConfig(),
	}
	err := s.Write(func(cfg *models.AppConfig) error {
		cfg.Peers = []models.Peer{{ID: "client", ExitNodeID: "missing", StrictPolicyRouting: true}}
		return nil
	})
	if err == nil {
		t.Fatal("Write accepted an invalid exit-node reference")
	}
	if len(s.config.Peers) != 0 {
		t.Fatal("invalid peer remained in memory")
	}
}

func TestReadReturnsIndependentSnapshot(t *testing.T) {
	s := &Store{config: validStoreConfig()}
	s.config.ZeroTier.Networks = []models.ZeroTierNetwork{{ID: "8056c2e21c000001", Name: "stored"}}
	var snapshot *models.AppConfig
	s.Read(func(cfg *models.AppConfig) { snapshot = cfg })
	snapshot.ZeroTier.Networks[0].Name = "changed"
	if got := s.config.ZeroTier.Networks[0].Name; got != "stored" {
		t.Fatalf("store was mutated through Read snapshot: %q", got)
	}
}

func TestRecordPeerLastSeenPersistsOnlyNewerHandshake(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	seen := time.Date(2026, time.August, 13, 15, 4, 5, 0, time.UTC)
	s := &Store{
		configPath: configPath,
		config: models.AppConfig{Peers: []models.Peer{{
			PublicKey: "peer-key",
		}}},
	}

	if err := s.RecordPeerLastSeen(map[string]time.Time{"peer-key": seen}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordPeerLastSeen(map[string]time.Time{"peer-key": seen.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted models.AppConfig
	if err := yaml.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if got := persisted.Peers[0].LastSeen; !got.Equal(seen) {
		t.Fatalf("persisted lastSeen = %s, want %s", got, seen)
	}
}

func TestWriteReportsRestartPendingUntilMarkedApplied(t *testing.T) {
	stubLiveServices(t, true)
	dir := t.TempDir()
	s := &Store{
		configPath:   filepath.Join(dir, "config.yaml"),
		wgConfigPath: filepath.Join(dir, "wg0.conf"),
		config:       validStoreConfig(),
	}
	s.MarkWireGuardRestarted()

	err := s.Write(func(cfg *models.AppConfig) error {
		cfg.Server.Address = "10.1.0.1/24"
		return nil
	})
	if !errors.Is(err, wireguard.ErrRestartNeeded) {
		t.Fatalf("address save error = %v, want restart needed", err)
	}
	if !strings.Contains(err.Error(), "Address changed") {
		t.Fatalf("address save error does not explain the restart: %v", err)
	}
	if err := s.Write(func(*models.AppConfig) error { return nil }); !errors.Is(err, wireguard.ErrRestartNeeded) {
		t.Fatalf("subsequent save error = %v, want pending restart", err)
	}

	s.MarkWireGuardRestarted()
	if err := s.Write(func(*models.AppConfig) error { return nil }); err != nil {
		t.Fatalf("save after restart marker = %v", err)
	}
}

func TestWriteDisablesBGPWhileWireGuardIsDown(t *testing.T) {
	originalReload, originalBGP := reloadWireGuard, configureBGP
	t.Cleanup(func() { reloadWireGuard, configureBGP = originalReload, originalBGP })
	reloadWireGuard = func(string) (bool, error) { return false, nil }
	configured := false
	configureBGP = func(cfg *models.AppConfig) error {
		configured = !cfg.Server.BGPEnabled
		return nil
	}
	dir := t.TempDir()
	s := &Store{
		configPath:   filepath.Join(dir, "config.yaml"),
		wgConfigPath: filepath.Join(dir, "wg0.conf"),
		config:       validStoreConfig(),
	}

	err := s.Write(func(cfg *models.AppConfig) error {
		cfg.Server.BGPEnabled = false
		return nil
	})
	if !errors.Is(err, wireguard.ErrInterfaceDown) {
		t.Fatalf("Write error = %v, want interface down", err)
	}
	if !configured {
		t.Fatal("BGP disable was skipped while WireGuard was down")
	}
}

func TestRenderWGConfigPreparesConfiguredPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom", "wg0.conf")
	s := &Store{wgConfigPath: path, config: validStoreConfig()}
	if err := s.RenderWGConfig(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("rendered config: %v", err)
	}
}

func stubLiveServices(t *testing.T, running bool) {
	t.Helper()
	originalReload, originalBGP := reloadWireGuard, configureBGP
	t.Cleanup(func() { reloadWireGuard, configureBGP = originalReload, originalBGP })
	reloadWireGuard = func(string) (bool, error) { return running, nil }
	configureBGP = func(*models.AppConfig) error { return nil }
}

func validStoreConfig() models.AppConfig {
	return models.AppConfig{Server: models.ServerConfig{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ListenPort: 51820,
		Address:    "10.0.0.1/24",
	}}
}
