package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yix/wg-busy/internal/models"
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
		config:       models.AppConfig{Server: models.ServerConfig{DNS: "old"}},
	}
	if err := s.saveYAML(); err != nil {
		t.Fatal(err)
	}
	s.wgConfigPath = dir // renaming a file over this directory must fail
	if err := s.Write(func(cfg *models.AppConfig) error {
		cfg.Server.DNS = "new"
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
	if persisted.Server.DNS != "old" || s.config.Server.DNS != "old" {
		t.Fatalf("rollback = disk %q memory %q, want old", persisted.Server.DNS, s.config.Server.DNS)
	}
}

func TestWriteRejectsInvalidExitNodeReferenceBeforeSaving(t *testing.T) {
	dir := t.TempDir()
	s := &Store{
		configPath:   filepath.Join(dir, "config.yaml"),
		wgConfigPath: filepath.Join(dir, "wg0.conf"),
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
