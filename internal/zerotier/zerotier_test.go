package zerotier

import (
	"testing"

	"github.com/yix/wg-busy/internal/models"
)

func TestConfigureCopiesDesiredNetworks(t *testing.T) {
	s := &Supervisor{}
	cfg := models.AppConfig{
		ZeroTier: models.ZeroTierConfig{
			Networks: []models.ZeroTierNetwork{{ID: "8056c2e21c000001", Name: "original"}},
		},
	}

	s.Configure(&cfg)
	cfg.ZeroTier.Networks[0].Name = "mutated"

	s.mu.Lock()
	got := s.desired.Networks[0].Name
	s.mu.Unlock()
	if got != "original" {
		t.Fatalf("desired network was aliased with caller: got %q", got)
	}
}
