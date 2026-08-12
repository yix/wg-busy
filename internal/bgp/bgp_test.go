package bgp

import (
	"errors"
	"testing"

	"github.com/bio-routing/bio-rd/protocols/kernel"

	"github.com/yix/wg-busy/internal/models"
)

func TestServerStateIncludesEveryRestartSensitiveSetting(t *testing.T) {
	base := models.ServerConfig{BGPASN: 64512, BGPListenAddress: "10.0.0.1", BGPListenPort: 179}
	want := stateFor(base, 1)
	for name, mutate := range map[string]func(*models.ServerConfig){
		"ASN":            func(c *models.ServerConfig) { c.BGPASN++ },
		"listen address": func(c *models.ServerConfig) { c.BGPListenAddress = "10.0.0.2" },
		"listen port":    func(c *models.ServerConfig) { c.BGPListenPort++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if got := stateFor(changed, 1); got == want {
				t.Fatalf("%s change did not alter BGP runtime state", name)
			}
		})
	}
	if got := stateFor(base, 2); got == want {
		t.Fatal("Router ID change did not alter BGP runtime state")
	}
	if got := stateFor(models.ServerConfig{BGPListenPort: 179}, 1).listenAddress; got != "::" {
		t.Fatalf("default listen address = %q, want ::", got)
	}
}

func TestFailedKernelInitializationLeavesBGPStoppedAndRetryable(t *testing.T) {
	mu.Lock()
	originalKernel, originalActive := newKernel, active
	active = nil
	newKernel = func() (*kernel.Kernel, error) { return nil, errors.New("kernel unavailable") }
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		newKernel, active = originalKernel, originalActive
		mu.Unlock()
	})

	cfg := &models.AppConfig{Server: models.ServerConfig{
		Address: "10.0.0.1/24", BGPEnabled: true, BGPASN: 64512,
		BGPListenAddress: "127.0.0.1", BGPListenPort: 179,
	}}
	if err := Configure(cfg); err == nil {
		t.Fatal("Configure succeeded despite kernel initialization failure")
	}
	mu.Lock()
	running := active != nil
	mu.Unlock()
	if running || GetBGPStats().Running {
		t.Fatal("partially initialized BGP runtime was published as running")
	}
	if err := Configure(cfg); err == nil {
		t.Fatal("second Configure did not retry kernel initialization")
	}
}
