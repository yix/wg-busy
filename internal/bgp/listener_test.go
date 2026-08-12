package bgp

import (
	"net"
	"testing"
	"time"

	"github.com/bio-routing/bio-rd/routingtable/vrf"
)

func TestListenerManagerCloseReleasesSocket(t *testing.T) {
	registry := vrf.NewVRFRegistry()
	defaultVRF := registry.CreateVRFIfNotExists(vrf.DefaultVRFName, 0)
	manager := newListenerManager(map[string][]string{vrf.DefaultVRFName: {"127.0.0.1:0"}})
	if err := manager.CreateListenersIfNotExists(defaultVRF); err != nil {
		t.Fatal(err)
	}
	listeners := manager.GetListeners(defaultVRF)
	if len(listeners) != 1 {
		t.Fatalf("listeners = %d, want 1", len(listeners))
	}
	address := listeners[0].(*managedListener).Addr().String()
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatalf("listener still accepted connections after Close on %s", address)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("second Close = %v, want idempotent success", err)
	}
}
