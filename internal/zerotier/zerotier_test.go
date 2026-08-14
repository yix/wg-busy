package zerotier

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
	"time"

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

func TestStopServiceWaitsForProcessExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process signals are Unix-specific")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	s := &Supervisor{cmd: cmd, processDone: done}
	s.mu.Lock()
	s.stopService()
	s.mu.Unlock()
	if cmd.ProcessState == nil {
		t.Fatal("stopService returned before child exit")
	}
}

func TestWaitForProcess(t *testing.T) {
	done := make(chan struct{})
	close(done)
	if !waitForProcess(done, time.Second) {
		t.Fatal("closed process channel did not complete")
	}
	if waitForProcess(make(chan struct{}), time.Millisecond) {
		t.Fatal("open process channel completed before timeout")
	}
}

func TestSnapshotRevisionIgnoresIdenticalSnapshots(t *testing.T) {
	s := New(t.TempDir())
	s.setSnapshot(Snapshot{Enabled: true, Running: true})
	_, first := s.SnapshotVersion()
	s.setSnapshot(Snapshot{Enabled: true, Running: true})
	_, second := s.SnapshotVersion()

	if first == 0 || second != first {
		t.Fatalf("identical update changed revision: %d -> %d", first, second)
	}
}

func TestWaitForChangeWakesOnMeaningfulSnapshotUpdate(t *testing.T) {
	s := New(t.TempDir())
	s.setSnapshot(Snapshot{Enabled: true, Running: true})
	_, revision := s.SnapshotVersion()

	result := make(chan bool, 1)
	go func() {
		result <- s.WaitForChange(context.Background(), revision, time.Second)
	}()
	time.Sleep(10 * time.Millisecond)
	s.setSnapshot(Snapshot{Enabled: true, Running: true, Status: &Status{Online: true}})

	if !<-result {
		t.Fatal("long poll did not wake for changed online status")
	}
}

func TestWaitForChangeTimesOutWithoutDuplicateState(t *testing.T) {
	s := New(t.TempDir())
	_, revision := s.SnapshotVersion()
	if s.WaitForChange(context.Background(), revision, time.Millisecond) {
		t.Fatal("unchanged snapshot was reported as changed")
	}
}
