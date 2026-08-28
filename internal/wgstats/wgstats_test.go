package wgstats

import (
	"fmt"
	"testing"
	"time"
)

func TestCollectorCombinesBaseAndLiveCounters(t *testing.T) {
	pubKey := "testpeerkey1="
	rawDump := fmt.Sprintf("interface: wg0\n%s\t(none)\t1.2.3.4:51820\t10.0.0.2/32\t1700000000\t100\t200\t25\n", pubKey)

	restore := SetRunWGShowDumpForTesting(func() ([]byte, error) {
		return []byte(rawDump), nil
	})
	t.Cleanup(restore)

	c := NewCollector()
	c.SetPeerBases(map[string]PeerTrafficBase{
		pubKey: {Rx: 1000, Tx: 2000},
	})

	// First poll: sees initial rx=100, tx=200 -> session delta = 0 -> total = 1000, 2000
	c.poll()

	stats := c.GetPeerStats(pubKey)
	if stats == nil {
		t.Fatalf("expected stats for peer %s", pubKey)
	}
	if stats.TransferRx != 1000 || stats.TransferTx != 2000 {
		t.Fatalf("initial stats = Rx:%d, Tx:%d, want Rx:1000, Tx:2000", stats.TransferRx, stats.TransferTx)
	}

	// Second poll: rx advances to 150 (delta +50), tx to 280 (delta +80)
	rawDump = fmt.Sprintf("interface: wg0\n%s\t(none)\t1.2.3.4:51820\t10.0.0.2/32\t1700000010\t150\t280\t25\n", pubKey)
	c.poll()

	stats = c.GetPeerStats(pubKey)
	if stats.TransferRx != 1050 || stats.TransferTx != 2080 {
		t.Fatalf("after traffic stats = Rx:%d, Tx:%d, want Rx:1050, Tx:2080", stats.TransferRx, stats.TransferTx)
	}

	iface := c.GetInterfaceStats()
	if iface.TotalRx != 1050 || iface.TotalTx != 2080 {
		t.Fatalf("iface stats = Rx:%d, Tx:%d, want Rx:1050, Tx:2080", iface.TotalRx, iface.TotalTx)
	}

	// Third poll: interface restart / counter reset -> rx drops to 10 (delta +10), tx to 20 (delta +20)
	rawDump = fmt.Sprintf("interface: wg0\n%s\t(none)\t1.2.3.4:51820\t10.0.0.2/32\t1700000020\t10\t20\t25\n", pubKey)
	c.poll()

	stats = c.GetPeerStats(pubKey)
	if stats.TransferRx != 1060 || stats.TransferTx != 2100 {
		t.Fatalf("after reset stats = Rx:%d, Tx:%d, want Rx:1060, Tx:2100", stats.TransferRx, stats.TransferTx)
	}
}

func TestCollectorOnStatsAndHandshakesCallbacks(t *testing.T) {
	pubKey := "testpeerkey2="
	rawDump := fmt.Sprintf("interface: wg0\n%s\t(none)\t1.2.3.4:51820\t10.0.0.2/32\t1700000000\t500\t600\t25\n", pubKey)

	restore := SetRunWGShowDumpForTesting(func() ([]byte, error) {
		return []byte(rawDump), nil
	})
	t.Cleanup(restore)

	c := NewCollector()
	var gotStats map[string]PeerStats
	var gotHandshakes map[string]time.Time

	c.OnStats(func(m map[string]PeerStats) {
		gotStats = m
	})
	c.OnHandshakes(func(m map[string]time.Time) {
		gotHandshakes = m
	})

	c.poll()

	if len(gotStats) != 1 || gotStats[pubKey].TransferRx != 0 || gotStats[pubKey].TransferTx != 0 {
		t.Fatalf("unexpected gotStats: %#v", gotStats)
	}
	if len(gotHandshakes) != 1 || gotHandshakes[pubKey].Unix() != 1700000000 {
		t.Fatalf("unexpected gotHandshakes: %#v", gotHandshakes)
	}
}

func TestCollectorResetPeerBase(t *testing.T) {
	pubKey := "testpeerkey3="
	c := NewCollector()
	c.SetPeerBases(map[string]PeerTrafficBase{
		pubKey: {Rx: 5000, Tx: 6000},
	})
	c.ResetPeerBase(pubKey)

	rawDump := fmt.Sprintf("interface: wg0\n%s\t(none)\t1.2.3.4:51820\t10.0.0.2/32\t1700000000\t50\t60\t25\n", pubKey)
	restore := SetRunWGShowDumpForTesting(func() ([]byte, error) {
		return []byte(rawDump), nil
	})
	t.Cleanup(restore)

	c.poll()
	stats := c.GetPeerStats(pubKey)
	if stats.TransferRx != 0 || stats.TransferTx != 0 {
		t.Fatalf("reset peer stats = Rx:%d, Tx:%d, want Rx:0, Tx:0", stats.TransferRx, stats.TransferTx)
	}
}

func TestNoValueAmplificationAcrossMultipleSaves(t *testing.T) {
	pubKey := "testpeerkey4="
	// Base loaded at server start = 1000 Rx, 2000 Tx
	initialBaseRx := int64(1000)
	initialBaseTx := int64(2000)

	c := NewCollector()
	c.SetPeerBases(map[string]PeerTrafficBase{
		pubKey: {Rx: initialBaseRx, Tx: initialBaseTx},
	})

	var currentDump string
	restore := SetRunWGShowDumpForTesting(func() ([]byte, error) {
		return []byte(currentDump), nil
	})
	t.Cleanup(restore)

	// Step 1: Initial poll - wg show reports 100 Rx, 200 Tx from kernel
	currentDump = fmt.Sprintf("interface: wg0\n%s\t(none)\t1.2.3.4:51820\t10.0.0.2/32\t1700000000\t100\t200\t25\n", pubKey)
	c.poll()

	stats := c.GetPeerStats(pubKey)
	if stats.TransferRx != 1000 || stats.TransferTx != 2000 {
		t.Fatalf("initial stats = Rx:%d, Tx:%d, want 1000, 2000", stats.TransferRx, stats.TransferTx)
	}

	// Step 2: Traffic flows (+50 Rx, +80 Tx). wg show reports 150 Rx, 280 Tx
	currentDump = fmt.Sprintf("interface: wg0\n%s\t(none)\t1.2.3.4:51820\t10.0.0.2/32\t1700000010\t150\t280\t25\n", pubKey)
	c.poll()

	stats = c.GetPeerStats(pubKey)
	if stats.TransferRx != 1050 || stats.TransferTx != 2080 {
		t.Fatalf("step 2 stats = Rx:%d, Tx:%d, want 1050, 2080", stats.TransferRx, stats.TransferTx)
	}

	// Simulated 1-minute periodic save: config file is saved with 1050 / 2080.
	// But server session base remains 1000 / 2000, NOT updated to 1050 / 2080.

	// Step 3: More traffic flows (+50 Rx, +20 Tx). wg show reports 200 Rx, 300 Tx
	currentDump = fmt.Sprintf("interface: wg0\n%s\t(none)\t1.2.3.4:51820\t10.0.0.2/32\t1700000020\t200\t300\t25\n", pubKey)
	c.poll()

	stats = c.GetPeerStats(pubKey)
	// If value amplification occurred, it would be 1050 + 100 = 1150 or similar wrong numbers.
	// The true traffic is: base(1000) + total session delta(100) = 1100 Rx, and base(2000) + total session delta(100) = 2100 Tx.
	if stats.TransferRx != 1100 || stats.TransferTx != 2100 {
		t.Fatalf("step 3 stats = Rx:%d, Tx:%d, want 1100, 2100 (amplification detected if higher)", stats.TransferRx, stats.TransferTx)
	}

	// Simulated 2-minute periodic save: config file is saved with 1100 / 2100.

	// Step 4: More traffic flows (+100 Rx, +50 Tx). wg show reports 300 Rx, 350 Tx
	currentDump = fmt.Sprintf("interface: wg0\n%s\t(none)\t1.2.3.4:51820\t10.0.0.2/32\t1700000030\t300\t350\t25\n", pubKey)
	c.poll()

	stats = c.GetPeerStats(pubKey)
	if stats.TransferRx != 1200 || stats.TransferTx != 2150 {
		t.Fatalf("step 4 stats = Rx:%d, Tx:%d, want 1200, 2150", stats.TransferRx, stats.TransferTx)
	}
}
