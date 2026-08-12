package ipam

import "testing"

func TestNextAvailableIPHandlesAddressLists(t *testing.T) {
	got, err := NextAvailableIP(
		"fd00::1/64, 10.0.0.1/24",
		[]string{"10.0.0.2/32, fd00::2/128"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.3/32" {
		t.Fatalf("NextAvailableIP = %q, want 10.0.0.3/32", got)
	}
}

func TestNextAvailableIPSupportsIPv6Only(t *testing.T) {
	got, err := NextAvailableIP("fd00::1/120", []string{"fd00::2/128"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "fd00::3/128" {
		t.Fatalf("NextAvailableIP = %q, want fd00::3/128", got)
	}
}
