package wireguard

import (
	"errors"
	"reflect"
	"testing"
)

func TestReloadWGConfigUsesDirectCommands(t *testing.T) {
	type call struct {
		name  string
		args  []string
		stdin string
	}
	var calls []call
	original := runCommand
	t.Cleanup(func() { runCommand = original })
	runCommand = func(name string, args []string, stdin []byte) ([]byte, error) {
		calls = append(calls, call{name, append([]string(nil), args...), string(stdin)})
		if name == "wg-quick" {
			return []byte("[Interface]\nListenPort = 51820\n"), nil
		}
		return nil, nil
	}

	running, err := ReloadWGConfig()
	if err != nil || !running {
		t.Fatalf("ReloadWGConfig() = running %v, err %v", running, err)
	}
	want := []call{
		{"ip", []string{"link", "show", "wg0"}, ""},
		{"wg-quick", []string{"strip", "wg0"}, ""},
		{"wg", []string{"syncconf", "wg0", "/dev/stdin"}, "[Interface]\nListenPort = 51820\n"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
}

func TestReloadWGConfigSkipsMissingInterface(t *testing.T) {
	original := runCommand
	t.Cleanup(func() { runCommand = original })
	runCommand = func(string, []string, []byte) ([]byte, error) { return nil, errors.New("missing") }
	running, err := ReloadWGConfig()
	if err != nil || running {
		t.Fatalf("ReloadWGConfig() = running %v, err %v", running, err)
	}
}
