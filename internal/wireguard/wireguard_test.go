package wireguard

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yix/wg-busy/internal/models"
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

	running, err := ReloadWGConfig("/tmp/wg0.conf")
	if err != nil || !running {
		t.Fatalf("ReloadWGConfig() = running %v, err %v", running, err)
	}
	want := []call{
		{"ip", []string{"link", "show", "wg0"}, ""},
		{"wg-quick", []string{"strip", "/tmp/wg0.conf"}, ""},
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
	running, err := ReloadWGConfig("/tmp/wg0.conf")
	if err != nil || running {
		t.Fatalf("ReloadWGConfig() = running %v, err %v", running, err)
	}
}

func TestRestartWGConfigUsesConfiguredPath(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(configPath, []byte("desired"), 0600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	original := runCommand
	t.Cleanup(func() { runCommand = original })
	runCommand = func(name string, args []string, _ []byte) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}

	if err := RestartWGConfig(configPath); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"ip", "link", "show", "wg0"}, {"wg-quick", "down", configPath}, {"wg-quick", "up", configPath}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
}

func TestRestartWGConfigSkipsDownOnlyWhenInterfaceIsMissing(t *testing.T) {
	var calls [][]string
	original := runCommand
	t.Cleanup(func() { runCommand = original })
	runCommand = func(name string, args []string, _ []byte) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if name == "ip" {
			return nil, errors.New("missing")
		}
		return nil, nil
	}

	if err := RestartWGConfig("/custom/wg0.conf"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"ip", "link", "show", "wg0"}, {"wg-quick", "up", "/custom/wg0.conf"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
}

func TestRestartWGConfigReportsDownFailure(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(configPath, []byte("desired"), 0600); err != nil {
		t.Fatal(err)
	}
	original := runCommand
	t.Cleanup(func() { runCommand = original })
	runCommand = func(name string, args []string, _ []byte) ([]byte, error) {
		if name == "wg-quick" && args[0] == "down" {
			_ = os.WriteFile(configPath, []byte("partial SaveConfig state"), 0600)
			return []byte("permission denied"), errors.New("exit 1")
		}
		return nil, nil
	}

	err := RestartWGConfig(configPath)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("RestartWGConfig error = %v", err)
	}
	got, readErr := os.ReadFile(configPath)
	if readErr != nil || string(got) != "desired" {
		t.Fatalf("config after failed down = %q, err %v", got, readErr)
	}
}

func TestRestartWGConfigRestoresDesiredFileAfterSaveConfigDown(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(configPath, []byte("desired YAML render"), 0600); err != nil {
		t.Fatal(err)
	}
	original := runCommand
	t.Cleanup(func() { runCommand = original })
	runCommand = func(name string, args []string, _ []byte) ([]byte, error) {
		if name == "wg-quick" && args[0] == "down" {
			return nil, os.WriteFile(configPath, []byte("live SaveConfig state"), 0600)
		}
		if name == "wg-quick" && args[0] == "up" {
			got, err := os.ReadFile(configPath)
			if err != nil {
				return nil, err
			}
			if string(got) != "desired YAML render" {
				return nil, errors.New("wg-quick up received overwritten SaveConfig state")
			}
		}
		return nil, nil
	}
	if err := RestartWGConfig(configPath); err != nil {
		t.Fatal(err)
	}
}

func TestServerRequiresRestart(t *testing.T) {
	base := models.ServerConfig{Address: "10.0.0.1/24", ListenPort: 51820}
	if ServerRequiresRestart(base, base) {
		t.Fatal("unchanged server requires restart")
	}
	listenChanged := base
	listenChanged.ListenPort++
	if ServerRequiresRestart(base, listenChanged) {
		t.Fatal("syncconf-compatible listen port change requires restart")
	}
	addressChanged := base
	addressChanged.Address = "10.1.0.1/24"
	if !ServerRequiresRestart(base, addressChanged) {
		t.Fatal("address change did not require restart")
	}
}
