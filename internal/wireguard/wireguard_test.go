package wireguard

import (
	"errors"
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
	configPath := "/custom/wg0.conf"
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
	configPath := "/custom/wg0.conf"
	original := runCommand
	t.Cleanup(func() { runCommand = original })
	runCommand = func(name string, args []string, _ []byte) ([]byte, error) {
		if name == "wg-quick" && args[0] == "down" {
			return []byte("permission denied"), errors.New("exit 1")
		}
		return nil, nil
	}

	err := RestartWGConfig(configPath)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("RestartWGConfig error = %v", err)
	}
}

func TestRestartWGConfigReportsUpCommandOutput(t *testing.T) {
	original := runCommand
	t.Cleanup(func() { runCommand = original })
	runCommand = func(name string, args []string, _ []byte) ([]byte, error) {
		if name == "ip" {
			return nil, errors.New("missing")
		}
		return []byte("iptables: Bad rule (does a matching rule exist?)"), errors.New("exit 1")
	}

	err := RestartWGConfig("/custom/wg0.conf")
	if err == nil || !strings.Contains(err.Error(), "iptables: Bad rule") {
		t.Fatalf("RestartWGConfig error = %v", err)
	}
}

func TestServerRestartReason(t *testing.T) {
	base := models.ServerConfig{Address: "10.0.0.1/24", ListenPort: 51820}
	if reason := ServerRestartReason(base, base); reason != nil {
		t.Fatalf("unchanged server requires restart: %v", reason)
	}
	listenChanged := base
	listenChanged.ListenPort++
	if reason := ServerRestartReason(base, listenChanged); reason != nil {
		t.Fatalf("syncconf-compatible listen port change requires restart: %v", reason)
	}
	addressChanged := base
	addressChanged.Address = "10.1.0.1/24"
	if reason := ServerRestartReason(base, addressChanged); reason == nil {
		t.Fatal("address change did not require restart")
	}

	hooksChanged := base
	hooksChanged.PostUp = "iptables -A FORWARD -i wg0 -j ACCEPT"
	reason := ServerRestartReason(base, hooksChanged)
	if !errors.Is(reason, ErrRestartNeeded) || !strings.Contains(reason.Error(), "PostUp changed") {
		t.Fatalf("PostUp restart reason = %v", reason)
	}

	crlf, lf := base, base
	crlf.PostUp = "iptables up-1\r\niptables up-2\r\n"
	lf.PostUp = "iptables up-1\niptables up-2"
	if reason := ServerRestartReason(crlf, lf); reason != nil {
		t.Fatalf("newline-only hook difference requires restart: %v", reason)
	}
}

func TestRenderServerConfigSplitsMultilineHooks(t *testing.T) {
	cfg := models.AppConfig{Server: models.ServerConfig{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ListenPort: 51820,
		Address:    "10.0.0.1/24",
		PreUp:      "echo pre-1\r\n\n echo pre-2 ",
		PostUp:     "iptables up-1\niptables up-2",
		PostDown:   "iptables down-1\niptables down-2",
		PreDown:    "echo down-1\necho down-2",
	}}

	got, err := RenderServerConfig(cfg, []string{"generated up"}, []string{"generated down"})
	if err != nil {
		t.Fatal(err)
	}
	want := "PreUp = echo pre-1\n" +
		"PreUp = echo pre-2\n" +
		"PostUp = iptables up-1\n" +
		"PostUp = iptables up-2\n" +
		"PostUp = generated up\n" +
		"PostDown = generated down\n" +
		"PostDown = iptables down-1\n" +
		"PostDown = iptables down-2\n" +
		"PreDown = echo down-1\n" +
		"PreDown = echo down-2\n"
	if !strings.Contains(got, want) {
		t.Fatalf("rendered hooks:\n%s\nwant contiguous block:\n%s", got, want)
	}
}
