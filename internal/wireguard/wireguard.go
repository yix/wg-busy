package wireguard

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"text/template"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/yix/wg-busy/internal/models"
)

var (
	ErrInterfaceDown = errors.New("WireGuard interface wg0 is not running")
	ErrRestartNeeded = errors.New("WireGuard requires a restart via Apply Config")
)

var runCommand = func(name string, args []string, stdin []byte) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// SetRunCommandForTesting overrides runCommand for unit testing.
func SetRunCommandForTesting(fn func(name string, args []string, stdin []byte) ([]byte, error)) func() {
	prev := runCommand
	runCommand = fn
	return func() { runCommand = prev }
}

// Gracefully reload WireGuard server configuration
// ReloadWGConfig gracefully reloads WireGuard server configuration.
// It checks if the interface exists before attempting reload to avoid errors during startup.
func ReloadWGConfig(configPath string) (bool, error) {
	// Check if interface exists
	if _, err := runCommand("ip", []string{"link", "show", "wg0"}, nil); err != nil {
		// Interface doesn't exist (e.g. during startup), skip reload
		return false, nil
	}

	stripped, err := runCommand("wg-quick", []string{"strip", configPath}, nil)
	if err != nil {
		return true, fmt.Errorf("stripping WireGuard config: %w: %s", err, strings.TrimSpace(string(stripped)))
	}
	out, err := runCommand("wg", []string{"syncconf", "wg0", "/dev/stdin"}, stripped)
	if err != nil {
		return true, fmt.Errorf("reloading WireGuard config: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return true, nil
}

// RestartWGConfig brings wg0 down and back up from the configured file. A
// missing interface on the way down is harmless; other teardown failures and
// failure to bring up the new configuration are not.
func RestartWGConfig(configPath string) error {
	if _, err := runCommand("ip", []string{"link", "show", "wg0"}, nil); err == nil {
		output, err := runCommand("wg-quick", []string{"down", configPath}, nil)
		if err != nil {
			return fmt.Errorf("bringing down WireGuard config %q: %w: %s", configPath, err, strings.TrimSpace(string(output)))
		}
	}
	output, err := runCommand("wg-quick", []string{"up", configPath}, nil)
	if err != nil {
		return fmt.Errorf("bringing up WireGuard config %q: %w: %s", configPath, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// ShowWG executes `wg show` and prepends each peer entry with its peer name comment (e.g. "# Alice").
func ShowWG(peers []models.Peer) (string, error) {
	out, err := runCommand("wg", []string{"show"}, nil)
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		if outStr != "" {
			return "", fmt.Errorf("wg show: %w: %s", err, outStr)
		}
		return "", fmt.Errorf("wg show: %w", err)
	}
	return FormatWGShow(string(out), peers), nil
}

// FormatWGShow takes raw `wg show` output and inserts peer names as comments above peer entries.
func FormatWGShow(raw string, peers []models.Peer) string {
	names := make(map[string]string, len(peers))
	for _, p := range peers {
		key := strings.TrimSpace(p.PublicKey)
		name := strings.TrimSpace(p.Name)
		if key != "" && name != "" {
			names[key] = name
		}
	}

	lines := strings.Split(raw, "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if strings.HasPrefix(trimmed, "peer: ") {
			key := strings.TrimSpace(strings.TrimPrefix(trimmed, "peer: "))
			if name, ok := names[key]; ok && name != "" {
				out = append(out, "# "+name)
			}
		}
		out = append(out, trimmed)
	}
	return strings.Join(out, "\n")
}

// ServerRestartReason names the wg-quick-owned fields that prevent syncconf
// from completing a live reload. These fields are deliberately absent from
// `wg-quick strip`, so syncconf can never make them live.
func ServerRestartReason(previous, next models.ServerConfig) error {
	var fields []string
	for _, field := range []struct {
		name    string
		changed bool
	}{
		{"Address", previous.Address != next.Address},
		{"DNS", previous.DNS != next.DNS},
		{"MTU", previous.MTU != next.MTU},
		{"Table", previous.Table != next.Table},
		{"FwMark", previous.FwMark != next.FwMark},
		// Hooks compare as rendered: a newline-only edit produces an identical
		// wg0.conf and must not cost the user every live tunnel.
		{"PreUp", !slices.Equal(hookLines(previous.PreUp), hookLines(next.PreUp))},
		{"PostUp", !slices.Equal(hookLines(previous.PostUp), hookLines(next.PostUp))},
		{"PreDown", !slices.Equal(hookLines(previous.PreDown), hookLines(next.PreDown))},
		{"PostDown", !slices.Equal(hookLines(previous.PostDown), hookLines(next.PostDown))},
	} {
		if field.changed {
			fields = append(fields, field.name)
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return fmt.Errorf("%w because %s changed; wg syncconf cannot apply wg-quick-managed settings", ErrRestartNeeded, strings.Join(fields, ", "))
}

// GenerateKeyPair generates a WireGuard private key and derives the public key.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generating private key: %w", err)
	}
	pub := priv.PublicKey()
	return priv.String(), pub.String(), nil
}

// GeneratePresharedKey generates a random preshared key.
func GeneratePresharedKey() (string, error) {
	key, err := wgtypes.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("generating preshared key: %w", err)
	}
	return key.String(), nil
}

// PublicKeyFromPrivate derives a public key from a base64-encoded private key.
func PublicKeyFromPrivate(privateKeyBase64 string) (string, error) {
	key, err := wgtypes.ParseKey(privateKeyBase64)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}
	return key.PublicKey().String(), nil
}

// serverConfData is the data passed to the server config template.
type serverConfData struct {
	Server           models.ServerConfig
	EnabledPeers     []peerConfData
	PostUpCommands   []string
	PostDownCommands []string
}

type peerConfData struct {
	models.Peer
	EffectiveAllowedIPs string
}

var serverConfTmpl = template.Must(template.New("server").Funcs(template.FuncMap{"hookLines": hookLines}).Parse(`[Interface]
PrivateKey = {{ .Server.PrivateKey }}
ListenPort = {{ .Server.ListenPort }}
Address = {{ .Server.Address }}
{{- if .Server.DNS }}
DNS = {{ .Server.DNS }}
{{- end }}
{{- if .Server.MTU }}
MTU = {{ .Server.MTU }}
{{- end }}
{{- if .Server.Table }}
Table = {{ .Server.Table }}
{{- end }}
{{- if .Server.FwMark }}
FwMark = {{ .Server.FwMark }}
{{- end }}
{{- range hookLines .Server.PreUp }}
PreUp = {{ . }}
{{- end }}
{{- range hookLines .Server.PostUp }}
PostUp = {{ . }}
{{- end }}
{{- range .PostUpCommands }}
PostUp = {{ . }}
{{- end }}
{{- range .PostDownCommands }}
PostDown = {{ . }}
{{- end }}
{{- range hookLines .Server.PostDown }}
PostDown = {{ . }}
{{- end }}
{{- range hookLines .Server.PreDown }}
PreDown = {{ . }}
{{- end }}
{{ range .EnabledPeers }}
[Peer]
# {{ .Name }}
PublicKey = {{ .PublicKey }}
{{- if .PresharedKey }}
PresharedKey = {{ .PresharedKey }}
{{- end }}
AllowedIPs = {{ .EffectiveAllowedIPs }}
{{- if .Endpoint }}
Endpoint = {{ .Endpoint }}
{{- end }}
{{- if .PersistentKeepalive }}
PersistentKeepalive = {{ .PersistentKeepalive }}
{{- end }}
{{ end }}`))

// RenderServerConfig produces the wg0.conf content.
// postUpCmds and postDownCmds are generated routing commands to inject.
func RenderServerConfig(cfg models.AppConfig, postUpCmds, postDownCmds []string) (string, error) {
	var peers []peerConfData
	for _, p := range cfg.Peers {
		if !p.Enabled {
			continue
		}
		effective := p.AllowedIPs
		if p.IsExitNode {
			if p.ExitNodeAllowAll {
				effective = "0.0.0.0/0, ::/0"
			} else if len(p.ExitNodeRoutes) > 0 {
				effective = fmt.Sprintf("%s, %s", p.AllowedIPs, strings.Join(p.ExitNodeRoutes, ", "))
			}
		}

		if len(p.AdvertisedRoutes) > 0 && effective != "0.0.0.0/0, ::/0" {
			effective = fmt.Sprintf("%s, %s", effective, strings.Join(p.AdvertisedRoutes, ", "))
		}

		peers = append(peers, peerConfData{
			Peer:                p,
			EffectiveAllowedIPs: effective,
		})
	}

	data := serverConfData{
		Server:           cfg.Server,
		EnabledPeers:     peers,
		PostUpCommands:   postUpCmds,
		PostDownCommands: postDownCmds,
	}

	var buf strings.Builder
	if err := serverConfTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("rendering server config: %w", err)
	}
	return buf.String(), nil
}

// clientConfData is the data passed to the client config template.
type clientConfData struct {
	Peer             models.Peer
	ServerPublicKey  string
	DNS              string
	ClientAllowedIPs string
	Endpoint         string
}

var clientConfTmpl = template.Must(template.New("client").Parse(`[Interface]
PrivateKey = {{ .Peer.PrivateKey }}
Address = {{ .Peer.AllowedIPs }}
{{- if .DNS }}
DNS = {{ .DNS }}
{{- end }}

[Peer]
PublicKey = {{ .ServerPublicKey }}
{{- if .Peer.PresharedKey }}
PresharedKey = {{ .Peer.PresharedKey }}
{{- end }}
AllowedIPs = {{ .ClientAllowedIPs }}
Endpoint = {{ .Endpoint }}
{{- if .Peer.PersistentKeepalive }}
PersistentKeepalive = {{ .Peer.PersistentKeepalive }}
{{- end }}
`))

func hookLines(value string) []string {
	var lines []string
	for line := range strings.SplitSeq(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// RenderClientConfig produces a client .conf file for a specific peer.
func RenderClientConfig(server models.ServerConfig, peer models.Peer) (string, error) {
	serverPub, err := PublicKeyFromPrivate(server.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("deriving server public key: %w", err)
	}

	dns := peer.DNS
	if dns == "" {
		dns = server.DNS
	}

	clientAllowedIPs := peer.ClientAllowedIPs
	if clientAllowedIPs == "" {
		clientAllowedIPs = "0.0.0.0/0, ::/0"
	}

	endpoint := server.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("SERVER_IP:%d", server.ListenPort)
	}

	data := clientConfData{
		Peer:             peer,
		ServerPublicKey:  serverPub,
		DNS:              dns,
		ClientAllowedIPs: clientAllowedIPs,
		Endpoint:         endpoint,
	}

	var buf strings.Builder
	if err := clientConfTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("rendering client config: %w", err)
	}
	return buf.String(), nil
}
