package wireguard

import (
	"fmt"
	"os/exec"
	"strings"
	"text/template"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/yix/wg-busy/internal/models"
)

// Gracefully reload WireGuard server configuration
func ReloadWGConfig() error {
	cmd := exec.Command("sh", "-c", "wg syncconf wg0 <(wg-quick strip wg0)")
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reload config: %v", err)
	}
	return nil
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

var serverConfTmpl = template.Must(template.New("server").Parse(`[Interface]
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
{{- if .Server.SaveConfig }}
SaveConfig = true
{{- end }}
{{- if .Server.PreUp }}
PreUp = {{ .Server.PreUp }}
{{- end }}
{{- if .Server.PostUp }}
PostUp = {{ .Server.PostUp }}
{{- end }}
{{- range .PostUpCommands }}
PostUp = {{ . }}
{{- end }}
{{- range .PostDownCommands }}
PostDown = {{ . }}
{{- end }}
{{- if .Server.PostDown }}
PostDown = {{ .Server.PostDown }}
{{- end }}
{{- if .Server.PreDown }}
PreDown = {{ .Server.PreDown }}
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
			effective = "0.0.0.0/0, ::/0"
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
