package handlers

import (
	"html/template"
	"time"
)

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"formatTime": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format("2006-01-02")
	},
	"safeHTML": func(s string) template.HTML {
		return template.HTML(s)
	},
}).Parse(`
{{define "toast-success"}}
<div class="toast toast-success" role="alert">{{.}}</div>
{{end}}

{{define "toast-error"}}
<div class="toast toast-error" role="alert">{{.}}</div>
{{end}}

{{define "stats-bar"}}
<div id="stats-bar" class="stats-bar" hx-get="stats" hx-trigger="every 2s" hx-swap="outerHTML">
    <div class="stats-bar-inner">
        <span class="stats-status">
            {{if .IsUp}}<span class="status-dot status-up"></span> wg0 up {{.Uptime}}{{else}}<span class="status-dot status-down"></span> wg0 down{{end}}
        </span>
        <span class="stats-transfer">
            <span class="stats-rx">&darr; {{.TotalRx}}</span>
            <span class="stats-tx">&uarr; {{.TotalTx}}</span>
        </span>
        <span class="stats-sparkline">{{.SparklineSVG | safeHTML}}</span>
    </div>
</div>
{{end}}

{{define "peers-list"}}
<div id="peers-list" hx-get="peers/stats" hx-trigger="every 2s" hx-swap="none">
    <div class="header-row">
        <h2>Peers ({{len .Peers}})</h2>
        <button hx-get="peers/new" hx-target="#modal-container" hx-swap="innerHTML">+ Add Peer</button>
    </div>
    {{if not .Peers}}
    <p>No peers configured. Add one to get started.</p>
    {{else}}
    {{range .Peers}}
    {{template "peer-row" .}}
    {{end}}
    {{end}}
</div>
{{end}}

{{define "peer-row"}}
<div class="peer-row {{if not .Peer.Enabled}}peer-disabled{{end}}" id="peer-{{.Peer.ID}}">
    <div class="peer-info">
        <strong>
            {{.Peer.Name}}
            {{if .Peer.IsExitNode}}<span class="badge badge-exit">Exit Node</span>{{end}}
            {{if .ExitNodeName}}<span class="badge badge-via">via {{.ExitNodeName}}</span>{{end}}
        </strong>
        <small id="peer-stats-{{.Peer.ID}}">
           {{template "peer-stats" .}}
        </small>
    </div>
    <div class="peer-actions">
        <button class="outline secondary qr-btn" title="QR Code"
                hx-get="peers/{{.Peer.ID}}/qr" hx-target="#modal-container" hx-swap="innerHTML">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M0 0h7v7H0V0zm1 1v5h5V1H1zm1 1h3v3H2V2zm8-2h7v7H10V0zm1 1v5h5V1h-5zm1 1h3v3h-3V2zM0 10h7v6H0v-6zm1 1v4h5v-4H1zm1 1h3v2H2v-2zm8-2h2v2h-2v-2zm3 0h3v2h-3v-2zm-3 3h2v3h-2v-3zm3 0h1v1h-1v-1zm2 0h1v1h-1v-1zm2 0h1v3h-1v-3zm-2 2h1v1h-1v-1z"/></svg>
        </button>
        <a href="api/peers/{{.Peer.ID}}/config" download role="button" class="outline secondary">Download</a>
        <button class="outline" hx-get="peers/{{.Peer.ID}}/edit" hx-target="#modal-container" hx-swap="innerHTML">Edit</button>
        <button class="outline secondary"
                hx-put="peers/{{.Peer.ID}}/toggle"
                hx-target="#peer-{{.Peer.ID}}"
                hx-swap="outerHTML">
            {{if .Peer.Enabled}}Disable{{else}}Enable{{end}}
        </button>
        <button class="outline" style="color:var(--pico-del-color);border-color:var(--pico-del-color)"
                hx-delete="peers/{{.Peer.ID}}"
                hx-target="#tab-content"
                hx-swap="innerHTML"
                hx-confirm="Delete peer {{.Peer.Name}}?">
            Delete
        </button>
    </div>
</div>
{{end}}

{{define "peer-stats-oob"}}
<small id="peer-stats-{{.Peer.ID}}" hx-swap-oob="true">
    {{template "peer-stats" .}}
</small>
{{end}}

{{define "peer-stats"}}
    {{.Peer.AllowedIPs}}
    {{if .HasStats}} &middot; &darr;{{.TransferRx}} &uarr;{{.TransferTx}} &middot; shake {{.Handshake}}{{end}}
    {{if not .HasStats}} &middot; Created {{formatTime .Peer.CreatedAt}}{{end}}
    {{if .HasStats}} <span class="peer-sparkline">{{.SparklineSVG | safeHTML}}</span>{{end}}
{{end}}

{{define "qr-modal"}}
<dialog>
    <article>
        <header>
            <button aria-label="Close" rel="prev" onclick="closeModal()"></button>
            <p><strong>QR Code &mdash; {{.Name}}</strong></p>
        </header>
        <div style="text-align:center">
            <img src="api/peers/{{.ID}}/qr" alt="QR Code for {{.Name}}" width="256" height="256"
                 style="image-rendering:pixelated">
            <p><small>Scan with the WireGuard mobile app to import this peer configuration.</small></p>
        </div>
        <footer>
            <button type="button" onclick="closeModal()">Close</button>
        </footer>
    </article>
</dialog>
{{end}}

{{define "peer-form"}}
<dialog>
    <article>
        <header>
            <button aria-label="Close" rel="prev" onclick="closeModal()"></button>
            <p><strong>{{if .IsNew}}Add Peer{{else}}Edit Peer{{end}}</strong></p>
        </header>
        <form {{if .IsNew}}hx-post="peers"{{else}}hx-put="peers/{{.Peer.ID}}"{{end}}
              hx-target="#tab-content" hx-swap="innerHTML"
              onsubmit="validatePeerForm(event)">

            {{if .Error}}<div class="toast toast-error">{{.Error}}</div>{{end}}

            <label>
                Name *
                <input type="text" name="name" value="{{.Peer.Name}}" required maxlength="64"
                       placeholder="e.g. Alice Laptop"
                       {{if .ValidationErrors.HasField "name"}}aria-invalid="true"{{end}}>
                {{range .ValidationErrors}}{{if eq .Field "name"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </label>

            <label>
                Allowed IPs
                <input type="text" name="allowedIPs" value="{{.Peer.AllowedIPs}}"
                       placeholder="Auto-assign (leave empty)"
                       {{if .ValidationErrors.HasField "allowedIPs"}}aria-invalid="true"{{end}}>
                <small>Leave empty to auto-assign next available IP from server subnet.</small>
                {{range .ValidationErrors}}{{if eq .Field "allowedIPs"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </label>

            <label>
                Client Allowed IPs
                <input type="text" name="clientAllowedIPs" value="{{if .Peer.ClientAllowedIPs}}{{.Peer.ClientAllowedIPs}}{{else}}0.0.0.0/0, ::/0{{end}}"
                       placeholder="0.0.0.0/0, ::/0">
                <small>Routes the client sends through the tunnel.</small>
            </label>

            <label>
                DNS (override)
                <input type="text" name="dns" value="{{.Peer.DNS}}"
                       placeholder="Inherit from server">
            </label>

            <label>
                Persistent Keepalive (seconds)
                <input type="number" name="persistentKeepalive"
                       value="{{if .Peer.PersistentKeepalive}}{{.Peer.PersistentKeepalive}}{{else}}25{{end}}"
                       min="0" max="65535">
            </label>

            <label>
                Endpoint
                <input type="text" name="endpoint" value="{{.Peer.Endpoint}}"
                       placeholder="Not usually needed for server-side peers">
            </label>

            <fieldset>
                <label>
                    <input type="checkbox" name="presharedKey" {{if or .IsNew .Peer.PresharedKey}}checked{{end}}>
                    {{if .IsNew}}Generate preshared key{{else}}Has preshared key{{end}}
                </label>
                <label>
                    <input type="checkbox" name="enabled" {{if or .IsNew .Peer.Enabled}}checked{{end}}>
                    Enabled
                </label>
            </fieldset>

            <fieldset>
                <label>
                    <input type="checkbox" name="isExitNode" {{if .Peer.IsExitNode}}checked{{end}}
                           onchange="toggleExitNodeFields(this)">
                    Exit Node
                </label>
            </fieldset>

            <div id="route-via-field" {{if .Peer.IsExitNode}}style="display:none"{{end}}>
                <label>
                    Route via (exit node)
                    <select name="exitNodeID">
                        <option value="">None</option>
                        {{range .ExitNodes}}
                        <option value="{{.ID}}" {{if eq .ID $.Peer.ExitNodeID}}selected{{end}}>{{.Name}} ({{.AllowedIPs}})</option>
                        {{end}}
                    </select>
                </label>
            </div>

            <footer>
                <button type="button" class="secondary" onclick="closeModal()">Cancel</button>
                <button type="submit">{{if .IsNew}}Create Peer{{else}}Save Changes{{end}}</button>
            </footer>
        </form>
    </article>
</dialog>
{{end}}

{{define "server-config"}}
<div id="server-config">
    <div class="header-row">
        <h2>Server Configuration</h2>
        <div class="btn-group">
            <a href="api/server/config" download role="button" class="outline secondary">Download wg0.conf</a>
            <button hx-post="api/server/apply" hx-target="#apply-result" hx-swap="innerHTML"
                    hx-confirm="Apply configuration? This will restart the WireGuard interface.">
                Apply Config
            </button>
        </div>
    </div>

    <div id="apply-result"></div>

    {{if .Success}}<div class="toast toast-success">{{.Success}}</div>{{end}}
    {{if .Error}}<div class="toast toast-error">{{.Error}}</div>{{end}}

    <form hx-put="server" hx-target="#tab-content" hx-swap="innerHTML"
          onsubmit="validateServerForm(event)">

        <div class="grid">
            <label>
                Listen Port *
                <input type="number" name="listenPort" value="{{.Server.ListenPort}}"
                       required min="1" max="65535"
                       {{if .ValidationErrors.HasField "listenPort"}}aria-invalid="true"{{end}}>
                {{range .ValidationErrors}}{{if eq .Field "listenPort"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </label>
            <label>
                Address (CIDR) *
                <input type="text" name="address" value="{{.Server.Address}}"
                       required placeholder="10.0.0.1/24"
                       {{if .ValidationErrors.HasField "address"}}aria-invalid="true"{{end}}>
                {{range .ValidationErrors}}{{if eq .Field "address"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </label>
        </div>

        <label>
            Public Endpoint
            <input type="text" name="endpoint" value="{{.Server.Endpoint}}"
                   placeholder="vpn.example.com:51820">
            <small>Public address clients connect to. Used when generating client configs.</small>
        </label>

        <div class="grid">
            <label>
                DNS
                <input type="text" name="dns" value="{{.Server.DNS}}"
                       placeholder="1.1.1.1, 8.8.8.8"
                       {{if .ValidationErrors.HasField "dns"}}aria-invalid="true"{{end}}>
                {{range .ValidationErrors}}{{if eq .Field "dns"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </label>
            <label>
                MTU
                <input type="number" name="mtu" value="{{if .Server.MTU}}{{.Server.MTU}}{{end}}"
                       min="1280" max="65535" placeholder="Default (auto)"
                       {{if .ValidationErrors.HasField "mtu"}}aria-invalid="true"{{end}}>
                {{range .ValidationErrors}}{{if eq .Field "mtu"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </label>
        </div>

        <details>
            <summary>Advanced Options</summary>
            <div class="grid">
                <label>
                    Table
                    <input type="text" name="table" value="{{.Server.Table}}" placeholder="auto">
                </label>
                <label>
                    FwMark
                    <input type="text" name="fwMark" value="{{.Server.FwMark}}" placeholder="off">
                </label>
            </div>
            <label>
                PreUp
                <textarea name="preUp" rows="2" placeholder="Script to run before interface up">{{.Server.PreUp}}</textarea>
            </label>
            <label>
                PostUp
                <textarea name="postUp" rows="2" placeholder="iptables -A FORWARD...">{{.Server.PostUp}}</textarea>
            </label>
            <label>
                PreDown
                <textarea name="preDown" rows="2" placeholder="Script to run before interface down">{{.Server.PreDown}}</textarea>
            </label>
            <label>
                PostDown
                <textarea name="postDown" rows="2" placeholder="iptables -D FORWARD...">{{.Server.PostDown}}</textarea>
            </label>
            <label>
                <input type="checkbox" name="saveConfig" {{if .Server.SaveConfig}}checked{{end}}>
                SaveConfig (wg-quick will overwrite the config on shutdown)
            </label>
        </details>

        <details>
            <summary>Server Private Key</summary>
            <p><small>Changing this will break all existing peer connections.</small></p>
            <code style="word-break:break-all;">{{.Server.PrivateKey}}</code>
        </details>

        <button type="submit">Save Configuration</button>
    </form>
</div>
{{end}}
`))
