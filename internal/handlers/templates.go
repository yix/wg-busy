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
<div class="toast toast-error" role="alert" hx-swap-oob="beforeend:#toast-container">{{.}}</div>
{{end}}

{{/* Summary of every validation error, so errors on fields without their own
     inline message (or with indexed names) are still shown. */}}
{{define "error-summary"}}
{{if .}}
<div class="toast toast-error" role="alert">
    <div>
        <strong>Could not save &mdash; please fix:</strong>
        <ul class="error-list">
            {{range .}}<li><code>{{.Field}}</code> {{.Message}}</li>{{end}}
        </ul>
    </div>
</div>
{{end}}
{{end}}

{{/* The polled stats fragment: the bar itself, plus an out-of-band swap per
     peer row so the list's own stats refresh on the same tick. */}}
{{define "stats-bar"}}
<div class="stats-bar-inner">
    <span class="stats-status">
        {{if .IsUp}}
        <span class="status-dot status-up"></span> wg0 up {{.Uptime}}
        {{else}}
        <span class="status-dot status-down"></span> wg0 down
        {{end}}
    </span>
    <span class="stats-transfer">
        <span class="stats-rx">&darr; {{.CurrentRxPS}} <small class="text-muted">({{.TotalRx}})</small></span>
        <span class="stats-tx">&uarr; {{.CurrentTxPS}} <small class="text-muted">({{.TotalTx}})</small></span>
    </span>
    <span class="stats-sparkline">{{.SparklineSVG | safeHTML}}</span>
</div>
{{range .Peers}}
<small id="peer-stats-{{.Peer.ID}}" hx-swap-oob="true">{{template "peer-stats" .}}</small>
{{end}}
{{end}}

{{define "peers-list"}}
<div id="peers-list" {{if .OOB}}hx-swap-oob="true"{{end}}>
    <div class="header-row">
        <h2>Peers ({{len .Peers}})</h2>
        <button class="btn btn-primary" hx-get="peers/new" hx-target="#modal-container" hx-swap="innerHTML">+ Add Peer</button>
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
            {{if .Peer.StrictPolicyRouting}}<span class="badge badge-warn" title="Traffic may only use this peer's own routes">Strict</span>{{end}}
        </strong>
        {{if .Endpoint}}<div style="font-size:0.8em;font-weight:normal;opacity:0.7;margin-top:0.1em">({{.Endpoint}})</div>{{end}}
        <small id="peer-stats-{{.Peer.ID}}">
           {{template "peer-stats" .}}
        </small>
    </div>
    <div class="peer-actions">
        <button class="btn btn-outline secondary qr-btn" title="QR Code"
                hx-get="peers/{{.Peer.ID}}/qr" hx-target="#modal-container" hx-swap="innerHTML">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M0 0h7v7H0V0zm1 1v5h5V1H1zm1 1h3v3H2V2zm8-2h7v7H10V0zm1 1v5h5V1h-5zm1 1h3v3h-3V2zM0 10h7v6H0v-6zm1 1v4h5v-4H1zm1 1h3v2H2v-2zm8-2h2v2h-2v-2zm3 0h3v2h-3v-2zm-3 3h2v3h-2v-3zm3 0h1v1h-1v-1zm2 0h1v1h-1v-1zm2 0h1v3h-1v-3zm-2 2h1v1h-1v-1z"/></svg>
        </button>
        <a href="api/peers/{{.Peer.ID}}/config" download role="button" class="btn btn-outline secondary">Download</a>
        <button class="btn btn-outline" hx-get="peers/{{.Peer.ID}}/edit" hx-target="#modal-container" hx-swap="innerHTML">Edit</button>
        <button class="btn btn-outline secondary"
                hx-put="peers/{{.Peer.ID}}/toggle"
                hx-target="#peer-{{.Peer.ID}}"
                hx-swap="outerHTML">
            {{if .Peer.Enabled}}Disable{{else}}Enable{{end}}
        </button>
        <button class="btn btn-outline-danger"
                hx-delete="peers/{{.Peer.ID}}"
                hx-target="#tab-content"
                hx-swap="innerHTML"
                hx-confirm="Delete peer {{.Peer.Name}}?">
            Delete
        </button>
    </div>
</div>
{{end}}

{{define "peer-stats"}}
    {{.Peer.AllowedIPs}}
    {{if .HasStats}} &middot; <span class="stats-rx">&darr;{{.CurrentRxPS}} <small class="text-muted">({{.TransferRx}})</small></span> <span class="stats-tx">&uarr;{{.CurrentTxPS}} <small class="text-muted">({{.TransferTx}})</small></span> &middot; shake {{.Handshake}}{{end}}
    {{if not .HasStats}} &middot; Created {{formatTime .Peer.CreatedAt}}{{end}}
    {{if .HasStats}} <span class="peer-sparkline">{{.SparklineSVG | safeHTML}}</span>{{end}}
{{end}}

{{define "qr-modal"}}
<dialog>
    <article>
        <header class="flex-row">
            <p class="mb-0"><strong>QR Code &mdash; {{.Name}}</strong></p>
            <button aria-label="Close" class="btn btn-outline secondary mb-0" style="padding: 0.1rem 0.6rem" onclick="closeModal()">X</button>
        </header>
        <div style="text-align:center">
            <img src="api/peers/{{.ID}}/qr" alt="QR Code for {{.Name}}" width="256" height="256"
                 style="image-rendering:pixelated">
            <p><small>Scan with the WireGuard mobile app to import this peer configuration.</small></p>
        </div>
        <footer>
            <button type="button" class="btn btn-secondary" onclick="closeModal()">Close</button>
        </footer>
    </article>
</dialog>
{{end}}

{{define "peer-form"}}
<dialog>
    <article>
        <header class="flex-row">
            <p class="mb-0"><strong>{{if .IsNew}}Add Peer{{else}}Edit Peer{{end}}</strong></p>
            <button aria-label="Close" class="btn btn-outline secondary mb-0" style="padding: 0.1rem 0.6rem" onclick="closeModal()">X</button>
        </header>
        <form {{if .IsNew}}hx-post="peers"{{else}}hx-put="peers/{{.Peer.ID}}"{{end}}
              hx-target="#modal-container" hx-swap="innerHTML">

            {{if .Error}}<div class="toast toast-error" role="alert">{{.Error}}</div>{{end}}
            {{template "error-summary" .ValidationErrors}}

            <label>
                Name *
                <input type="text" name="name" value="{{.Peer.Name}}" required maxlength="64"
                       placeholder="e.g. Alice Laptop"
                       {{if .ValidationErrors.HasField "name"}}aria-invalid="true"{{end}}>
                {{range .ValidationErrors}}{{if eq .Field "name"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </label>

            <label>
                Client IP
                <input type="text" name="allowedIPs" value="{{.Peer.AllowedIPs}}"
                       placeholder="Auto-assign (leave empty)"
                       {{if .ValidationErrors.HasField "allowedIPs"}}aria-invalid="true"{{end}}>
                <small>Leave empty to auto-assign next available IP from server subnet.</small>
                {{range .ValidationErrors}}{{if eq .Field "allowedIPs"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </label>

            <label>
                Allowed Client IPs
                <input type="text" name="clientAllowedIPs" value="{{if .Peer.ClientAllowedIPs}}{{.Peer.ClientAllowedIPs}}{{else}}0.0.0.0/0, ::/0{{end}}"
                       placeholder="0.0.0.0/0, ::/0">
                <small>Routes the client sends through the tunnel.</small>
            </label>

            <label>
                Advertised Routes
                <textarea name="advertisedRoutes" rows="2"
                          placeholder="10.1.2.0/24">{{range .Peer.AdvertisedRoutes}}{{.}}
{{end}}</textarea>
                <small>Networks behind this peer to route through the tunnel (one CIDR per line or comma-separated).</small>
                {{range .ValidationErrors}}{{if eq .Field "advertisedRoutes"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </label>
            
            <label>
                Policy Routes
                <textarea name="policyRoutes" rows="2"
                          placeholder="10.5.5.0/24 via 10.0.0.1">{{range .Peer.PolicyRoutes}}{{.}}
{{end}}</textarea>
                <small>Format: &lt;CIDR&gt; via &lt;Gateway IP&gt;, one per line. Traffic to these subnets from this peer will be routed via the gateway.</small>
                <small>
                    The gateway can be a WireGuard peer or a ZeroTier peer &mdash; the route follows whichever interface it is on-link for. Available:
                    {{range $i, $g := .Gateways}}{{if $i}}, {{end}}<code>{{$g.CIDR}}</code> ({{$g.Device}}){{else}}none configured{{end}}
                </small>
                {{range .ValidationErrors}}{{if eq .Field "policyRoutes"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </label>

            <fieldset>
                <label>
                    <input type="checkbox" name="strictPolicyRouting" {{if .Peer.StrictPolicyRouting}}checked{{end}}>
                    Strict policy routing
                </label>
                <small>
                    Traffic from this peer may only use the routes above. Anything they do not
                    match is rejected instead of falling back to the server's main routing table,
                    so nothing can leak out of the intended path.
                </small>
                {{range .ValidationErrors}}{{if eq .Field "strictPolicyRouting"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </fieldset>

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
                    <input type="checkbox" name="presharedKey" {{if or .Defaults .Peer.PresharedKey}}checked{{end}}>
                    {{if .IsNew}}Generate preshared key{{else}}Has preshared key{{end}}
                </label>
                <label>
                    <input type="checkbox" name="enabled" {{if or .Defaults .Peer.Enabled}}checked{{end}}>
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

            <div id="exit-node-config" {{if not .Peer.IsExitNode}}style="display:none"{{end}} class="exit-node-field">
                <fieldset>
                    <legend>Exit Node Configuration</legend>
                    <label>
                        <input type="checkbox" name="exitNodeAllowAll"
                               {{if or .Defaults .Peer.ExitNodeAllowAll}}checked{{end}}
                               onchange="toggleExitNodeRoutes(this)">
                        Route all traffic via this node (0.0.0.0/0)
                    </label>

                    <div id="exit-node-routes-field" {{if or .Defaults .Peer.ExitNodeAllowAll}}style="display:none"{{end}}>
                        <label>
                            Specific Routes (CIDRs)
                            <textarea name="exitNodeRoutes" rows="3" 
                                      placeholder="10.0.0.0/24">{{range .Peer.ExitNodeRoutes}}{{.}}
{{end}}</textarea>
                            <small>One CIDR per line. Leave empty to route nothing (if check disabled).</small>
                        </label>
                    </div>
                </fieldset>
            </div>

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

            <fieldset>
                <legend>BGP Overlay Settings</legend>
                <label>
                    <input type="checkbox" id="bgpEnabled" name="bgpEnabled" {{if .Peer.BGPEnabled}}checked{{end}} onchange="toggleBGPSettings(this)">
                    Enable BGP
                </label>
                <div id="bgp-settings-config" {{if not .Peer.BGPEnabled}}style="display:none"{{end}}>
                    <label>
                        <input type="checkbox" name="bgpConnect" {{if .Peer.BGPConnect}}checked{{end}} title="Actively initiate connection to the peer"> Connect
                    </label>
                    <div class="grid">
                        <label>
                            Peer BGP IP *
                            <input type="text" name="bgpPeerIP" value="{{.Peer.BGPPeerIP}}" placeholder="10.0.0.123" {{if .ValidationErrors.HasField "bgpPeerIP"}}aria-invalid="true"{{end}}>
                            {{range .ValidationErrors}}{{if eq .Field "bgpPeerIP"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
                        </label>
                        <label>
                            Peer ASN *
                            <input type="number" name="bgpPeerAsn" value="{{if .Peer.BGPPeerASN}}{{.Peer.BGPPeerASN}}{{else}}64512{{end}}" {{if .ValidationErrors.HasField "bgpPeerAsn"}}aria-invalid="true"{{end}}>
                            {{range .ValidationErrors}}{{if eq .Field "bgpPeerAsn"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
                        </label>
                        <label>
                            Peer Port *
                            <input type="number" name="bgpPeerPort" value="179" min="179" max="179" readonly {{if .ValidationErrors.HasField "bgpPeerPort"}}aria-invalid="true"{{end}}>
                            <small>The embedded BGP engine currently supports peer port 179.</small>
                            {{range .ValidationErrors}}{{if eq .Field "bgpPeerPort"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
                        </label>
                    </div>
                    
                    <div style="margin-top: 1rem;">
                        <label>Received Prefix Filters</label>
                        <small>Controls which prefixes received from this peer are accepted. Leave empty to accept everything.</small>
                        <div id="bgp-route-filters-list">
                            {{range $i, $filter := .Peer.BGPRouteFilters}}
                            <div class="route-filter-row" style="display:flex; gap:0.5rem; margin-bottom:0.5rem;">
                                <input type="text" name="filterPrefix[]" value="{{$filter.Prefix}}" placeholder="Prefix (e.g. 10.1.0.0/16)" style="flex:1">
                                <select name="filterMatcher[]" style="width:auto">
                                    <option value="exact" {{if eq $filter.Matcher "exact"}}selected{{end}}>Exact</option>
                                    <option value="orlonger" {{if eq $filter.Matcher "orlonger"}}selected{{end}}>Or Longer</option>
                                </select>
                                <select name="filterAction[]" style="width:auto">
                                    <option value="accept" {{if eq $filter.Action "accept"}}selected{{end}}>Accept</option>
                                    <option value="reject" {{if eq $filter.Action "reject"}}selected{{end}}>Reject</option>
                                </select>
                                <button type="button" class="btn btn-outline-danger" style="width:auto" onclick="this.closest('.route-filter-row').remove()">X</button>
                            </div>
                            {{end}}
                        </div>
                        <button type="button" class="btn btn-outline secondary" style="width:auto; margin-top:0.5rem;" onclick="addRouteFilterRow()">+ Add Filter</button>
                    </div>

                    <div style="margin-top: 1rem;">
                        <label>Advertised Prefix Filters</label>
                        <small>Controls which locally known prefixes are advertised to this peer. Leave empty to advertise everything.</small>
                        <div id="bgp-export-filters-list">
                            {{range $i, $filter := .Peer.BGPExportFilters}}
                            <div class="route-filter-row" style="display:flex; gap:0.5rem; margin-bottom:0.5rem;">
                                <input type="text" name="exportFilterPrefix[]" value="{{$filter.Prefix}}" placeholder="Prefix (e.g. 10.1.0.0/16)" style="flex:1">
                                <select name="exportFilterMatcher[]" style="width:auto">
                                    <option value="exact" {{if eq $filter.Matcher "exact"}}selected{{end}}>Exact</option>
                                    <option value="orlonger" {{if eq $filter.Matcher "orlonger"}}selected{{end}}>Or Longer</option>
                                </select>
                                <select name="exportFilterAction[]" style="width:auto">
                                    <option value="accept" {{if eq $filter.Action "accept"}}selected{{end}}>Accept</option>
                                    <option value="reject" {{if eq $filter.Action "reject"}}selected{{end}}>Reject</option>
                                </select>
                                <button type="button" class="btn btn-outline-danger" style="width:auto" onclick="this.closest('.route-filter-row').remove()">X</button>
                            </div>
                            {{end}}
                        </div>
                        <button type="button" class="btn btn-outline secondary" style="width:auto; margin-top:0.5rem;" onclick="addRouteFilterRow('bgp-export-filters-list', 'exportFilter')">+ Add Filter</button>
                    </div>
                </div>
            </fieldset>

            <footer>
                <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button type="submit" class="btn btn-primary">{{if .IsNew}}Create Peer{{else}}Save Changes{{end}}</button>
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
            <a href="api/server/config" download role="button" class="btn btn-outline secondary">Download wg0.conf</a>
            <button class="btn btn-primary" hx-post="api/server/apply" hx-target="#apply-result" hx-swap="innerHTML"
                    hx-confirm="Apply configuration? This will restart the WireGuard interface.">
                Apply Config
            </button>
        </div>
    </div>

    <div id="apply-result"></div>

    {{if .Success}}<div class="toast toast-success" role="alert">{{.Success}}</div>{{end}}
    {{if .Error}}<div class="toast toast-error" role="alert">{{.Error}}</div>{{end}}
    {{template "error-summary" .ValidationErrors}}

    <form hx-put="server" hx-target="#tab-content" hx-swap="innerHTML">

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

        <fieldset>
            <legend>BGP Server Configuration</legend>
            <label>
                <input type="checkbox" name="bgpEnabled" {{if .Server.BGPEnabled}}checked{{end}}>
                Enable BGP Overlay
            </label>
            <div class="grid">
                <label>
                    BGP ASN
                    <input type="number" name="bgpAsn" value="{{if .Server.BGPASN}}{{.Server.BGPASN}}{{else}}64512{{end}}" placeholder="64512" {{if .ValidationErrors.HasField "bgpAsn"}}aria-invalid="true"{{end}}>
                    {{range .ValidationErrors}}{{if eq .Field "bgpAsn"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
                </label>
                <label>
                    BGP Listen Address
                    <input type="text" name="bgpListenAddress" value="{{.Server.BGPListenAddress}}" placeholder="(Optional, wg0 IP)" {{if .ValidationErrors.HasField "bgpListenAddress"}}aria-invalid="true"{{end}}>
                    {{range .ValidationErrors}}{{if eq .Field "bgpListenAddress"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
                </label>
                <label>
                    BGP Listen Port
                    <input type="number" name="bgpListenPort" value="{{if .Server.BGPListenPort}}{{.Server.BGPListenPort}}{{else}}179{{end}}" placeholder="179" {{if .ValidationErrors.HasField "bgpListenPort"}}aria-invalid="true"{{end}}>
                    {{range .ValidationErrors}}{{if eq .Field "bgpListenPort"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
                </label>
            </div>
        </fieldset>

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

        <button type="submit" class="btn btn-primary">Save Configuration</button>
    </form>
</div>
{{end}}

{{define "zerotier-tab"}}
<div id="zerotier">
    <div class="header-row">
        <h2>ZeroTier</h2>
        <div class="btn-group">
            <button class="btn btn-outline secondary" hx-post="api/zerotier/restart"
                    hx-target="#zerotier-action-result" hx-swap="innerHTML"
                    hx-confirm="Restart the ZeroTier service?">
                Restart Service
            </button>
        </div>
    </div>

    <div id="zerotier-action-result"></div>

    {{if .Success}}<div class="toast toast-success" role="alert">{{.Success}}</div>{{end}}
    {{if .Error}}<div class="toast toast-error" role="alert">{{.Error}}</div>{{end}}
    {{template "error-summary" .ValidationErrors}}

    <form hx-put="zerotier" hx-target="#tab-content" hx-swap="innerHTML">
        <fieldset>
            <label>
                <input type="checkbox" name="ztEnabled" {{if .Config.Enabled}}checked{{end}}>
                Enable ZeroTier
            </label>
        </fieldset>
        <div class="grid">
            <label>
                Primary Port
                <input type="number" name="ztPort" value="{{.Port}}" min="1024" max="65535"
                       placeholder="9993"
                       {{if .ValidationErrors.HasField "ztPort"}}aria-invalid="true"{{end}}>
                <small>UDP port for peer-to-peer traffic. Changing it restarts the service.</small>
            </label>
        </div>
        <button type="submit" class="btn btn-primary">Save Settings</button>
    </form>

    <h3>Networks</h3>
    <form hx-post="zerotier/networks" hx-target="#tab-content" hx-swap="innerHTML">
        <div class="grid">
            <label>
                Network ID *
                <input type="text" name="networkID" required minlength="16" maxlength="16"
                       placeholder="8056c2e21c000001" pattern="[0-9a-fA-F]{16}">
            </label>
            <label>
                Label
                <input type="text" name="networkName" maxlength="64" placeholder="e.g. Home LAN">
            </label>
        </div>
        <fieldset>
            <label><input type="checkbox" name="allowManaged" checked> Allow managed IPs and routes</label>
            <label><input type="checkbox" name="allowGlobal"> Allow global (public) IP assignments</label>
            <label><input type="checkbox" name="allowDefault"> Allow default route override</label>
            <label><input type="checkbox" name="allowDNS"> Allow DNS configuration</label>
        </fieldset>
        <button type="submit" class="btn btn-primary">Join Network</button>
    </form>

    <div id="zerotier-status" hx-get="zerotier/status" hx-trigger="every 2s" hx-swap="innerHTML">
        {{template "zerotier-status" .}}
    </div>
</div>
{{end}}

{{define "zerotier-status"}}
{{if not .Config.Enabled}}
<article class="toast toast-error">ZeroTier is disabled. Enable it above to start the service.</article>
{{else}}
    {{if .Snapshot.ServiceErr}}
    <div class="toast toast-error" role="alert">
        <div>
            <strong>ZeroTier service problem</strong>
            <div>{{.Snapshot.ServiceErr}}</div>
            {{if .Snapshot.Hint}}<div><small>{{.Snapshot.Hint}}</small></div>{{end}}
        </div>
    </div>
    {{end}}
    {{if .Snapshot.Err}}<div class="toast toast-error" role="alert">{{.Snapshot.Err}}</div>{{end}}

    <div class="grid" style="margin-bottom: 2rem;">
        <article>
            <header><strong>Service</strong></header>
            {{if .Snapshot.ServiceErr}}
            <span class="status-dot status-down"></span> Running, degraded
            {{else if .Snapshot.Running}}
            <span class="status-dot status-up"></span> Running {{.Uptime}}
            {{else}}
            <span class="status-dot status-down"></span> Not running
            {{end}}
        </article>
        <article>
            <header><strong>Node Address</strong></header>
            {{if .Snapshot.Status}}<code>{{.Snapshot.Status.Address}}</code>{{else}}&mdash;{{end}}
        </article>
        <article>
            <header><strong>My ZeroTier IP</strong></header>
            {{if .Addresses}}
                {{range .Addresses}}<div><code>{{.}}</code></div>{{end}}
            {{else}}
                <span class="text-muted">Not assigned yet</span>
            {{end}}
        </article>
        <article>
            <header><strong>Online</strong></header>
            {{if .Snapshot.Status}}
                {{if .Snapshot.Status.Online}}
                <span class="status-dot status-up"></span> Online{{if .Snapshot.Status.TCPFallbackActive}} (TCP relay){{end}}
                {{else}}
                <span class="status-dot status-down"></span> Offline
                {{end}}
                <div><small class="text-muted">v{{.Snapshot.Status.Version}}</small></div>
            {{else}}&mdash;{{end}}
        </article>
    </div>

    {{if .Pending}}
    <h4>Not Joined ({{len .Pending}})</h4>
    {{range .Pending}}
    <article class="toast toast-error" role="alert">
        <div>
            {{if .Name}}{{.Name}} &mdash; {{end}}<code>{{.ID}}</code> is configured but the ZeroTier service has not joined it.
            <div><small>Check the service problem above, or confirm the network ID exists.</small></div>
        </div>
    </article>
    {{end}}
    {{end}}

    <h4>Joined Networks ({{len .Networks}})</h4>
    {{if not .Networks}}
    <p>No networks joined yet.</p>
    {{else}}
    {{range .Networks}}
    <article style="margin-bottom: 1.5rem;">
        <header class="flex-row">
            <strong>
                {{if .Label}}{{.Label}} &mdash; {{end}}<code>{{.ID}}</code>
                {{if .Name}}<span class="badge badge-via">{{.Name}}</span>{{end}}
                {{if eq .Status "OK"}}<span class="badge badge-ok">{{.Status}}</span>{{else}}<span class="badge badge-warn">{{.Status}}</span>{{end}}
            </strong>
            <button class="btn btn-outline-danger" style="width:auto"
                    hx-delete="zerotier/networks/{{.ID}}"
                    hx-target="#tab-content" hx-swap="innerHTML"
                    hx-confirm="Leave network {{.ID}}?">
                Leave
            </button>
        </header>

        <p>
            <small>
                {{if .AssignedAddresses}}{{range $i, $a := .AssignedAddresses}}{{if $i}}, {{end}}<code>{{$a}}</code>{{end}}{{else}}No address assigned{{end}}
                {{if .PortDeviceName}} &middot; {{.PortDeviceName}}{{end}}
                {{if .MTU}} &middot; MTU {{.MTU}}{{end}}
                {{if .Type}} &middot; {{.Type}}{{end}}
            </small>
        </p>

        <p>
            {{if and .PortDeviceName (not .PortError)}}
            <span class="stats-rx">&darr; {{if .RxPS}}{{.RxPS}} {{end}}<small class="text-muted">({{.Rx}})</small></span>
            <span class="stats-tx">&uarr; {{if .TxPS}}{{.TxPS}} {{end}}<small class="text-muted">({{.Tx}})</small></span>
            {{else if .PortError}}
            <small class="field-error">No network interface: ZeroTier could not create <code>{{.PortDeviceName}}</code> (port error {{.PortError}}). Traffic cannot flow over this network.</small>
            {{else if eq .Status "ACCESS_DENIED"}}
            <small class="field-error">Not authorized &mdash; approve this node in ZeroTier Central to get an address.</small>
            {{else}}
            <small class="text-muted">No interface yet &mdash; waiting for the network configuration.</small>
            {{end}}
        </p>

        {{$dev := .PortDeviceName}}
        <strong><small>Routes received from this network ({{len .Routes}})</small></strong>
        {{if .Routes}}
        <table role="grid">
            <thead><tr><th scope="col">Target</th><th scope="col">Via</th><th scope="col">Metric</th></tr></thead>
            <tbody>
            {{range .Routes}}
            <tr>
                <td><code>{{.Target}}</code></td>
                <td>{{if .Via}}<code>{{.Via}}</code>{{else}}<span class="text-muted">on-link ({{$dev}})</span>{{end}}</td>
                <td>{{.Metric}}</td>
            </tr>
            {{end}}
            </tbody>
        </table>
        {{else}}
        <p><small class="text-muted">No routes pushed by this network.</small></p>
        {{end}}
    </article>
    {{end}}
    {{end}}

    <h4>Peers ({{len .Peers}})</h4>
    {{if not .Peers}}
    <p>No peers known.</p>
    {{else}}
    <table role="grid">
        <thead>
            <tr>
                <th scope="col">Address</th>
                <th scope="col">Role</th>
                <th scope="col">Version</th>
                <th scope="col">Latency</th>
                <th scope="col">Paths</th>
            </tr>
        </thead>
        <tbody>
            {{range .Peers}}
            <tr>
                <td><code>{{.Address}}</code></td>
                <td>{{.Role}}</td>
                <td>{{if .Version}}{{.Version}}{{else}}&mdash;{{end}}</td>
                <td>{{.LatencyText}}</td>
                <td><small>{{.PathText}}</small></td>
            </tr>
            {{end}}
        </tbody>
    </table>
    <p><small class="text-muted">ZeroTier does not report per-peer byte counters; traffic is shown per network interface above.</small></p>
    {{end}}
{{end}}
{{end}}

{{define "bgp-custom-peers"}}
<div id="bgp-custom-peers-list" {{if .OOB}}hx-swap-oob="true"{{end}}>
    <div class="header-row">
        <h3>Custom BGP Peers</h3>
        <button class="btn btn-primary" style="width:auto" hx-get="bgp/peers/new" hx-target="#modal-container" hx-swap="innerHTML">+ Add Peer</button>
    </div>
    {{if not .Peers}}
    <p><small class="text-muted">No standalone BGP peers configured. A WireGuard peer can also enable BGP from its own edit form.</small></p>
    {{else}}
    {{range .Peers}}
    <article class="flex-row" style="align-items:center;">
        <div>
            <strong>{{.Name}}</strong> {{if not .Enabled}}<span class="badge badge-warn">Disabled</span>{{end}}
            <div><small class="text-muted">{{.PeerIP}} (AS{{.PeerASN}}) &middot; {{if .Connect}}active{{else}}passive{{end}}{{if .RouteFilters}} &middot; {{len .RouteFilters}} received filter(s){{end}}{{if .ExportFilters}} &middot; {{len .ExportFilters}} advertised filter(s){{end}}</small></div>
        </div>
        <div class="btn-group">
            <button class="btn btn-outline" style="width:auto" hx-get="bgp/peers/{{.ID}}/edit" hx-target="#modal-container" hx-swap="innerHTML">Edit</button>
            <button class="btn btn-outline-danger" style="width:auto" hx-delete="bgp/peers/{{.ID}}" hx-target="#tab-content" hx-swap="innerHTML" hx-confirm="Delete BGP peer {{.Name}}?">Delete</button>
        </div>
    </article>
    {{end}}
    {{end}}
</div>
{{end}}

{{define "bgp-peer-form"}}
<dialog>
    <article>
        <header class="flex-row">
            <p class="mb-0"><strong>{{if .IsNew}}Add BGP Peer{{else}}Edit BGP Peer{{end}}</strong></p>
            <button aria-label="Close" class="btn btn-outline secondary mb-0" style="padding: 0.1rem 0.6rem" onclick="closeModal()">X</button>
        </header>
        <form {{if .IsNew}}hx-post="bgp/peers"{{else}}hx-put="bgp/peers/{{.Peer.ID}}"{{end}}
              hx-target="#modal-container" hx-swap="innerHTML">

            {{if .Error}}<div class="toast toast-error" role="alert">{{.Error}}</div>{{end}}
            {{template "error-summary" .ValidationErrors}}

            <label>
                Name *
                <input type="text" name="name" value="{{.Peer.Name}}" required maxlength="64"
                       placeholder="e.g. Route Reflector"
                       {{if .ValidationErrors.HasField "name"}}aria-invalid="true"{{end}}>
                {{range .ValidationErrors}}{{if eq .Field "name"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
            </label>

            <input type="hidden" name="bgpEnabled" value="on">
            <label>
                <input type="checkbox" name="bgpConnect" {{if .Peer.Connect}}checked{{end}} title="Actively initiate connection to the peer"> Connect
            </label>

            <div class="grid">
                <label>
                    Peer BGP IP *
                    <input type="text" name="bgpPeerIP" value="{{.Peer.PeerIP}}" placeholder="10.0.0.123" {{if .ValidationErrors.HasField "bgpPeerIP"}}aria-invalid="true"{{end}}>
                    {{range .ValidationErrors}}{{if eq .Field "bgpPeerIP"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
                </label>
                <label>
                    Peer ASN *
                    <input type="number" name="bgpPeerAsn" value="{{if .Peer.PeerASN}}{{.Peer.PeerASN}}{{else}}64512{{end}}" {{if .ValidationErrors.HasField "bgpPeerAsn"}}aria-invalid="true"{{end}}>
                    {{range .ValidationErrors}}{{if eq .Field "bgpPeerAsn"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
                </label>
                <label>
                    Peer Port *
                    <input type="number" name="bgpPeerPort" value="179" min="179" max="179" readonly {{if .ValidationErrors.HasField "bgpPeerPort"}}aria-invalid="true"{{end}}>
                    <small>The embedded BGP engine currently supports peer port 179.</small>
                    {{range .ValidationErrors}}{{if eq .Field "bgpPeerPort"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
                </label>
            </div>

            <div style="margin-top: 1rem;">
                <label>Received Prefix Filters</label>
                <small>Controls which prefixes received from this peer are accepted. Leave empty to accept everything.</small>
                <div id="bgp-route-filters-list">
                    {{range $i, $filter := .Peer.RouteFilters}}
                    <div class="route-filter-row" style="display:flex; gap:0.5rem; margin-bottom:0.5rem;">
                        <input type="text" name="filterPrefix[]" value="{{$filter.Prefix}}" placeholder="Prefix (e.g. 10.1.0.0/16)" style="flex:1">
                        <select name="filterMatcher[]" style="width:auto">
                            <option value="exact" {{if eq $filter.Matcher "exact"}}selected{{end}}>Exact</option>
                            <option value="orlonger" {{if eq $filter.Matcher "orlonger"}}selected{{end}}>Or Longer</option>
                        </select>
                        <select name="filterAction[]" style="width:auto">
                            <option value="accept" {{if eq $filter.Action "accept"}}selected{{end}}>Accept</option>
                            <option value="reject" {{if eq $filter.Action "reject"}}selected{{end}}>Reject</option>
                        </select>
                        <button type="button" class="btn btn-outline-danger" style="width:auto" onclick="this.closest('.route-filter-row').remove()">X</button>
                    </div>
                    {{end}}
                </div>
                <button type="button" class="btn btn-outline secondary" style="width:auto; margin-top:0.5rem;" onclick="addRouteFilterRow()">+ Add Filter</button>
            </div>

            <div style="margin-top: 1rem;">
                <label>Advertised Prefix Filters</label>
                <small>Controls which locally known prefixes are advertised to this peer. Leave empty to advertise everything.</small>
                <div id="bgp-export-filters-list">
                    {{range $i, $filter := .Peer.ExportFilters}}
                    <div class="route-filter-row" style="display:flex; gap:0.5rem; margin-bottom:0.5rem;">
                        <input type="text" name="exportFilterPrefix[]" value="{{$filter.Prefix}}" placeholder="Prefix (e.g. 10.1.0.0/16)" style="flex:1">
                        <select name="exportFilterMatcher[]" style="width:auto">
                            <option value="exact" {{if eq $filter.Matcher "exact"}}selected{{end}}>Exact</option>
                            <option value="orlonger" {{if eq $filter.Matcher "orlonger"}}selected{{end}}>Or Longer</option>
                        </select>
                        <select name="exportFilterAction[]" style="width:auto">
                            <option value="accept" {{if eq $filter.Action "accept"}}selected{{end}}>Accept</option>
                            <option value="reject" {{if eq $filter.Action "reject"}}selected{{end}}>Reject</option>
                        </select>
                        <button type="button" class="btn btn-outline-danger" style="width:auto" onclick="this.closest('.route-filter-row').remove()">X</button>
                    </div>
                    {{end}}
                </div>
                <button type="button" class="btn btn-outline secondary" style="width:auto; margin-top:0.5rem;" onclick="addRouteFilterRow('bgp-export-filters-list', 'exportFilter')">+ Add Filter</button>
            </div>

            <fieldset>
                <label>
                    <input type="checkbox" name="enabled" {{if or .Defaults .Peer.Enabled}}checked{{end}}>
                    Enabled
                </label>
            </fieldset>

            <footer>
                <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button type="submit" class="btn btn-primary">{{if .IsNew}}Create Peer{{else}}Save Changes{{end}}</button>
            </footer>
        </form>
    </article>
</dialog>
{{end}}

{{define "bgp-tab"}}
<div id="bgp-stats">
    <div class="header-row">
        <h2>BGP Statistics</h2>
    </div>

    {{template "bgp-custom-peers" .CustomPeers}}

    <div id="bgp-live-stats" hx-get="bgp/live-stats" hx-trigger="every 2s" hx-swap="innerHTML">
        {{template "bgp-live-stats" .BGPStats}}
    </div>
</div>
{{end}}

{{define "bgp-live-stats"}}
    {{if not .Running}}
    <article class="toast toast-error">
        BGP Service is currently disabled or not started. Enable it in the Server Configuration.
    </article>
    {{else}}
    <div class="grid" style="margin-bottom: 2rem;">
        <article>
            <header><strong>Router ID</strong></header>
            {{.RouterID}}
        </article>
        <article>
            <header><strong>Local ASN</strong></header>
            {{.ASN}}
        </article>
        <article>
            <header><strong>Service Status</strong></header>
            <span class="status-dot status-up"></span> Running
        </article>
    </div>

    <h3>BGP Peers</h3>
    {{if not .Peers}}
    <p>No BGP peers configured.</p>
    {{else}}
    {{range .Peers}}
    <article>
        <header class="flex-row">
            <strong>{{.IP}} (AS{{.ASN}})</strong>
            <span>
                {{if eq .State "Established"}}
                <span class="status-dot status-up"></span> {{.State}} &middot; Uptime: {{.Uptime}}
                {{else}}
                <span class="status-dot status-down"></span> {{.State}}
                {{end}}
            </span>
        </header>

        <p><small>Updates Received: {{.UpdatesReceived}} &middot; Prefixes Received: {{len .Routes}} &middot; Prefixes Advertised: {{len .AdvertisedRoutes}}</small></p>

        {{if .Routes}}
        <details>
            <summary><strong><small>Received routes ({{len .Routes}})</small></strong></summary>
            <table role="grid">
                <thead>
                    <tr>
                        <th scope="col">Prefix</th>
                        <th scope="col">Next Hop</th>
                        <th scope="col">Local Pref</th>
                        <th scope="col">AS Path</th>
                        <th scope="col">Status</th>
                    </tr>
                </thead>
                <tbody>
                    {{range $i, $route := .Routes}}
                    <tr class="{{if ne $route.Status "Accepted"}}route-filtered{{end}} {{if gt $i 9}}hidden-route{{end}}">
                        <td><code>{{$route.Prefix}}</code></td>
                        <td><code>{{$route.NextHop}}</code></td>
                        <td>{{$route.LocalPref}}</td>
                        <td>{{if $route.ASPath}}{{$route.ASPath}}{{else}}Local{{end}}</td>
                        <td>
                            {{if eq $route.Status "Accepted"}}<span class="badge badge-ok">{{$route.Status}}</span>
                            {{else}}<span class="badge badge-via">{{$route.Status}}</span>{{end}}
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{if gt (len .Routes) 10}}
            <button class="btn btn-outline secondary" onclick="showAllRoutes(this)">Show All {{len .Routes}} Routes</button>
            {{end}}
        </details>
        {{end}}

        {{if .AdvertisedRoutes}}
        <details>
            <summary><strong><small>Advertised routes ({{len .AdvertisedRoutes}})</small></strong></summary>
            <table role="grid">
                <thead>
                    <tr>
                        <th scope="col">Prefix</th>
                        <th scope="col">Next Hop</th>
                        <th scope="col">Local Pref</th>
                        <th scope="col">AS Path</th>
                        <th scope="col">Status</th>
                    </tr>
                </thead>
                <tbody>
                    {{range $i, $route := .AdvertisedRoutes}}
                    <tr class="{{if gt $i 9}}hidden-route{{end}}">
                        <td><code>{{$route.Prefix}}</code></td>
                        <td><code>{{$route.NextHop}}</code></td>
                        <td>{{$route.LocalPref}}</td>
                        <td>{{if $route.ASPath}}{{$route.ASPath}}{{else}}Local{{end}}</td>
                        <td><span class="badge badge-ok">{{$route.Status}}</span></td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{if gt (len .AdvertisedRoutes) 10}}
            <button class="btn btn-outline secondary" onclick="showAllRoutes(this)">Show All {{len .AdvertisedRoutes}} Routes</button>
            {{end}}
        </details>
        {{end}}

    </article>
    {{end}}
    {{end}}
    {{end}}
{{end}}
`))
