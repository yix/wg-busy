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

{{define "peers-list"}}
<div id="peers-list" {{if .OOB}}hx-swap-oob="true"{{end}}>
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
        {{if .Endpoint}}<div style="font-size:0.8em;font-weight:normal;opacity:0.7;margin-top:0.1em">({{.Endpoint}})</div>{{end}}
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

{{define "peer-stats"}}
    {{.Peer.AllowedIPs}}
    {{if .HasStats}} &middot; <span class="stats-rx">&darr;{{.CurrentRxPS}} <small class="text-muted">({{.TransferRx}})</small></span> <span class="stats-tx">&uarr;{{.CurrentTxPS}} <small class="text-muted">({{.TransferTx}})</small></span> &middot; shake {{.Handshake}}{{end}}
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
              hx-target="#modal-container" hx-swap="innerHTML"
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
                {{range .ValidationErrors}}{{if eq .Field "policyRoutes"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
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

            <div id="exit-node-config" {{if not .Peer.IsExitNode}}style="display:none"{{end}} class="exit-node-field">
                <fieldset>
                    <legend>Exit Node Configuration</legend>
                    <label>
                        <input type="checkbox" name="exitNodeAllowAll" 
                               {{if or (not .Peer.ID) .Peer.ExitNodeAllowAll}}checked{{end}}
                               onchange="toggleExitNodeRoutes(this)">
                        Route all traffic via this node (0.0.0.0/0)
                    </label>
                    
                    <div id="exit-node-routes-field" {{if or (not .Peer.ID) .Peer.ExitNodeAllowAll}}style="display:none"{{end}}>
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
                            <input type="number" name="bgpPeerPort" value="{{if .Peer.BGPPeerPort}}{{.Peer.BGPPeerPort}}{{else}}179{{end}}" {{if .ValidationErrors.HasField "bgpPeerPort"}}aria-invalid="true"{{end}}>
                            {{range .ValidationErrors}}{{if eq .Field "bgpPeerPort"}}<small class="field-error">{{.Message}}</small>{{end}}{{end}}
                        </label>
                    </div>
                    
                    <div style="margin-top: 1rem;">
                        <label>Route Filters</label>
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
                                <button type="button" class="secondary outline" style="color:var(--pico-del-color);border-color:var(--pico-del-color);width:auto" onclick="this.closest('.route-filter-row').remove()">X</button>
                            </div>
                            {{end}}
                        </div>
                        <button type="button" class="secondary outline" style="width:auto; margin-top:0.5rem;" onclick="addRouteFilterRow()">+ Add Filter</button>
                    </div>
                </div>
            </fieldset>

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

        <button type="submit">Save Configuration</button>
    </form>
</div>
{{end}}

{{define "bgp-stats"}}
<div id="bgp-stats">
    <div class="header-row">
        <h2>BGP Statistics</h2>
    </div>

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
    <article style="margin-bottom: 2rem;">
        <header style="display: flex; justify-content: space-between; align-items: center;">
            <strong>{{.IP}} (AS{{.ASN}})</strong>
            <span>
                {{if eq .State "Established"}}
                <span class="status-dot status-up"></span> {{.State}} &middot; Uptime: {{.Uptime}}
                {{else}}
                <span class="status-dot status-down"></span> {{.State}}
                {{end}}
            </span>
        </header>

        <p><small>Updates Received: {{.UpdatesReceived}} &middot; Prefixes Received: {{len .Routes}}</small></p>

        {{if .Routes}}
        <details>
            <summary>View Received Routes ({{len .Routes}})</summary>
            <figure>
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
                        <tr {{if ne $route.Status "Accepted"}}style="opacity: 0.45;"{{end}} {{if gt $i 9}}class="expanded-route hidden-route"{{end}}>
                            <td>{{$route.Prefix}}</td>
                            <td>{{$route.NextHop}}</td>
                            <td>{{$route.LocalPref}}</td>
                            <td>{{if $route.ASPath}}{{$route.ASPath}}{{else}}Local{{end}}</td>
                            <td>
                                <span>{{$route.Status}}</span>
                            </td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </figure>
            {{if gt (len .Routes) 10}}
            <button class="outline secondary" onclick="this.style.display='none'; Array.from(this.previousElementSibling.querySelectorAll('.hidden-route')).forEach(function(el){el.style.display='table-row'});">Show All {{len .Routes}} Routes</button>
            <style>
                .hidden-route { display: none; }
            </style>
            {{end}}
        </details>
        {{end}}

    </article>
    {{end}}
    {{end}}
    {{end}}
</div>
{{end}}
`))
