# WG-Busy Design Document

WireGuard server management web UI. Go backend serving a single HTML page using htmx and custom CSS. YAML config persistence, rendered to WireGuard .conf on every change. Exit node routing via Linux policy routing.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Browser (Single HTML Page)                     │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐    │
│  │ Peers Tab │  │Server Tab │  │ BGP Tab   │    │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘    │
│        │               │                         │
│   HTML fragments via htmx (no full reloads)      │
└────────┼───────────────┼─────────────────────────┘
         │               │
┌────────┼───────────────┼─────────────────────────┐
│  Go HTTP Server (net/http, Go 1.22+ ServeMux)    │
│        │               │                         │
│  ┌─────┴─────┐  ┌──────┴────┐  ┌──────────────┐ │
│  │  handlers/ │  │  handlers/ │  │  handlers/   │ │
│  │  peers.go  │  │  server.go │  │  export.go   │ │
│  └─────┬──────┘  └──────┬────┘  └──────┬───────┘ │
│        │               │               │         │
│  ┌─────┴───────────────┴───────────────┴──────┐  │
│  │              config.Store                   │  │
│  │       (RWMutex + YAML file + wg0.conf)     │  │
│  └─────────────────┬───────────────────────────┘  │
│                    │                              │
│  ┌────────┐  ┌────┴────┐  ┌──────────┐  ┌─────┐ │
│  │  ipam  │  │wireguard│  │  models   │  │route│ │
│  └────────┘  └─────────┘  └──────────┘  └─────┘ │
└───────────────────────────────────────────────────┘
         │
    ┌────┴────┐
    │  YAML   │  config.yaml (persistence / source of truth)
    │  file   │  wg0.conf   (rendered output, written on every save)
    └─────────┘
```

## Project Structure

```
wg-busy/
├── main.go                       # Entrypoint, embed.FS, CLI flags, HTTP server, auto-start WG
├── go.mod                        # github.com/yix/wg-busy
├── internal/
│   ├── models/models.go          # Data structures + validation
│   ├── config/config.go          # YAML persistence + wg0.conf rendering on save
│   ├── wireguard/wireguard.go    # Key generation, .conf rendering
│   ├── ipam/ipam.go              # IP address allocation
│   ├── routing/routing.go        # Exit node policy routing command generation
│   ├── wgstats/wgstats.go       # Background stats collector (wg show polling, ring buffer)
│   ├── zerotier/
│   │   ├── client.go             # ZeroTier local control API client (127.0.0.1:9993)
│   │   └── zerotier.go           # Service supervisor: process, network reconcile, counters
│   └── handlers/
│       ├── handlers.go           # Router, handler struct, error logging middleware
│       ├── templates.go          # html/template definitions
│       ├── peers.go              # Peer CRUD (HTML fragments)
│       ├── server.go             # Server config (HTML fragments)
│       ├── zerotier.go           # ZeroTier tab, join/leave, restart (HTML fragments)
│       ├── export.go             # Download/apply config
│       └── stats.go              # Stats bar + QR code handlers
├── web/
│   └── index.html                # Single page: htmx + custom css
├── Dockerfile                    # Multi-stage: build + alpine runtime
├── docker-compose.yml            # Sample compose with all WireGuard settings
└── Makefile                      # build, run, dev, test, docker-*
```

## Data Models

### AppConfig (top-level, persisted as YAML)

```go
type AppConfig struct {
    Server   ServerConfig   `yaml:"server"`
    Peers    []Peer         `yaml:"peers"`
    ZeroTier ZeroTierConfig `yaml:"zerotier,omitempty"`
}
```

### ServerConfig ([Interface] section)

| Field | Type | Required | Validation | WG Key |
|-------|------|----------|------------|--------|
| PrivateKey | string | yes | base64, 44 chars | PrivateKey |
| ListenPort | uint16 | yes | 1-65535 | ListenPort |
| Address | string | yes | valid CIDR | Address |
| DNS | string | no | comma-separated IPs/hostnames | DNS |
| MTU | uint16 | no | 1280-65535, 0=unset | MTU |
| Table | string | no | "off"/"auto"/numeric | Table |
| FwMark | string | no | uint32, hex, or "off" | FwMark |
| PreUp | string | no | max 4096 chars | PreUp |
| PostUp | string | no | max 4096 chars | PostUp |
| PreDown | string | no | max 4096 chars | PreDown |
| PostDown | string | no | max 4096 chars | PostDown |
| SaveConfig | bool | no | boolean | SaveConfig |
| Endpoint | string | no | host:port (for client config generation) | — |

### Peer

| Field | Type | Required | Validation | WG Key |
|-------|------|----------|------------|--------|
| ID | string | auto | UUID | — |
| Name | string | yes | max 64, `[a-zA-Z0-9 _.-]+` | # comment |
| PrivateKey | string | auto | base64, 44 chars | — (app only) |
| PublicKey | string | auto | derived from PrivateKey | PublicKey |
| PresharedKey | string | no | base64, 44 chars | PresharedKey |
| AllowedIPs | string | yes* | CIDR list, auto-assigned if empty | AllowedIPs |
| Endpoint | string | no | host:port | Endpoint |
| PersistentKeepalive | uint16 | no | 0-65535, 0=off | PersistentKeepalive |
| DNS | string | no | inherits server DNS if empty | — (client conf) |
| ClientAllowedIPs | string | no | CIDR list, default "0.0.0.0/0, ::/0" | — (client conf) |
| IsExitNode | bool | no | mutually exclusive with ExitNodeID | — |
| ExitNodeID | string | no | valid exit node peer ID | — |
| ExitNodeAllowAll | bool | no | true=full tunnel (0.0.0.0/0), false=split | — |
| ExitNodeRoutes | []string | no | list of CIDRs for split tunnel | — |
| AdvertisedRoutes | []string | no | list of CIDRs to route through peer | — |
| PolicyRoutes | []string | no | list of "CIDR via IP" strings | — |
| StrictPolicyRouting | bool | no | reject traffic not matching this peer's own routes | — |
| RoutingTableID | uint | auto | assigned when IsExitNode=true | — |
| PolicyRoutingTableID | uint | auto | assigned when PolicyRoutes is set | — |
| Enabled | bool | no | default true | — (controls inclusion) |
| CreatedAt | time | auto | — | — |
| UpdatedAt | time | auto | — | — |

### AllowedIPs vs ClientAllowedIPs

These are two distinct concepts that map to `AllowedIPs` in different WireGuard config files:

**AllowedIPs** — used in the **server's** wg0.conf `[Peer]` section for this peer. This is the peer's tunnel IP address (e.g. `10.0.0.2/32`). It tells the WireGuard server which source IPs to accept from this peer and which destination IPs to route to this peer. For regular peers this is their /32 tunnel address. For exit node peers, this is overridden to `0.0.0.0/0, ::/0` in the rendered wg0.conf (so the server forwards all return traffic back to the exit node), while the YAML retains the /32 tunnel IP.

**ClientAllowedIPs** — used in the **client's** downloaded .conf file `[Peer]` section (where the peer is the server). This tells the client which destination IPs to route through the WireGuard tunnel. Default `0.0.0.0/0, ::/0` means "route all traffic through the tunnel" (full tunnel). Setting it to e.g. `10.0.0.0/24` would create a split tunnel where only VPN subnet traffic goes through WireGuard.

```
Server wg0.conf:              Client peer.conf:
[Peer]                        [Peer]
# Alice                       PublicKey = <server_pubkey>
PublicKey = <alice_pubkey>    AllowedIPs = 0.0.0.0/0, ::/0  ← ClientAllowedIPs
AllowedIPs = 10.0.0.2/32     ← AllowedIPs
```

## Routing & Traffic Management

### Concept
Any peer can be marked as an **exit node**. Other peers can route their traffic through a specific exit node. The WireGuard server acts as a policy router using Linux `ip rule` + custom routing tables.

### How It Works

**Full Tunnel (Default)**:
```
                        Internet
                           ↑
                    ┌──────┴──────┐
                    │  Exit Node  │  (e.g. 10.0.0.5)
                    │  (peer)     │
                    └──────┬──────┘
                           │ WireGuard tunnel
                           ↓
┌──────────────────────────────────────────────┐
│  WG Server (10.0.0.1)                        │
│                                              │
│  ip rule: from 10.0.0.2 → lookup table 100  │
│  table 100: default via 10.0.0.5 dev wg0    │
│                                              │
└──────────────────────┬───────────────────────┘
                       │ WireGuard tunnel
                       ↓
                ┌──────────────┐
                │ Alice Laptop │  (10.0.0.2)
                │ (peer)       │
                └──────────────┘
```

Alice's traffic: Alice → wg0 server → policy route table 100 → exit node 10.0.0.5 → Internet

**Split Tunnel**:
If an exit node is configured with specific routes (e.g. `10.10.0.0/24`), only traffic for those subnets is routed through it. The `wg0.conf` `AllowedIPs` for that peer will be restricted to its tunnel IP + the routed subnets.

### Data Model
```yaml
- id: "exit-us"
  name: "US Exit"
  allowedIPs: "10.0.0.5/32"       # tunnel IP (YAML)
  isExitNode: true
  routingTableID: 100              # auto-assigned, persisted

- id: "alice"
  name: "Alice Laptop"
  allowedIPs: "10.0.0.2/32"
  exitNodeID: "exit-us"            # route through US Exit
```

### wg0.conf Rendering
- Exit node peers: `AllowedIPs` are calculated based on routing mode:
    - **Full Tunnel** (`ExitNodeAllowAll=true`): `AllowedIPs = 0.0.0.0/0, ::/0`
    - **Split Tunnel** (`ExitNodeAllowAll=false`): `AllowedIPs = <PeerIP>, <Route1>, <Route2>...`
- Routing commands injected into PostUp/PostDown (after user-defined commands):

```ini
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; ...     # user-defined
PostUp = ip route add default via 10.0.0.5 dev wg0 table 100
PostUp = ip rule add from 10.0.0.2 table 100
PostDown = ip rule del from 10.0.0.2 table 100
PostDown = ip route del default via 10.0.0.5 dev wg0 table 100
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; ...   # user-defined
```

### Routing Table ID Management
- Base: 100 (constant)
- Auto-assigned when `IsExitNode` set to true, persisted in YAML
- Freed when `IsExitNode` set to false
- Scan existing peers to find next unused ID

### Routing Module (`internal/routing/routing.go`)
- `GeneratePostUpCommands(cfg AppConfig) []string`
- `GeneratePostDownCommands(cfg AppConfig) []string`
- `AssignRoutingTableID(peers []Peer) uint`
- Per exit node: `ip route add default via <exit_ip> dev wg0 table <table_id>`
- Per peer using exit node: `ip rule add from <peer_ip> table <table_id>`
- PostDown: mirror teardown in reverse order

### Validation
- Peer cannot be both exit node AND use an exit node
- ExitNodeID must reference an existing, enabled, IsExitNode peer
- Cascade: disabling/deleting exit node clears ExitNodeID on all dependents

### UI
- Peer list: "Exit Node" badge, "via <name>" label
- Peer form: "Exit Node" checkbox (hides Route via), "Route via" dropdown (hides when Exit Node checked)

### Advertised Routes
Peers can declare "Advertised Routes", which are subnets that reside behind the peer. These CIDRs are appended to the `AllowedIPs` directive in the server's `wg0.conf` for the peer. WireGuard's `wg-quick` will automatically add standard static routes for these subnets targeting the WireGuard interface, ensuring returning or transit traffic reaches the peer.

### Policy Routes
If you need granular control where traffic from a specific peer destined to specific subnets must be routed via a distinct gateway IP, you can configure "Policy Routes" (formatted as `<CIDR> via <Gateway IP>`).
When defined, WG-Busy assigns a dedicated `PolicyRoutingTableID` to the peer and injects:
- `ip rule add from <peer_ip> table <table_id>`
- `ip route add <CIDR> via <Gateway IP> dev <iface> table <table_id>`
These commands are added to `PostUp` and mirrored in `PostDown` for clean teardown. They do not
depend on exit nodes — a peer with only policy routes still gets both.

**The gateway picks the interface.** `models.GatewayNets` collects every on-link network: the
WireGuard `Address` (as `wg0`) plus each joined ZeroTier network's assigned addresses (as its
`zt*` device). `models.DeviceForGateway` then resolves `<iface>` by finding which of those subnets
contains the gateway IP, so a ZeroTier peer IP is a valid gateway and its route is pinned to the
ZeroTier interface. The same list drives validation, so an unreachable gateway is rejected with the
usable subnets listed. Routes over a `zt*` device are suffixed with `|| true`: those interfaces
only exist once the network is authorized, and a missing one must not abort `wg-quick up`.

Because `wg syncconf` does not re-run `PostUp`, the store also reconciles these commands directly
after every successful live WireGuard reload and whenever ZeroTier gateway networks change.

### NAT for ZeroTier egress

A packet routed out a ZeroTier interface still carries its original source — a WireGuard peer IP
that the ZeroTier network has no route back to — so replies would never return. While ZeroTier is
enabled, `PostUp` installs:

```
iptables -t nat -C POSTROUTING -o zt+ -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o zt+ -j MASQUERADE
```

The `zt+` wildcard covers every ZeroTier interface, including networks joined after wg0 came up, so
the rule never needs to know device names. `PostDown` removes it with a trailing `|| true`.

### Generated commands must be idempotent

wg-quick runs hooks with `(eval "$hook")` under `set -e`, so **any hook that fails aborts the
bring-up and deletes the interface**. Every generated command is therefore written to converge
rather than fail:

| Command | Hazard | Form used |
|---|---|---|
| `ip rule add … priority N` | `EEXIST` if the priority is taken by a stale rule | `ip rule del priority N 2>/dev/null \|\| true; ip rule add …` |
| `ip route add … table N` | `EEXIST` if the route is already present | `ip route replace … table N` |
| policy routes | gateway not on-link yet (ZeroTier still starting) | trailing `\|\| true` |
| `iptables -A` | duplicate rule when a teardown never ran | `-C … \|\| -A …` |
| all deletes | rule already gone | trailing `\|\| true` |

This is not defensive styling — each one has been observed to take WireGuard down. A policy route
whose ZeroTier gateway was not yet on-link fell back to `dev wg0`, failed with *"Nexthop has
invalid gateway"*, and left the host with no `wg0` at all.

The store remembers the last successfully applied config and gateway set. Reconciliation runs the
previous `PostDown` commands before the new `PostUp` commands, so rules and routes that disappear
from the config are removed instead of lingering in the kernel. If installation fails, the old
`PostUp` state is restored best-effort. `Store.ReapplyRouting` uses the same path when ZeroTier
reports new on-link networks.

### Strict Policy Routing

`StrictPolicyRouting` confines a peer to its own tables. After the peer's lookups a reject rule is
installed, so unmatched traffic stops there instead of falling through to `main`:

```
ip rule add from 10.0.0.2 table 100 priority 10000   # the peer's policy table
ip rule add from 10.0.0.2 prohibit  priority 10001   # everything else is refused
...
32766: from all lookup main                          # never reached by this peer
```

Rule priorities are **explicit** (`rulePriorityBase = 10000`). This is load-bearing: `ip rule add`
without a priority assigns a *descending* number, so the last rule added would be evaluated first —
putting the reject ahead of the table lookup and blackholing the peer completely. Both `PostUp` and
`PostDown` render from the same `peerRules` specs, so teardown deletes by exact priority and
repeated applies cannot accumulate duplicate rules.

A strict peer that also uses an exit node keeps both lookups (exit node, then policy table) before
the reject. `prohibit` is used rather than `blackhole` so the client fails fast with an
administratively-prohibited error instead of hanging. Store-level validation requires the selected
exit node to exist, be enabled, and be marked as an exit node. The generator still emits `prohibit`
for an invalid hand-edited strict config, failing closed rather than leaking traffic through `main`.

## Config Persistence: YAML → .conf

Source of truth: `config.yaml`. On every mutation:
1. Clone the complete config, including nested slices, for rollback and live-state reconciliation
2. Apply the mutation and validate cross-peer exit-node references
3. Save `config.yaml` and render `wg0.conf` atomically (write `.tmp`, rename); restore YAML on render failure
4. Reload WireGuard with direct `wg-quick strip` → `wg syncconf` commands (no shell process substitution)
5. Reconcile previous routing state to the new state and configure BGP
6. Notify the asynchronous ZeroTier supervisor

Persistence errors roll back the mutation. A live service failure returns a typed `ApplyError`:
the UI reports that configuration was saved but not fully applied and renders the persisted state,
so resubmitting cannot duplicate a create/delete operation. **Apply Config** restarts WireGuard and
then retries routing and BGP reconciliation.

## BGP Runtime Lifecycle

BGP runtime state owns the `bio-rd` server, VRF registry, kernel route client, a closeable listener
manager, and the active Router ID/ASN/listen address/listen port. Startup builds these as a local
candidate and publishes it only after kernel registration and peer/listener creation succeed.
Failures dispose the candidate and leave BGP stopped and retryable.

Changing any restart-sensitive server field shuts down the active runtime and starts a new one.
The app supplies a small `bio-rd` listener manager because the dependency's built-in manager has no
close API; this releases TCP sockets on disable and rebind. Peer add/replace and filter errors are
returned to the store instead of being logged as successful. The dashboard reports Running only
when a fully initialized runtime is published.

## API Endpoints

### HTML Fragment Endpoints (htmx swap targets)

```
GET  /                          → index.html (full page, initial load only)
GET  /peers                     → peers list fragment (with exit node badges)
GET  /peers/new                 → create peer <dialog> form (with exit node options)
GET  /peers/{id}/edit           → edit peer <dialog> form
POST /peers                     → create peer → return updated list
PUT  /peers/{id}                → update peer → return updated list
DELETE /peers/{id}              → delete peer (cascade) → empty
PUT  /peers/{id}/toggle         → toggle enabled (cascade if exit node) → updated row

GET  /server                    → server config form fragment
PUT  /server                    → update config → return form + success toast
```

### File/Action Endpoints

```
GET  /api/peers/{id}/config             → download client .conf
GET  /api/server/config                 → download wg0.conf (with routing rules)
POST /api/server/apply                  → wg-quick down/up
POST /api/peers/{id}/regenerate-keys    → new keypair → return updated form
```

## UI Layout

Single HTML page with two tabs controlled by htmx:

```
┌──────────────────────────────────────────┐
│  WG Busy — WireGuard Server Manager      │
├──────────────┬────────────────────────┬──────────┤
│ [Peers]      │ [Server]               │ [BGP]    │
├──────────────┴────────────────────────┴──────────┤
│                                          │
│  ┌── #tab-content ─────────────────────┐ │
│  │                                     │ │
│  │  (Peers list OR Server config form) │ │
│  │  loaded via htmx fragments          │ │
│  │                                     │ │
│  └─────────────────────────────────────┘ │
│                                          │
│  ┌── #modal-container ─────────────────┐ │
│  │  (<dialog> for create/edit peer)    │ │
│  └─────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

### Peers Tab Content
- Header: "Peers (N)" + "Add Peer" button
- Peer rows: name, IP, **exit node badge**, **"via <name>"**, actions (Download, Edit, Toggle, Delete)
- Empty state when no peers

### Server Tab Content
- ListenPort, Address, Endpoint, DNS, MTU
- `<details>` for advanced: Table, FwMark, Pre/Post Up/Down, SaveConfig
- Server private key in collapsed `<details>`
- "Download wg0.conf" and "Apply Config" buttons

### Peer Form (Create/Edit Dialog)
- Name, AllowedIPs (empty = auto-assign), Client Allowed IPs, DNS, Persistent Keepalive
- **Exit Node checkbox** (hides Route via when checked)
- **Route via dropdown** (lists exit node peers + None; hidden when Exit Node checked)
- Checkboxes: Generate preshared key, Enabled

## Docker

### docker-compose.yml (included in repo)
```yaml
services:
  wg-busy:
    build: .
    image: wg-busy:latest
    container_name: wg-busy
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
    ports:
      - "8080:8080"           # Web UI
      - "51820:51820/udp"     # WireGuard
    volumes:
      - ./data:/app/data                    # config.yaml persistence
      - /lib/modules:/lib/modules:ro        # kernel modules for wireguard
    restart: unless-stopped
```

### Multi-stage Dockerfile
```
Stage 1: golang:1.23-alpine  → build binary (CGO_ENABLED=0)
Stage 2: alpine:3.20         → runtime with wireguard-tools, iptables, iproute2
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `build` | `CGO_ENABLED=0 go build` → `bin/wg-busy` |
| `run` | Build + run with default flags |
| `dev` | `go run .` for fast iteration |
| `test` | `go test -v -race ./...` |
| `clean` | Remove `bin/` and temp files |
| `docker-build` | Build Docker image |
| `docker-run` | Build + run container with proper caps/ports |
| `fmt` | `gofmt -s -w . && goimports -w .` |
| `tidy` | `go mod tidy` |

## CLI Flags

```
-listen      :8080                          HTTP listen address
-config      ./data/config.yaml             YAML config file path
-wg-config   /etc/wireguard/wg0.conf        WireGuard config output path
```

## WireGuard Auto-Start

On startup, `main.go` runs `wg-quick up wg0` to bring the WireGuard interface up automatically. This ensures the VPN is running when the Docker container starts. The startup sequence:

1. Load config, generate server keys if needed
2. Render wg0.conf to disk
3. Run `wg-quick up wg0` (log errors but don't fatal — wg0 may already be up)
4. Start stats collector goroutine
5. Start HTTP server

## Stats Collection (`internal/wgstats/wgstats.go`)

Background goroutine that polls `wg show wg0 dump` every 2 seconds to collect interface and per-peer statistics.

### Data Source

`wg show wg0 dump` produces tab-separated output:
- Line 1 (interface): `private-key \t public-key \t listen-port \t fwmark`
- Lines 2+ (peers): `public-key \t preshared-key \t endpoint \t allowed-ips \t latest-handshake \t transfer-rx \t transfer-tx \t persistent-keepalive`

### Architecture

```go
type Collector struct {
    mu          sync.RWMutex
    startedAt   time.Time               // when WireGuard was started (for uptime)
    iface       InterfaceStats           // aggregate interface stats
    peers       map[string]*PeerStats    // keyed by public key
    history     []HistoryPoint           // ring buffer, ~60 samples (2min at 2s intervals)
    peerHistory map[string][]HistoryPoint // per-peer bandwidth history
}

type InterfaceStats struct {
    TotalRx     int64   // cumulative bytes received
    TotalTx     int64   // cumulative bytes sent
    CurrentRxPS float64 // bytes/sec receive (computed from delta)
    CurrentTxPS float64 // bytes/sec transmit
}

type PeerStats struct {
    PublicKey       string
    Endpoint        string
    LatestHandshake time.Time
    TransferRx      int64
    TransferTx      int64
    CurrentRxPS     float64
    CurrentTxPS     float64
}

type HistoryPoint struct {
    Time time.Time
    RxPS float64  // bytes/sec
    TxPS float64
}
```

### Sparkline SVG Rendering

Server-side SVG generation for inline sparkline graphs:
- `RenderSparklineSVG(history []HistoryPoint, width, height int) string`
- Returns `<svg>` element with `<polyline>` for Rx (blue) and Tx (green)
- Dimensions: 120×24 px for stats bar, 80×16 px for peer rows
- Auto-scales Y axis to max value in window

### Thread Safety

`Collector` uses `sync.RWMutex`. Read methods called by HTTP handlers, write by the polling goroutine.

## QR Code Generation

Each peer's client config can be displayed as a QR code for mobile WireGuard client scanning.

### Endpoint

```
GET /api/peers/{id}/qr → PNG image (256×256, QR code of client .conf content)
```

### Implementation

- Library: `github.com/skip2/go-qrcode`
- Content: full client `.conf` text (same as download)
- Size: 256×256 pixels, Medium error correction
- Response: `image/png` content type

### UI

QR glyph button appears to the left of the "Download" button in each peer row. Clicking opens a modal `<dialog>` with the QR code image loaded via htmx.

## Stats Bar

A stats bar appears above the tab navigation showing server-level WireGuard statistics.

### Layout

```
┌─────────────────────────────────────────────────────────────┐
│  ● wg0 up 2h 15m  │  ↓ 1.2 MB/s (1.2 GB)  ↑ 340 KB/s (340 MB)  │ ▁▃▅▂▇▃ │
└─────────────────────────────────────────────────────────────┘
```

- **Status indicator**: green dot when wg0 is up, interface name, uptime
- **Transfer counters**: cumulative Rx/Tx with human-readable formatting
- **Sparkline graph**: bandwidth over last ~2 minutes (Rx + Tx overlaid)

### Endpoint

```
GET /stats → stats bar HTML fragment (polled every 2s via htmx hx-trigger="every 2s")
```

### Template Data

```go
type StatsBarData struct {
    IsUp        bool
    Uptime      string   // "2h 15m"
    TotalRx     string   // "1.2 GB"
    TotalTx     string   // "340 MB"
    SparklineSVG string  // inline <svg> element
}
```

## Per-Peer Stats

Each peer row displays inline stats without adding vertical space — stats appear in the existing `<small>` info line.

### Layout

```
┌────────────────────────────────────────────────────────────────────────┐
│ Alice Laptop [Exit Node]                                               │
│ 10.0.0.2/32 · ↓ 45 KB/s (45 MB) ↑ 12 KB/s (12 MB) · shake 2m ago · ▁▃▅▂  [QR][DL]│
└────────────────────────────────────────────────────────────────────────┘
```

- Transfer Rx/Tx counters
- Latest handshake relative time ("2m ago", "never")
- Mini sparkline SVG (80×16 px)
- All inline in the existing peer row info section

### Data Flow

1. `ListPeers` handler reads stats from `Collector`
2. Stats matched to peers by public key
3. `peerRowData` extended with stats fields
4. Template renders inline stats in `<small>` element

## API Endpoints (Updated)

### HTML Fragment Endpoints (htmx swap targets)

```
GET  /                          → index.html (full page, initial load only)
GET  /peers                     → peers list fragment (with exit node badges + stats)
GET  /peers/new                 → create peer <dialog> form (with exit node options)
GET  /peers/{id}/edit           → edit peer <dialog> form
POST /peers                     → create peer → return updated list
PUT  /peers/{id}                → update peer → return updated list
DELETE /peers/{id}              → delete peer (cascade) → empty
PUT  /peers/{id}/toggle         → toggle enabled (cascade if exit node) → updated row

GET  /server                    → server config form fragment
PUT  /server                    → update config → return form + success toast

GET  /stats                     → stats bar HTML fragment (polled every 2s)
GET  /bgp/stats                 → BGP statistics fragment

GET  /zerotier                  → ZeroTier tab (settings + status + networks + peers)
GET  /zerotier/status           → live status fragment (polled every 2s while the tab is open)
PUT  /zerotier                  → enable/disable + primary port → return tab
POST /zerotier/networks         → join (or update flags of) a network → return tab
DELETE /zerotier/networks/{id}  → leave a network → return tab
```

### File/Action Endpoints

```
GET  /api/peers/{id}/config             → download client .conf
GET  /api/peers/{id}/qr                 → QR code PNG of client .conf
GET  /api/server/config                 → download wg0.conf (with routing rules)
POST /api/server/apply                  → wg-quick down/up
POST /api/peers/{id}/regenerate-keys    → new keypair → return updated form
POST /api/zerotier/restart              → restart zerotier-one → toast
```

## ZeroTier (`internal/zerotier/`)

The ZeroTier client runs as a supervised child process. Desired state lives in `config.yaml`
(`ZeroTierConfig`); the service is reconciled toward it.

### Why a supervisor goroutine, not `Configure()` like BGP

`bgp.Configure` runs in-process and returns in microseconds, so `config.Store.Write` calls it while
holding the write lock. Every ZeroTier operation is a blocking HTTP call to the local control API,
so the same pattern would hold the write lock for seconds against a wedged daemon — blocking every
`Store.Read`, including the status handler.

Instead `Store.OnChange` notifies `Supervisor.Configure`, which only copies the desired config and
bumps a generation counter. One background goroutine (2s tick, the same interval as `wgstats`) does
all the work:

1. **Process**: start `zerotier-one -p<port> <homeDir>` when enabled and not running, SIGTERM when
   disabled, restart when the port changes. A crashed daemon is restarted on the next tick, subject
   to a 15s backoff so a broken binary cannot spin.
2. **Networks** (only when the generation changed): `POST /network/{id}` for *every* configured
   network — the endpoint is join-or-update, which is how a changed `allow*` flag reaches the
   service — plus `DELETE` for any joined network no longer in the config.
3. **Counters**: read `/sys/class/net/<portDeviceName>/statistics/{rx,tx}_bytes` per network and
   derive rates against the previous tick.

Owning the tick also keeps rates correct when several browsers poll the status fragment at once:
a delta derived from consecutive HTTP requests would be split between concurrent pollers.

### Traffic data

ZeroTier's local API exposes no byte counters anywhere — `/peer` reports latency, role, version and
paths; `/network` reports configuration. Traffic therefore comes from the OS interface counters of
the `zt*` device, which makes it **per network, not per peer**. Totals and rates are formatted with
the existing `wgstats.FormatBytes` / `FormatBytesPerSec`.

### Data directory and packaging

`-zt-data` (default `./data/zerotier`, `/app/data/zerotier` in the container) holds
`identity.secret`, `authtoken.secret` and `networks.d`; persisting it keeps the node's ZeroTier
address stable across restarts. The binary is copied into the image from the Alpine/musl-built
`zyclonite/zerotier` image, because Alpine dropped its own `zerotier-one` package after 3.17.
The service needs `/dev/net/tun` and `NET_ADMIN` to create interfaces.

## UI Layout (Updated)

```
┌──────────────────────────────────────────┐
│  WG Busy — WireGuard Server Manager      │
├──────────────────────────────────────────┤
│  ┌── #stats-bar (hx-trigger every 2s) ┐ │
│  │ ● wg0 up 2h 15m │ ↓1.2GB ↑340MB │▁▃│ │
│  └────────────────────────────────────┘ │
├──────────┬───────────┬───────┬────────────┤
│ [Peers]  │ [Server]  │ [BGP] │ [ZeroTier] │
├──────────┴───────────┴───────┴────────────┴──────┤
│  ┌── #tab-content ─────────────────────────────┐ │
│  │  (Peers / Server config / BGP / ZeroTier)   │ │
│  └─────────────────────────────────────────────┘ │
│  ┌── #modal-container ─────────────────┐ │
│  │  (<dialog> for peer form / QR code) │ │
│  └─────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

## Key Technical Decisions

- **YAML config** as source of truth, rendered to .conf on every save
- **Routing via PostUp/PostDown** in wg0.conf — wg-quick handles setup/teardown
- **Routing table IDs persisted** in YAML for stability across restarts
- **Exit node AllowedIPs override** — YAML keeps /32, wg0.conf gets 0.0.0.0/0
- **Cascade on exit node removal** — clears all ExitNodeID references
- **CDN for htmx**, **Go 1.22+ ServeMux**, **wgtypes for keys**, **stateless IPAM**
- **WireGuard auto-start** on Docker container startup via `wg-quick up wg0`
- **Background stats polling** via `wg show wg0 dump` every 2s with ring buffer
- **Server-side SVG sparklines** — no client-side JS charting needed
- **QR codes** via `github.com/skip2/go-qrcode` — PNG endpoint consumed by `<img>` tag
- **Per-peer stats** matched by public key, rendered inline without extra vertical space
