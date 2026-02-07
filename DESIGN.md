# WG-Busy Design Document

WireGuard server management web UI. Go backend serving a single HTML page using htmx and pico.css. YAML config persistence, rendered to WireGuard .conf on every change. Exit node routing via Linux policy routing.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Browser (Single HTML Page)                     │
│  ┌───────────┐  ┌───────────┐                   │
│  │ Peers Tab │  │Server Tab │   htmx + pico.css │
│  └─────┬─────┘  └─────┬─────┘                   │
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
├── main.go                       # Entrypoint, embed.FS, CLI flags, HTTP server
├── go.mod                        # github.com/yix/wg-busy
├── internal/
│   ├── models/models.go          # Data structures + validation
│   ├── config/config.go          # YAML persistence + wg0.conf rendering on save
│   ├── wireguard/wireguard.go    # Key generation, .conf rendering
│   ├── ipam/ipam.go              # IP address allocation
│   ├── routing/routing.go        # Exit node policy routing command generation
│   └── handlers/
│       ├── handlers.go           # Router, handler struct
│       ├── templates.go          # html/template definitions
│       ├── peers.go              # Peer CRUD (HTML fragments)
│       ├── server.go             # Server config (HTML fragments)
│       └── export.go             # Download/apply config
├── web/
│   └── index.html                # Single page: htmx + pico.css (CDN)
├── Dockerfile                    # Multi-stage: build + alpine runtime
├── docker-compose.yml            # Sample compose with all WireGuard settings
└── Makefile                      # build, run, dev, test, docker-*
```

## Data Models

### AppConfig (top-level, persisted as YAML)

```go
type AppConfig struct {
    Server ServerConfig `yaml:"server"`
    Peers  []Peer       `yaml:"peers"`
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
| RoutingTableID | uint | auto | assigned when IsExitNode=true | — |
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

## Exit Node Routing

### Concept
Any peer can be marked as an **exit node**. Other peers can route their traffic through a specific exit node. The WireGuard server acts as a policy router using Linux `ip rule` + custom routing tables.

### How It Works

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
- Exit node peers: `AllowedIPs` overridden to `0.0.0.0/0, ::/0` in wg0.conf
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

## Config Persistence: YAML → .conf

Source of truth: `config.yaml`. On every mutation:
1. Save `config.yaml` atomically (write .tmp, rename)
2. Generate routing commands via routing module
3. Render `wg0.conf` (user PostUp/Down + routing commands + peer sections with AllowedIPs overrides)
4. Write `wg0.conf` atomically

"Apply" only reloads WireGuard — the .conf is already on disk.

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
├──────────────┬───────────────────────────┤
│ [Peers]      │ [Server]                  │
├──────────────┴───────────────────────────┤
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
    environment:
      - WG_BUSY_LISTEN=:8080
      - WG_BUSY_CONFIG=/app/data/config.yaml
      - WG_BUSY_WG_CONFIG=/etc/wireguard/wg0.conf
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

## Key Technical Decisions

- **YAML config** as source of truth, rendered to .conf on every save
- **Routing via PostUp/PostDown** in wg0.conf — wg-quick handles setup/teardown
- **Routing table IDs persisted** in YAML for stability across restarts
- **Exit node AllowedIPs override** — YAML keeps /32, wg0.conf gets 0.0.0.0/0
- **Cascade on exit node removal** — clears all ExitNodeID references
- **CDN for htmx/pico.css**, **Go 1.22+ ServeMux**, **wgtypes for keys**, **stateless IPAM**
