# WG-Busy

<p align="center">
  <img src="docs/wg-busy-logo.jpg" alt="WG-Busy Mascot Logo" width="340" />
</p>

 > **Geek-friendly WireGuard server management with advanced routing capabilities.**

WG-Busy is a web-based UI for managing a WireGuard server. It is inspired by projects like wg-easy but designed for power users who need more control over their configuration and routing.

![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=flat&logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)
[![Build and Push Multi-Arch Image](https://github.com/yix/wg-busy/actions/workflows/build-and-push.yaml/badge.svg)](https://github.com/yix/wg-busy/actions/workflows/build-and-push.yaml)

> [!NOTE]
> **WG-Busy is in early development.** Features may be incomplete, rough around the edges, or behave unexpectedly in certain environments. If you run into any issues or have ideas for improvement, please [open an issue](https://github.com/yix/wg-busy/issues) — feedback is very much appreciated and helps shape the project.

## Features

- **Geek Friendly**: Single Go binary, no complex dependencies. Uses `htmx` and custom CSS for a fast, lightweight UI.
- **Full Control**: Persistence via YAML, but renders standard `wg0.conf` files. You can customize `PostUp`/`PostDown` scripts and other advanced settings directly.
- **Advanced Routing**:
  - **Flexible Exit Nodes**: Any peer can be an exit node for any other peer.
  - **Split Tunneling**: Configure exit nodes to route all traffic or only specific subnets.
  - **Advertised Routes**: Expose networks behind a peer to the VPN.
  - **Policy Routing**: Define custom routes with specific gateways (`CIDR via IP`) per peer, automatically managing Linux policy routing tables. The gateway can be a WireGuard peer *or* a ZeroTier peer — each route is pinned to whichever interface its gateway is on-link for.
  - **Strict Policy Routing**: Confine a peer to its own routes. Traffic that matches none of them is rejected instead of falling back to the server's main table, so nothing leaks out of the intended path.
- **Real-time Stats**: Live bandwidth usage, sparkline graphs, connection status, and actual peer endpoint (IP:port) display.
- **Dynamic BGP Routing**: Native `bio-rd` integration with dual-stack (IPv4 + IPv6) support for automated route advertisement and learning right into the Linux kernel routing table, complete with a BGP dashboard and per-peer route filters.
- **Managed ZeroTier Client**: Runs and supervises `zerotier-one` alongside WireGuard — join and leave networks from the UI, with node status, assigned addresses, managed routes, peer latency/paths, and per-interface traffic counters.
- **Multi-Architecture**: Pre-built Docker images for both `linux/amd64` and `linux/arm64`.
- **QR Codes**: Generate configuration QR codes for mobile clients.

> [!WARNING]
> **Security Notice**: WG-Busy **does not** implement authentication. It is intended to be run behind a reverse proxy (like Caddy, Nginx, or Traefik) that handles authentication (Basic Auth, OAuth, etc.) and TLS. Do not expose this UI directly to the public internet.

## Usage

### Docker Compose

The easiest way to run WG-Busy is using Docker Compose.

```yaml
services:
  wg-busy:
    image: ghcr.io/yix/wg-busy:latest
    container_name: wg-busy
    security_opt:
      - systempaths=unconfined
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    devices:
      - /dev/net/tun:/dev/net/tun # Required for ZeroTier
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
      - net.ipv6.conf.all.disable_ipv6=0
    ports:
      - "8080:8080"       # Web UI
      - "51820:51820/udp" # WireGuard
      - "9993:9993/udp"   # ZeroTier
    volumes:
      - ./data:/app/data             # Configuration persistence
      - /lib/modules:/lib/modules:ro # Required for WireGuard kernel module
    restart: unless-stopped
```

### Manual Installation

1.  **Prerequisites**: Linux host with WireGuard installed (`wireguard-tools`, `iptables`).
2.  **Build**:
    ```bash
    make build
    ```
3.  **Run**:
    ```bash
    sudo ./bin/wg-busy-amd64 -config config.yaml -wg-config /etc/wireguard/wg0.conf
    ```

## Configuration

The application is configured via CLI flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:8080` | HTTP listen address for the UI |
| `-config` | `./data/config.yaml` | Path to the persistent YAML config file |
| `-wg-config` | `/etc/wireguard/wg0.conf` | Path where the standard WireGuard config will be rendered |
| `-zt-data` | `./data/zerotier` | ZeroTier home directory (identity, authtoken, joined networks) |

### Routing & Advanced Traffic Management

One of WG-Busy's key features is the ability to define complex routing topologies. For a visual architecture guide with sequence and flow diagrams of all supported routing use cases, see [**ROUTING_SHOWCASE.md**](ROUTING_SHOWCASE.md).

-   **Exit Node**: Toggle "Exit Node" on a peer to allow it to route traffic for others.
-   **Route Via**: For any other peer, select an available Exit Node to route all their traffic through that peer.
-   **Advertised Routes**: Define subnets that reside behind a peer. The server will automatically route traffic for these subnets to the peer.
-   **Policy Routes**: Configure explicit `CIDR via Gateway IP` rules per client. All traffic matching the CIDR and originating from that client will be directed to a dedicated policy routing table and pushed out the specified gateway.
-   **Strict Policy Routing**: Confine a peer to its own routes. Traffic that matches none of them is rejected (`prohibit`) instead of falling back to the server's main table.

This is implemented using Linux policy routing (`ip rule` and custom routing tables), which WG-Busy manages automatically in the `PostUp`/`PostDown` hooks.

### Dynamic BGP Routing via bio-rd

WG-Busy integrates deeply with `bio-rd` to provide a seamless BGP routing daemon working alongside WireGuard:

- **Server BGP Configuration**: Enable BGP globally and configure the local BGP ASN and Listen addresses directly from the UI.
- **Per-Peer Sessions**: Turn any WireGuard client into a BGP peer by providing their overlay BGP IP, ASN, and Port.
- **Dual-Stack Support**: Both IPv4 and IPv6 address families are negotiated over a single BGP session, allowing peers to advertise routes of either family.
- **Strict Route Filtering**: Dynamically attach "Exact" or "Or Longer" route filters and inclusive maximum prefix lengths to accept or reject received and advertised BGP announcements individually per peer.
- **Kernel Route Injection**: Accepted routes are immediately injected natively into the Linux host routing table (LocRIB), enabling zero-touch routing configurations.
- **BGP Dashboard**: A dedicated BGP stats tab displaying real-time peer connection states, uptimes, updates received, and expandable route tables showing each prefix as **Accepted** or **Filtered** (with accepted routes sorted first and filtered routes visually faded).


### Sample BGP configuration on Mikrotik

```
# 64000 - WG-Busy ASN
# 64001 - Mikrotik ASN
# 10.1.2.1 - WG-Busy BGP IP
# 10.1.2.3 - Mikrotik BGP IP

/routing bgp instance
add as=64001 disabled=no name=my-router router-id=10.1.2.3 routing-table=main

/routing bgp connection
add afi=ip as=64001 connect=yes disabled=no instance=my-router local.role=ebgp name=wg-busy output.filter-chain=wg-busy-out .keep-sent-attributes=yes .redistribute=connected,static remote.address=10.1.2.1 .as=64000 routing-table=main

# a list of allowed networks used in the bgp filter, if you would like to restrict advertised prefixes
/ip firewall address-list
# list will match exact network - 10.10.0.0/24 and longer prefixes, such as 10.10.0.1/32, 10.10.0.0/25, etc.
add address=10.10.0.0/24 list=wg-busy-out-allowed
add address=10.10.5.0/24 list=wg-busy-out-allowed

/routing filter rule
# match using an adress-list
add chain=wg-busy-out rule="if (dst in wg-busy-out-allowed) {accept}"
# match using a specific prefix, matches exact prefix unlike above ^^^
add chain=wg-busy-out rule="if (dst == 192.168.10.0/24) {accept}"
# reject all prefixes not matched by previous rules
add chain=wg-busy-out rule=reject
```

### ZeroTier

WG-Busy bundles the `zerotier-one` client and supervises it as a child process, so ZeroTier is
managed the same way as WireGuard: the desired state lives in `config.yaml` and the service is
reconciled toward it.

- **On/Off and Port**: Enable the client and set its primary UDP port from the ZeroTier tab. The service starts, stops, and restarts to match.
- **Join / Leave**: Add a 16-character network ID with the `allowManaged`, `allowGlobal`, `allowDefault` and `allowDNS` flags. Networks in the config are joined, networks removed from it are left. Changing a flag on an already-joined network applies without a rejoin.
- **Status**: Node address, this node's own ZeroTier IPs, online state and version, plus each network's status, assigned addresses, MTU and interface name.
- **Received Routes**: The managed routes each network pushes, with their target, gateway and metric.
- **Policy Route Gateways**: Any ZeroTier peer IP can be used as the gateway of a WireGuard peer's policy route. wg-busy pins the route to the right `zt*` interface, so traffic from a WireGuard client can be steered into a ZeroTier network.
- **Optional NAT**: By default, traffic leaving over any ZeroTier interface is masqueraded behind this node's ZeroTier address (`iptables -t nat -A POSTROUTING -o zt+ -j MASQUERADE`), so WireGuard clients reach ZeroTier hosts without the ZeroTier network needing a route back to the WireGuard subnet. Disable it in the ZeroTier tab when the remote network already has a route back to the WireGuard subnet, or exempt enabled peers' advertised networks while retaining NAT for other traffic.
- **Traffic**: Per-network totals and live rates, read from the interface counters of each `zt*` device. ZeroTier's local API exposes no byte counters, so traffic is per interface, not per peer.
- **Peers**: Address, role, version, latency, and the active physical paths (or `relayed` when no direct path exists).
- **State**: Node identity, auth token and joined networks persist in `/app/data/zerotier`, so the node keeps its address across restarts. Requires `/dev/net/tun` and `NET_ADMIN`.
- **Failure Reporting**: The daemon's own output is logged with a `[ZT]` prefix, and its errors are shown in the tab with a remediation hint. A missing `/dev/net/tun` — where ZeroTier keeps running but can never create an interface — is detected up front and reported as "Running, degraded" rather than failing silently. Configured networks the service has not joined are listed separately under **Not Joined**.

Members still need to be authorized in ZeroTier Central (or your own controller) before a network
leaves `ACCESS_DENIED` and gets an address.

## Development

-   `make dev`: Run locally (requires macOS/Linux with Go). Note that WireGuard interface management commands will fail on non-Linux systems or without sudo.
-   `make build`: Cross-compile binaries for both `linux/amd64` and `linux/arm64`.
-   `make build-amd64`: Compile the `linux/amd64` binary only.
-   `make build-arm64`: Compile the `linux/arm64` binary only.
-   `make docker-build`: Build the Docker image.

## UI Preview

WG-Busy provides a clean, modern interface for managing your WireGuard server and advanced overlay routing.

### Peers Dashboard
Manage all your WireGuard clients, configure exit nodes, toggle policy routing, and view real-time bandwidth usage.

![Peers Dashboard](docs/wg-busy-1-peers.jpg)

### Server Configuration
Configure the WireGuard server settings, including BGP overlay enablement, ASN, listen ports, and DNS preferences.

![Server Configuration](docs/wg-busy-2-server.jpg)

### BGP Statistics
A dedicated dashboard for BGP sessions showing realtime stats on peer uptimes, received prefixes, and exactly which routes were accepted or filtered.

![BGP Statistics](docs/wg-busy-3-bgp.jpg)

### ZeroTier Management
Run the managed ZeroTier client, join networks, inspect service and network status, and troubleshoot networks that have not joined.

![ZeroTier Management](docs/wg-busy-4-zerotier.jpg)

## License

MIT
