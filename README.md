# WG-Busy

> **Geek-friendly WireGuard server management with advanced routing capabilities.**

WG-Busy is a web-based UI for managing a WireGuard server. It is inspired by projects like wg-easy but designed for power users who need more control over their configuration and routing.

![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=flat&logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)
[![Build and Push Multi-Arch Image](https://github.com/yix/wg-busy/actions/workflows/build-and-push.yaml/badge.svg)](https://github.com/yix/wg-busy/actions/workflows/build-and-push.yaml)

## Features

- **Geek Friendly**: Single Go binary, no complex dependencies. Uses `htmx` and `pico.css` for a fast, lightweight UI.
- **Full Control**: Persistence via YAML, but renders standard `wg0.conf` files. You can customize `PostUp`/`PostDown` scripts and other advanced settings directly.
- **Advanced Routing**:
  - **Flexible Exit Nodes**: Any peer can be an exit node for any other peer.
  - **Split Tunneling**: Configure exit nodes to route all traffic or only specific subnets.
  - **Advertised Routes**: Expose networks behind a peer to the VPN.
  - **Policy Routing**: Define custom routes with specific gateways (`CIDR via IP`) per peer, automatically managing Linux policy routing tables.
- **Real-time Stats**: Live bandwidth usage, sparkline graphs, connection status, and actual peer endpoint (IP:port) display.
- **Dynamic BGP Routing**: Native `bio-rd` integration with dual-stack (IPv4 + IPv6) support for automated route advertisement and learning right into the Linux kernel routing table, complete with a BGP dashboard and per-peer route filters.
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
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
      - net.ipv6.conf.all.disable_ipv6=0
    ports:
      - "8080:8080"       # Web UI
      - "51820:51820/udp" # WireGuard
    volumes:
      - ./data:/app/data             # Configuration persistence
      - /lib/modules:/lib/modules:ro # Required for WireGuard kernel module
    environment:
      - WG_BUSY_LISTEN=:8080
      - WG_BUSY_CONFIG=/app/data/config.yaml
      - WG_BUSY_WG_CONFIG=/etc/wireguard/wg0.conf
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
    sudo ./bin/wg-busy -config config.yaml -wg-config /etc/wireguard/wg0.conf
    ```

## Configuration

The application is configured via CLI flags or environment variables:

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `-listen` | `WG_BUSY_LISTEN` | `:8080` | HTTP listen address for the UI |
| `-config` | `WG_BUSY_CONFIG` | `./data/config.yaml` | Path to the persistent YAML config file |
| `-wg-config` | `WG_BUSY_WG_CONFIG` | `/etc/wireguard/wg0.conf` | Path where the standard WireGuard config will be rendered |

### Routing & Advanced Traffic Management

One of WG-Busy's key features is the ability to define complex routing topologies.

-   **Exit Node**: Toggle "Exit Node" on a peer to allow it to route traffic for others.
-   **Route Via**: For any other peer, select an available Exit Node to route all their traffic through that peer.
-   **Advertised Routes**: Define subnets that reside behind a peer. The server will automatically route traffic for these subnets to the peer.
-   **Policy Routes**: Configure explicit `CIDR via Gateway IP` rules per client. All traffic matching the CIDR and originating from that client will be directed to a dedicated policy routing table and pushed out the specified gateway.

This is implemented using Linux policy routing (`ip rule` and custom routing tables), which WG-Busy manages automatically in the `PostUp`/`PostDown` hooks.

### Dynamic BGP Routing via bio-rd

WG-Busy integrates deeply with `bio-rd` to provide a seamless BGP routing daemon working alongside WireGuard:

- **Server BGP Configuration**: Enable BGP globally and configure the local BGP ASN and Listen addresses directly from the UI.
- **Per-Peer Sessions**: Turn any WireGuard client into a BGP peer by providing their overlay BGP IP, ASN, and Port.
- **Dual-Stack Support**: Both IPv4 and IPv6 address families are negotiated over a single BGP session, allowing peers to advertise routes of either family.
- **Strict Route Filtering**: Dynamically attach "Exact" or "Or Longer" route filters to accept or reject received BGP announcements individually per peer.
- **Kernel Route Injection**: Accepted routes are immediately injected natively into the Linux host routing table (LocRIB), enabling zero-touch routing configurations.
- **BGP Dashboard**: A dedicated BGP stats tab displaying real-time peer connection states, uptimes, updates received, and expandable route tables showing each prefix as **Accepted** or **Filtered** (with accepted routes sorted first and filtered routes visually faded).

## Development

-   `make dev`: Run locally (requires macOS/Linux with Go). Note that WireGuard interface management commands will fail on non-Linux systems or without sudo.
-   `make build`: Cross-compile binaries for both `linux/amd64` and `linux/arm64`.
-   `make build-amd64`: Compile the `linux/amd64` binary only.
-   `make build-arm64`: Compile the `linux/arm64` binary only.
-   `make docker-build`: Build the Docker image.

## License

MIT
