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
  - **Policy Routing**: Automatically manages Linux policy routing tables to direct traffic through specific peers.
- **Real-time Stats**: Live bandwidth usage, sparkline graphs, and connection status.
- **QR Codes**: Generate configuration QR codes for mobile clients.

> [!WARNING]
> **Security Notice**: WG-Busy **does not** implement authentication. It is intended to be run behind a reverse proxy (like Caddy, Nginx, or Traefik) that handles authentication (Basic Auth, OAuth, etc.) and TLS. Do not expose this UI directly to the public internet.

## Usage

### Docker Compose

The easiest way to run WG-Busy is using Docker Compose.

```yaml
services:
  wg-busy:
    image: ghcr.io/yix/wg-busy:latest # Replace with actual image if available
    container_name: wg-busy
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
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

### Routing & Exit Nodes

One of WG-Busy's key features is the ability to define complex routing topologies.

-   **Exit Node**: Toggle "Exit Node" on a peer to allow it to route traffic for others.
-   **Route Via**: For any other peer, select an available Exit Node to route all their traffic through that peer.

This is implemented using Linux policy routing (`ip rule` and custom routing tables), which WG-Busy manages automatically in the `PostUp`/`PostDown` hooks.

## Development

-   `make dev`: Run locally (requires macOS/Linux with Go). Note that WireGuard interface management commands will fail on non-Linux systems or without sudo.
-   `make build`: Compile the binary.
-   `make docker-build`: Build the Docker image.

## License

MIT
