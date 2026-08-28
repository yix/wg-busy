# WG-Busy Routing Capabilities & Architecture Showcase

> **Visual guide and technical deep-dive into WG-Busy's policy routing, dynamic BGP routing, ZeroTier integration, and traffic management.**

![WG-Busy Core Features Overview](docs/wg-busy-routing-overview.jpg)

### What Can WG-Busy Do? (At a Glance)

WG-Busy serves as a powerful central hub for managing WireGuard VPNs with flexible traffic steering:

* 🔒 **Secure WireGuard VPN**: Connect laptops, smartphones, and remote devices through high-speed encrypted tunnels.
* 🌐 **WireGuard Exit Nodes**: Bounce any client's internet traffic through a designated exit node peer (e.g. a VPS in another region or country).
* ⚡ **ZeroTier Mesh Integration**: Seamlessly route WireGuard clients into ZeroTier networks with automatic NAT masquerading.
* 📡 **Simple BGP Dynamic Routing**: Automatically exchange and inject live network routes with hardware routers (Mikrotik, VyOS, Cisco) and Cloud VPCs.
* 🎯 **Policy & Strict Routing**: Steer specific subnets to specific gateways per client, or lock down contractor peers so unauthorized traffic is safely dropped.

---

## Master Architecture & Detailed Packet Flow

The diagram below illustrates how incoming packets on `wg0` traverse WG-Busy's priority-ordered Linux Policy Routing rules (`ip rule`), custom routing tables, BGP-injected kernel routes, ZeroTier interfaces, and egress gateways.

```mermaid
flowchart TD
    %% Styling
    classDef client fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#01579b
    classDef engine fill:#ede7f6,stroke:#5e35b1,stroke-width:2px,color:#311b92
    classDef table fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#e65100
    classDef egress fill:#e8f5e9,stroke:#388e3c,stroke-width:2px,color:#1b5e20
    classDef bgp fill:#fce4ec,stroke:#c2185b,stroke-width:2px,color:#880e4f
    classDef drop fill:#ffebee,stroke:#d32f2f,stroke-width:2px,color:#b71c1c

    %% Ingress Clients
    subgraph Ingress ["Ingress Peers (dev wg0)"]
        P_REG["Peer A: Regular Client<br/>(10.0.0.2)"]:::client
        P_PARTIAL["Peer B: Partial Policy Client<br/>(10.0.0.3)"]:::client
        P_STRICT["Peer C: Strict Policy Client<br/>(10.0.0.4)"]:::client
        P_EXIT_CLI["Peer D: Exit Node Client<br/>(10.0.0.5)"]:::client
    end

    %% Linux Policy Routing Engine (ip rule)
    subgraph PolicyEngine ["Linux Policy Routing Engine (ip rule Evaluation)"]
        direction TB
        R_START{"Packet Ingress<br/>Evaluate Source IP"}:::engine
        
        R_EXIT["Priority 10000: from 10.0.0.5<br/>lookup table 100 (Exit Node Table)"]:::engine
        R_POL_B["Priority 10000: from 10.0.0.3<br/>lookup table 101 (Policy Table)"]:::engine
        R_POL_C["Priority 10000: from 10.0.0.4<br/>lookup table 102 (Strict Policy Table)"]:::engine
        R_STRICT_PROHIBIT["Priority 10001: from 10.0.0.4<br/>prohibit (Strict Reject)"]:::drop
        
        R_MAIN["Priority 32766: from all<br/>lookup main (Main Routing Table)"]:::engine
    end

    %% Routing Tables
    subgraph RoutingTables ["Kernel Routing Tables"]
        T_EXIT["Table 100 (Exit Node Table)<br/>- default dev wg0<br/>(or split subnets dev wg0)"]:::table
        T_POL_B["Table 101 (Peer B Policy Table)<br/>- 192.168.50.0/24 via 10.0.0.10 dev wg0<br/>- 172.16.0.0/16 via 10.147.17.50 dev zt0"]:::table
        T_POL_C["Table 102 (Peer C Policy Table)<br/>- 10.200.0.0/16 via 10.0.0.20 dev wg0"]:::table
        T_MAIN["Table main (Default / BGP FIB)<br/>- default via eth0 (Server Gateway)<br/>- 10.0.0.0/24 dev wg0<br/>- BGP learned routes (via bio-rd)"]:::table
    end

    %% BGP Control Plane
    subgraph BGPPlane ["BGP Dynamic Routing (bio-rd)"]
        BGP_PEER["Remote BGP Peer / Router"]:::bgp
        BGP_FILTER{"BGP Route Filter Chain<br/>- Max Prefix Length<br/>- Exact / OrLonger match<br/>- Default Reject"}:::bgp
        BGP_RIB["LocRIB / Kernel Client"]:::bgp
        BGP_DROP["RIB Status: Filtered"]:::drop
        
        BGP_PEER -->|"BGP Update (Routes)"| BGP_FILTER
        BGP_FILTER -->|"Accepted Routes"| BGP_RIB
        BGP_FILTER -.->|"Filtered / Dropped"| BGP_DROP
        BGP_RIB -->|"Direct Kernel Injection"| T_MAIN
    end

    %% Egress & Forwarding
    subgraph Egress ["Egress Targets"]
        E_DEF["Server Default Gateway<br/>(Internet via eth0 + NAT)"]:::egress
        E_EXIT_NODE["Exit Node Peer (10.0.0.50)<br/>(dev wg0 -> Remote Internet)"]:::egress
        E_WG_PEER["WireGuard Peer Gateway<br/>(10.0.0.10 / 10.0.0.20 on wg0)"]:::egress
        
        subgraph ZTEgress ["ZeroTier Egress Pipeline"]
            ZT_NAT["iptables NAT Masquerade<br/>-o zt+ -j MASQUERADE"]:::egress
            ZT_NET["ZeroTier Network Endpoint<br/>(10.147.17.50 dev zt0)"]:::egress
        end
        
        E_PROHIBIT["ICMP Host Prohibited<br/>(Traffic Blackholed Safely)"]:::drop
    end

    %% Connections
    P_REG --> R_START
    P_PARTIAL --> R_START
    P_STRICT --> R_START
    P_EXIT_CLI --> R_START

    R_START --> R_EXIT
    R_START --> R_POL_B
    R_START --> R_POL_C
    R_START --> R_MAIN

    %% Exit node path
    R_EXIT -->|"Match src 10.0.0.5"| T_EXIT
    T_EXIT -->|"Forward via wg0"| E_EXIT_NODE

    %% Partial policy routing path
    R_POL_B -->|"Match src 10.0.0.3"| T_POL_B
    T_POL_B -->|"Match 192.168.50.0/24"| E_WG_PEER
    T_POL_B -->|"Match 172.16.0.0/16"| ZT_NAT
    T_POL_B -->|"Unmatched fallback"| R_MAIN

    %% Strict policy routing path
    R_POL_C -->|"Match src 10.0.0.4"| T_POL_C
    T_POL_C -->|"Match 10.200.0.0/16"| E_WG_PEER
    T_POL_C -->|"Unmatched fallback"| R_STRICT_PROHIBIT
    R_STRICT_PROHIBIT --> E_PROHIBIT

    %% ZeroTier Masquerade to ZT endpoint
    ZT_NAT --> ZT_NET

    %% Main table routing paths
    R_MAIN --> T_MAIN
    T_MAIN -->|"Default route"| E_DEF
    T_MAIN -->|"BGP Learned Destination"| E_WG_PEER
```

---

## 1. Regular WireGuard Peer (Server Default Gateway)

### Overview
A standard WireGuard client configuration. Traffic arrives across the `wg0` tunnel interface, has no policy rules targeting its source IP, falls through to the Linux `main` routing table (`priority 32766`), and exits via the host server's default WAN gateway (e.g. `eth0`).

```mermaid
sequenceDiagram
    autonumber
    actor Client as Regular Peer (10.0.0.2)
    participant WG as WG-Busy Server (wg0: 10.0.0.1)
    participant Rule as Linux ip rule (Priority 32766)
    participant MainTable as Main Routing Table
    participant WAN as Server Default Gateway (eth0)
    actor Internet as Target Host (e.g. 8.8.8.8)

    Client->>WG: Encrypted packet (Src: 10.0.0.2, Dst: 8.8.8.8)
    WG->>Rule: Lookup policy rules (no source rule matches 10.0.0.2)
    Rule->>MainTable: Fallback to table main
    MainTable->>WAN: Matched default route via eth0
    WAN->>Internet: Forward via eth0 with iptables MASQUERADE
    Internet-->>WAN: Return traffic
    WAN-->>WG: Return packet directed to 10.0.0.2
    WG-->>Client: Encrypted return packet over wg0
```

### Configuration Example
```yaml
peers:
  - id: "client-alice"
    name: "Alice Laptop"
    allowedIPs: "10.0.0.2/32"
    clientAllowedIPs: "0.0.0.0/0, ::/0"
    enabled: true
```

---

## 2. Policy Routing

WG-Busy manages Linux Policy Based Routing (PBR) using source routing (`ip rule from <peer_ip>`). Priorities start at `10000` (well below `main` at `32766`), ensuring policy rules are evaluated first.

```
Rule Priority Hierarchy:
  10000: from <peer_ip> lookup <exit_node_table>  (if routing via Exit Node)
  10001: from <peer_ip> lookup <policy_table>     (if custom Policy Routes exist)
  10002: from <peer_ip> prohibit                  (if Strict Policy Routing is enabled)
  ...
  32766: from all lookup main                     (standard kernel routes)
```

---

### 2.1 Partial Policy Routing (Split Subnet Routing)

#### Overview
A peer routes specific destination subnets through designated gateways (which can be other WireGuard peers or ZeroTier hosts), while all other traffic falls through to the server's default gateway.

```mermaid
flowchart TD
    classDef client fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#01579b
    classDef rule fill:#ede7f6,stroke:#5e35b1,stroke-width:2px,color:#311b92
    classDef gw fill:#e8f5e9,stroke:#388e3c,stroke-width:2px,color:#1b5e20
    classDef fallback fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#e65100

    Client["Peer Traffic (Src: 10.0.0.3)"]:::client --> PRule{"ip rule Priority 10000<br/>from 10.0.0.3 lookup table 101"}:::rule
    
    PRule --> Table101["Policy Table 101"]:::fallback
    
    Table101 -->|"Dst in 192.168.50.0/24"| GW_WG["via 10.0.0.10 dev wg0<br/>(Branch Office WG Peer)"]:::gw
    Table101 -->|"Dst in 172.16.0.0/16"| GW_ZT["via 10.147.17.50 dev zt0<br/>(ZeroTier Endpoint)"]:::gw
    Table101 -->|"Unmatched Destination<br/>(e.g. 1.1.1.1)"| Fallthrough["Fallthrough to main Table<br/>(Priority 32766)"]:::fallback
    
    Fallthrough --> DefaultGW["Server Default Gateway<br/>(eth0 / Internet)"]:::fallback
```

#### Generated System Commands
```bash
# Injected into wg0 PostUp:
ip rule del priority 10000 2>/dev/null || true; ip rule add from 10.0.0.3 table 101 priority 10000
ip route replace 192.168.50.0/24 via 10.0.0.10 dev wg0 table 101 || true
ip route replace 172.16.0.0/16 via 10.147.17.50 dev zt0 table 101 || true
```

#### Configuration Example
```yaml
peers:
  - id: "client-bob"
    name: "Bob Workstation"
    allowedIPs: "10.0.0.3/32"
    policyRoutingTableID: 101
    policyRoutes:
      - "192.168.50.0/24 via 10.0.0.10"
      - "172.16.0.0/16 via 10.147.17.50"
    strictPolicyRouting: false
    enabled: true
```

---

### 2.2 Full Policy Routing

#### (a) Via Manual Routing Table with Strict Policy Routing (`strictPolicyRouting: true`)

When a peer must be completely isolated to its assigned policy routes, **Strict Policy Routing** adds a trailing `prohibit` rule. Any packet not matching the custom table is rejected with an ICMP Host Prohibited error rather than falling back to the `main` table.

```mermaid
flowchart TD
    classDef client fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#01579b
    classDef rule fill:#ede7f6,stroke:#5e35b1,stroke-width:2px,color:#311b92
    classDef gw fill:#e8f5e9,stroke:#388e3c,stroke-width:2px,color:#1b5e20
    classDef drop fill:#ffebee,stroke:#d32f2f,stroke-width:2px,color:#b71c1c

    Client["Peer Traffic (Src: 10.0.0.4)"]:::client --> R1{"ip rule Priority 10000<br/>from 10.0.0.4 lookup table 102"}:::rule
    
    R1 -->|"Lookup Table 102"| Table102["Policy Table 102<br/>- 10.200.0.0/16 via 10.0.0.20 dev wg0"]:::rule
    
    Table102 -->|"Matched (10.200.x.x)"| GW["via 10.0.0.20 dev wg0<br/>(Designated Secure Gateway)"]:::gw
    Table102 -->|"Unmatched Destination"| R2{"ip rule Priority 10001<br/>from 10.0.0.4 prohibit"}:::drop
    
    R2 -->|"Matches"| Drop["ICMP Destination Administratively Prohibited<br/>(Fails Closed - Zero Leakage)"]:::drop
```

#### Generated System Commands
```bash
ip rule del priority 10000 2>/dev/null || true; ip rule add from 10.0.0.4 table 102 priority 10000
ip rule del priority 10001 2>/dev/null || true; ip rule add from 10.0.0.4 prohibit priority 10001
ip route replace 10.200.0.0/16 via 10.0.0.20 dev wg0 table 102 || true
```

#### Configuration Example
```yaml
peers:
  - id: "client-strict"
    name: "Secure Contractor"
    allowedIPs: "10.0.0.4/32"
    policyRoutingTableID: 102
    policyRoutes:
      - "10.200.0.0/16 via 10.0.0.20"
    strictPolicyRouting: true
    enabled: true
```

---

#### (b) Via Exit Node

Any peer can be configured as an **Exit Node**. Other peers can select it via `exitNodeID`, steering all their outbound internet (or split subnets) through that peer.

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Client Peer (10.0.0.2)
    participant Server as WG-Busy Server (10.0.0.1)
    participant ExitNode as Exit Node Peer (10.0.0.50)
    actor Target as Remote Internet / Service

    Note over Server: Exit Node Config: Table 100<br/>ip route replace default dev wg0 table 100<br/>ip rule add from 10.0.0.2 table 100 priority 10000
    
    Alice->>Server: VPN packet (Src: 10.0.0.2, Dst: 93.184.216.34)
    Server->>Server: ip rule matches 10.0.0.2 -> lookup table 100
    Server->>Server: Table 100 matches default -> dev wg0
    Server->>ExitNode: Forward packet out wg0 to Exit Node (10.0.0.50)
    ExitNode->>Target: Forward to Internet with local NAT/masquerade
    Target-->>ExitNode: Response packet
    ExitNode-->>Server: Return packet over wg0
    Server-->>Alice: Return packet to client over wg0
```

#### Exit Node Modes:
* **Full Tunnel (`exitNodeAllowAll: true`)**: Server wg0.conf sets `AllowedIPs = 0.0.0.0/0, ::/0` for the exit peer and installs `default dev wg0 table <ID>`.
* **Split Tunnel (`exitNodeAllowAll: false`)**: Server installs only the specific `exitNodeRoutes` in table `<ID>` and sets `AllowedIPs = <PeerIP>, <Route1>, <Route2>...`.

#### Configuration Example
```yaml
peers:
  # The Exit Node Peer
  - id: "exit-us"
    name: "US Exit Gateway"
    allowedIPs: "10.0.0.50/32"
    isExitNode: true
    exitNodeAllowAll: true
    routingTableID: 100
    enabled: true

  # The Client routing through the Exit Node
  - id: "client-alice"
    name: "Alice Laptop"
    allowedIPs: "10.0.0.2/32"
    exitNodeID: "exit-us"
    enabled: true
```

---

## 3. Routing via ZeroTier Network Endpoint(s)

WG-Busy supervises an embedded `zerotier-one` process, monitors on-link ZeroTier interfaces (`zt*`), pins policy routes to the appropriate ZeroTier device, and applies automated NAT masquerade.

```mermaid
flowchart LR
    classDef wg fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#01579b
    classDef core fill:#ede7f6,stroke:#5e35b1,stroke-width:2px,color:#311b92
    classDef zt fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#e65100

    subgraph WGNetwork ["WireGuard Overlay (wg0)"]
        WGP["WG Client<br/>(10.0.0.3)"]:::wg
    end

    subgraph WGBusy ["WG-Busy Core Routing"]
        P_ROUTE["Policy Route Match<br/>10.50.0.0/16 via 10.147.17.99"]:::core
        DEV_RES["Device Resolution<br/>Gateway 10.147.17.99 -> dev zt5u4va25t"]:::core
        NAT["iptables NAT POSTROUTING<br/>-s 10.0.0.3 -o zt+ -j MASQUERADE<br/>(Source rewritten to 10.147.17.10)"]:::core
    end

    subgraph ZTNetwork ["ZeroTier SDN (zt*)"]
        ZTG["ZeroTier Gateway Peer<br/>(10.147.17.99)"]:::zt
        ZTTarget["Target Remote Network<br/>(10.50.0.0/16)"]:::zt
    end

    WGP -->|"Src: 10.0.0.3<br/>Dst: 10.50.1.5"| P_ROUTE
    P_ROUTE --> DEV_RES
    DEV_RES --> NAT
    NAT -->|"Src: 10.147.17.10<br/>Dst: 10.50.1.5"| ZTG
    ZTG --> ZTTarget
```

### Key Technical Mechanisms:
1. **Dynamic Gateway Resolution**: `models.DeviceForGateway` matches the gateway IP (`10.147.17.99`) against joined ZeroTier networks and binds the route to `dev zt5u4va25t`.
2. **ZeroTier Egress NAT**: WireGuard source IPs (`10.0.0.3`) are masqueraded behind the WG-Busy node's ZeroTier IP (`iptables -t nat -A POSTROUTING -o zt+ -j MASQUERADE`), ensuring return packets route correctly without remote ZeroTier controllers needing return routes.
3. **Idempotent / Safe Hooks**: ZeroTier policy routes include trailing `|| true` so a temporarily unassigned ZeroTier interface does not break `wg-quick up`.

---

## 4. Routing via Dynamic BGP Received Routes

WG-Busy embeds `bio-rd` to establish dual-stack (IPv4/IPv6) BGP peering sessions over WireGuard tunnels, ZeroTier networks, or physical LANs. Accepted routes are injected directly into the Linux kernel `main` routing table.

```mermaid
flowchart TD
    classDef bgp fill:#fce4ec,stroke:#c2185b,stroke-width:2px,color:#880e4f
    classDef core fill:#ede7f6,stroke:#5e35b1,stroke-width:2px,color:#311b92
    classDef kernel fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#e65100
    classDef client fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#01579b
    classDef target fill:#e8f5e9,stroke:#388e3c,stroke-width:2px,color:#1b5e20

    subgraph BGPPeer ["External BGP Router (e.g. Mikrotik / VyOS / FRR)"]
        PEER_RIB["Peer BGP Daemon"]:::bgp
    end

    subgraph WGBusyHost ["WG-Busy Server"]
        subgraph BioRD ["bio-rd BGP Protocol Engine"]
            SESSION["Dual-Stack BGP Session (TCP:179)<br/>IPv4 and IPv6 Unicast AFI"]:::core
            IMPORT_CHAIN["Import Filter Chain Evaluation"]:::core
            LOC_RIB["Default VRF LocRIB"]:::core
        end
        
        subgraph KernelFIB ["Linux Kernel Routing Engine"]
            K_CLIENT["bio-rd bgpKernelClient"]:::kernel
            MAIN_TABLE["Kernel main Routing Table"]:::kernel
        end
    end

    subgraph Clients ["Ingress WireGuard Clients"]
        CLI["Peer A (10.0.0.2)"]:::client
    end

    subgraph Targets ["Target Corporate / Remote Subnets"]
        TARG["Subnet: 192.168.100.0/24<br/>via BGP Peer IP"]:::target
    end

    PEER_RIB -->|"1. BGP UPDATE Prefix: 192.168.100.0/24"| SESSION
    SESSION --> IMPORT_CHAIN
    IMPORT_CHAIN -->|"2. Filter: ACCEPT"| LOC_RIB
    LOC_RIB -->|"3. AddPath"| K_CLIENT
    K_CLIENT -->|"4. Netlink Route Injection"| MAIN_TABLE

    CLI -->|"5. Packet to 192.168.100.25"| MAIN_TABLE
    MAIN_TABLE -->|"6. Routed via Next-Hop"| TARG
```

---

## 5. BGP Route Filtering Pipeline

WG-Busy provides granular per-peer route filters on both **import** (received prefixes) and **export** (advertised prefixes) chains.

```mermaid
flowchart TD
    classDef inputNode fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#01579b
    classDef stepNode fill:#ede7f6,stroke:#5e35b1,stroke-width:2px,color:#311b92
    classDef acceptNode fill:#e8f5e9,stroke:#388e3c,stroke-width:2px,color:#1b5e20
    classDef rejectNode fill:#ffebee,stroke:#d32f2f,stroke-width:2px,color:#b71c1c

    subgraph Inbound ["Inbound BGP Announcement (from Peer)"]
        ADV["Received Prefix (e.g. 10.10.5.0/24)"]:::inputNode
    end

    subgraph FilterChain ["bio-rd Filter Evaluation Pipeline"]
        direction TB
        
        STEP_MAX{"Max Prefix Length Check<br/>Prefix length exceeds limit?"}:::stepNode
        
        STEP_TERMS{"Evaluate User Terms in Order<br/>(Term 0, Term 1, ... Term N)"}:::stepNode
        
        MATCH_TYPE{"Matcher Type"}:::stepNode
        M_EXACT["exact<br/>(matches exact CIDR only)"]:::stepNode
        M_ORLONGER["orlonger<br/>(matches prefix and any subnet)"]:::stepNode
        
        ACTION{"Action"}:::stepNode
        ACT_ACCEPT["accept"]:::acceptNode
        ACT_REJECT["reject"]:::rejectNode
        
        DEFAULT_REJECT["Implicit Default Reject Term<br/>(rejects unmatched prefixes)"]:::rejectNode
    end

    subgraph Destination ["Route Destination & Dashboard State"]
        ACCEPTED["Accepted into LocRIB<br/>- Injected into Kernel main table<br/>(Dashboard: Bold 'Accepted')"]:::acceptNode
        FILTERED["Discarded from FIB<br/>(Dashboard: Faded 'Filtered')"]:::rejectNode
    end

    ADV --> STEP_MAX
    STEP_MAX -->|"Length > Max"| FILTERED
    STEP_MAX -->|"Length <= Max"| STEP_TERMS
    
    STEP_TERMS --> MATCH_TYPE
    MATCH_TYPE --> M_EXACT
    MATCH_TYPE --> M_ORLONGER
    
    M_EXACT --> ACTION
    M_ORLONGER --> ACTION
    
    ACTION -->|"Rule Action = accept"| ACCEPTED
    ACTION -->|"Rule Action = reject"| FILTERED
    
    STEP_TERMS -->|"No user terms match"| DEFAULT_REJECT
    DEFAULT_REJECT --> FILTERED
```

### BGP Configuration Example
```yaml
server:
  bgpEnabled: true
  bgpListenAddress: "::"
  bgpListenPort: 179
  bgpAsn: 64000

bgpPeers:
  - id: "bgp-core-router"
    name: "Core Mikrotik Router"
    peerIP: "10.0.0.10"
    peerPort: 179
    peerAsn: 64001
    connect: false                # Passive listener mode
    redistributeConnected: true   # Advertise WG & ZT subnets with Next-Hop-Self
    maxReceivedPrefixLength: 24   # Drop prefixes smaller than /24
    routeFilters:
      - prefix: "10.10.0.0/16"
        matcher: "orlonger"
        action: "accept"
      - prefix: "192.168.1.0/24"
        matcher: "exact"
        action: "accept"
      - prefix: "10.0.0.0/8"
        matcher: "orlonger"
        action: "reject"
    enabled: true
```

---

## Technical Comparison Matrix

| Routing Capability | `ip rule` Priority | Kernel Table | Egress Dev | Default Gateway Fallback | NAT Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Regular WG Peer** | `32766` (`main`) | `main` | `eth0` / WAN | **Yes** (Primary egress) | Host WAN Masquerade |
| **Partial Policy Routing** | `10000+` (`from <peer>`) | Custom Table (e.g. `101`) | `wg0` or `zt*` | **Yes** (Unmatched falls through to `main`) | Device-dependent |
| **Full Policy (Strict)** | `10000` (lookup), `10001` (`prohibit`) | Custom Table (e.g. `102`) | `wg0` or `zt*` | **No** (Unmatched fails closed with ICMP Prohibited) | Device-dependent |
| **Full Policy (Exit Node)**| `10000+` (`from <peer>`) | Exit Table (e.g. `100`) | `wg0` | **No** (All traffic steered to exit peer) | Exit Node handles NAT |
| **ZeroTier Endpoint** | `10000+` (`from <peer>`) | Custom Table (e.g. `101`) | `zt*` device | Configurable (Strict vs Non-Strict) | `iptables -o zt+ -j MASQUERADE` |
| **BGP Dynamic Routes** | `32766` (`main`) | `main` | `wg0` / `zt*` / WAN | **Yes** (Evaluated via LPM in `main`) | Standard routing |
| **BGP Route Filtering** | N/A (Control Plane) | `LocRIB` $\rightarrow$ `main` | N/A | Rejected prefixes never touch kernel FIB | N/A |
