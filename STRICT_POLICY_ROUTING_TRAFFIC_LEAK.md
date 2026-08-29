# [High] Strict policy routing can fail open and expose the server public IP

## Summary

Traffic from a WireGuard peer configured for strict policy routing can leave through the server's normal uplink instead of the configured remote ZeroTier gateway. When that happens, public-IP check services report the server's public IP rather than the remote ZeroTier host's public IP.

The generated steady-state policy rules contain an `ip rule ... prohibit` fallback, but strictness is not preserved during every live-state transition. The current reconciliation sequence removes the previous rules before installing the replacement state. Saved configuration can also get ahead of the rules actually applied to the kernel. In either case, traffic can fall through to the main routing table and then be masqueraded by the server's existing `eth0` NAT rule.

Strict mode should prefer a temporary outage over a privacy leak. In addition to fixing the policy-routing update order, strict peers need a filter-table egress guard that rejects forwarded traffic whenever its destination and output interface do not match the configured strict route.

## Severity and impact

**Severity: High.** This violates the main security and privacy promise of strict routing.

- A peer can expose the VPN server's public IP.
- Traffic can use the server's ordinary internet connection without an obvious client-side error.
- The failure may be intermittent during configuration, BGP, or ZeroTier gateway updates, making it difficult to diagnose.
- A persistent apply failure can leave the UI/YAML showing strict mode while the kernel still has the previous non-strict state.

## Observed behavior

1. Connect through WireGuard to the server.
2. Configure the client peer to use a policy route whose gateway is a remote ZeroTier host.
3. Enable strict policy routing.
4. Open several public-IP check services from the client.
5. Some requests report the WireGuard server's public IP instead of the remote ZeroTier gateway's public IP.

The checked-in runtime snapshot also demonstrates the fail-open result, although it is not currently a strict configuration:

- `data/config.yaml` does not set `strictPolicyRouting` for the peer.
- `data/wg0.conf` installs the peer's table lookup but has no matching `ip rule ... prohibit` rule.
- `data/wg0.conf` retains `iptables -A POSTROUTING -t nat -o eth0 -j MASQUERADE`.

With that live state, traffic not matched by the peer's policy table falls through to the main table, leaves on `eth0`, and is translated to the server's public IP.

## Expected behavior

For every enabled strict peer and every authorized IPv4/IPv6 source:

- traffic matching a configured route may leave only through the interface resolved for that route;
- traffic not matching a configured strict route must be rejected;
- loss of the ZeroTier network, gateway, or route must block traffic;
- an apply/reconcile failure must keep the peer blocked;
- traffic must never fall through to the server's main route or be masqueraded on `eth0`;
- the UI must distinguish saved configuration from successfully applied live state.

## Root cause

### 1. Routing reconciliation removes the fail-closed rule first

`internal/routing/routing.go` generates a final `prohibit` rule for a strict peer after its table lookups. That steady-state ordering is correct.

However, `Reconcile` currently performs this sequence:

1. run every `PostDown` command for the previous state;
2. run every `PostUp` command for the next state;
3. if installation fails, best-effort restore the previous state.

`generatePostDownCommands` removes the peer rules, including the strict `prohibit`, before replacement routes and rules are ready. During that gap, packets can use the main table. The same path is used for live routing reapplication, including ZeroTier gateway and BGP-driven changes.

Restoring the previous state after an error does not close the exposure window. It also restores a non-strict state when a change from non-strict to strict fails.

### 2. Saved state can differ from applied state

`internal/config/config.go` saves `config.yaml` and renders `wg0.conf` before live routing reconciliation. If WireGuard is down, a restart is pending, or reconciliation fails, `Write` returns an `ApplyError`, but the desired configuration remains saved.

The live routing snapshot is updated only after successful reconciliation. This is correct internally, but the product can still present the saved peer as strict without clearly indicating that the strict rules are not active in the kernel.

### 3. An unresolved gateway falls back to `wg0`

`policyRouteCmd` uses `models.DeviceForGateway` to select `wg0` or a ZeroTier interface. If no matching gateway network is known, it currently falls back to `wg0`, and every route command ends in `|| true`.

For strict mode this is unsafe. A missing ZeroTier device must produce a blocked state, not an alternative route. Overlapping WireGuard and ZeroTier CIDRs can also make `DeviceForGateway` select the first match rather than report an ambiguous interface.

### 4. The server's uplink NAT makes fallback visible as the server IP

The default server hook masquerades traffic leaving on `eth0`. Once a strict peer's traffic reaches the main route, that NAT rule converts the packet source to the server's public address. The NAT rule is not itself the bug; the bug is allowing strict traffic to reach it.

## Proposed fix

### A. Make strict reconciliation fail closed

For all peer sources affected by a transition, where “affected” is the union of the previous and next strict peer sources:

1. Install a temporary filter-table reject at the top of `FORWARD`.
2. Build or refresh the permanent strict egress chain while the temporary reject blocks traffic.
3. Install the next policy routes and lookup rules.
4. Install/verify the next `ip rule ... prohibit` entries.
5. Remove obsolete previous routes and rules without removing a guard needed by the next state.
6. Verify the expected rules, routes, and firewall jump exist.
7. Remove the temporary reject only after the complete next state is active.

If any step fails, leave the temporary or permanent reject in place and return `ApplyError`. A later successful reconcile may remove it. This intentionally trades availability for confidentiality in strict mode.

For a strict-to-non-strict change, remove the final firewall guard and `prohibit` rule only after the requested non-strict state has applied successfully.

### B. Add an iptables egress guard for strict peers

Create application-owned filter chains and jump to them before broad user `FORWARD` accepts:

```sh
iptables -w -N WG_BUSY_STRICT4 2>/dev/null || true
iptables -w -C FORWARD -i wg0 -j WG_BUSY_STRICT4 2>/dev/null || \
  iptables -w -I FORWARD 1 -i wg0 -j WG_BUSY_STRICT4

ip6tables -w -N WG_BUSY_STRICT6 2>/dev/null || true
ip6tables -w -C FORWARD -i wg0 -j WG_BUSY_STRICT6 2>/dev/null || \
  ip6tables -w -I FORWARD 1 -i wg0 -j WG_BUSY_STRICT6
```

For each strict peer source and configured route, add an allow-return rule for the route's destination and resolved output interface. Follow all allowed route/interface pairs for that source with a terminal reject.

Example: WireGuard source `10.0.0.2/32` has `0.0.0.0/0` routed through ZeroTier interface `ztabc12345`:

```sh
iptables -w -A WG_BUSY_STRICT4 \
  -s 10.0.0.2/32 -d 0.0.0.0/0 -o ztabc12345 -j RETURN
iptables -w -A WG_BUSY_STRICT4 \
  -s 10.0.0.2/32 -j REJECT --reject-with icmp-admin-prohibited
```

IPv6 must be guarded independently:

```sh
ip6tables -w -A WG_BUSY_STRICT6 \
  -s fd00::2/128 -d ::/0 -o ztabc12345 -j RETURN
ip6tables -w -A WG_BUSY_STRICT6 \
  -s fd00::2/128 -j REJECT --reject-with icmp6-adm-prohibited
```

`RETURN` is intentional. It confirms that strict routing permits this destination/interface pair, then returns control to the host's existing `FORWARD` policy. Using `ACCEPT` here could bypass firewall rules owned by the administrator.

The terminal reject blocks all of the following:

- an allowed destination leaving on `eth0` or another wrong interface;
- a destination not present in the peer's strict route set;
- traffic after the ZeroTier route or device disappears;
- main-table fallback during policy-rule reconciliation.

The filter decision occurs before `nat/POSTROUTING`, so rejected traffic cannot reach the existing `eth0` masquerade rule.

For an exit-node route, derive the allowed destination prefixes from the exit node's effective routes and use `wg0` as the expected output interface. For a policy route, resolve the expected interface from its gateway. Do not add an allow rule if resolution is missing or ambiguous; retain only the peer's terminal reject.

Rules should match both destination and output interface. A peer-wide list of permitted interfaces is insufficient when one peer has routes through multiple gateways: it could allow a packet for one route to leave through another route's interface.

### C. Stage firewall updates without an unguarded window

Flushing and rebuilding `WG_BUSY_STRICT4` or `WG_BUSY_STRICT6` directly creates another fail-open interval. Before changing a chain, insert temporary source-specific rejects at the top of `FORWARD`:

```sh
iptables -w -I FORWARD 1 -i wg0 -s 10.0.0.2/32 \
  -m comment --comment 'wg-busy strict apply' \
  -j REJECT --reject-with icmp-admin-prohibited
```

Then rebuild the owned chain, update policy routing, verify the final state, and delete the exact temporary rule. Use the same process with `ip6tables` for IPv6. On crash or failure the temporary rule remains, which is the desired fail-closed behavior. Startup reconciliation must recognize and safely remove stale temporary guards only after a successful apply.

Use `-w` for the xtables lock and idempotent `-C` checks before adding shared jumps. Cleanup must delete only rules and chains owned by this application; it must not flush administrator-managed chains.

### D. Remove unsafe gateway fallback

Change route generation so an unresolved strict gateway does not default to `wg0`.

- Return a typed resolution/apply error for missing or ambiguous gateways.
- Leave the strict firewall reject and policy `prohibit` active.
- Do not emit a `route replace` command for that route.
- Resolve overlapping gateway networks by longest-prefix match; if equally specific matches point to different devices, reject the configuration as ambiguous.
- Continue allowing best-effort route cleanup by destination/table key during `PostDown`.

Non-strict behavior can remain best-effort if compatibility requires it, but the UI should warn that the route is not applied.

### E. Expose desired versus applied state

When `Write` persists a change but live apply fails or is pending:

- display “saved, not applied” rather than presenting strict mode as active;
- include the apply error and whether WireGuard restart is required;
- do not clear the warning until live rules have been reconciled and verified;
- if strict mode was newly requested, keep the peer blocked until application succeeds.

## Suggested implementation locations

- `internal/routing/routing.go`
  - generate IPv4/IPv6 strict egress specifications;
  - install temporary guards before teardown;
  - reconcile routes/rules while guarded;
  - update permanent chains and remove guards only after success;
  - remove the unresolved-gateway fallback for strict routes.
- `internal/models/models.go`
  - return unique/ambiguous gateway resolution rather than the first matching network;
  - validate conflicting gateway networks and policy-route destinations.
- `internal/config/config.go`
  - preserve and expose distinct desired/applied routing state;
  - ensure pending restart and interface-down paths retain strict blocking.
- peer handlers/templates
  - show a clear pending/failed-apply status next to the strict badge.

Keep the implementation inside the existing routing package and use the system `iptables`/`ip6tables` commands already used by the project. A new firewall abstraction or dependency is not required.

## Acceptance criteria

- A strict peer using a ZeroTier default route consistently sees the remote ZeroTier host's public IP.
- Packets from that peer attempting to leave on `eth0` are rejected before NAT; the matching `eth0` masquerade counter does not increase.
- Removing or stopping the ZeroTier interface blocks the strict peer instead of exposing the server IP.
- A forced failure at every reconciliation step leaves a reject guard active.
- BGP and ZeroTier-triggered reapplication has no unguarded interval.
- Enabling strict mode from a non-strict state blocks traffic until the new state is fully applied.
- Disabling strict mode removes the block only after the non-strict state is fully applied.
- IPv4 and IPv6 are tested independently.
- Multiple strict peers and multiple destination/interface pairs remain isolated.
- Disabling or deleting a peer cleans up only that peer's owned rules.
- Non-strict peers retain their current behavior.
- The UI differentiates saved configuration from verified live state.

## Test plan

### Unit tests

- Generate allow-return rules for every `(source, destination, expected interface)` tuple.
- Generate a terminal reject for every strict IPv4 and IPv6 source.
- Emit no interface allow when gateway resolution is missing or ambiguous.
- Verify temporary guards are installed before any previous `prohibit` is removed.
- Verify temporary guards are removed only after routes, lookup rules, `prohibit`, and permanent firewall rules succeed.
- Inject a command failure at each apply step and assert that a strict reject remains.
- Verify strict-to-non-strict and non-strict-to-strict ordering.
- Verify repeated apply and process restart are idempotent.

### Linux network-namespace integration test

Create isolated `wg0`, ZeroTier-like, and `eth0` interfaces with separate next hops:

1. Confirm a strict test flow reaches the expected ZeroTier-like interface.
2. Remove its policy route or interface.
3. Confirm the packet is rejected and no packet reaches `eth0`.
4. Run reconciliation repeatedly while generating traffic.
5. Confirm there is no packet on `eth0` during any transition.
6. Repeat for IPv6 and for an injected mid-reconcile failure.

## Operational verification

After applying the fix, inspect both routing and filtering state:

```sh
ip -4 rule show
ip -6 rule show
ip -4 route show table all
ip -6 route show table all
iptables -w -S FORWARD
iptables -w -S WG_BUSY_STRICT4
ip6tables -w -S FORWARD
ip6tables -w -S WG_BUSY_STRICT6
```

For each strict peer source, a table lookup must be followed by an `ip rule ... prohibit`, and the strict chain must end with a reject after all valid destination/interface pairs. During fault testing, packet counters may increase on the strict reject but must not increase on an `eth0` forwarding/NAT path for that peer.

## Scope note

This issue covers traffic forwarded by the server from WireGuard peers. Browser WebRTC exposure, client-side DNS behavior, traffic generated by a server-side proxy, and client routes that bypass WireGuard are separate leak classes and require client/application-specific controls.
