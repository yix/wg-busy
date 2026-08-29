# Critical Issues Review

Date: 2026-08-29  
Scope: Go service, HTTP/authentication boundary, WireGuard and BGP lifecycle, container defaults, and persistence/apply paths.

## Executive summary

The project has one critical deployment-to-code exploit chain and four additional issues worth fixing. The most urgent problem is not merely that authentication is optional: the supplied deployment publishes the unauthenticated control plane on all host interfaces, while that control plane can save arbitrary `wg-quick` hook commands and execute them inside a highly privileged container. A reachable default deployment therefore exposes configuration secrets and can become remote command execution.

Fix order:

1. Fail closed and stop publishing the unauthenticated admin port by default.
2. Replace the custom WebAuthn verifier with a maintained implementation.
3. Make WireGuard apply transactional with automatic rollback.
4. Add BGP session authentication or clearly constrain BGP to authenticated overlays.
5. Bound unauthenticated HTTP resource use.

## Findings

### 1. Critical — default exposure can become privileged remote command execution

Evidence:

- Authentication is bypassed whenever `requirePasskey` is false or no passkey exists (`internal/handlers/handlers.go:214-228`). That is the default state.
- The supplied Compose configuration publishes `8080:8080`, which binds the UI to every host interface by default (`compose.yml:17-20`). The README example does the same (`README.md:39-66`), even though its warning says not to expose the UI (`README.md:34-35`).
- The service accepts `PreUp`, `PostUp`, `PreDown`, and `PostDown` directly from the server form (`internal/handlers/server.go:31-55`) and renders them as executable `wg-quick` hooks (`internal/wireguard/wireguard.go:186-219`).
- Any unauthenticated caller can invoke the apply endpoint (`internal/handlers/handlers.go:334-340`), which runs `wg-quick down`/`up` and therefore executes those hooks (`internal/handlers/export.go:81-90`, `internal/wireguard/wireguard.go:61-71`).
- The container is intentionally powerful: `NET_ADMIN`, `SYS_MODULE`, `/dev/net/tun`, host kernel modules, and `systempaths=unconfined` are present in the supplied deployment (`compose.yml:6-24`).
- The same unauthenticated boundary exposes server and client configuration download endpoints, including WireGuard private keys (`internal/handlers/handlers.go:334-339`, `internal/handlers/export.go:19-78`).

Impact: anyone who can reach port 8080 on a fresh/default deployment can steal VPN credentials, replace network configuration, disrupt routing, and execute shell commands in a highly privileged container. Depending on the host/container configuration, that may enable broader host or network compromise.

Recommended fix:

- Make the application fail closed until an administrator completes a secure bootstrap. Do not treat “no passkeys” as authorization for all administrative routes.
- Do not publish the admin port in the default Compose file. Put it on an internal proxy network, or bind it to loopback for host-based proxies.
- Keep reverse-proxy authentication as defense in depth, not the only barrier. Update the stale README statement that the project has no authentication.
- Consider removing editable shell hooks from the UI, or gate them behind a separate explicit opt-in. They turn any control-plane authentication failure into command execution.

### 2. High — the custom WebAuthn verifier omits mandatory security checks

Evidence:

- Registration checks the ceremony type and challenge, but never validates `clientData.origin`, `crossOrigin`, the RP ID hash in the first 32 bytes of authenticator data, the attestation format/statement, or that the outer credential IDs match the attested ID (`internal/auth/webauthn.go:167-264`).
- Login likewise checks type, challenge, user-presence, and signature, but not origin, cross-origin state, or RP ID hash (`internal/auth/webauthn.go:293-400`).
- `getRPID` derives the RP ID from the request `Host` header (`internal/handlers/auth.go:40-52`), and the expected RP ID/origin is not persisted with the challenge or passed into either finish method.
- The stored signature counter is overwritten without rejecting a non-increasing nonzero value (`internal/auth/webauthn.go:346`, `internal/auth/webauthn.go:400-404`).

The WebAuthn Level 3 verification procedures require the relying party to validate the expected origin and RP ID hash during both registration and assertion verification. See the [W3C WebAuthn specification](https://www.w3.org/TR/webauthn-3/#sctn-rp-operations).

Impact: the server is not enforcing WebAuthn’s complete origin/RP binding and clone-detection guarantees. A conforming browser/authenticator blocks many straightforward attacks client-side, but the relying party must not delegate these checks to clients. The omissions are especially dangerous with an untrusted proxy/Host path, a faulty or malicious authenticator/client, or future cross-origin deployment changes.

Recommended fix: replace the hand-written ceremony verifier with a maintained Go WebAuthn library. Configure an explicit trusted RP ID and allowed origin list; bind each challenge to its ceremony type, RP ID, origin, and short-lived server-side session; verify credential ID consistency, authenticator flags, attestation format, and signature-counter semantics. Authentication is the wrong subsystem to maintain as custom parsing and crypto glue.

### 3. High — failed WireGuard apply leaves the interface down with no rollback

Evidence:

- `RestartWGConfig` brings the live interface down before attempting to bring the new file up (`internal/wireguard/wireguard.go:61-71`).
- If `wg-quick up` fails, the function only returns an error; it does not restore the previously working configuration (`internal/wireguard/wireguard.go:68-70`).
- The apply handler reports the failure and returns, leaving recovery to the operator (`internal/handlers/export.go:81-90`).
- Configuration writes replace the on-disk `wg0.conf` before apply, so the previous known-good rendered file is not available to this restart path (`internal/config/config.go:394-449`).

Impact: a hook error, kernel/network failure, invalid external/manual change, or other `wg-quick up` failure can disconnect every peer and remotely lock the operator out. Restarting the container retries the same desired file, so it may remain unavailable.

Recommended fix: retain a known-good applied config separately from the desired config. Preflight the candidate as far as possible, then on failed `up` automatically attempt to restore and start the last-known-good file. Return a joined error that clearly distinguishes candidate failure from rollback failure. Add a test proving the command sequence is `down candidate → up candidate → up previous` when candidate activation fails.

### 4. High when used outside WireGuard/ZeroTier — BGP sessions cannot be authenticated

Evidence:

- Every peer is constructed with an empty authentication key (`internal/bgp/bgp.go:217-245`).
- The managed listener explicitly rejects any non-empty TCP MD5 secret (`internal/bgp/listener.go:121-125`).
- An empty listen address becomes the wildcard IPv6 address (`::`), covering all interfaces (`internal/bgp/bgp.go:155-165`).
- The product supports custom BGP peers not tied to WireGuard, so transport authentication cannot always be delegated to the overlay (`internal/handlers/handlers.go:320-325`).

Impact: on-path or suitably positioned network actors can spoof/reset an unauthenticated configured neighbor and, where import policy permits it, inject routes into the host routing table. WireGuard- or ZeroTier-only BGP sessions inherit overlay protection; custom/LAN peers do not.

Recommended fix: support TCP MD5 (or TCP-AO if the chosen stack can support it) end to end, store the secret as sensitive configuration, and refuse wildcard/plain-network BGP listeners unless the operator explicitly acknowledges the risk. At minimum, document that custom peers require an independently trusted network and firewall the listener to configured peer addresses.

### 5. Medium — unauthenticated HTTP resource use is unbounded

Evidence:

- The service uses `http.ListenAndServe` without `ReadHeaderTimeout`, `ReadTimeout`, `IdleTimeout`, or `MaxHeaderBytes` (`main.go:163-167`). Go documents zero timeout values as unbounded in [`net/http.Server`](https://pkg.go.dev/net/http#Server).
- Login-begin is intentionally unauthenticated (`internal/handlers/handlers.go:231-243`) and every request allocates a challenge in an in-memory map for five minutes (`internal/auth/session.go:112-162`). There is no per-client rate limit or global cap.
- Form and JSON handlers do not wrap bodies with `http.MaxBytesReader` before parsing/decoding (for example `internal/handlers/auth.go:78-84` and `internal/handlers/server.go:31-35`).

Impact: slow headers, many idle connections, oversized bodies, or challenge floods can exhaust connections, memory, or CPU. A reverse proxy can mitigate this only when every path is forced through it.

Recommended fix: instantiate `http.Server` with conservative header and idle timeouts and a header-size limit; keep any write timeout compatible with the 25-second ZeroTier long poll. Cap request bodies per endpoint, rate-limit authentication-begin requests, and bound/prune the challenge store independently of new challenge creation.

## Additional hardening

- Session cookies are `HttpOnly` and `SameSite=Lax` but not `Secure` (`internal/auth/session.go:55-63`). Set `Secure` when the public origin is HTTPS and validate trusted proxy headers explicitly.
- Add CSRF/origin validation for state-changing requests. SameSite cookies are useful defense in depth but are not a complete policy for same-site sibling origins.
- Revoking a passkey does not revoke sessions created with it because sessions are not associated with credential IDs (`internal/auth/session.go:18-110`, `internal/handlers/auth.go:209-260`). Consider revoking all sessions when authentication policy or credentials change.

## Validation performed

- `go test ./...`: passed for all packages.
- `go vet ./...`: passed with no findings.
- Existing Graphify project graph was queried first, then candidate call paths were verified directly in source.
- Race tests could not run in this environment because the installed Go toolchain could not locate its `runtime/race` package.
- `govulncheck` and `golangci-lint` could not produce results because the installed analyzers were built for Go 1.26 while the active toolchain is Go 1.27. Dependency vulnerability status is therefore not claimed by this review.

## Suggested implementation sequence

1. Ship the fail-closed/default-bind fix immediately and document a safe upgrade/bootstrap path.
2. Adopt a maintained WebAuthn library before advertising passkeys as a security boundary.
3. Add known-good rollback to WireGuard apply, with a failure-path unit test.
4. Decide whether custom non-overlay BGP is supported securely; implement authentication or narrow the feature contract.
5. Add HTTP limits and the smaller cookie/session hardening changes.
