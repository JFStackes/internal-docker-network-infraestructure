# Validation record and production gate

Build date: 2026-10-15. Release: 0.1.0. Status: source-level implementation delivered; live deployment acceptance is pending.

## Executed in the build container

- Python automated tests for inventory validation, rendering, access rules, PKI, filesystem protections and operational safeguards.
- Real OpenSSL encrypted-root generation in a separate custody directory, intermediate CSR generation/signing, chain verification, pinned trust and key/certificate mismatch rejection, in disposable temporary directories.
- Real `htpasswd` bcrypt generation and verification during local preparation and stopped AdGuard password-rotation tests.
- Python byte-compilation, repository/documentation consistency and generic/JFStack configuration generation checks.

The final test count and command output are recorded in `tests/BUILD-RESULTS.txt`. Temporary PKI files are not shipped.

## Not executed here

There is no Docker daemon/CLI, reachable WireGuard infrastructure or `age` executable in the artifact build environment. Accordingly, **container image pulls/startup, Docker Compose's own parser, real AdGuard DNS evaluation, step-ca startup, end-to-end ACME issuance/renewal, customer OS/browser trust, encrypted backup/restore roundtrip and actual firewall behavior have not been demonstrated**. Python parsing of YAML is not vendor configuration validation. No remote deployment, public-proxy modification, WireGuard change, vulnerability scan or customer penetration test was performed.

CI includes repository checks and Compose syntax validation when run in its declared GitHub runner environment; that workflow has not been executed by creating this archive. A future green CI run is still not live deployment acceptance.

## OVH central deployment progress (2026-10-16)

The following checks were executed on the intended OVH central host. They are deployment progress, not production acceptance:

- Debian 13.7, Docker Engine 29.7.2, Compose 5.5.0, OpenSSL 3.5.7, `htpasswd` and `iproute2` are present; the rootful Docker daemon is active.
- `wg0` owns the inventory central address `10.77.0.1/24`; the declared node `10.77.0.2` and administrator peer `10.77.0.10` answered ICMP over the VPN.
- No listener was found on `10.77.0.1` TCP/UDP 53, TCP 3000 or TCP 9000. The configured `172.30.40.0/28` central container subnet did not overlap the host routes observed at this check.
- The JFStack private inventory passed schema-v1 validation. Its image tags were resolved to registry manifest digests and pinned in the private, Git-ignored inventory.
- The central deployment rendered to `/opt/private-infra/central`, and Docker Compose 5.5.0 accepted the generated Compose model with `config --quiet`.
- Central preparation created the AdGuard bcrypt credential, encrypted intermediate unlock material and encrypted P-256 intermediate key with mode `0600`. The generated CSR passed OpenSSL self-signature verification with subject `CN=JFStack Private CA Intermediate`.
- Architecture review accepted a separate encrypted central-host root vault for this single-administrator private installation; see ADR-0001. The encrypted root stayed outside deployment/container/backup paths, signed the intermediate and was imported with pinned SHA-256 fingerprint `5f00a28e720d3c2e877e8f78d512b3fb1c8a51592102bb771e902db54f90621b`.
- The first live central startup exposed an image/runtime compatibility defect: both pinned binaries carry a `NET_BIND_SERVICE` file capability and Linux rejected execution after `cap_drop: ALL`. Reproduction isolated the required bounding capability. After a stopped configuration sync, both containers started as UID/GID 10000 with all capabilities dropped except `NET_BIND_SERVICE`, read-only roots, `no-new-privileges`, zero restarts and no OOM event.
- The step-ca image healthcheck initially lacked a CA URL for this custom layout. A second stopped sync installed an argument-list check against the VPN-bound CA URL using the pinned root; step-ca then reported `healthy` with no failing streak.
- Live DNS returned the expected A records for central, node apex and service descendants over UDP and TCP; AAAA, TXT and HTTPS produced NODATA for known private names, while unknown `.internal` names returned NXDOMAIN for all four tested types.
- `ca.internal` returned HTTP 200 on `/health` with TLS 1.3, a verified hostname and a chain to the pinned root. AdGuard returned its authenticated HTTP redirect on `10.77.0.1:3000`.
- The supported AdGuard credential rotation stopped both central containers cleanly, replaced the bcrypt administrator credential without exposing it, passed preflight and restarted with zero restarts. AdGuard again returned its login redirect, the CA health endpoint verified successfully, and central/node/service DNS answers remained correct over UDP and TCP. The new plaintext password was not disclosed to or tested by the validation process; browser sign-in remains an operator check.
- Runtime listeners were limited to `10.77.0.1` TCP/UDP 53, TCP 3000 and TCP 9000; no central wildcard IPv4/IPv6 binding was observed. The iptables backend had IPv4 `FORWARD DROP`, but no central per-peer port rules; production ACL and non-VPN exposure tests remain pending.
- `scripts/check_repository.py` passed and `scripts/test.sh` passed all 58 tests on this host, including bcrypt password replacement and refusal to modify a running central profile.

The central profile is running and locally/VPN-smoke-tested, but this is not production acceptance. Packet-capture DNS-leak evidence, unauthorized-peer and non-VPN exposure tests, CA policy rejection, node ACME issuance/renewal, reboot persistence and restore drills remain pending. `age` was unavailable, so encrypted deployment backup/restore and the separate root-vault backup were not tested.

## Required lab acceptance evidence

| Gate | Evidence to capture |
|---|---|
| Inventory | Correct addresses, unique project IDs, real admin peer, no subnet collisions |
| VPN | Laptop -> central and node; node -> central; central CA container -> node443; correct source/return routes |
| Compose | Vendor `docker compose config --quiet` succeeds for both rendered profiles |
| Containers | All pinned images start as UID10000 with configured restrictions; no unexpected writable paths |
| Existing services | Public Traefik/routes and current WireGuard handshake remain operational |
| DNS | Private A answers; known AAAA/TXT/HTTPS return no public data; unknown .internal NXDOMAIN; TCP and UDP |
| DNS leak | Capture upstream DNS while querying random known/unknown private names and RR types; no private query forwarded |
| Initial PKI | Root pin matches; intermediate key stays central; root key is encrypted and outside deployment/container/backup paths; custody mode and fingerprint are recorded |
| CA policy | An undeclared/foreign name and a wildcard cannot obtain a cert; declared name still requires ALPN proof |
| HTTPS | Trusted root/chain, hostname match, valid lifetime, strict unknown-SNI behavior and no bypass |
| Renewal | Observe a real renewed certificate in an isolated shorter-lifetime lab, preserve account across restarts |
| ACL | Authorized administrator succeeds; unauthorized peer fails; actual client IP visible rather than SNAT |
| External exposure | Without VPN, service ports not reachable even with forced DNS/Host/SNI; test public IPv4/IPv6 and LAN paths |
| Application | Real backend/container reachability; required app auth/proxy-host settings; WebSocket/media/upload behavior |
| Reboot | VPN ready before bindings; central/node survive actual host restarts with existing state |
| Update | Staging change/removed service behaves correctly; stopped sync preserves hashes/keys/state |
| Backup/restore | Real age encryption/decryption, corrupted archive rejection, isolated cold restore, fresh ACME order after recovery |
| Customer onboarding | Separate inventory/root/identity; removing JFStack example has no effect on generic runtime |

Check a failure from a non-VPN network with forced resolution, not just failed DNS: private DNS alone is not isolation. For example, use a controlled test client with the intended hostname and destination public IP, and verify no backend is served. Do not test networks you are not authorized to assess.

## Acceptance levels

**Development/merge:** local tests, repository check, code review and CI syntax checks. **Release/lab:** vendor runtime and integration checks above. **Production:** all applicable gates, documented firewall/source-IP behavior, restore evidence, customer-specific licensing/security review and operator sign-off. Do not call version 0.1.0 certified, hardened against every threat, or universally compatible based on unit tests alone.
