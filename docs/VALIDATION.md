# Validation record and production gate

Build date: 2026-10-15. Release: 0.1.0. Status: source-level implementation delivered; live deployment acceptance is pending.

## Executed in the build container

- Python automated tests for inventory validation, rendering, access rules, PKI, filesystem protections and operational safeguards.
- Real OpenSSL encrypted-root generation, intermediate CSR generation, offline signing, chain verification, pinned trust and key/certificate mismatch rejection, in disposable temporary directories.
- Real `htpasswd` bcrypt generation during local preparation tests.
- Python byte-compilation, repository/documentation consistency and generic/JFStack configuration generation checks.

The final test count and command output are recorded in `tests/BUILD-RESULTS.txt`. Temporary PKI files are not shipped.

## Not executed here

There is no Docker daemon/CLI, reachable WireGuard infrastructure or `age` executable in the artifact build environment. Accordingly, **container image pulls/startup, Docker Compose's own parser, real AdGuard DNS evaluation, step-ca startup, end-to-end ACME issuance/renewal, customer OS/browser trust, encrypted backup/restore roundtrip and actual firewall behavior have not been demonstrated**. Python parsing of YAML is not vendor configuration validation. No remote deployment, public-proxy modification, WireGuard change, vulnerability scan or customer penetration test was performed.

CI includes repository checks and Compose syntax validation when run in its declared GitHub runner environment; that workflow has not been executed by creating this archive. A future green CI run is still not live deployment acceptance.

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
| Initial PKI | Root pin matches; intermediate key stays central; no root key on any online host |
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
