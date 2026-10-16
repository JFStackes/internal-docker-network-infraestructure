# Security policy and threat model

Report issues privately to the repository owner through the internal Git platform. Do not publish inventories, private keys, ACME files, logs with credentials or customer topology in public issues. No public vulnerability mailbox is fabricated by this template.

## Intended trust boundary

One administrator controls the VPN, central host and nodes in each installation. Infrastructure identities are separate per device/service but initially share this administrative trust domain. Different customers require separate deployments/roots/VPNs. The project is not a security boundary between mutually hostile Docker workloads or tenants.

An Internet attacker should not reach DNS, CA, admin UI or node ingress. An unauthorized VPN peer should not reach protected apps. A compromised rootful Docker host can compromise its containers and keys. A compromised central host always exposes the online intermediate. When the accepted local root-vault mode is used, it can also expose the encrypted root for offline attack; if the root is unlocked during compromise, treat it as exposed. Offline/removable root custody remains the stronger option.

## Implemented controls

Private-address-only publishing, rootless container processes (not a rootless Docker daemon), all capabilities dropped except `NET_BIND_SERVICE` in the central images whose executable file metadata requires it, read-only container root filesystems, bounded tmpfs/logging/resources, no Docker socket, no host networking/privilege, explicit private-file permissions, pinned root import and no TLS verification bypass.

Strict inventory validation rejects duplicate/unknown keys, unsafe input, unrestricted names and common invalid backends. File operations refuse symlink paths. External tools are invoked using argument arrays, not shell interpolation. Secret values are not command arguments; password input uses stdin or protected files. Keys are never silently overwritten. Runtime startup is explicit and guarded by preflight and firewall acknowledgment.

CA names are authority-wide allowlisted and validated through TLS-ALPN-01. No EAB or account-specific authorization is claimed. Individual service certificates reduce cross-service key reuse, but compromising a proxy can expose all keys on that proxy.

## Required deployment controls

Review provider and host firewalls, actual Docker forwarding chains and VPN inter-peer rules. Binding an IP is not an ingress-interface or user ACL. UFW/INPUT alone may not control Docker-published traffic. Handle iptables versus nftables according to the installed Docker backend; this tool never flushes/edits either.

Preserve source IPs between VPN peers. Verify Traefik sees the actual laptop IP; do not authorize an entire Docker subnet as an expedient fix. TLS-ALPN validation must reach node443 before HTTP authorization; application ACLs do not protect the challenge listener. Restrict central CA access to node infrastructure and administrators at the firewall. Restrict central admin3000 to administrator peers, DNS53 to authorized VPN peers and the dedicated container network.

AdGuard administration uses HTTP within the encrypted VPN by default; this is an explicit bootstrap/management exception. Do not expose it to the public Internet, LAN by wildcard binding, or an untrusted VPN user pool. Additional browser-HTTPS management ingress needs a separately reviewed design.

Retain application authentication. Avoid logging full request URLs/tokens. Inspect effective configuration before adding DNS filters, disabling authentication or broadening ranges. Accurate time/NTP, patched hosts, encrypted backups and protected root custody remain operator responsibilities. A local root vault must stay outside deployment trees and container mounts, be root-owned, use an unstored password and have a separate encrypted recovery copy.

## Revocation and limitations

A VPN peer is a network identity, not a human SSO identity. Removing an inventory name blocks future issuance but does not invalidate an already issued certificate. Browser revocation enforcement is not guaranteed; containment, short lifetimes and a tested rotation process matter. Leaf certificates are 7 days by default; the implementation includes no automatic revocation infrastructure or CRL/OCSP distribution service.

No firewall certification, compliance certification, remote penetration test, package vulnerability scan or live ACME test was performed in the build environment. See docs/VALIDATION.md. Container tag pinning is not immutable; pin reviewed digests for promoted deployments. Existing public services remain public until separately reconfigured.
