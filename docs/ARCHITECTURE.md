# Architecture freeze - v1

Status: design accepted; implementation 0.1.0 delivered for merge/lab acceptance, not production certification.

## Decisions

One main branch contains independent `central` and `node` profiles. A strict schema-v1 inventory is the single declarative asset for addresses, service backends and access categories. Generated files are reviewable YAML/JSON, not hidden state in a management UI. One command-line toolkit operates locally; it never performs remote SSH writes.

```
Authorized laptop -- existing WireGuard --> central VPN router
                       |                         |
                       | DNS query               +-- AdGuard Home
                       |                         +-- step-ca intermediate / ACME
                       |
                       +-- routed HTTPS --> node VPN IP:443 --> Traefik --> backend
```

DNS and CA are centralized; ingress and certificate keys are per node. HTTPS terminates at that node. The root CA uses protected custody outside every deployment and container. Offline/removable custody is preferred; [ADR-0001](ADR-0001-root-custody.md) accepts a separate encrypted central-host vault for a single-administrator private installation. The central public Traefik is a separate system and its public services stay public. A VPN-only alias does not revoke an existing public domain.

## Identity and naming

Initial roles are administrator and infrastructure. They are IP-based access classes and distinct device/service credentials, not a user directory. WireGuard peer configuration is external. `admin` services accept admin CIDRs; `infrastructure` services accept infrastructure plus admin CIDRs. Application authentication remains enabled.

The DNS namespace is `internal` by default in the JFStack example, or a dedicated subtree such as `customer.internal` for generic use. Node apex and all descendants resolve to its VPN address. ICANN reserved `.internal` against root delegation; this does not automatically install DNS or browser trust.

The source code has no customer keys. Separate customer deployments use different site IDs, inventories, VPN address plans, PKI roots, intermediate keys, ACME state and encrypted backups. Do not claim a shared instance isolates hostile tenants.

## Interfaces

| Source | Destination | Protocol | Reason |
|---|---|---|---|
| VPN peers allowed to resolve | Central VPN IP | TCP/UDP 53 | Private and ordinary DNS |
| Administrator | Central VPN IP | TCP 3000 | AdGuard administration, HTTP inside WireGuard |
| Node ACME clients + administrator | Central VPN IP | TCP 9000 | Private CA HTTPS |
| Approved app clients | Node VPN IP | TCP 443 | Application HTTPS |
| Central CA container | Node VPN IP | TCP 443 | TLS-ALPN-01 proof |
| Node proxy container | Explicit backend | Per inventory | Application upstream |
| AdGuard | Configured upstream resolvers | TCP/UDP 53 | Non-private names only |

No public application ports are added centrally. The node container listens on unprivileged 8443 behind a host 443 mapping. Node port 8082 is only a container-local diagnostic entrypoint. No dashboard is exposed.

## PKI contract

Encrypted P-256 root (10 years) in a separate custody vault, online encrypted P-256 intermediate (3 years), EC256 per-service certificates (default 168 hours). These are defaults, not organizational PKI policy certification. Root and intermediate expiry need independent monitoring. A local central-host vault is never mounted into containers, never included in deployment backups and never stores its password; it is weaker than offline custody.

ACME TLS-ALPN-01 requires step-ca to resolve private names and reach the node TLS endpoint. A dedicated ACME server does not require public DNS or Internet validation. No wildcard certificates: DNS-01 and authoritative DNS updates are out of scope. Traefik trusts the root via `LEGO_CA_CERTIFICATES`; clients import the same public root after fingerprint verification. Its private key is never distributed.

The open-source CA allowlist applies authority-wide. Each declared name must be proven on its routed IP. There is no EAB enrollment or per-account name-policy enforcement in this release. This is sufficient only inside the documented single-administrator trust boundary. Stronger independent-node authorization requires a reviewed enrollment/policy design, not a checkbox. Each customer gets a separate CA.

## Failure and persistence

| Failure | Effect / recovery |
|---|---|
| Central VPN host down | Remote access fails; DNS/CA also unavailable. Distributed proxies do not remove this dependency. |
| Only CA down | Existing node certificates keep serving until expiry. New issuance and renewal fail. |
| Only AdGuard down | New private resolution and CA challenges can fail; cached answers may work temporarily. |
| Node restart | Persistent ACME account/certificates are reused. `prepare` never rotates them. |
| Host boot before wg0 | Private bindings can fail. Arrange host service ordering externally; verify cold boot. |
| Expired intermediate/root | Issuance/trust fails; perform planned rotation, not automatic root replacement. |
| Application backend down | DNS/TLS may remain healthy, but proxy returns gateway failure. |
| Backup restore incomplete | Marker blocks CLI startup; investigate/discard incomplete destination before retry. |
| Central compromised with local root vault | Assume the encrypted vault was copied; if unlocked during compromise, rotate the entire root trust domain. |

## Accepted debt and triggers

Single DNS/CA instance and manual maintenance windows are intentional. Introduce tested redundancy only when availability objectives require it. The accepted central-host root vault is intentional debt for a private, single-administrator installation; migrate to offline custody or a reviewed HSM/KMS design before public dependency, hostile tenancy, independent administrators, contractual security obligations or production certification. Inventory changes restart the affected profile; adding a service updates central CA policy as well as the node. Manual application network attachment is a prerequisite, not application orchestration. Firewall rules are reviewed externally because blindly changing Docker/VPN policy is unsafe.

Image versions are pinned to full tags, with digest input supported. Tags are not immutable supply-chain locks; production promotion should record reviewed digests. The target platform matrix is Linux IPv4/rootful Docker only. An `age` roundtrip and real Docker/ACME integration remain release gates. No claim of ENS/ISO/GDPR compliance is made.

## Delivery boundary

The repository is ready for Git review and lab deployment. Production acceptance requires the evidence in VALIDATION.md, encrypted restore testing and a review of actual source IPs/firewall behavior. Security, PKI and network identity changes need architecture review.
