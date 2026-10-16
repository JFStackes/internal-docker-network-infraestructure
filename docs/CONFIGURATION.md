# Inventory schema and generated configuration

The input is schema-v1 YAML. Duplicate keys and unknown fields are errors. Do not add passwords, private keys or shell fragments. Inventory is topology-sensitive even though it is not a credential; keep effective customer inventories in private operational storage.

## Contract

| Field | Meaning |
|---|---|
| `site.id` | Stable lowercase installation identifier used in Compose project names |
| `site.name` | Human-readable installation name |
| `site.namespace` | `internal` or a DNS subtree ending `.internal` |
| `vpn.network`, `vpn.interface` | Existing RFC1918 IPv4 VPN network and interface |
| `central.vpn_ip` | Existing central address, never configured by the tool |
| `central.docker_subnet` | Explicit private /24..../28 bridge subnet, disjoint from VPN and actual host networks |
| `central.dns_container_ip` | Reserved address inside that bridge for AdGuard |
| `central.dns_name`, `central.ca_name` | Unique names inside the chosen namespace |
| `central.admin_port`, `central.ca_port` | Host VPN-only ports, defaults 3000 and 9000 |
| `central.upstream_dns` | IPv4 upstream resolver addresses; no credentialed URLs/DoH bootstrap in v0.1 |
| `pki.name`, `pki.email` | CA display name (3..64 safe ASCII characters) and ACME contact value; replace example `.invalid` email |
| `pki.certificate_hours` | Leaf default/max lifetime and matching Traefik renewal horizon |
| `access.admin_cidrs` | Authorized administrator VPN source ranges |
| `access.infrastructure_cidrs` | Infrastructure VPN source ranges |
| `nodes.<id>.vpn_ip` | Existing unique node VPN address |
| `nodes.<id>.external_networks` | Optional existing Docker networks joined by its proxy |
| `nodes.<id>.services.<id>.enabled` | Include/exclude its route and CA allowlist entry |
| `...backend` | Root HTTP(S) URL reachable from the proxy container |
| `...access` | `admin` or `infrastructure` (the latter includes admins) |
| `...description` | Optional human note, not an executed template |
| `images.*` | Full reviewed version tags or immutable sha256 digests |

The node identifier `central` is reserved to prevent Compose project collisions. The validator rejects duplicate IPs/names, broad/public ACLs, localhost backend addresses, URL credentials, queries/fragments and path-prefix backends. External network aliases are allowed. HTTPS upstreams keep certificate verification enabled; private upstream roots use the installed CA. Subpath rewrites, mTLS upstreams and service-specific header injection are not implemented in v0.1.

A service hostname is synthesized as `<service>.<node>.<namespace>`. A node may have no enabled services, but the site needs at least one enabled service for its CA allowlist. There is no automatic public certificate or Cloudflare integration.

## Files generated per profile

Central: fully rendered `compose.yaml`, `config/adguard/AdGuardHome.yaml`, `config/step-ca/ca.json`, `server.tpl`, metadata and empty protected runtime directories.

Node: fully rendered `compose.yaml`, `config/traefik/traefik.yml`, one centralized `config/traefik/dynamic/routes.yml`, metadata and protected runtime directories. Separate enabled service blocks remain readable in that one file; no application Compose labels are needed.

Each output includes `inventory.snapshot.yaml`, `deployment.json` and `render-manifest.json`. The manifest describes the original render, not a cryptographic signature or the subsequent prepared/AdGuard-normalized runtime configuration. `prepare` intentionally changes the admin hash and state; AdGuard may normalize its own config. Do not treat manifest differences as automatically malicious.

## Add a service

Add an enabled service to the private inventory, validate, and generate fresh central/node staging directories. Use the exact same updated inventory for both:

```bash
.venv/bin/python bin/private-infra validate --inventory local/site.yaml
.venv/bin/python bin/private-infra render --inventory local/site.yaml \
  --profile central --output /tmp/central-next
.venv/bin/python bin/private-infra render --inventory local/site.yaml \
  --profile node --node node01 --output /tmp/node01-next
```

Transfer each staging directory to its matching host securely, or render there. Stop only the affected profile, then apply explicitly using the `infra` function defined in DEPLOYMENT.md:

```bash
infra compose --deployment /opt/private-infra/central --action stop --execute
infra sync-config --deployment /opt/private-infra/central --staging /tmp/central-next
infra sync-config --deployment /opt/private-infra/central --staging /tmp/central-next --execute
infra compose --deployment /opt/private-infra/central --action up --execute --ack-firewall
```

Repeat for `/opt/private-infra/node01` with `/tmp/node01-next`. Apply central first so the exact certificate name is authorized before the node requests it. The central restart temporarily interrupts DNS/CA, not WireGuard. The node restart temporarily interrupts its private applications; schedule a maintenance window. Existing application containers/public proxy are not changed.

There is intentionally no fictional `add-service.sh`: the implemented method is inventory -> validation -> staging render -> explicit sync. The directory replacement removes obsolete routes; it never imports staging secrets or resets state. Direct manual edits are not preserved. Staging reuse is not allowed for a new render; create a new empty directory.

## Add a node

Provision and validate its WireGuard peer outside this project. Add its unique name/IP, optional network attachments and services to the inventory. Update central DNS/CA, then render/install a new node profile. Trust the existing public root by fingerprint; do not create a new root per node. Other nodes need no route changes. A separate customer is different: create a separate installation and root, not just another node here.

## DNS behavior

Per-node suffix rules resolve its apex and descendants to its VPN IPv4 address. Known names have A answers and no AAAA/HTTPS/TXT data from this private rule unless explicitly supported; unknown `.internal` queries should be answered NXDOMAIN locally. Central names map to central VPN IP. The generated syntax uses `dnsrewrite` with `denyallow` exceptions so NXDOMAIN does not override positive entries.

No catch-all for `.arpa` is created. The generated node PTR records use reverse DNS zones legitimately. Ordinary non-private queries go to the configured upstreams. Live validation must test A/AAAA/TXT/HTTPS and inspect upstream traffic; a text-level unit test cannot prove the runtime resolver never leaks a query.

## Backend reachability

`127.0.0.1` inside Traefik is the proxy container, not the host; therefore loopback backends are rejected. Use an explicitly reachable WireGuard host mapping or a shared Docker network alias. Adding a network attachment is opt-in through `external_networks`, which preflight checks for existence. The tool does not attach application containers or weaken their isolation.

For applications behind proxies, review their trusted-proxy/allowed-host/CSRF/URL settings using their own documentation. Do not globally disable those controls to hide a 403 or host-header error.
