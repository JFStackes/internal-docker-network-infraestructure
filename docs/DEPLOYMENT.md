# Deployment runbook

These are **real CLI commands**, but the IPs in the generic example are placeholders for a separate lab. Never copy them into an existing VPN without adapting the inventory. No command here installs WireGuard or edits a firewall.

## 1. Prepare tools and a private inventory

On every target Linux host and the offline PKI workstation, provision Python >=3.11/OpenSSL 3. On target hosts also provide rootful Docker >=28, Compose >=2.24, `iproute2`, `apache2-utils`; install `age` for backups. Docker group membership is effectively host administration; this guide uses explicit sudo instead.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
REPO="$PWD"
mkdir -p local
cp examples/inventory.example.yaml local/site.yaml
chmod 700 local
chmod 600 local/site.yaml
# Edit the inventory. Use inventory.jfstack.yaml only for the described JFStack lab.
.venv/bin/python bin/private-infra validate --inventory local/site.yaml
```

Define a convenience function **on target hosts only** to preserve the virtualenv interpreter under sudo:

```bash
infra() { sudo "$REPO/.venv/bin/python" "$REPO/bin/private-infra" "$@"; }
```

Place the same reviewed private inventory on each relevant host. The public product example is not the production inventory. Use an encrypted channel, not a public gist.

## 2. Network prerequisite gate

Confirm laptop VPN handshake and direct laptop-to-node reachability before this project. Check hub IPv4 forwarding, each peer's AllowedIPs, return routes, interface names, MTU and firewall. Preserve individual source addresses; broad masquerading between VPN peers would invalidate source-IP authorization.

Reserve central UDP/TCP53 and TCP3000/9000 on its VPN IP. Reserve node TCP443 only on its VPN IP. Existing `0.0.0.0:443` on a node conflicts; resolve that explicitly. The central public Traefik can remain on 80/443 because this profile uses neither. Loopback-only systemd-resolved on 127.0.0.53/54 can remain installed.

Verify central Docker subnet does not overlap the VPN, any LAN, existing Docker bridges or routed remote networks. The schema checks overlap with the VPN, not all host routes. Confirm Docker will not break the host's VPN forwarding policy. Review TCP and UDP DNS plus IPv4/IPv6 exposure, despite this deployment using IPv4.

Firewall acceptance must include actual Docker forwarding paths, not just INPUT/UFW. Allow central CA -> node443 for TLS validation independently of the HTTP application IP middleware. ALPN validation occurs before HTTP middleware. Node containers need egress to central DNS53 and CA9000. Proxies must reach their configured upstreams from their own container namespace.

## 3. Render and prepare central

On the central host:

```bash
infra render --inventory "$REPO/local/site.yaml" --profile central \
  --output /opt/private-infra/central
infra prepare --deployment /opt/private-infra/central
infra pki-csr --deployment /opt/private-infra/central
```

`prepare` prompts for the AdGuard administrator password (16+ characters, <=72 UTF-8 bytes), stores a bcrypt hash, and creates the intermediate key unlock secret. It does not launch services. Its files will be owned by runtime UID10000. Use sudo to inspect them; do not relax modes to make casual access easier.

Complete the **offline root ceremony** in [PKI.md](PKI.md). Transfer only the CSR to the offline machine, then root/intermediate public certificates back. Pin the fingerprint obtained independently:

```bash
infra pki-import --deployment /opt/private-infra/central \
  --root /secure-transfer/root_ca.crt \
  --intermediate /secure-transfer/intermediate_ca.crt \
  --fingerprint VERIFIED_ROOT_SHA256
infra preflight --deployment /opt/private-infra/central
infra compose --deployment /opt/private-infra/central --action config --execute
infra compose --deployment /opt/private-infra/central --action pull --execute
infra compose --deployment /opt/private-infra/central --action up --execute --ack-firewall
infra compose --deployment /opt/private-infra/central --action ps --execute
```

`VERIFIED_ROOT_SHA256` is a placeholder to replace, not a literal value. `--ack-firewall` records an operator acknowledgment; it is not an automated firewall audit. Preflight can reject required-version, port, ownership, trust or VPN-address errors; it cannot prove the whole network is safe.

At this stage inspect logs and test DNS/CA health with verified TLS. AdGuard administration is `http://CENTRAL_VPN_IP:3000`, over WireGuard only. The generated configuration is authoritative; use the UI for inspection, not unrecorded edits. AdGuard and the CA run as separate containers on the central bridge. The CA resolves through AdGuard's bridge IP, avoiding a DNS dependency on a missing host name at bootstrap.

## 4. Render and prepare a node

On node01, with its matching inventory:

```bash
infra render --inventory "$REPO/local/site.yaml" --profile node --node node01 \
  --output /opt/private-infra/node01
infra prepare --deployment /opt/private-infra/node01
infra trust --deployment /opt/private-infra/node01 \
  --root /secure-transfer/root_ca.crt --fingerprint VERIFIED_ROOT_SHA256
infra preflight --deployment /opt/private-infra/node01
infra compose --deployment /opt/private-infra/node01 --action pull --execute
infra compose --deployment /opt/private-infra/node01 --action up --execute --ack-firewall
infra compose --deployment /opt/private-infra/node01 --action logs --execute
```

The root is imported **before** starting Traefik; no self-signed-certificate bypass is used. TLS certificates may not be ready immediately on the first startup. Verify issuance in logs and with `doctor`; strict SNI intentionally refuses unknown/unissued names instead of silently trusting a fallback.

The generic backend `http://10.88.0.2:8080` is illustrative. Arrange a real backend or a temporary authorized test application before expecting application success. There is no backend deployed by this repository.

## 5. Client DNS and trust

Only after central DNS is confirmed, set the VPN client's DNS to the central VPN IP. The WireGuard profile must route that IP and the node VPN IPs through the tunnel. OS DNS integration differs; NetworkManager/systemd-resolved and Windows/macOS clients may use different mechanisms. Prevent browser DNS-over-HTTPS/private DNS from bypassing the resolver for internal names. Do not add a public secondary resolver for the private namespace.

Distribute the public root certificate and verified fingerprint to authorized laptops. Install the root in the applicable OS and browser trust stores; never distribute its key. See PKI.md for the trust process. A new laptop needs both a VPN identity and explicit trust installation, not just a URL.

From the authorized laptop (generic example):

```bash
.venv/bin/python bin/private-infra doctor --inventory local/site.yaml \
  --root /secure-transfer/root_ca.crt --node node01
```

Doctor checks DNS, CA health, TLS chain/hostname/expiry and HTTP reachability. It does not inspect WireGuard private keys or replace packet-level firewall/leak checks.

## 6. JFStack-specific adaptation

Use namespace `internal`, central `10.77.0.1`, node `dust01` at `10.77.0.2`. `wire.jfstack.es` remains only the public WireGuard endpoint; the product does not manage its Cloudflare record. The proposed administrator address `10.77.0.10` must actually be assigned to your laptop peer first.

Radarr, Sonarr, Prowlarr, Bazarr, Jellyfin and Seerr have WG host mappings in the example. Verify reachability **from the Traefik container**, not just from the VPS host. qBittorrent currently exposes loopback8081 and File Browser loopback8090; both remain disabled. Later attach the proxy to a suitable external network and enable their named backends. Public Jellyfin/Seerr routes stay untouched; do not remove their WG bindings without separately adapting the public proxy.

## 7. Promotion gate

Run every live acceptance check in VALIDATION.md, including restart/renewal/restore and tests without VPN. Record evidence privately. Only then promote this particular installation to production; uploading the source to Git is not deployment acceptance.
