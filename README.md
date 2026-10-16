# Private Infrastructure

Reusable, configuration-driven private DNS, certificate authority and HTTPS ingress for servers connected through an **existing VPN**. Maintained by JFStack; deployment names, addressing and applications are not tied to JFStack.

[Leer en español](docs/README.es.md)

**Version 0.1.0 - implementation baseline, pending live deployment acceptance.** Local automated checks are included. Docker startup, real DNS behavior, ACME issuance/renewal and firewall enforcement must pass the [acceptance checklist](docs/VALIDATION.md) before production. Nothing is deployed automatically by cloning this repository.

## Architecture

| Deployment profile | Runs | Responsibility |
|---|---|---|
| `central` | AdGuard Home + Smallstep step-ca | Private DNS and an online intermediate CA |
| `node` | Traefik with File Provider | Per-server HTTPS ingress and ACME certificates |
| Outside this project | Existing WireGuard, host firewall, applications | Connectivity, authorization at the network/application layer |

A private name such as `app.node01.client.internal` resolves to the **node's VPN IP**. The browser then connects to that node on TCP 443 through the VPN router. DNS does not proxy HTTP. The central server remains in the remote network path; distributing proxies does not bypass its VPN bandwidth.

There are **no Docker labels, Docker socket mounts or automatic discovery**. One inventory generates DNS rules, CA name policy and each node's centralized `routes.yml`. The public reverse proxy is not modified. Each customer should have a separate VPN trust domain, inventory, CA and state, using the same source code.

## What is included

- Independent central/node Compose templates, deterministic renderer, strict inventory validation and generic/JFStack examples.
- Offline-root/online-intermediate PKI tooling; pinned root import; individual service certificates through ACME TLS-ALPN-01.
- Local lifecycle CLI with explicit execution, preflight, stopped configuration synchronization and live DNS/TLS diagnostics.
- Cold encrypted backup/restore using `age`, with safe extraction and no automatic service start.
- Tests, CI, bilingual entry documentation and deployment/security/recovery runbooks.

No WireGuard installation, firewall editing, remote SSH orchestration, application deployment, user directory, SSO, multi-tenant CA or high-availability cluster is included.

## Requirements

Target baseline: **Debian 12/13 or Ubuntu 24.04 LTS, rootful Linux Docker Engine >= 28, Compose plugin >= 2.24**, Python >= 3.11, OpenSSL 3, `iproute2`, and `htpasswd` (`apache2-utils`). `age` is required only for encrypted backup/restore. This is a target matrix, not a claim of tests on every OS. Rootless Docker, Swarm, Docker Desktop and IPv6 deployment are outside v0.1 support.

The existing VPN must provide peer-to-peer routing, the correct return routes, source-IP preservation and host firewall rules. System time must be correct. Use one unique runtime deployment directory per instance, outside the repository. Runtime containers use UID/GID `10000:10000`; inspect this choice on each host.

## Start with validation and rendering

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
mkdir -p local
cp examples/inventory.example.yaml local/site.yaml
# Edit local/site.yaml for this installation before rendering.
.venv/bin/python bin/private-infra validate --inventory local/site.yaml
.venv/bin/python bin/private-infra render --inventory local/site.yaml \
  --profile central --output /tmp/private-infra-central-preview
.venv/bin/python bin/private-infra render --inventory local/site.yaml \
  --profile node --node node01 --output /tmp/private-infra-node-preview
```

Rendering writes files only, refuses nonempty output, and does not generate keys or start Docker. The root `.env.example` is informational: **inventory YAML is the configuration contract**, not a second source of truth. The generated Compose files contain concrete values.

For the discussed JFStack topology, start from `examples/inventory.jfstack.yaml` instead. It uses `10.77.0.1`, `10.77.0.2`, and `radarr.dust01.internal`. The laptop address is proposed, not an existing peer. qBittorrent and File Browser are disabled until their proxy-container connectivity is configured. Existing public Jellyfin/Seerr exposure remains unchanged.

## Deployment workflow

Follow [DEPLOYMENT](docs/DEPLOYMENT.md) and [PKI](docs/PKI.md), in this order:

1. Verify the existing VPN and firewall independently; render to a protected directory on the target host.
2. `prepare` the central deployment; generate its intermediate CSR. Create/sign with the root on an offline workstation, then import only public certificates using a verified SHA-256 fingerprint.
3. Start the central profile explicitly; validate DNS, private CA health and external exposure.
4. Render/prepare the node, pin the public root, then start Traefik explicitly. Install the public root in trusted client certificate stores.
5. Test initial issuance, renewal, source-IP ACLs and application connectivity before accepting the deployment.

Use `bin/private-infra --help` for all supported commands. `compose`, `sync-config`, `backup` and `restore` preview by default and require `--execute`; `compose --action up` also requires `--ack-firewall`. Rendering, preparing and PKI commands are explicit local writes, not dry runs.

## Configuration and maintenance

Edit the private inventory, validate it, render fresh staging directories and use `sync-config` during a maintenance window. Do not hand-edit generated files or use the AdGuard UI as a second configuration source. Configuration synchronization requires the affected profile stopped, preserves credentials/state, and snapshots the previous configuration. It is not a transactional database migration or automatic image rollback.

A new service needs its node route **and the central CA's exact-name allowlist** updated; the per-node DNS rule already covers it. A new node requires central DNS/CA updates and its own node deployment. No other node or public proxy requires changes. See [CONFIGURATION](docs/CONFIGURATION.md).

## Security boundaries

Only private VPN addresses are used for host bindings. **A private binding is not a firewall policy.** Docker forwarding/NAT and host rules must be reviewed; enabling WireGuard alone does not authorize every peer. The admin HTTP interface defaults to VPN-only TCP 3000 (protected by WireGuard and a bcrypt password), not browser HTTPS; never expose it on a shared/untrusted network. Node application ingress is HTTPS only.

The root key stays offline. The intermediate key, its local unlock secret, ACME accounts and application private keys are sensitive runtime data, excluded from Git. Protect full hosts and encrypted backups as well as file permissions. The root certificate is public but grants trust: verify its fingerprint independently before installing it.

CA policy in this edition is **authority-wide**, restricted to declared service names; TLS-ALPN-01 proves control of each node endpoint. Distinct ACME accounts do **not** implement per-account tenant isolation. Do not mix mutually untrusted customers in one CA. No EAB onboarding or account-specific policy is implemented.

## Development and verification

```bash
.venv/bin/python scripts/check_repository.py
PATH="$PWD/.venv/bin:$PATH" ./scripts/test.sh
```

The tests need OpenSSL and htpasswd, but do not start Docker or contact production. See [VALIDATION](docs/VALIDATION.md) for the actual validation record and outstanding integration tests. The optional GitHub workflow only checks the repository; the same commands work with an internal Git server.

## Documentation

[Architecture](docs/ARCHITECTURE.md) - [Deployment](docs/DEPLOYMENT.md) - [PKI](docs/PKI.md) - [Inventory](docs/CONFIGURATION.md) - [Operations/recovery](docs/OPERATIONS.md) - [Security](SECURITY.md) - [Validation](docs/VALIDATION.md) - [Sources](docs/SOURCES.md).

## License

This delivery is private/proprietary, not an open-source license. See [LICENSE](LICENSE). Third-party dependencies retain their own licenses; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.md). Decide distribution and customer licensing before publishing a public repository.
