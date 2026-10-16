# Repository instructions

## Purpose and architecture

Build a reusable private infrastructure toolkit: central AdGuard Home/step-ca, node Traefik File Provider, existing VPN outside scope. The frozen design is in docs/ARCHITECTURE.md. Version 0.1.0 is not live-production certified.

## Non-negotiable invariants

- One source repository, two independent deployment profiles. Never represent customers/nodes as long-lived Git branches.
- No Docker labels/provider/socket, automatic SSH deployment, WireGuard edits, firewall edits, public-proxy changes or public-domain dependency.
- DNS namespace must be `internal` or a subtree. No arbitrary `.arpa`, `.local`, `.lan`, wildcard CA certificates or TLS-verification bypass.
- Root private keys stay outside deployment trees, containers, Git and routine deployment backups. Offline/removable encrypted custody is preferred; an encrypted central-host vault outside the deployment is accepted only for a single-administrator private installation, with a manually entered password that is never stored. Pin public root imports by SHA-256; never silently replace a root or key.
- Runtime files and secrets live outside Git. Do not generate keys into the source tree. Do not print passwords, PEM keys, ACME JSON or intermediate unlock secrets.
- Explicit execution for service lifecycle. Dry run by default for compose/sync/backup/restore. Never `down -v`, auto-reset CA, flush firewall or delete user data.
- Tenant/customer isolation is a separate deployment/CA/VPN, not an unimplemented account policy. Describe implemented security, not aspirations.
- Generated config has one declarative source: inventory. Add a parameter only when its validation, renderer, examples, tests and documentation agree.

## Structure

`src/private_infra/` contains the CLI, schema validator, deterministic renderer, PKI, local operations, diagnostics and encrypted backup. `central/` and `node/` are renderer templates, not directly runnable Compose files. `examples/` contains synthetic/documented topology, never credentials. `tests/` does not require external services.

## Commands

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/check_repository.py
PATH="$PWD/.venv/bin:$PATH" ./scripts/test.sh
.venv/bin/python bin/private-infra --help
```

Run OpenSSL/htpasswd-backed tests rather than replacing them with mocks. New file mutations must reject symlinks and preserve secure permissions. Use subprocess argument lists, never a shell. Network/timeouts and external process errors must be bounded. Add tests for destructive-operation refusal paths and idempotence.

## Documentation and delivery

Root README.md is English with `[Leer en espanol]` rendered with the correct Spanish accent in its actual link text, pointing to docs/README.es.md. The Spanish counterpart must be complete and synchronized, with a reciprocal Read in English link to the root README. AGENTS stays English. Do not translate code identifiers.

Update the validation record with checks actually executed, and separately record tests blocked by missing Docker/VPN/age. Do not convert a local test pass into a production claim. Review dependency versions against official sources, pin full image versions/digests and full workflow action commit hashes. No automatic version/tag/release changes without an explicit request. Preserve proprietary license until the owner decides otherwise.

## Changes requiring architectural review

Namespace/CA identity changes, PKI lifetime/policy changes, image major upgrades, state migrations, public bindings, multi-tenant use, non-VPN ingress, secrets storage, rootless/IPv6 support or automatic remote deployment.
