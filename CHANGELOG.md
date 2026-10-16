# Changelog

## Unreleased

- Added an explicitly reviewed encrypted central-host root-vault custody mode for single-administrator private installations. Offline/removable custody remains preferred; root keys remain forbidden from deployment trees, containers and deployment backups.
- Added a stopped-profile AdGuard administrator password rotation command with bcrypt verification and refusal tests.
- Fixed the pinned central images' `NET_BIND_SERVICE` capability requirement and replaced step-ca's incompatible image healthcheck with a pinned-root health probe.

## 0.1.0 - 2026-10-15

Initial implementation of the agreed private infrastructure design: central AdGuard/step-ca, per-node Traefik File Provider, schema-v1 declarative inventory, offline-root PKI ceremony, explicit local lifecycle CLI, diagnostics, cold encrypted backup/restore, automated tests and deployment runbooks.

No existing infrastructure was migrated or deployed. Initial delivery targets source review and lab acceptance; Docker/ACME/VPN/age integration requires the documented live gates. WireGuard, firewall and public Traefik remain outside scope.
