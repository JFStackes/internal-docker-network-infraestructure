# ADR-0001: encrypted root custody modes

Status: accepted on 2026-10-16.

## Context

The initial architecture required the private root key to remain offline. The current JFStack installation is a private, single-administrator deployment and the operator explicitly accepts simpler local custody while the deployment is brought into service. Keeping the root in the runtime deployment or mounting it into step-ca would still collapse the root/intermediate separation and would make routine backups and container compromise unnecessarily dangerous.

## Decision

The toolkit supports two custody modes without changing the inventory schema:

1. Offline or removable encrypted custody remains preferred.
2. A central-host encrypted root vault is accepted for a single-administrator private installation when it is stored outside every rendered deployment, owned by root with mode `0700` directories and `0600` files, never mounted into a container, and protected by a password that is entered manually and never stored on the host.

The current local-vault convention is `/opt/private-infra-root/SITE_ID`; the central runtime remains `/opt/private-infra/central`. Deployment preflight and backup/restore continue to reject root private keys inside deployment trees. Root creation and intermediate signing remain explicit, non-idempotent operator actions. Public root import remains pinned by an independently checked SHA-256 fingerprint.

## Consequences

A central-host compromise can copy the encrypted root vault for offline password attack. If the host is compromised while the operator unlocks the root, the root must be considered exposed and rotated. Encryption at rest and separation from containers reduce risk but do not provide the isolation of an offline workstation or HSM.

The root vault is not included in deployment backups. It requires a separate encrypted backup and a separately retained password. Loss of either may prevent future intermediate rotation; loss of both vault copies may make the trust domain unrecoverable.

This mode does not raise version 0.1.0 to production certification and does not make shared or hostile tenancy acceptable.

## Migration trigger

Move the root to offline removable custody or a reviewed HSM/KMS design before any public ingress dependency, mutually untrusted customer, multiple independent administrators, contractual availability/security obligation, or production certification. After migration, remove the online vault only through a reviewed, recoverable procedure and verify the offline backup first.
