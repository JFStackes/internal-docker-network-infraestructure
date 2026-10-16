# Private PKI and trust

## Key placement and defaults

| Material | Where | Sensitivity |
|---|---|---|
| Root private key | Encrypted offline storage only | Highest; never online/Git |
| Root certificate + SHA-256 fingerprint | Offline master, central, nodes, approved clients | Public, integrity-critical |
| Intermediate private key | Central runtime PKI directory | Sensitive, encrypted at rest |
| Intermediate unlock secret | Central protected secrets directory | Sensitive; host compromise can access both |
| Intermediate certificate | Central, delivered in certificate chains | Public |
| ACME account and leaf private keys | Each node's persistent acme.json | Sensitive, never copied to other nodes |

Default validity is 3650 days for the root, 1095 days for the intermediate, and 168 hours for application certificates. This does not implement HSM protection, offline intermediate signing or an enterprise revocation distribution system. The online unlock secret means encryption is not protection against root on the central host. Keep systems patched and backups encrypted.

## Offline root ceremony

On an offline workstation, with the toolkit and dependencies installed beforehand:

```bash
.venv/bin/python bin/private-infra pki-root \
  --output /encrypted-offline/private-infra-root --name "Example Private Root CA"
```

Choose and separately retain a strong password. Record the printed SHA-256 fingerprint through an independent channel. The command creates `root_ca.key`, `root_ca.crt`, `root_ca.sha256`; it never stores the root password. It refuses a nonempty output directory. The code warns about offline operation but cannot prove the machine is disconnected.

On the central host, `prepare` and `pki-csr` create the intermediate encrypted key locally and output a **public CSR** at `pki/intermediate_ca.csr`. Transfer that CSR to the offline workstation. Its private key must remain centrally.

On the offline workstation:

```bash
.venv/bin/python bin/private-infra pki-sign \
  --root-dir /encrypted-offline/private-infra-root \
  --csr /secure-transfer/intermediate_ca.csr \
  --output /secure-transfer/signed-central
```

Review which customer/site you are signing. Keep separate root directories for different trust domains. Transfer only `root_ca.crt`, `intermediate_ca.crt` and the independently verified fingerprint back to the central host. Never copy the entire offline directory. Import with the commands in DEPLOYMENT.md; the importer verifies fingerprint, chain, CA constraints and private/public key match.

## ACME lifecycle

The directory is `https://CA_NAME:CA_PORT/acme/internal/directory`. The node trusts the root via `LEGO_CA_CERTIFICATES`. step-ca queries AdGuard for the requested name and opens TCP443 to that node using TLS-ALPN-01. The challenge responder is handled at TLS level, before the application's HTTP IP allowlist. Therefore central-to-node443 must be allowed even when central is not an application administrator.

Only exact enabled inventory hostnames are permitted; wildcard issuance is disabled. Distinct nodes keep independent ACME accounts, but OSS authority-wide policy is not per-account RBAC. TLS validation proves endpoint control, not a personal user's identity. Nodes share one trusted administration boundary; different customers must not share it.

Traefik `certificatesDuration` is aligned with the CA's configured duration so renewal scheduling is appropriate. It does not itself force the CA's issued lifetime. step-ca legacy `/renew` is disabled in this configuration; ACME clients renew through fresh ACME orders. Test that behavior with the pinned versions before production.

## Install root trust on clients

Verify the root fingerprint out of band first. The toolkit `trust` command only installs trust for a deployment container, **not the laptop OS**. Install the public root certificate manually into the appropriate OS trusted root store under administrator control. On Debian/Ubuntu this generally means a `.crt` file under `/usr/local/share/ca-certificates/` followed by `update-ca-certificates`; on Windows import into Trusted Root Certification Authorities; on macOS use the applicable Keychain trust settings. Browser/mobile stores and enterprise management may differ; verify the actual target client rather than assuming automatic inheritance.

Do not distribute intermediate/leaf certificates as universal trusted roots. Do not bypass warnings or set insecure TLS options. Track which devices trust the root; remove that trust when access is revoked or the trust domain is retired. VPN authorization and root trust are separate controls.

## Renewal acceptance and monitoring

Use a separate lab CA/inventory and shorter allowed leaf lifetime (minimum supported inventory value applies) to observe a real renewal; do not reduce production lifetimes blindly. Record certificate serial/notBefore/notAfter before and after renewal, verify trust remains intact, then restart node and central independently. Never delete a production acme.json merely to simulate renewal. Initial issuance is not evidence of renewal.

Monitor leaf expiry and issuance failures, plus intermediate/root expiry. `doctor` warns/fails when a leaf has less than 24 hours remaining. This release provides an on-demand command, not an installed scheduler/alert service. Long CA outages will eventually expire leaf certificates, even though already issued certificates initially continue to work.

## Rotation and compromise

Root/intermediate replacement is deliberately not automated. Take a verified cold encrypted backup, freeze configuration changes and plan a maintenance window. For a routine intermediate renewal, retain the trust root, create/review a new intermediate key/CSR and distribute the signed intermediate by an operator-controlled migration. Current import refuses overwriting a different intermediate; do not bypass this without a reviewed change.

For root rotation, distribute a new public root to every relying client before issuing new service chains. Maintain an overlap plan where supported, verify all clients and then retire old trust. This version's one-root deployment model does not automate dual-root rollout.

For a compromised node, remove/disable its VPN access and services, revoke/replace affected credentials and rebuild its ACME state through a reviewed procedure. Removing a hostname from CA policy blocks future issuance but does not erase an already issued certificate. Revocation checking is not guaranteed in every browser; use short lifetimes, network containment and emergency root/intermediate procedures proportionately.

For central compromise, assume the intermediate key and local unlock secret are both exposed. Isolate it, perform incident response and decide whether replacement of the intermediate or entire root trust is required. Restore from backup only after establishing trustworthy hosts and credentials.
