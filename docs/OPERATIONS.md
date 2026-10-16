# Operations, updates and recovery

Use the `infra` sudo/virtualenv function from DEPLOYMENT.md on target hosts. Keep operational inventory and the deployed source version recorded. Source Git updates do not automatically modify rendered installations.

## Daily checks

Run `doctor` from an authorized VPN client; inspect profile-specific `compose --action ps/logs --execute`, disk usage, DNS health, CA errors and certificate expiry. Verify backups periodically. `doctor` is on demand; no monitoring daemon, cron job or email sender is installed. An external scheduler may call it and alert on nonzero status after deployment acceptance.

Logs are container json-file with size/rotation limits. Query logging, statistics and Traefik access logging are disabled by default to reduce stored user data. Enable extra troubleshooting logs only deliberately and protect them. Do not paste full ACME JSON or signing secrets into tickets.

## Change a forgotten AdGuard password

Changing the generated administrator credential requires a short central maintenance window. The command refuses to modify a running profile, prompts twice without echoing the new password, replaces only the bcrypt credential and leaves services stopped for inspection. It does not reset AdGuard, DNS data, CA state or keys.

```bash
infra compose --deployment /opt/private-infra/central --action stop --execute
infra admin-password --deployment /opt/private-infra/central
infra preflight --deployment /opt/private-infra/central
infra compose --deployment /opt/private-infra/central --action up --execute --ack-firewall
```

Use at least 16 characters and no more than 72 UTF-8 bytes. Do not put the plaintext password in inventory, Git or shell arguments. DNS and CA service are unavailable while central is stopped. After startup, sign in as `admin` at the private AdGuard URL and run the normal DNS/CA health checks.

## Versioned update

1. Record current source version, image references/digests, inventory and runtime health. Review upstream notes and state migration compatibility.
2. Test the new product/images with a separate lab CA and inventory. Run repository tests and live acceptance.
3. Stop only the relevant profile and create a verified encrypted cold backup. Central downtime affects DNS/CA but not the externally managed WireGuard interface.
4. Generate staging with the new source and inventory. `sync-config` requires the deployment stopped, backs up config and preserves runtime data/keys.
5. Run preflight, pull reviewed images, start explicitly, run diagnostics and verify renewal/normalization behavior.

Configuration snapshots under `config-backups/` contain sensitive topology and may include the AdGuard password hash. Keep them protected. They are not backups of the CA database. Rename-based configuration replacement reduces accidental partial writes but does not provide an all-files transaction or schema rollback. If a process/host fails mid-change, stop the deployment and compare the snapshot/metadata before proceeding.

## Cold encrypted backup

Install `age` separately. Generate an age recovery identity on a recovery workstation and store it securely; the backup host normally needs only its public recipient. Do not keep the decryption identity beside the backups. With the deployment stopped:

```bash
infra compose --deployment /opt/private-infra/central --action stop --execute
infra backup --deployment /opt/private-infra/central \
  --output /secure-backups/central-YYYYMMDD.age --recipient age1REPLACE_WITH_RECIPIENT
infra backup --deployment /opt/private-infra/central \
  --output /secure-backups/central-YYYYMMDD.age --recipient age1REPLACE_WITH_RECIPIENT --execute
infra compose --deployment /opt/private-infra/central --action up --execute --ack-firewall
```

Substitute an actual age recipient and unique output filename. The archive streams into age; no plaintext archive is written. Backup includes generated config, intermediate key/secret, CA database and protected state. A node backup includes its ACME accounts/private keys. The root private key is prohibited from deployment backups and requires a separate encrypted custody backup; keep its password separately. Keep external firewall/VPN/application backups independently because they are outside scope.

Cold backup consistency assumes the operator prevents another process from restarting the profile during the backup. The CLI detects running containers before starting; it is not a distributed maintenance lock. Check successful exit and file existence; failure must not be mistaken for a usable backup. Regularly perform a real restore drill, not just checksum the encrypted file.

## Restore into a new destination

On an isolated recovery host with the same reviewed product/images, existing VPN prerequisites and a protected age identity file (0600):

```bash
infra restore --archive /secure-backups/central-YYYYMMDD.age \
  --identity /secure-recovery/age-identity.txt \
  --output /opt/private-infra/central-restored --execute
infra permissions --deployment /opt/private-infra/central-restored
infra preflight --deployment /opt/private-infra/central-restored
```

Restore refuses a nonempty destination and rejects traversal, links, special files and excessive archive size/count. It does not start services. An interrupted/authentication-failed restore leaves `RESTORE-INCOMPLETE`; CLI deployment operations refuse that tree. Investigate it and retry into a new directory; do not remove the marker merely to force startup.

Do not run old and restored instances with the same identity/database simultaneously. Ensure the intended VPN address exists, the previous instance is stopped, and directories are correctly owned before starting the restored profile explicitly. Validate public root fingerprint, DNS, CA health, issuance, existing node trust and normal application access. Record recovery time and data loss, rather than inventing RTO/RPO guarantees.

## Rollback

For configuration-only failure with unchanged compatible state, stop the profile, restore its previous reviewed config/metadata snapshot and permissions, then validate/start. For an image upgrade that changed persistent state, restore the full cold backup with the matching old images/source version. Merely checking out an earlier Git commit does not revert an on-disk CA/AdGuard migration.

Keep namespace/VPN/CA identity changes outside routine sync. Root/intermediate rotation requires PKI.md procedures. Never use `docker compose down -v`, delete acme.json, regenerate a CA or flush a firewall as a generic troubleshooting step.

## Decommission

Disable service issuance/routes through reviewed inventory changes, remove client/network authorization, stop the profile and retain encrypted backups according to the owner's retention policy. Remove root trust from relying devices when an entire installation is retired. Secure deletion on virtual/cloud disks needs provider/storage-level controls; no destructive cleanup command is included.
