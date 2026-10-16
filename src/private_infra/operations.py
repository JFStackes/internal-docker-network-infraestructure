"""Explicit local lifecycle operations. No SSH, firewall, WireGuard or public proxy changes."""
from __future__ import annotations
import getpass
import json
import os
import re
import secrets
import shutil
import socket
from datetime import datetime, timezone
from pathlib import Path
import yaml
from .model import load_inventory
from .render import PASSWORD_SENTINEL, dump
from .safeio import InfraError, atomic_write, no_symlinks, private_dir, json_read, run, secret_read
from .pki import fingerprint, verify_root


def deployment_info(path: Path) -> tuple[Path, dict, dict]:
    path = no_symlinks(path)
    if (path / 'RESTORE-INCOMPLETE').exists():
        raise InfraError('Incomplete restore marker found; this directory must not be started')
    m = json_read(path / 'deployment.json')
    required = {'schema_version', 'product_version', 'site_id', 'profile', 'node', 'runtime_uid', 'runtime_gid'}
    if not isinstance(m, dict) or set(m) != required or m.get('runtime_uid') != 10000 or m.get('runtime_gid') != 10000:
        raise InfraError('Invalid deployment metadata or runtime identity')
    if m.get('schema_version') != 1 or m.get('profile') not in ('central', 'node'):
        raise InfraError('Not a recognized deployment directory')
    d = load_inventory(path / 'inventory.snapshot.yaml')
    if m.get('site_id') != d['site']['id'] or (m['profile'] == 'node' and m.get('node') not in d['nodes']):
        raise InfraError('Deployment metadata does not match its inventory snapshot')
    return path, m, d


def compose_args(path: Path, action: str) -> list[str]:
    path, m, d = deployment_info(path)
    project = f"private-{d['site']['id']}-" + ('central' if m['profile'] == 'central' else m['node'])
    actions = {'config': ['config', '--quiet'], 'pull': ['pull'],
               'up': ['up', '-d', '--remove-orphans'], 'stop': ['stop'],
               'ps': ['ps'], 'logs': ['logs', '--tail', '150'],
               'running': ['ps', '--status', 'running', '-q']}
    if action not in actions:
        raise InfraError('Unsupported Compose action')
    return ['docker', 'compose', '--project-directory', str(path),
            '--env-file', str(path / '.env'), '-p', project, '-f', str(path / 'compose.yaml')] + actions[action]


def require_stopped(path: Path) -> None:
    if run(compose_args(path, 'running')).stdout.strip():
        raise InfraError('Stop this deployment first. Live config replacement/backup is not allowed.')


def repair_permissions(path: Path) -> None:
    path, m, _ = deployment_info(path)
    # Only paths belonging to this deployment. Refuse symlinks before changing anything.
    members = []
    for directory in ('config', 'state', 'secrets', 'trust', 'pki'):
        root = path / directory
        private_dir(root)
        members += [root, *root.rglob('*')]
    for entry in members:
        no_symlinks(entry)
        if not entry.is_file() and not entry.is_dir():
            raise InfraError('Only regular files and directories are supported in deployment state')
    for entry in members:
        os.chmod(entry, 0o700 if entry.is_dir() else 0o600)
        if os.geteuid() == 0:
            os.chown(entry, m['runtime_uid'], m['runtime_gid'])
    if os.geteuid() != 0:
        print('Permission modes prepared; run permissions as root before Docker deployment (UID/GID 10000).')


def prepare(path: Path, password_file: Path | None = None) -> None:
    path, m, _ = deployment_info(path)
    if m['profile'] == 'central':
        secret = path / 'secrets/intermediate_password'
        if not secret.exists():
            atomic_write(secret, secrets.token_urlsafe(48) + '\n')
        secret_read(secret)
        conf_file = path / 'config/adguard/AdGuardHome.yaml'
        conf = yaml.safe_load(conf_file.read_text())
        hash_file = path / 'secrets/adguard_admin.hash'
        if not hash_file.exists():
            password = secret_read(password_file) if password_file else getpass.getpass('AdGuard admin password (16+ chars): ')
            if not password_file and password != getpass.getpass('Repeat password: '):
                raise InfraError('Passwords do not match')
            if len(password) < 16 or len(password.encode()) > 72 or any(c in password for c in '\r\n\x00'):
                raise InfraError('AdGuard password must be 16+ characters and no more than 72 UTF-8 bytes')
            result = run(['htpasswd', '-niBC', '12', 'admin'],
                         input_data=(password + '\n').encode(), quiet_errors=True)
            hashed = result.stdout.decode().strip().split(':', 1)[1]
            atomic_write(hash_file, hashed + '\n')
        hashed = secret_read(hash_file)
        if not re.fullmatch(r'\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}', hashed):
            raise InfraError('Invalid bcrypt hash')
        conf['users'] = [{'name': 'admin', 'password': hashed}]
        atomic_write(conf_file, dump(conf))
    else:
        acme = path / 'state/traefik/acme.json'
        if not acme.exists():
            atomic_write(acme, '{}\n')
    repair_permissions(path)


def file_checks(path: Path) -> list[str]:
    path, m, d = deployment_info(path)
    errors = []
    for entry in path.rglob('*'):
        if entry.is_symlink():
            errors.append(f'Symlink in deployment: {entry.relative_to(path)}')
    # Root private keys must never be in the online deployment tree.
    for root in ('root_ca.key', 'root.key'):
        if list(path.rglob(root)):
            errors.append('An offline root key was found in the deployment; remove it securely')
    root = path / 'trust/root_ca.crt'
    pin = path / 'trust/root_ca.sha256'
    try:
        verify_root(root, pin.read_text().strip())
    except (InfraError, OSError) as exc:
        errors.append(f'Trust root not ready: {exc}')
    if m['profile'] == 'central':
        required = ['pki/certs/root_ca.crt', 'pki/certs/intermediate_ca.crt',
                    'pki/secrets/intermediate_ca.key', 'secrets/intermediate_password']
        config = yaml.safe_load((path / 'config/adguard/AdGuardHome.yaml').read_text())
        users = config.get('users', [])
        if len(users) != 1 or not users[0].get('password', '').startswith(('$2a$', '$2b$', '$2y$')):
            errors.append('AdGuard authentication is not initialized (run prepare)')
        for relative in required:
            if not (path / relative).is_file():
                errors.append('Missing ' + relative)
        if not errors:
            try:
                from .pki import import_intermediate
                # Validate without rewriting files or requiring a mutation.
                run(['openssl', 'verify', '-CAfile', str(path / 'pki/certs/root_ca.crt'),
                     str(path / 'pki/certs/intermediate_ca.crt')])
                if fingerprint(path / 'pki/certs/root_ca.crt') != fingerprint(root):
                    errors.append('Online PKI root does not match the pinned trust root')
                secret_read(path / 'secrets/intermediate_password')
            except InfraError as exc:
                errors.append(str(exc))
    else:
        acme = path / 'state/traefik/acme.json'
        if not acme.is_file() or acme.stat().st_mode & 0o077:
            errors.append('acme.json missing or not mode 0600/0400')
    for directory in ('config', 'state', 'secrets', 'trust', 'pki'):
        for entry in [path / directory, *(path / directory).rglob('*')]:
            if entry.exists() and (entry.stat().st_uid != 10000 or entry.stat().st_gid != 10000):
                errors.append('Runtime ownership mismatch (run permissions as root)')
                break
    return errors


def preflight(path: Path, host: bool = True) -> list[str]:
    path, m, d = deployment_info(path)
    errors = file_checks(path)
    if not host:
        return errors
    try:
        output = json.loads(run(['ip', '-j', 'addr', 'show', d['vpn']['interface']]).stdout)
        ips = [x['local'] for row in output for x in row.get('addr_info', []) if x.get('family') == 'inet']
        bind = d['central']['vpn_ip'] if m['profile'] == 'central' else d['nodes'][m['node']]['vpn_ip']
        if bind not in ips:
            errors.append(f'Expected bind address {bind} is not assigned to {d["vpn"]["interface"]}')
    except (InfraError, ValueError) as exc:
        errors.append(str(exc))
    try:
        engine = run(['docker', 'version', '--format', '{{.Server.Version}}']).stdout.decode().strip()
        compose_version = run(['docker', 'compose', 'version', '--short']).stdout.decode().strip().lstrip('v')
        if int(engine.split('.')[0]) < 28:
            errors.append('Docker Engine >= 28 is required by the supported baseline')
        if tuple(int(x) for x in compose_version.split('.')[:2]) < (2, 24):
            errors.append('Docker Compose >= 2.24 is required')
        run(compose_args(path, 'config'))
        # Detect public port collisions on clean deployment. Running project is allowed.
        running = run(compose_args(path, 'running')).stdout.strip()
        if not running:
            ports = [(443, socket.SOCK_STREAM)] if m['profile'] == 'node' else [
                (53, socket.SOCK_STREAM), (53, socket.SOCK_DGRAM),
                (d['central']['admin_port'], socket.SOCK_STREAM), (d['central']['ca_port'], socket.SOCK_STREAM)]
            bind = d['central']['vpn_ip'] if m['profile'] == 'central' else d['nodes'][m['node']]['vpn_ip']
            for port, protocol in ports:
                try:
                    with socket.socket(socket.AF_INET, protocol) as sock:
                        sock.bind((bind, port))
                except OSError as exc:
                    errors.append(f'Cannot bind {bind}:{port}: {exc}')
        if m['profile'] == 'node':
            for net in d['nodes'][m['node']]['external_networks']:
                run(['docker', 'network', 'inspect', net])
        else:
            if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '1':
                errors.append('IPv4 forwarding is off; configure the VPN router separately')
    except (InfraError, OSError, ValueError) as exc:
        errors.append(str(exc))
    return errors


def sync_config(deployment: Path, staging: Path, execute: bool) -> list[str]:
    deployment, old, old_inv = deployment_info(deployment)
    staging, new, new_inv = deployment_info(staging)
    for k in ('site_id', 'profile', 'node'):
        if old[k] != new[k]:
            raise InfraError('Staging belongs to a different site/profile/node')
    if old_inv['site'] != new_inv['site'] or old_inv['vpn'] != new_inv['vpn']:
        raise InfraError('Namespace/VPN changes require a migration, not sync-config')
    for k in ('vpn_ip', 'docker_subnet', 'dns_container_ip', 'ca_name', 'ca_port'):
        if old_inv['central'][k] != new_inv['central'][k]:
            raise InfraError('CA/network identity changes require a migration')
    managed = ['compose.yaml', 'inventory.snapshot.yaml', 'deployment.json', 'render-manifest.json']
    managed += [str(p.relative_to(staging)) for p in (staging / 'config').rglob('*') if p.is_file()]
    if not execute:
        return managed
    for base in (deployment / 'config', staging / 'config'):
        for entry in [base, *base.rglob('*')]:
            no_symlinks(entry)
    require_stopped(deployment)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    snapshot = private_dir(deployment / 'config-backups' / stamp)
    shutil.copytree(deployment / 'config', snapshot / 'config')
    for name in ('compose.yaml', 'inventory.snapshot.yaml', 'deployment.json', 'render-manifest.json'):
        shutil.copy2(deployment / name, snapshot / name)
    # No state, secrets, trust, or PKI are copied from a staging render.
    replacement = private_dir(deployment / '.next-config')
    if any(replacement.iterdir()):
        raise InfraError('Previous incomplete .next-config exists; inspect it before retrying')
    shutil.copytree(staging / 'config', replacement, dirs_exist_ok=True)
    if old['profile'] == 'central':
        conf_file = replacement / 'adguard/AdGuardHome.yaml'
        conf = yaml.safe_load(conf_file.read_text())
        conf['users'] = [{'name': 'admin', 'password': secret_read(deployment / 'secrets/adguard_admin.hash')}]
        atomic_write(conf_file, dump(conf))
    # Services are stopped; remove stale routes, not just overwrite existing ones.
    previous = deployment / '.previous-config'
    if previous.exists():
        raise InfraError('Inspect the previous incomplete .previous-config before retrying')
    os.replace(deployment / 'config', previous)
    try:
        os.replace(replacement, deployment / 'config')
    except OSError:
        os.replace(previous, deployment / 'config')
        raise
    shutil.rmtree(previous)
    for name in ('compose.yaml', 'inventory.snapshot.yaml', 'deployment.json', 'render-manifest.json'):
        atomic_write(deployment / name, (staging / name).read_bytes())
    repair_permissions(deployment)
    return managed
