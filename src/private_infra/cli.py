"""CLI: declarative file generation and explicit, local-only operations."""
from __future__ import annotations
import argparse
import getpass
import os
import shlex
import sys
import subprocess
import tarfile
from pathlib import Path
from . import __version__
from . import pki
from .model import load_inventory
from .render import render
from .safeio import InfraError, run, secret_read
from .operations import change_adguard_password, deployment_info, prepare, repair_permissions, preflight, compose_args, sync_config
from .diagnostics import doctor


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='private-infra', description='Private DNS, CA and ingress deployment toolkit')
    p.add_argument('--version', action='version', version=__version__)
    sub = p.add_subparsers(dest='command', required=True)
    def command(name, help_text, deploy=False):
        s = sub.add_parser(name, help=help_text)
        if deploy:
            s.add_argument('--deployment', type=Path, required=True)
        return s
    s = command('validate', 'Validate an inventory; no changes')
    s.add_argument('--inventory', type=Path, required=True)
    s = command('render', 'Generate a new deployment/staging directory; never starts services')
    s.add_argument('--inventory', type=Path, required=True)
    s.add_argument('--profile', choices=('central', 'node'), required=True)
    s.add_argument('--node')
    s.add_argument('--output', type=Path, required=True)
    s = command('prepare', 'Create local secrets/state; never rotates existing keys', True)
    s.add_argument('--admin-password-file', type=Path)
    s = command('admin-password', 'Replace the stopped central AdGuard administrator password', True)
    s.add_argument('--admin-password-file', type=Path)
    command('permissions', 'Repair only this deployment runtime ownership and modes', True)
    s = command('pki-root', 'Create an encrypted root in a protected custody directory')
    s.add_argument('--output', type=Path, required=True)
    s.add_argument('--name', required=True)
    s.add_argument('--password-file', type=Path)
    command('pki-csr', 'Generate the central intermediate key and CSR', True)
    s = command('pki-sign', 'Sign an intermediate CSR from the protected root vault')
    s.add_argument('--root-dir', type=Path, required=True)
    s.add_argument('--csr', type=Path, required=True)
    s.add_argument('--output', type=Path, required=True)
    s.add_argument('--password-file', type=Path)
    s = command('pki-import', 'Verify and install a central intermediate certificate', True)
    s.add_argument('--root', type=Path, required=True)
    s.add_argument('--intermediate', type=Path, required=True)
    s.add_argument('--fingerprint', required=True)
    s = command('trust', 'Import a root ONLY after an out-of-band fingerprint check', True)
    s.add_argument('--root', type=Path, required=True)
    s.add_argument('--fingerprint', required=True)
    s = command('fingerprint', 'Print a public certificate SHA-256 fingerprint')
    s.add_argument('--certificate', type=Path, required=True)
    s = command('preflight', 'Check files, ownership, host VPN IP and Compose availability', True)
    s.add_argument('--files-only', action='store_true')
    s = command('compose', 'Preview an explicit local Compose action; use --execute to run', True)
    s.add_argument('--action', choices=('config', 'pull', 'up', 'stop', 'ps', 'logs'), required=True)
    s.add_argument('--execute', action='store_true')
    s.add_argument('--ack-firewall', action='store_true', help='Required for up: host/VPN firewall reviewed independently')
    s = command('sync-config', 'Replace stopped deployment config from a staging render', True)
    s.add_argument('--staging', type=Path, required=True)
    s.add_argument('--execute', action='store_true')
    s = command('doctor', 'Check live DNS and trusted TLS from an authorized VPN client')
    s.add_argument('--inventory', type=Path, required=True)
    s.add_argument('--root', type=Path, required=True)
    s.add_argument('--node')
    s = command('backup', 'Create a cold, age-encrypted backup; deployment must be stopped', True)
    s.add_argument('--output', type=Path, required=True)
    s.add_argument('--recipient', required=True)
    s.add_argument('--execute', action='store_true')
    s = command('restore', 'Decrypt into a new directory; never starts the restored services')
    s.add_argument('--archive', type=Path, required=True)
    s.add_argument('--identity', type=Path, required=True)
    s.add_argument('--output', type=Path, required=True)
    s.add_argument('--execute', action='store_true')
    return p


def _password(args, confirm=False):
    if args.password_file:
        return secret_read(args.password_file)
    value = getpass.getpass('Root vault password: ')
    if confirm and value != getpass.getpass('Repeat password: '):
        raise InfraError('Passwords do not match')
    return value


def main(argv=None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    try:
        c = args.command
        if c == 'validate':
            load_inventory(args.inventory)
            print('Inventory valid (schema v1).')
        elif c == 'render':
            output = render(load_inventory(args.inventory), args.profile, args.output, args.node)
            print(f'Rendered {args.profile}: {output}\nNo services started; no host or VPN settings changed.')
        elif c == 'prepare':
            prepare(args.deployment, args.admin_password_file)
            print('Local secrets/state prepared. Existing keys were not rotated.')
        elif c == 'admin-password':
            change_adguard_password(args.deployment, args.admin_password_file)
            print('AdGuard administrator password updated. Services remain stopped.')
        elif c == 'permissions':
            repair_permissions(args.deployment)
        elif c == 'pki-root':
            print('ROOT CUSTODY OPERATION. Keep the vault outside deployments; never store its password.')
            print('Root SHA-256:', pki.init_root(args.output, args.name, _password(args, True)))
        elif c == 'pki-csr':
            path, meta, inv = deployment_info(args.deployment)
            if meta['profile'] != 'central':
                raise InfraError('pki-csr only applies to central')
            print('CSR:', pki.intermediate_csr(path, inv['pki']['name'] + ' Intermediate'))
            repair_permissions(path)
        elif c == 'pki-sign':
            print('Root SHA-256:', pki.sign_intermediate(args.root_dir, args.csr, args.output, _password(args)))
        elif c == 'pki-import':
            path, meta, _ = deployment_info(args.deployment)
            if meta['profile'] != 'central':
                raise InfraError('pki-import only applies to central')
            print('Trusted root SHA-256:', pki.import_intermediate(path, args.root, args.intermediate, args.fingerprint))
            repair_permissions(path)
        elif c == 'trust':
            path, _, _ = deployment_info(args.deployment)
            print('Trusted root SHA-256:', pki.import_trust(path, args.root, args.fingerprint))
            repair_permissions(path)
        elif c == 'fingerprint':
            print(pki.fingerprint(args.certificate))
        elif c == 'preflight':
            errors = preflight(args.deployment, host=not args.files_only)
            for message in errors:
                print('FAIL:', message)
            if errors:
                return 1
            print('Preflight passed. Firewall enforcement and end-to-end ACME still need live acceptance.')
        elif c == 'compose':
            cmd = compose_args(args.deployment, args.action)
            print(shlex.join(cmd))
            if args.execute:
                if args.action == 'up':
                    if not args.ack_firewall:
                        raise InfraError('Review host/VPN firewall first; --ack-firewall is required')
                    errors = preflight(args.deployment)
                    if errors:
                        raise InfraError('Preflight failed:\n' + '\n'.join(errors))
                result = run(cmd, timeout=600)
                print(result.stdout.decode(), end='')
                print(result.stderr.decode(), end='', file=sys.stderr)
            else:
                print('Dry run. Add --execute for this local action.')
        elif c == 'sync-config':
            for file in sync_config(args.deployment, args.staging, args.execute):
                print(file)
            print('Applied; services remain stopped.' if args.execute else 'Dry run. No files changed.')
        elif c == 'doctor':
            inv = load_inventory(args.inventory)
            if args.node and args.node not in inv['nodes']:
                raise InfraError('Unknown node')
            good, bad = doctor(inv, args.root, args.node)
            for message in good:
                print('OK:', message)
            for message in bad:
                print('FAIL:', message)
            return int(bool(bad))
        elif c == 'backup':
            if args.execute:
                from .backup import backup
                backup(args.deployment, args.output, args.recipient)
                print('Encrypted cold backup created:', args.output)
            else:
                print('Dry run: stop the deployment, then add --execute to create an encrypted backup.')
        elif c == 'restore':
            if args.execute:
                from .backup import restore
                restore(args.archive, args.identity, args.output)
                print('Restored. Run permissions and preflight; no services started.')
            else:
                print('Dry run: add --execute to decrypt into a NEW directory.')
        return 0
    except (tarfile.TarError, subprocess.SubprocessError):
        print('ERROR: Archive processing or encryption process failed. Do not use a partial restore.', file=sys.stderr)
        return 1
    except (InfraError, OSError, ValueError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Interrupted. No implicit retry or service restart.', file=sys.stderr)
        return 130

if __name__ == '__main__':
    raise SystemExit(main())
