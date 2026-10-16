"""Cold encrypted backups. age is an optional host dependency; no plaintext tar is written."""
from __future__ import annotations
import os
import shutil
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from .safeio import InfraError, no_symlinks, private_dir, atomic_write
from .operations import deployment_info, require_stopped

ALLOWED_TOP = {'config', 'state', 'secrets', 'trust', 'pki', 'compose.yaml',
               'inventory.snapshot.yaml', 'deployment.json', 'render-manifest.json', '.env'}


def safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(path.parts) and not path.is_absolute() and '..' not in path.parts and path.parts[0] in ALLOWED_TOP and path.name not in ('root_ca.key', 'root.key')


def backup(deployment: Path, output: Path, recipient: str) -> None:
    deployment, _, _ = deployment_info(deployment)
    output = no_symlinks(output)
    if output.is_relative_to(deployment):
        raise InfraError('Backup output must be outside the deployment')
    if not recipient.startswith('age1') or not recipient.isalnum():
        raise InfraError('Use an age X25519 public recipient (age1...)')
    if not shutil.which('age'):
        raise InfraError('Install the age executable before creating encrypted backups')
    require_stopped(deployment)
    for path in deployment.rglob('*'):
        no_symlinks(path)
        if path.name in ('root_ca.key', 'root.key'):
            raise InfraError('Offline root keys must not be included in online backups')
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as encrypted:
            process = subprocess.Popen(['age', '--encrypt', '--recipient', recipient], stdin=subprocess.PIPE,
                                       stdout=encrypted, stderr=subprocess.PIPE)
            try:
                with tarfile.open(fileobj=process.stdin, mode='w|gz') as archive:
                    for top in sorted(ALLOWED_TOP):
                        path = deployment / top
                        if path.exists():
                            archive.add(path, arcname=top, recursive=True)
                process.stdin.close()
                process.wait(timeout=300)
                if process.returncode:
                    raise InfraError('age failed; encrypted backup is incomplete')
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
    except Exception:
        output.unlink(missing_ok=True)
        raise


def restore(archive_path: Path, identity: Path, output: Path) -> None:
    archive_path, identity, output = map(no_symlinks, (archive_path, identity, output))
    if not shutil.which('age'):
        raise InfraError('Install the age executable before restoring encrypted backups')
    if identity.stat().st_mode & 0o077:
        raise InfraError('age identity must be mode 0600 or 0400')
    if output.exists() and any(output.iterdir()):
        raise InfraError('Restore requires a new, empty directory')
    private_dir(output)
    marker = output / 'RESTORE-INCOMPLETE'
    atomic_write(marker, 'Do not start this directory until restoration is verified.\n')
    process = subprocess.Popen(['age', '--decrypt', '--identity', str(identity), str(archive_path)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    count, total = 0, 0
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|gz') as archive:
            for entry in archive:
                count += 1
                total += entry.size
                if count > 100000 or total > 4 * 1024 ** 3:
                    raise InfraError('Backup exceeds the v1 safety limit (100000 files / 4 GiB)')
                if not safe_member(entry.name) or not (entry.isfile() or entry.isdir()):
                    raise InfraError('Unsafe archive member (path, link or special file)')
                dest = no_symlinks(output / entry.name)
                if entry.isdir():
                    private_dir(dest)
                    continue
                private_dir(dest.parent)
                if dest.exists():
                    raise InfraError('Duplicate file in archive')
                source = archive.extractfile(entry)
                if source is None:
                    raise InfraError('Unable to read archived file')
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
        # Drain the decrypted stream so age authenticates its final chunk.
        trailing = 0
        while True:
            chunk = process.stdout.read(65536)
            if not chunk:
                break
            trailing += len(chunk)
            if trailing > 1024 * 1024:
                raise InfraError('Unexpected trailing data after the archive')
        process.wait(timeout=30)
        if process.returncode:
            raise InfraError('Decryption failed; do not use the partial restore')
        marker.unlink()
        try:
            deployment_info(output)
        except Exception:
            atomic_write(marker, 'Restored metadata failed validation. Do not start.\n')
            raise
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
