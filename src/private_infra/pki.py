"""Offline-root / online-intermediate PKI, using the host OpenSSL executable."""
from __future__ import annotations
import hashlib
import os
import re
import secrets
from pathlib import Path
from .safeio import InfraError, no_symlinks, private_dir, atomic_write, secret_read, run


def _name(name: str) -> str:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{2,79}', name):
        raise InfraError('CA names must be 3..80 ASCII letters, digits, spaces, dots, underscores or hyphens')
    return name


def fingerprint(cert: Path) -> str:
    der = run(['openssl', 'x509', '-in', str(no_symlinks(cert)), '-outform', 'DER']).stdout
    return hashlib.sha256(der).hexdigest()


def verify_root(cert: Path, expected: str) -> str:
    expected = expected.replace(':', '').lower()
    if not re.fullmatch('[0-9a-f]{64}', expected):
        raise InfraError('Expected root fingerprint must be SHA-256 (64 hexadecimal characters)')
    actual = fingerprint(cert)
    if not secrets.compare_digest(actual, expected):
        raise InfraError('Root fingerprint mismatch. Do not import this certificate.')
    run(['openssl', 'verify', '-check_ss_sig', '-CAfile', str(cert), str(cert)])
    ext = run(['openssl', 'x509', '-in', str(cert), '-noout', '-ext', 'basicConstraints']).stdout
    if b'CA:TRUE' not in ext:
        raise InfraError('Trust anchor is not a CA certificate')
    identity = run(['openssl', 'x509', '-in', str(cert), '-noout', '-subject', '-issuer', '-nameopt', 'RFC2253']).stdout.decode().splitlines()
    if len(identity) != 2 or identity[0].split('=', 1)[1] != identity[1].split('=', 1)[1]:
        raise InfraError('Trust anchor must be a self-issued root')
    return actual


def _new_key(path: Path, password: str) -> None:
    if len(password) < 16:
        raise InfraError('PKI passwords must have at least 16 characters')
    if path.exists():
        raise InfraError(f'Refusing to replace private key: {path}')
    atomic_write(path, '')
    run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
         '-aes-256-cbc', '-pass', 'stdin', '-out', str(path)],
        input_data=(password + '\n').encode(), quiet_errors=True)
    os.chmod(path, 0o600)


def init_root(output: Path, name: str, password: str) -> str:
    """Create an encrypted root in a separately protected custody directory."""
    name = _name(name)
    output = no_symlinks(output)
    if output.exists() and any(output.iterdir()):
        raise InfraError('Root custody directory must be empty; existing roots are never replaced')
    private_dir(output)
    key, cert = output / 'root_ca.key', output / 'root_ca.crt'
    _new_key(key, password)
    atomic_write(cert, '')
    run(['openssl', 'req', '-new', '-x509', '-sha256', '-key', str(key), '-passin', 'stdin',
         '-out', str(cert), '-days', '3650', '-subj', '/CN=' + name,
         '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:1',
         '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
         '-addext', 'subjectKeyIdentifier=hash'], input_data=(password + '\n').encode(), quiet_errors=True)
    fp = fingerprint(cert)
    atomic_write(output / 'root_ca.sha256', fp + '\n')
    atomic_write(output / 'ROOT-CUSTODY.txt',
        'Keep this directory separate from every deployment and never mount it into a container.\n'
        'Offline or removable encrypted custody is preferred. A local online vault has a weaker trust boundary.\n'
        'The password is NOT stored here. Back up the encrypted root and password separately.\n')
    return fp


def intermediate_csr(deployment: Path, name: str) -> Path:
    name = _name(name)
    key = deployment / 'pki/secrets/intermediate_ca.key'
    csr = deployment / 'pki/intermediate_ca.csr'
    if csr.exists() or key.exists():
        raise InfraError('Intermediate already prepared; automatic key rotation is forbidden')
    password = secret_read(deployment / 'secrets/intermediate_password')
    _new_key(key, password)
    atomic_write(csr, '')
    run(['openssl', 'req', '-new', '-sha256', '-key', str(key), '-passin', 'stdin',
         '-out', str(csr), '-subj', '/CN=' + name],
        input_data=(password + '\n').encode(), quiet_errors=True)
    return csr


def sign_intermediate(root_dir: Path, csr: Path, output: Path, password: str) -> str:
    """The CSR is public; the intermediate private key stays on the central host."""
    root_dir, csr, output = map(no_symlinks, (root_dir, csr, output))
    if output.exists() and any(output.iterdir()):
        raise InfraError('Signed-certificate output must be empty')
    run(['openssl', 'req', '-in', str(csr), '-noout', '-verify'])
    private_dir(output)
    ext = output / 'intermediate.extensions'
    atomic_write(ext, 'basicConstraints=critical,CA:TRUE,pathlen:0\n'
                     'keyUsage=critical,keyCertSign,cRLSign\n'
                     'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
    cert = output / 'intermediate_ca.crt'
    atomic_write(cert, '')
    run(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(root_dir / 'root_ca.crt'),
         '-CAkey', str(root_dir / 'root_ca.key'), '-passin', 'stdin',
         '-out', str(cert), '-days', '1095', '-sha256', '-set_serial', '0x' + secrets.token_hex(19),
         '-extfile', str(ext)], input_data=(password + '\n').encode(), quiet_errors=True)
    run(['openssl', 'verify', '-CAfile', str(root_dir / 'root_ca.crt'), str(cert)])
    atomic_write(output / 'root_ca.crt', (root_dir / 'root_ca.crt').read_bytes())
    fp = fingerprint(output / 'root_ca.crt')
    atomic_write(output / 'root_ca.sha256', fp + '\n')
    return fp


def import_trust(deployment: Path, root: Path, expected: str) -> str:
    root = no_symlinks(root)
    fp = verify_root(root, expected)
    dest = deployment / 'trust/root_ca.crt'
    if dest.exists() and fingerprint(dest) != fp:
        raise InfraError('A different root is already installed. Follow the CA rotation runbook.')
    atomic_write(dest, root.read_bytes())
    atomic_write(deployment / 'trust/root_ca.sha256', fp + '\n')
    return fp


def import_intermediate(deployment: Path, root: Path, cert: Path, expected: str) -> str:
    root, cert = map(no_symlinks, (root, cert))
    fp = verify_root(root, expected)
    dest = deployment / 'pki/certs/intermediate_ca.crt'
    if dest.exists() and fingerprint(dest) != fingerprint(cert):
        raise InfraError('Intermediate rotation requires a maintenance procedure; refusing overwrite')
    run(['openssl', 'verify', '-CAfile', str(root), str(cert)])
    constraints = run(['openssl', 'x509', '-in', str(cert), '-noout', '-ext', 'basicConstraints']).stdout
    if b'CA:TRUE, pathlen:0' not in constraints:
        raise InfraError('Intermediate must be a CA with pathlen:0')
    password = secret_read(deployment / 'secrets/intermediate_password')
    private_pub = run(['openssl', 'pkey', '-in', str(deployment / 'pki/secrets/intermediate_ca.key'),
                       '-passin', 'stdin', '-pubout'], input_data=(password + '\n').encode(), quiet_errors=True).stdout
    cert_pub = run(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout']).stdout
    if private_pub.strip() != cert_pub.strip():
        raise InfraError('Intermediate certificate does not match this host private key')
    import_trust(deployment, root, expected)
    atomic_write(deployment / 'pki/certs/root_ca.crt', root.read_bytes())
    atomic_write(dest, cert.read_bytes())
    return fp
