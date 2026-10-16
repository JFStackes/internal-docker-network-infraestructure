import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import yaml
from private_infra.model import load_inventory
from private_infra.render import render
from private_infra.operations import change_adguard_password, prepare, file_checks, repair_permissions
from private_infra.safeio import atomic_write, InfraError, run
from private_infra import pki

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which('openssl') and shutil.which('htpasswd'), 'OpenSSL and htpasswd required')
class PKITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temp.name)
        cls.inv = load_inventory(ROOT / 'examples/inventory.example.yaml')
        cls.central = render(cls.inv, 'central', cls.base / 'central')
        cls.password_file = cls.base / 'test-password'
        atomic_write(cls.password_file, 'temporary-test-password-ONLY-1234\n')
        prepare(cls.central, cls.password_file)
        cls.root = cls.base / 'root-vault'
        cls.fp = pki.init_root(cls.root, 'Integration Test Root', 'offline-test-password-ONLY-4567')
        cls.csr = pki.intermediate_csr(cls.central, 'Integration Test Intermediate')
        cls.signed = cls.base / 'signed'
        pki.sign_intermediate(cls.root, cls.csr, cls.signed, 'offline-test-password-ONLY-4567')
        pki.import_intermediate(cls.central, cls.signed / 'root_ca.crt',
                                cls.signed / 'intermediate_ca.crt', cls.fp)
        repair_permissions(cls.central)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_root_is_encrypted_and_outside_deployment(self):
        data = (self.root / 'root_ca.key').read_text()
        self.assertIn('ENCRYPTED PRIVATE KEY', data)
        self.assertFalse(any(self.central.rglob('root_ca.key')))
        self.assertTrue((self.root / 'ROOT-CUSTODY.txt').is_file())

    def test_intermediate_is_encrypted_and_matches_certificate(self):
        key = self.central / 'pki/secrets/intermediate_ca.key'
        self.assertIn('ENCRYPTED PRIVATE KEY', key.read_text())
        result = run(['openssl', 'verify', '-CAfile', str(self.root / 'root_ca.crt'),
                      str(self.central / 'pki/certs/intermediate_ca.crt')])
        self.assertIn(b'OK', result.stdout)

    def test_wrong_fingerprint_is_rejected(self):
        with self.assertRaisesRegex(InfraError, 'mismatch'):
            pki.verify_root(self.root / 'root_ca.crt', '0' * 64)

    def test_existing_root_not_overwritten(self):
        with self.assertRaises(InfraError):
            pki.init_root(self.root, 'Another Root', 'long-test-password-never-used')

    def test_existing_intermediate_not_overwritten(self):
        with self.assertRaises(InfraError):
            pki.intermediate_csr(self.central, 'Another Intermediate')

    def test_prepare_does_not_rotate_existing_secrets(self):
        before_key = (self.central / 'pki/secrets/intermediate_ca.key').read_bytes()
        before_password = (self.central / 'secrets/intermediate_password').read_bytes()
        before_hash = (self.central / 'secrets/adguard_admin.hash').read_bytes()
        prepare(self.central, self.password_file)
        self.assertEqual(before_key, (self.central / 'pki/secrets/intermediate_ca.key').read_bytes())
        self.assertEqual(before_password, (self.central / 'secrets/intermediate_password').read_bytes())
        self.assertEqual(before_hash, (self.central / 'secrets/adguard_admin.hash').read_bytes())

    def test_adguard_password_rotation_updates_hash_and_config(self):
        password_file = self.base / 'replacement-password'
        password = 'replacement-test-password-ONLY-7890'
        atomic_write(password_file, password + '\n')
        with patch('private_infra.operations.require_stopped'):
            change_adguard_password(self.central, password_file)
        hashed = (self.central / 'secrets/adguard_admin.hash').read_text().strip()
        config = yaml.safe_load((self.central / 'config/adguard/AdGuardHome.yaml').read_text())
        self.assertEqual(config['users'], [{'name': 'admin', 'password': hashed}])
        verification = self.base / 'adguard-users'
        atomic_write(verification, 'admin:' + hashed + '\n')
        result = run(['htpasswd', '-vi', str(verification), 'admin'],
                     input_data=(password + '\n').encode(), quiet_errors=True)
        self.assertIn(b'correct', result.stdout + result.stderr)
        with self.assertRaises(InfraError):
            run(['htpasswd', '-vi', str(verification), 'admin'],
                input_data=b'temporary-test-password-ONLY-1234\n', quiet_errors=True)

    def test_central_files_preflight(self):
        errors = file_checks(self.central)
        if os.geteuid() != 0:
            errors = [e for e in errors if 'ownership mismatch' not in e]
        self.assertEqual(errors, [])

    def test_node_trust_bootstrap_is_pinned(self):
        node = render(self.inv, 'node', self.base / 'test-node', 'node01')
        prepare(node)
        pki.import_trust(node, self.root / 'root_ca.crt', self.fp)
        repair_permissions(node)
        errors = file_checks(node)
        if os.geteuid() != 0:
            errors = [e for e in errors if 'ownership mismatch' not in e]
        self.assertEqual(errors, [])
        self.assertEqual((node / 'state/traefik/acme.json').read_text(), '{}\n')
        self.assertEqual((node / 'state/traefik/acme.json').stat().st_mode & 0o777, 0o600)

    def test_mismatched_key_certificate_rejected(self):
        other = render(self.inv, 'central', self.base / 'other')
        prepare(other, self.password_file)
        pki.intermediate_csr(other, 'Other Intermediate')
        with self.assertRaisesRegex(InfraError, 'does not match'):
            pki.import_intermediate(other, self.root / 'root_ca.crt', self.signed / 'intermediate_ca.crt', self.fp)

if __name__ == '__main__':
    unittest.main()
