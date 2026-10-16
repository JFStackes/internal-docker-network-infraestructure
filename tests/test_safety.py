import copy
import io
import os
import struct
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch
from private_infra.backup import safe_member
from private_infra.cli import main
from private_infra.diagnostics import parse_dns
from private_infra.model import load_inventory
from private_infra.render import render
from private_infra.operations import compose_args, sync_config, deployment_info
from private_infra.safeio import InfraError, atomic_write, secret_read

ROOT = Path(__file__).resolve().parents[1]

class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.inv = load_inventory(ROOT / 'examples/inventory.example.yaml')

    def test_no_files_changed_by_validate(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(['validate', '--inventory', str(ROOT / 'examples/inventory.example.yaml')]), 0)
        self.assertEqual(list(self.base.iterdir()), [])

    def test_compose_dry_run_never_runs_docker(self):
        out = render(self.inv, 'node', self.base / 'node', 'node01')
        with patch('private_infra.cli.run') as command:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(['compose', '--deployment', str(out), '--action', 'up']), 0)
            command.assert_not_called()

    def test_compose_up_requires_firewall_ack(self):
        out = render(self.inv, 'node', self.base / 'node', 'node01')
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(['compose', '--deployment', str(out), '--action', 'up', '--execute']), 1)

    def test_compose_actions_scoped_to_one_project(self):
        out = render(self.inv, 'node', self.base / 'node', 'node01')
        args = compose_args(out, 'stop')
        self.assertIn('private-example-node01', args)
        self.assertNotIn('--volumes', args)
        self.assertNotIn('down', args)
        with self.assertRaises(InfraError):
            compose_args(out, 'rm')

    def test_secret_world_readable_rejected(self):
        secret = self.base / 'secret'
        atomic_write(secret, 'value', 0o644)
        with self.assertRaises(InfraError):
            secret_read(secret)

    def test_symlink_secret_rejected(self):
        secret = self.base / 'secret'
        atomic_write(secret, 'value')
        link = self.base / 'link'
        link.symlink_to(secret)
        with self.assertRaises(InfraError):
            secret_read(link)

    def test_archive_path_controls(self):
        for bad in ('/etc/passwd', '../secret', 'state/../../secret', 'outside/key', '.ssh/id_rsa'):
            with self.subTest(path=bad):
                self.assertFalse(safe_member(bad))
        for good in ('state/step-ca/file', 'trust/root_ca.crt', 'compose.yaml'):
            self.assertTrue(safe_member(good))

    def test_dns_parser_positive(self):
        header = struct.pack('!6H', 123, 0x8180, 0, 1, 0, 0)
        rr = b'\0' + struct.pack('!HHIH', 1, 1, 60, 4) + bytes([10, 88, 0, 2])
        self.assertEqual(parse_dns(header + rr, 123)['addresses'], ['10.88.0.2'])

    def test_dns_parser_nxdomain(self):
        header = struct.pack('!6H', 123, 0x8183, 0, 0, 0, 0)
        self.assertEqual(parse_dns(header, 123)['rcode'], 3)

    def test_dns_parser_rejects_malformed(self):
        for packet in (b'', b'bad', struct.pack('!6H', 99, 0x8180, 0, 0, 0, 0),
                       struct.pack('!6H', 123, 0x8380, 0, 0, 0, 0)):
            with self.subTest(packet=packet):
                with self.assertRaises(InfraError):
                    parse_dns(packet, 123)

    def test_sync_dry_run_preserves_state(self):
        out = render(self.inv, 'node', self.base / 'node', 'node01')
        stage = render(self.inv, 'node', self.base / 'stage', 'node01')
        atomic_write(out / 'state/traefik/acme.json', 'important existing account')
        sync_config(out, stage, False)
        self.assertEqual((out / 'state/traefik/acme.json').read_text(), 'important existing account')
        self.assertFalse((out / 'config-backups').exists())

    def test_sync_rejects_namespace_change(self):
        out = render(self.inv, 'node', self.base / 'node', 'node01')
        change = copy.deepcopy(self.inv)
        change['site']['namespace'] = 'new.internal'
        change['central']['ca_name'] = 'ca.new.internal'
        change['central']['dns_name'] = 'dns.new.internal'
        stage = render(change, 'node', self.base / 'stage', 'node01')
        with self.assertRaises(InfraError):
            sync_config(out, stage, False)

    def test_sync_cold_preserves_acme_and_removes_stale_routes(self):
        out = render(self.inv, 'node', self.base / 'node', 'node01')
        atomic_write(out / 'state/traefik/acme.json', 'important existing account')
        atomic_write(out / 'config/traefik/dynamic/obsolete.yml', 'obsolete')
        changed = copy.deepcopy(self.inv)
        changed['nodes']['node01']['services']['app']['backend'] = 'http://10.88.0.2:9090'
        stage = render(changed, 'node', self.base / 'stage', 'node01')
        with patch('private_infra.operations.require_stopped'):
            sync_config(out, stage, True)
        self.assertEqual((out / 'state/traefik/acme.json').read_text(), 'important existing account')
        self.assertFalse((out / 'config/traefik/dynamic/obsolete.yml').exists())
        self.assertTrue((out / 'config-backups').exists())

if __name__ == '__main__':
    unittest.main()
