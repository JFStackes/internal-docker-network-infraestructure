import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch
from private_infra.model import load_inventory, validate_inventory
from private_infra.render import render
from private_infra.safeio import InfraError, atomic_write
from private_infra.operations import deployment_info, preflight, sync_config
from private_infra.cli import main

ROOT = Path(__file__).resolve().parents[1]

class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.data = load_inventory(ROOT / 'examples/inventory.example.yaml')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_repository_consistency(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        self.addCleanup(lambda: sys.path.remove(str(ROOT / 'scripts')))
        from check_repository import check
        self.assertEqual(check(), [])

    def test_reserved_node_name_cannot_collide_with_central(self):
        self.data['nodes']['central'] = self.data['nodes'].pop('node01')
        with self.assertRaises(InfraError):
            validate_inventory(self.data)

    def test_ca_name_matches_openssl_subject_contract(self):
        for name in ('bad/name', 'bad\\name', 'ab', 'A' * 65):
            with self.subTest(name=name):
                self.data['pki']['name'] = name
                with self.assertRaises(InfraError):
                    validate_inventory(self.data)

    def test_incomplete_restore_blocks_deployment(self):
        out = render(self.data, 'central', self.base / 'central')
        atomic_write(out / 'RESTORE-INCOMPLETE', 'failed restore\n')
        with self.assertRaises(InfraError):
            deployment_info(out)

    def test_modified_runtime_identity_rejected(self):
        out = render(self.data, 'central', self.base / 'central')
        metadata = json.loads((out / 'deployment.json').read_text())
        metadata['runtime_uid'] = 0
        atomic_write(out / 'deployment.json', json.dumps(metadata))
        with self.assertRaises(InfraError):
            deployment_info(out)

    def test_files_only_preflight_reports_unprepared_ca(self):
        out = render(self.data, 'central', self.base / 'central')
        errors = preflight(out, host=False)
        self.assertTrue(any('Trust root not ready' in x for x in errors))
        self.assertTrue(any('Missing pki/' in x for x in errors))

    def test_sync_rejects_running_profile(self):
        out = render(self.data, 'node', self.base / 'node', 'node01')
        stage = render(self.data, 'node', self.base / 'stage', 'node01')
        before = (out / 'compose.yaml').read_bytes()
        with patch('private_infra.operations.require_stopped', side_effect=InfraError('running')):
            with self.assertRaises(InfraError):
                sync_config(out, stage, True)
        self.assertEqual((out / 'compose.yaml').read_bytes(), before)
        self.assertFalse((out / 'config-backups').exists())

    def test_backup_and_restore_preview_do_not_execute_tools(self):
        out = render(self.data, 'central', self.base / 'central')
        commands = [
            ['backup', '--deployment', str(out), '--output', str(self.base / 'b.age'), '--recipient', 'age1example'],
            ['restore', '--archive', str(self.base / 'b.age'), '--identity', str(self.base / 'i.txt'), '--output', str(self.base / 'restored')],
        ]
        with patch('private_infra.backup.backup') as save, patch('private_infra.backup.restore') as restore:
            for command in commands:
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(main(command), 0)
            save.assert_not_called()
            restore.assert_not_called()
        self.assertFalse((self.base / 'restored').exists())

    def test_restore_members_cannot_include_offline_root_keys(self):
        from private_infra.backup import safe_member
        for name in ('pki/secrets/root_ca.key', 'secrets/root.key', 'state/backup/root_ca.key'):
            self.assertFalse(safe_member(name))

    def test_jfstack_backend_exceptions_remain_disabled(self):
        data = load_inventory(ROOT / 'examples/inventory.jfstack.yaml')
        services = data['nodes']['dust01']['services']
        self.assertFalse(services['files']['enabled'])
        self.assertFalse(services['torrent']['enabled'])
        self.assertEqual(services['torrent']['backend'], 'http://qbittorrent:8081')
        self.assertEqual(data['access']['admin_cidrs'], ['10.77.0.10/32'])
        self.assertEqual(data['site']['namespace'], 'internal')

if __name__ == '__main__':
    unittest.main()
