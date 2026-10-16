import copy
import tempfile
import unittest
from pathlib import Path
from private_infra.model import load_inventory, validate_inventory, service_hosts, backend
from private_infra.safeio import InfraError

ROOT = Path(__file__).resolve().parents[1]

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.data = load_inventory(ROOT / 'examples/inventory.example.yaml')

    def invalid(self, path, value):
        d = copy.deepcopy(self.data)
        ref = d
        for key in path[:-1]:
            ref = ref[key]
        ref[path[-1]] = value
        with self.assertRaises((InfraError, ValueError)):
            validate_inventory(d)

    def test_examples(self):
        for file in (ROOT / 'examples').glob('inventory*.yaml'):
            with self.subTest(file=file.name):
                load_inventory(file)

    def test_private_namespaces(self):
        for zone in ('arpa', 'lan', 'lab', 'test', 'internal.example.com', 'example.com', 'bad..internal'):
            with self.subTest(zone=zone):
                self.invalid(['site', 'namespace'], zone)

    def test_schema_rejects_ambiguous_inputs(self):
        cases = [(['schema_version'], True), (['schema_version'], 2),
                 (['site', 'id'], '../../bad'), (['site', 'id'], 'Name'),
                 (['vpn', 'network'], '0.0.0.0/0'), (['vpn', 'network'], '10.88.0.2/24'),
                 (['central', 'vpn_ip'], '0.0.0.0'), (['central', 'vpn_ip'], '10.88.0.255'),
                 (['central', 'vpn_ip'], '10.89.0.1'), (['central', 'ca_port'], 443),
                 (['central', 'ca_port'], 3000), (['central', 'ca_port'], True),
                 (['central', 'ca_name'], 'ca.public.net'),
                 (['central', 'dns_name'], 'ca.client.internal'),
                 (['central', 'dns_name'], 'node01.client.internal'),
                 (['central', 'docker_subnet'], '10.88.0.0/24'),
                 (['central', 'dns_container_ip'], '172.30.40.1'),
                 (['central', 'upstream_dns'], ['10.88.0.1']),
                 (['central', 'upstream_dns'], ['https://dns.example.com/query']),
                 (['access', 'admin_cidrs'], ['0.0.0.0/0']),
                 (['access', 'admin_cidrs'], []),
                 (['access', 'infrastructure_cidrs'], ['192.168.0.0/24']),
                 (['nodes', 'node01', 'vpn_ip'], '10.88.0.1'),
                 (['nodes', 'node01', 'services', 'app', 'enabled'], 'false'),
                 (['nodes', 'node01', 'services', 'app', 'access'], 'everyone'),
                 (['nodes', 'node01', 'external_networks'], ['../../bad']),
                 (['pki', 'certificate_hours'], 2), (['pki', 'email'], 'not-an-email'),
                 (['images', 'traefik'], 'traefik:latest'), (['images', 'traefik'], 'traefik:v3')]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                self.invalid(path, value)

    def test_forbids_unknown_keys(self):
        d = copy.deepcopy(self.data)
        d['central']['privileged'] = True
        with self.assertRaises(InfraError):
            validate_inventory(d)

    def test_backend_rejects_unsafe_or_unreachable_defaults(self):
        for url in ('http://127.0.0.1:80', 'http://localhost:80', 'http://169.254.169.254',
                    'http://0.0.0.0', 'ftp://service:21', 'http://user:pass@service:80',
                    'http://service:80/api', 'http://service:0', 'http://service:99999',
                    'http://service:80?token=a', 'http://service:80/#fragment',
                    'http://bad`host:80', 'http://${HOST}:80'):
            with self.subTest(url=url):
                with self.assertRaises(InfraError):
                    backend(url, 'test')

    def test_known_good_backends(self):
        for url in ('http://radarr:7878', 'https://app.client.internal:8443', 'http://10.88.0.2:8080'):
            self.assertEqual(backend(url, 'test'), url)

    def test_duplicate_yaml_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'duplicate.yaml'
            file.write_text('schema_version: 1\nschema_version: 1\n')
            with self.assertRaisesRegex(InfraError, 'Duplicate'):
                load_inventory(file)

    def test_yaml_tags_are_not_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'unsafe.yaml'
            file.write_text('!!python/object/apply:os.system ["true"]')
            with self.assertRaises(InfraError):
                load_inventory(file)

    def test_disabled_services_not_authorized_by_ca(self):
        d = load_inventory(ROOT / 'examples/inventory.jfstack.yaml')
        hosts = service_hosts(d)
        self.assertIn('radarr.dust01.internal', hosts)
        self.assertNotIn('files.dust01.internal', hosts)
        self.assertNotIn('torrent.dust01.internal', hosts)

    def test_digest_images_allowed(self):
        self.data['images']['traefik'] = 'traefik@sha256:' + 'a' * 64
        validate_inventory(self.data)

if __name__ == '__main__':
    unittest.main()
