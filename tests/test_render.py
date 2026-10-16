import copy
import json
import tempfile
import unittest
from pathlib import Path
import yaml
from private_infra.model import load_inventory, service_hosts
from private_infra.render import render, dns_rules, routes_config, ca_config, PASSWORD_SENTINEL
from private_infra.safeio import InfraError

ROOT = Path(__file__).resolve().parents[1]

class RenderTests(unittest.TestCase):
    def setUp(self):
        self.data = load_inventory(ROOT / 'examples/inventory.example.yaml')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_render_two_independent_profiles(self):
        for role in ('central', 'node'):
            with self.subTest(role=role):
                out = render(self.data, role, self.base / role, 'node01' if role == 'node' else None)
                compose = yaml.safe_load((out / 'compose.yaml').read_text())
                expected = {'adguard', 'step-ca'} if role == 'central' else {'traefik'}
                self.assertEqual(set(compose['services']), expected)
                self.assertNotIn('${', (out / 'compose.yaml').read_text())
                self.assertFalse(any(out.rglob('*.key')))
                self.assertFalse(any(out.rglob('acme.json')))

    def test_all_bindings_are_explicit_private_ipv4(self):
        for role in ('central', 'node'):
            out = render(self.data, role, self.base / role, 'node01' if role == 'node' else None)
            compose = yaml.safe_load((out / 'compose.yaml').read_text())
            ip = '10.88.0.1' if role == 'central' else '10.88.0.2'
            for svc in compose['services'].values():
                for port in svc['ports']:
                    self.assertTrue(port.startswith(ip + ':'))

    def test_hardening_in_both_profiles(self):
        for role in ('central', 'node'):
            out = render(self.data, role, self.base / role, 'node01' if role == 'node' else None)
            compose = yaml.safe_load((out / 'compose.yaml').read_text())
            for svc in compose['services'].values():
                self.assertEqual(svc['user'], '10000:10000')
                self.assertEqual(svc['cap_drop'], ['ALL'])
                if role == 'central':
                    self.assertEqual(svc['cap_add'], ['NET_BIND_SERVICE'])
                else:
                    self.assertNotIn('cap_add', svc)
                self.assertTrue(svc['read_only'])
                self.assertIn('no-new-privileges:true', svc['security_opt'])
                self.assertNotIn('labels', svc)
                self.assertNotIn('privileged', svc)
                self.assertNotIn('network_mode', svc)
                self.assertNotIn('docker.sock', str(svc))
                for mount in svc['volumes']:
                    self.assertFalse(mount['bind']['create_host_path'])

    def test_central_does_not_publish_80_443_or_wireguard(self):
        out = render(self.data, 'central', self.base / 'central')
        compose = yaml.safe_load((out / 'compose.yaml').read_text())
        ports = [int(p.split(':')[1]) for svc in compose['services'].values() for p in svc['ports']]
        self.assertFalse(set(ports) & {80, 443, 51820})
        self.assertEqual(set(ports), {53, 3000, 9000})
        health = compose['services']['step-ca']['healthcheck']['test']
        self.assertEqual(health[:4], ['CMD', 'step', 'ca', 'health'])
        self.assertIn('https://10.88.0.1:9000', health)
        self.assertIn('/home/step/certs/root_ca.crt', health)

    def test_node_uses_file_provider_only_and_trusted_ca(self):
        out = render(self.data, 'node', self.base / 'node', 'node01')
        config = yaml.safe_load((out / 'config/traefik/traefik.yml').read_text())
        self.assertEqual(set(config['providers']), {'file'})
        acme = config['certificatesResolvers']['private-ca']['acme']
        self.assertIn('/acme/internal/directory', acme['caServer'])
        self.assertEqual(acme['certificatesDuration'], self.data['pki']['certificate_hours'])
        self.assertEqual(acme['tlsChallenge'], {})
        self.assertNotIn('api', config)
        self.assertNotIn('accessLog', config)
        routes = yaml.safe_load((out / 'config/traefik/dynamic/routes.yml').read_text())
        self.assertTrue(routes['tls']['options']['default']['sniStrict'])
        self.assertNotIn('insecureSkipVerify', str(routes))

    def test_ca_limits_are_exact_and_wildcards_disabled(self):
        config = ca_config(self.data)
        auth = config['authority']
        self.assertEqual(auth['policy']['x509']['allow']['dns'], service_hosts(self.data))
        self.assertFalse(auth['policy']['x509']['allowWildcardNames'])
        self.assertFalse(auth['enableAdmin'])
        self.assertEqual(auth['provisioners'][0]['challenges'], ['tls-alpn-01'])
        self.assertEqual(auth['claims']['defaultTLSCertDuration'], '168h')
        self.assertNotIn('root_ca.key', json.dumps(config))

    def test_acl_source_ranges_not_forwarded_headers(self):
        routes = routes_config(self.data, 'node01')
        allow = routes['http']['middlewares']['admin-only']['ipAllowList']
        self.assertEqual(allow, {'sourceRange': ['10.88.0.10/32']})
        self.assertNotIn('ipStrategy', allow)

    def test_dns_rules_are_local_for_all_rr_types(self):
        rules = dns_rules(self.data)
        block = next(r for r in rules if 'NXDOMAIN' in r)
        self.assertIn('||internal^$', block)
        self.assertIn('denyallow=', block)
        self.assertIn('node01.client.internal', block)
        self.assertIn('||node01.client.internal^$dnsrewrite=NOERROR;A;10.88.0.2', rules)
        self.assertTrue(any(';PTR;node01.client.internal.' in r for r in rules))

    def test_adguard_not_open_admin(self):
        out = render(self.data, 'central', self.base / 'central')
        conf = yaml.safe_load((out / 'config/adguard/AdGuardHome.yaml').read_text())
        self.assertEqual(len(conf['users']), 1)
        self.assertEqual(conf['users'][0]['password'], PASSWORD_SENTINEL)
        self.assertFalse(conf['dhcp']['enabled'])
        self.assertFalse(conf['querylog']['enabled'])
        self.assertEqual(conf['dns']['fallback_dns'], [])
        self.assertEqual(conf['schema_version'], 34)

    def test_render_refuses_existing_output(self):
        out = render(self.data, 'central', self.base / 'central')
        with self.assertRaises(InfraError):
            render(self.data, 'central', out)

    def test_render_rejects_symlink_output(self):
        target = self.base / 'target'
        target.mkdir()
        linked = self.base / 'linked'
        linked.symlink_to(target, target_is_directory=True)
        with self.assertRaises(InfraError):
            render(self.data, 'central', linked)

    def test_external_networks_are_opt_in(self):
        self.data['nodes']['node01']['external_networks'] = ['app_proxy']
        out = render(self.data, 'node', self.base / 'node', 'node01')
        compose = yaml.safe_load((out / 'compose.yaml').read_text())
        self.assertEqual(compose['networks']['external0'], {'external': True, 'name': 'app_proxy'})
        self.assertIn('external0', compose['services']['traefik']['networks'])

    def test_deterministic_render(self):
        a = render(self.data, 'central', self.base / 'a')
        b = render(self.data, 'central', self.base / 'b')
        for name in ('compose.yaml', 'render-manifest.json', 'config/step-ca/ca.json', 'config/adguard/AdGuardHome.yaml'):
            self.assertEqual((a / name).read_bytes(), (b / name).read_bytes())

    def test_unknown_node_rejected(self):
        with self.assertRaises(InfraError):
            render(self.data, 'node', self.base / 'node', 'absent')

if __name__ == '__main__':
    unittest.main()
