"""Deterministic renderer. Produces files, never deploys or changes a host."""
from __future__ import annotations
import hashlib
import ipaddress
import json
import os
import shutil
from pathlib import Path
from string import Template
import yaml
from . import __version__
from .model import validate_inventory, service_hosts
from .safeio import InfraError, private_dir, atomic_write, no_symlinks

REPO = Path(__file__).resolve().parents[2]
PASSWORD_SENTINEL = 'NOT_INITIALIZED_RUN_PREPARE'


def dump(data) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


def dns_rules(d: dict) -> list[str]:
    """Local answers for every RR type; unknown .internal never goes upstream."""
    zone = d['site']['namespace']
    records = {d['central']['dns_name']: d['central']['vpn_ip'],
               d['central']['ca_name']: d['central']['vpn_ip']}
    records.update({f'{n}.{zone}': node['vpn_ip'] for n, node in d['nodes'].items()})
    names = sorted(records)
    rules = ['! Managed by Private Infrastructure. Change the inventory, not this list.']
    # denyallow avoids NXDOMAIN taking precedence over the positive rewrites.
    rules.append('||internal^$dnsrewrite=NXDOMAIN;;,denyallow=' + '|'.join(names))
    rules += [f'||{name}^$dnsrewrite=NOERROR;A;{records[name]}' for name in names]
    # One unambiguous PTR per node, not one per application.
    for name, node in sorted(d['nodes'].items()):
        reverse = ipaddress.ip_address(node['vpn_ip']).reverse_pointer
        rules.append(f'||{reverse}^$dnsrewrite=NOERROR;PTR;{name}.{zone}.')
    return rules


def adguard_config(d: dict) -> dict:
    return {
        'http': {'address': '0.0.0.0:3000', 'session_ttl': '8h',
                 'pprof': {'enabled': False, 'port': 6060}},
        'users': [{'name': 'admin', 'password': PASSWORD_SENTINEL}],
        'auth_attempts': 5, 'block_auth_min': 15, 'language': 'en',
        'dns': {
            'bind_hosts': ['0.0.0.0'], 'port': 53,
            'upstream_dns': d['central']['upstream_dns'],
            'bootstrap_dns': [], 'fallback_dns': [], 'upstream_mode': 'load_balance',
            'allowed_clients': [d['vpn']['network'], d['central']['docker_subnet']],
            'ratelimit': 50, 'ratelimit_subnet_len_ipv4': 32,
            'refuse_any': True, 'enable_dnssec': False,
            'use_private_ptr_resolvers': False, 'local_ptr_upstreams': [],
            'cache_enabled': True, 'cache_size': 4194304, 'cache_optimistic': False,
            'hostsfile_enabled': False,
        },
        'tls': {'enabled': False},
        'querylog': {'enabled': False, 'file_enabled': False},
        'statistics': {'enabled': False},
        'filtering': {'protection_enabled': True, 'filtering_enabled': True,
                      'blocking_mode': 'nxdomain', 'blocked_response_ttl': 60,
                      'rewrites': [], 'safe_search': {'enabled': False}},
        'filters': [], 'whitelist_filters': [], 'user_rules': dns_rules(d),
        'dhcp': {'enabled': False},
        'schema_version': 34,
    }


def ca_config(d: dict) -> dict:
    hours = d['pki']['certificate_hours']
    return {
        'root': '/home/step/certs/root_ca.crt',
        'crt': '/home/step/certs/intermediate_ca.crt',
        'key': '/home/step/secrets/intermediate_ca.key',
        'address': ':9000',
        'dnsNames': [d['central']['ca_name'], d['central']['vpn_ip']],
        'logger': {'format': 'json'},
        'db': {'type': 'badgerv2', 'dataSource': '/home/step/db'},
        'authority': {
            'enableAdmin': False,
            'claims': {'minTLSCertDuration': '1h', 'defaultTLSCertDuration': f'{hours}h',
                       'maxTLSCertDuration': f'{hours}h', 'disableRenewal': True},
            'policy': {'x509': {'allow': {'dns': service_hosts(d)}, 'allowWildcardNames': False}},
            'provisioners': [{
                'type': 'ACME', 'name': 'internal', 'challenges': ['tls-alpn-01'],
                'options': {'x509': {'templateFile': '/home/step/config/server.tpl'}}
            }],
        },
        'tls': {'minVersion': 1.2, 'maxVersion': 1.3, 'renegotiation': False},
    }

SERVER_TEMPLATE = '''{
  "subject": {{ toJson .Subject }},
  "sans": {{ toJson .SANs }},
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["serverAuth"],
  "basicConstraints": {"isCA": false}
}
'''


def traefik_config(d: dict) -> dict:
    c = d['central']
    return {
        'global': {'checkNewVersion': False, 'sendAnonymousUsage': False},
        'entryPoints': {
            'websecure': {'address': ':8443'},
            'health': {'address': ':8082'},
        },
        'ping': {'entryPoint': 'health'},
        'providers': {'file': {'directory': '/etc/traefik/dynamic', 'watch': True}},
        'log': {'level': 'INFO', 'format': 'json'},
        'certificatesResolvers': {'private-ca': {'acme': {
            'caServer': f"https://{c['ca_name']}:{c['ca_port']}/acme/internal/directory",
            'email': d['pki']['email'], 'storage': '/var/lib/traefik/acme.json',
            'certificatesDuration': d['pki']['certificate_hours'],
            'keyType': 'EC256', 'tlsChallenge': {},
        }}},
    }


def routes_config(d: dict, name: str) -> dict:
    result = {'http': {
        'routers': {}, 'services': {},
        'middlewares': {
            'admin-only': {'ipAllowList': {'sourceRange': d['access']['admin_cidrs']}},
            'infra-and-admin': {'ipAllowList': {'sourceRange': sorted(set(
                d['access']['admin_cidrs'] + d['access']['infrastructure_cidrs']))}},
            'private-headers': {'headers': {'contentTypeNosniff': True,
                'referrerPolicy': 'same-origin',
                'customResponseHeaders': {'Server': '', 'X-Powered-By': ''}}},
        },
        'serversTransports': {'verified-upstream': {
            'rootCAs': ['/etc/private-ca/root_ca.crt'],
            'forwardingTimeouts': {'dialTimeout': '10s', 'responseHeaderTimeout': '60s'},
        }},
    }, 'tls': {'options': {'default': {'minVersion': 'VersionTLS12', 'sniStrict': True}}}}
    for service, spec in sorted(d['nodes'][name]['services'].items()):
        if not spec['enabled']:
            continue
        result['http']['routers'][service] = {
            'rule': f"Host(`{service}.{name}.{d['site']['namespace']}`)",
            'entryPoints': ['websecure'], 'service': service,
            'middlewares': ['admin-only' if spec['access'] == 'admin' else 'infra-and-admin', 'private-headers'],
            'tls': {'certResolver': 'private-ca'},
        }
        result['http']['services'][service] = {'loadBalancer': {
            'passHostHeader': True, 'serversTransport': 'verified-upstream',
            'servers': [{'url': spec['backend']}],
        }}
    return result


def render(d: dict, role: str, output: Path, node: str | None = None) -> Path:
    validate_inventory(d)
    if role not in ('central', 'node'):
        raise InfraError('Profile must be central or node')
    if role == 'node' and node not in d['nodes']:
        raise InfraError('Unknown node; select a name from the inventory')
    if role == 'central' and node:
        raise InfraError('--node only applies to the node profile')
    output = no_symlinks(output)
    if output.exists() and any(output.iterdir()):
        raise InfraError('Output must be empty. Render updates to a separate staging directory.')
    private_dir(output)
    for directory in ('config', 'state', 'secrets', 'trust', 'pki/certs', 'pki/secrets'):
        private_dir(output / directory)
    c = d['central']
    variables = {
        'SITE_ID': d['site']['id'], 'NODE_ID': node or '',
        'BIND_IP': c['vpn_ip'] if role == 'central' else d['nodes'][node]['vpn_ip'],
        'ADMIN_PORT': str(c['admin_port']), 'CA_PORT': str(c['ca_port']),
        'DNS_CONTAINER_IP': c['dns_container_ip'], 'DOCKER_SUBNET': c['docker_subnet'],
        'DNS_IP': c['vpn_ip'], 'ADGUARD_IMAGE': d['images']['adguard'],
        'STEP_CA_IMAGE': d['images']['step_ca'], 'TRAEFIK_IMAGE': d['images']['traefik'],
    }
    template = (REPO / role / 'compose.yaml').read_text(encoding='utf-8')
    compose = yaml.safe_load(Template(template).substitute(variables))
    if role == 'central':
        files = {
            'config/adguard/AdGuardHome.yaml': dump(adguard_config(d)),
            'config/step-ca/ca.json': json.dumps(ca_config(d), indent=2) + '\n',
            'config/step-ca/server.tpl': SERVER_TEMPLATE,
        }
        for directory in ('state/adguard', 'state/step-ca'):
            private_dir(output / directory)
    else:
        for index, net in enumerate(d['nodes'][node]['external_networks']):
            key = f'external{index}'
            compose['networks'][key] = {'external': True, 'name': net}
            compose['services']['traefik']['networks'].append(key)
        files = {
            'config/traefik/traefik.yml': dump(traefik_config(d)),
            'config/traefik/dynamic/routes.yml': dump(routes_config(d, node)),
        }
        private_dir(output / 'state/traefik')
    files['compose.yaml'] = dump(compose)
    files['inventory.snapshot.yaml'] = dump(d)
    metadata = {'schema_version': 1, 'product_version': __version__,
                'site_id': d['site']['id'], 'profile': role, 'node': node,
                'runtime_uid': 10000, 'runtime_gid': 10000}
    files['deployment.json'] = json.dumps(metadata, indent=2) + '\n'
    for name, content in files.items():
        atomic_write(output / name, content)
    # Inventory and generated files are not credentials, but reveal topology.
    manifest = {name: hashlib.sha256(content.encode()).hexdigest() for name, content in sorted(files.items())}
    atomic_write(output / 'render-manifest.json', json.dumps(manifest, indent=2) + '\n')
    atomic_write(output / '.env', '# No credentials. compose.yaml is fully rendered; no interpolation is needed.\n')
    return output
