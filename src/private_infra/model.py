"""Strict inventory contract. A single installation is one trust domain."""
from __future__ import annotations
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit
import yaml
from .safeio import InfraError, no_symlinks

class UniqueSafeLoader(yaml.SafeLoader):
    pass

def _mapping(loader, node, deep=False):
    result = {}
    for key, value in node.value:
        name = loader.construct_object(key, deep=deep)
        if not isinstance(name, str):
            raise InfraError("All YAML mapping keys must be strings")
        if name in result:
            raise InfraError(f"Duplicate YAML key: {name}")
        result[name] = loader.construct_object(value, deep=deep)
    return result

UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)

LABEL = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
IMAGE = re.compile(r"[a-z0-9./_-]+(?::[A-Za-z0-9_.-]+)?(?:@sha256:[a-f0-9]{64})?\Z")
ROOT_KEYS = {"schema_version", "site", "vpn", "central", "pki", "access", "nodes", "images"}


def keys(obj, allowed, required, where):
    if not isinstance(obj, dict):
        raise InfraError(f"{where}: expected a mapping")
    if set(obj) - set(allowed):
        raise InfraError(f"{where}: unknown keys {sorted(set(obj) - set(allowed))}")
    if set(required) - set(obj):
        raise InfraError(f"{where}: missing keys {sorted(set(required) - set(obj))}")


def text(value, where, max_len=253):
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise InfraError(f"{where}: expected a nonempty string (max {max_len})")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise InfraError(f"{where}: control characters are not allowed")
    return value


def label(value, where):
    value = text(value, where, 40)
    if not LABEL.fullmatch(value):
        raise InfraError(f"{where}: use lowercase letters, digits and internal hyphens")
    return value


def fqdn(value, where):
    value = text(value, where)
    if any(not LABEL.fullmatch(part) or len(part) > 63 for part in value.split('.')):
        raise InfraError(f"{where}: invalid lowercase DNS name")
    return value


def integer(value, low, high, where):
    if type(value) is not int or not low <= value <= high:
        raise InfraError(f"{where}: expected an integer in {low}..{high}")
    return value


def network(value, where):
    try:
        net = ipaddress.IPv4Network(text(value, where), strict=True)
    except ValueError as exc:
        raise InfraError(f"{where}: invalid canonical IPv4 network") from exc
    rfc1918 = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if not any(net.subnet_of(x) for x in rfc1918):
        raise InfraError(f"{where}: use an RFC1918 network")
    return net


def address(value, net, where):
    try:
        addr = ipaddress.IPv4Address(text(value, where))
    except ValueError as exc:
        raise InfraError(f"{where}: invalid IPv4 address") from exc
    if addr not in net or addr in (net.network_address, net.broadcast_address):
        raise InfraError(f"{where}: address must be a usable host inside {net}")
    return addr


def backend(value, where):
    value = text(value, where, 2048)
    if any(x in value for x in (' ', '\\', '$', '`')):
        raise InfraError(f"{where}: unsafe URL characters")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise InfraError(f"{where}: expected an http:// or https:// upstream URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise InfraError(f"{where}: embedded credentials, query strings and fragments are forbidden")
    if parsed.path not in ("", "/"):
        raise InfraError(f"{where}: upstream path prefixes are not supported in v1")
    try:
        port = parsed.port
    except ValueError as exc:
        raise InfraError(f"{where}: invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise InfraError(f"{where}: invalid port")
    if parsed.hostname in ("localhost", "host.docker.internal"):
        raise InfraError(f"{where}: use an explicit reachable address or Docker network alias")
    try:
        ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        fqdn(parsed.hostname, where)
    else:
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            raise InfraError(f"{where}: loopback, link-local, multicast and wildcard backends are forbidden")
    return value


def load_inventory(path: Path) -> dict:
    raw = no_symlinks(path).read_text(encoding="utf-8")
    if len(raw) > 1_000_000:
        raise InfraError("Inventory exceeds 1 MB")
    try:
        data = yaml.load(raw, Loader=UniqueSafeLoader)
    except yaml.YAMLError as exc:
        raise InfraError(f"Invalid YAML: {exc}") from exc
    validate_inventory(data)
    return data


def validate_inventory(d: dict) -> None:
    keys(d, ROOT_KEYS, ROOT_KEYS, "inventory")
    if type(d['schema_version']) is not int or d['schema_version'] != 1:
        raise InfraError("Only schema_version: 1 is supported")
    keys(d['site'], {'id', 'name', 'namespace'}, {'id', 'name', 'namespace'}, 'site')
    label(d['site']['id'], 'site.id')
    text(d['site']['name'], 'site.name', 80)
    zone = fqdn(d['site']['namespace'], 'site.namespace')
    if zone != 'internal' and not zone.endswith('.internal'):
        raise InfraError("Private namespaces must be internal or a subdomain of .internal")
    keys(d['vpn'], {'network', 'interface'}, {'network', 'interface'}, 'vpn')
    vpn = network(d['vpn']['network'], 'vpn.network')
    label(d['vpn']['interface'], 'vpn.interface')
    keys(d['central'], {'vpn_ip', 'docker_subnet', 'dns_container_ip', 'dns_name', 'ca_name',
                        'admin_port', 'ca_port', 'upstream_dns'},
         {'vpn_ip', 'docker_subnet', 'dns_container_ip', 'dns_name', 'ca_name',
          'admin_port', 'ca_port', 'upstream_dns'}, 'central')
    c = d['central']
    central_ip = address(c['vpn_ip'], vpn, 'central.vpn_ip')
    docker_net = network(c['docker_subnet'], 'central.docker_subnet')
    if docker_net.overlaps(vpn) or not 24 <= docker_net.prefixlen <= 28:
        raise InfraError("central.docker_subnet must be a non-overlapping /24 through /28")
    dns_ip = address(c['dns_container_ip'], docker_net, 'central.dns_container_ip')
    if dns_ip == docker_net.network_address + 1:
        raise InfraError("dns_container_ip cannot use the Docker bridge gateway")
    names = set()
    for key in ('dns_name', 'ca_name'):
        value = fqdn(c[key], 'central.' + key)
        if not value.endswith('.' + zone) or value in names:
            raise InfraError("Central names must be distinct and within site.namespace")
        names.add(value)
    for key in ('admin_port', 'ca_port'):
        integer(c[key], 1024, 65535, 'central.' + key)
    if c['admin_port'] == c['ca_port']:
        raise InfraError("Central ports must be distinct")
    if not isinstance(c['upstream_dns'], list) or not c['upstream_dns']:
        raise InfraError("central.upstream_dns must be a nonempty list")
    for upstream in c['upstream_dns']:
        # Literal public IPv4 avoids bootstrap-DNS dependency and shell/config injection.
        try:
            ip = ipaddress.IPv4Address(upstream)
        except (ValueError, TypeError) as exc:
            raise InfraError("v1 upstream_dns requires literal public IPv4 addresses") from exc
        if not ip.is_global:
            raise InfraError("upstream_dns must be public recursive DNS addresses")
    keys(d['pki'], {'name', 'email', 'certificate_hours'}, {'name', 'email', 'certificate_hours'}, 'pki')
    text(d['pki']['name'], 'pki.name', 64)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{2,63}', d['pki']['name']):
        raise InfraError('pki.name must be 3..64 ASCII letters, digits, spaces, dots, underscores or hyphens')
    email = text(d['pki']['email'], 'pki.email', 200)
    if not re.fullmatch(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", email):
        raise InfraError("pki.email must be an email address")
    integer(d['pki']['certificate_hours'], 24, 720, 'pki.certificate_hours')
    keys(d['access'], {'admin_cidrs', 'infrastructure_cidrs'},
         {'admin_cidrs', 'infrastructure_cidrs'}, 'access')
    for group, ranges in d['access'].items():
        if not isinstance(ranges, list) or not ranges:
            raise InfraError(f"access.{group} must be nonempty")
        for value in ranges:
            if not network(value, 'access.' + group).subnet_of(vpn):
                raise InfraError(f"access.{group} must stay inside vpn.network")
    if not isinstance(d['nodes'], dict) or not d['nodes']:
        raise InfraError("At least one node must be declared")
    ips = {central_ip}
    total_services = 0
    for node_name, node in d['nodes'].items():
        label(node_name, 'node name')
        if node_name == 'central':
            raise InfraError('Node name central is reserved for the central Compose project')
        keys(node, {'vpn_ip', 'external_networks', 'services'}, {'vpn_ip', 'external_networks', 'services'}, node_name)
        ip = address(node['vpn_ip'], vpn, node_name + '.vpn_ip')
        if ip in ips:
            raise InfraError("VPN IPs must be unique")
        ips.add(ip)
        apex = f"{node_name}.{zone}"
        for name in names:
            if name == apex or name.endswith('.' + apex) or apex.endswith('.' + name):
                raise InfraError("Node DNS zone overlaps a central DNS name")
        if not isinstance(node['external_networks'], list):
            raise InfraError("external_networks must be a list")
        for item in node['external_networks']:
            if not isinstance(item, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}', item):
                raise InfraError("Invalid external Docker network name")
        if len(set(node['external_networks'])) != len(node['external_networks']):
            raise InfraError("Duplicate external networks")
        if not isinstance(node['services'], dict):
            raise InfraError("services must be a mapping")
        for service_name, service in node['services'].items():
            label(service_name, 'service name')
            keys(service, {'backend', 'enabled', 'access', 'description'},
                 {'backend', 'enabled', 'access'}, f'{node_name}.{service_name}')
            if type(service['enabled']) is not bool:
                raise InfraError("service.enabled must be true or false")
            if service['access'] not in ('admin', 'infrastructure'):
                raise InfraError("service.access must be admin or infrastructure")
            backend(service['backend'], f'{node_name}.{service_name}.backend')
            if 'description' in service:
                text(service['description'], 'service.description', 400)
            fqdn(f'{service_name}.{apex}', 'service FQDN')
            total_services += int(service['enabled'])
    if total_services == 0:
        raise InfraError("At least one service must be enabled for the CA allowlist")
    keys(d['images'], {'adguard', 'step_ca', 'traefik'}, {'adguard', 'step_ca', 'traefik'}, 'images')
    for name, image in d['images'].items():
        if not isinstance(image, str) or not IMAGE.fullmatch(image):
            raise InfraError(f"images.{name}: invalid image reference")
        if '@sha256:' not in image:
            tag = image.rsplit('/', 1)[-1].partition(':')[2]
            if not tag or not re.fullmatch(r'v?\d+\.\d+\.\d+', tag):
                raise InfraError(f"images.{name}: pin a complete stable version or sha256 digest")


def service_hosts(d: dict) -> list[str]:
    zone = d['site']['namespace']
    return sorted(f'{s}.{n}.{zone}' for n, node in d['nodes'].items()
                  for s, spec in node['services'].items() if spec['enabled'])
