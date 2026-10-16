"""Read-only DNS and TLS checks, designed to run from an authorized VPN client."""
from __future__ import annotations
import ipaddress
import secrets
import socket
import ssl
import struct
import time
from pathlib import Path
from .safeio import InfraError


def _skip_name(packet: bytes, offset: int) -> int:
    for _ in range(128):
        if offset >= len(packet):
            raise InfraError('Truncated DNS name')
        size = packet[offset]
        offset += 1
        if size == 0:
            return offset
        if size & 0xC0 == 0xC0:
            if offset >= len(packet):
                raise InfraError('Truncated DNS compression pointer')
            return offset + 1
        if size & 0xC0 or size > 63:
            raise InfraError('Invalid DNS label')
        offset += size
    raise InfraError('Oversized DNS name')


def parse_dns(packet: bytes, txid: int) -> dict:
    if len(packet) < 12:
        raise InfraError('Truncated DNS response')
    ident, flags, qcount, acount, _, _ = struct.unpack('!6H', packet[:12])
    if ident != txid or not flags & 0x8000 or flags & 0x0200:
        raise InfraError('Unexpected or truncated DNS response')
    offset = 12
    for _ in range(qcount):
        offset = _skip_name(packet, offset) + 4
    answers = []
    for _ in range(acount):
        offset = _skip_name(packet, offset)
        if offset + 10 > len(packet):
            raise InfraError('Truncated DNS RR')
        rrtype, _, _, size = struct.unpack('!HHIH', packet[offset:offset + 10])
        offset += 10
        data = packet[offset:offset + size]
        if len(data) != size:
            raise InfraError('Truncated DNS RR data')
        if rrtype == 1 and size == 4:
            answers.append(str(ipaddress.IPv4Address(data)))
        offset += size
    return {'rcode': flags & 0x0F, 'addresses': answers, 'answer_count': acount}


def _read_exact(sock, size: int) -> bytes:
    result = b''
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise InfraError('Connection ended before the response was complete')
        result += chunk
    return result


def dns_query(server: str, name: str, rrtype: int = 1, tcp: bool = False, port: int = 53) -> dict:
    txid = secrets.randbelow(65536)
    qname = b''.join(bytes([len(p)]) + p.encode('ascii') for p in name.split('.')) + b'\x00'
    packet = struct.pack('!6H', txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack('!HH', rrtype, 1)
    try:
        if tcp:
            with socket.create_connection((server, port), timeout=5) as sock:
                sock.sendall(struct.pack('!H', len(packet)) + packet)
                length = struct.unpack('!H', _read_exact(sock, 2))[0]
                response = _read_exact(sock, length)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.connect((server, port))
                sock.send(packet)
                response = sock.recv(65535)
        return parse_dns(response, txid)
    except (OSError, ValueError, struct.error) as exc:
        raise InfraError(f'DNS query failed for {name}: {exc}') from exc


def tls_probe(ip: str, host: str, port: int, root: Path, path: str = '/') -> dict:
    context = ssl.create_default_context(cafile=str(root))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((ip, port), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                tls.sendall(f'GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
                response = b''
                while b'\r\n' not in response and len(response) < 4096:
                    data = tls.recv(1024)
                    if not data:
                        break
                    response += data
                first_line = response.split(b'\r\n', 1)[0].decode('ascii', 'replace')
                parts = first_line.split(' ')
                status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                remaining = ssl.cert_time_to_seconds(cert['notAfter']) - time.time()
                return {'status': status, 'tls_version': tls.version(),
                        'expires_in_hours': round(remaining / 3600, 1)}
    except (OSError, ValueError) as exc:
        raise InfraError(f'TLS/HTTP check failed for {host}: {exc}') from exc


def doctor(d: dict, root: Path, node: str | None = None) -> tuple[list[str], list[str]]:
    good, bad = [], []
    central = d['central']
    dns = central['vpn_ip']
    targets = [(central['ca_name'], dns, central['ca_port'], '/health', False)]
    for name, spec in d['nodes'].items():
        if node and name != node:
            continue
        for service, conf in spec['services'].items():
            if conf['enabled']:
                targets.append((f"{service}.{name}.{d['site']['namespace']}", spec['vpn_ip'], 443, '/', True))
    for host, ip, port, path, leaf in targets:
        try:
            for tcp in (False, True):
                result = dns_query(dns, host, tcp=tcp)
                if result['rcode'] != 0 or result['addresses'] != [ip]:
                    raise InfraError(f'Unexpected DNS answer for {host}: {result}')
            aaa = dns_query(dns, host, rrtype=28)
            if aaa['rcode'] != 0 or aaa['answer_count']:
                raise InfraError(f'Expected IPv4-only AAAA NODATA for {host}')
            result = tls_probe(ip, host, port, root, path)
            if not 200 <= result['status'] < 500:
                raise InfraError(f"{host}: HTTP {result['status']} (proxy/backend may not be ready)")
            if leaf and result['expires_in_hours'] < 24:
                raise InfraError(f'{host}: certificate expires in less than 24 hours')
            good.append(f'{host}: DNS UDP/TCP, AAAA NODATA, verified TLS; {result}')
        except InfraError as exc:
            bad.append(str(exc))
    unknown = 'unknown-' + secrets.token_hex(6) + '.internal'
    try:
        for rr in (1, 28, 16, 65):
            if dns_query(dns, unknown, rrtype=rr)['rcode'] != 3:
                raise InfraError('Unknown .internal names must return NXDOMAIN for A/AAAA/TXT/HTTPS')
        good.append('Unknown .internal names return NXDOMAIN (not a packet-capture proof of no leakage)')
    except InfraError as exc:
        bad.append(str(exc))
    return good, bad
