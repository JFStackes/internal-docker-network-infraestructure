#!/usr/bin/env python3
"""Regenerate documentation-only examples from the generic inventory."""
from pathlib import Path
import json
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from private_infra.model import load_inventory
from private_infra.render import dump, routes_config, traefik_config, ca_config, dns_rules


def expected_examples():
    inv = load_inventory(ROOT / 'examples/inventory.example.yaml')
    return {
        'traefik.routes.example.yaml': '# Generated example only; edit inventory, not this file.\n' + dump(routes_config(inv, 'node01')),
        'traefik.static.example.yaml': '# Generated example only; edit inventory, not this file.\n' + dump(traefik_config(inv)),
        'step-ca.example.json': json.dumps(ca_config(inv), indent=2) + '\n',
        'adguard.rules.example.txt': '\n'.join(dns_rules(inv)) + '\n',
    }


if __name__ == '__main__':
    for name, content in expected_examples().items():
        (ROOT / 'examples' / name).write_text(content, encoding='utf-8')
    print('Documentation examples regenerated; no deployment or keys created.')
