#!/usr/bin/env python3
"""Offline source hygiene and documentation/example consistency checks."""
from pathlib import Path
import re
import sys
import yaml
from export_examples import expected_examples

ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', '.venv', '__pycache__', 'local', 'build', 'dist', '.pytest_cache'}


def check():
    errors = []
    for name in ('README.md', 'docs/README.es.md', 'AGENTS.md', 'LICENSE', 'SECURITY.md',
                 'docs/DEPLOYMENT.md', 'docs/PKI.md', 'docs/ARCHITECTURE.md', 'docs/VALIDATION.md'):
        if not (ROOT / name).is_file():
            errors.append('Missing required file: ' + name)
    english = (ROOT / 'README.md').read_text(encoding='utf-8')
    spanish = (ROOT / 'docs/README.es.md').read_text(encoding='utf-8')
    if '[Leer en espa\u00f1ol](docs/README.es.md)' not in english:
        errors.append('Missing English-to-Spanish link')
    if '[Read in English](../README.md)' not in spanish:
        errors.append('Missing Spanish-to-English link')
    # Preserve all executable quick-start blocks identically in both entry docs.
    pattern = r'```bash\n(.*?)```'
    if re.findall(pattern, english, re.S) != re.findall(pattern, spanish, re.S):
        errors.append('Bilingual README shell examples differ')
    for name, expected in expected_examples().items():
        p = ROOT / 'examples' / name
        if not p.exists() or p.read_text(encoding='utf-8') != expected:
            errors.append('Stale generated example: ' + name)
    for p in ROOT.rglob('*'):
        rel = p.relative_to(ROOT)
        if any(x in SKIP for x in rel.parts):
            continue
        if p.is_symlink():
            errors.append('Unexpected repository symlink: ' + str(rel))
        if not p.is_file():
            continue
        if p.name == '.env' or p.suffix in ('.key', '.pem', '.csr', '.age') or p.name == 'acme.json':
            errors.append('Runtime/secret file in source: ' + str(rel))
        try:
            content = p.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            errors.append('Unexpected binary in source: ' + str(rel))
            continue
        if '\r' in content:
            errors.append('Non-LF line endings: ' + str(rel))
        if re.search(r'^-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----$', content, re.M):
            errors.append('Private key material in source: ' + str(rel))
        if p.suffix == '.md':
            for target in re.findall(r'(?<!!)\[[^\]]*\]\(([^)]+)\)', content):
                if '://' in target or target.startswith(('mailto:', '#')):
                    continue
                target = target.split('#')[0]
                if not (p.parent / target).exists():
                    errors.append(f'Broken link in {rel}: {target}')
    workflow = yaml.load((ROOT / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
    if workflow.get('permissions') != {'contents': 'read'}:
        errors.append('CI must request read-only contents permissions')
    for job in workflow.get('jobs', {}).values():
        for step in job.get('steps', []):
            action = step.get('uses')
            if action and not re.fullmatch(r'[\w./-]+@[0-9a-f]{40}', action):
                errors.append('CI action must use a complete immutable commit: ' + action)
    for name in ('central/compose.yaml', 'node/compose.yaml'):
        raw = (ROOT / name).read_text()
        if 'docker.sock' in raw or re.search(r'^\s+labels:', raw, re.M):
            errors.append('Forbidden Docker auto-discovery configuration: ' + name)
    version = (ROOT / 'VERSION').read_text().strip()
    if version not in english or version not in spanish:
        errors.append('README version mismatch')
    return errors


if __name__ == '__main__':
    errors = check()
    for error in errors:
        print('FAIL:', error)
    if errors:
        raise SystemExit(1)
    print('Repository checks passed: documentation, examples, CI and source hygiene.')
