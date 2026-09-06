#!/usr/bin/env python3
"""Collect installed dependency license texts for a locked release target."""
import argparse
import json
from pathlib import Path
import subprocess


def render(metadata):
    nodes = {node['id']: node for node in metadata['resolve']['nodes']}
    pending = [metadata['resolve']['root']]
    selected = set()
    while pending:
        ident = pending.pop()
        if ident in selected:
            continue
        selected.add(ident)
        pending.extend(dep['pkg'] for dep in nodes[ident]['deps']
                       if any(kind['kind'] != 'dev' for kind in dep['dep_kinds']))
    sections = ['# Third-party notices\n\nNormal and build dependencies for this release target.\n']
    for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        if package['id'] not in selected or not package['source']:
            continue
        root = Path(package['manifest_path']).parent
        paths = {path for path in root.iterdir() if path.is_file()
                 and path.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE'))}
        if package.get('license_file'):
            paths.add(root / package['license_file'])
        if not paths:
            raise ValueError(f"Missing license text: {package['name']} {package['version']}")
        sections.append(f"\n## {package['name']} {package['version']}\n\nLicense: {package.get('license') or 'See license text'}\n")
        for path in sorted(paths):
            sections.append(f'\n### {path.name}\n\n{path.read_text()}\n')
    return ''.join(sections)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output([
        'cargo', 'metadata', '--offline', '--locked', '--format-version', '1',
        '--filter-platform', args.target,
    ]))
    text = render(metadata)
    # Never replace an existing release artifact implicitly.
    with args.output.open('x') as output:
        output.write(text)


if __name__ == '__main__':
    main()
