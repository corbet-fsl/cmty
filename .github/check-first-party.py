#!/usr/bin/env python3
"""Require main declarations and unique locks with original issuer selectors."""
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

FIRST_PARTY = re.compile(r"^(?:git\+)?https://(?:git\.corbet\.ch|github\.com)/(?:corbet-(?:foss|fsl|libre)|cmtymt)/")
SHA = re.compile(r"^[0-9a-f]{40}$")
# These are the original transitive issuer owners, not alternative selectors
# for product declarations. The maintained CBLC issuer still consumes them.
ORIGINAL_ISSUERS = {
    'cmbl': ('0.1.0', 'https://git.corbet.ch/corbet-foss/cmbl.git'),
    'cmmr': ('0.1.0', 'https://git.corbet.ch/corbet-foss/cmmr.git'),
}



def check_lock(packages):
    names = {p['name'] for p in packages
             if FIRST_PARTY.match(p.get('source', '')) or p['name'] in ORIGINAL_ISSUERS}
    for name in names:
        entries = [p for p in packages if p['name'] == name]
        if len(entries) != 1:
            raise ValueError(f'Duplicate first-party crate: {name}')
        package = entries[0]
        raw = package.get('source', '')
        source = urlsplit(raw.removeprefix('git+'))
        query = parse_qs(source.query, keep_blank_values=True)
        if not SHA.fullmatch(source.fragment):
            raise ValueError(f'Missing resolved revision for {name}')
        if query == {'branch': ['main']} and FIRST_PARTY.match(raw):
            continue
        legacy = ORIGINAL_ISSUERS.get(name)
        if (legacy is None or package.get('version') != legacy[0]
                or raw != f'git+{legacy[1]}?branch=v01#{source.fragment}'):
            raise ValueError(f'Invalid first-party source selector for {name}')


def check_manifest(value):
    if isinstance(value, dict):
        if FIRST_PARTY.match(value.get('git', '')):
            if value.get('branch') != 'main' or {'rev', 'tag'}.intersection(value):
                raise ValueError('First-party dependency must declare branch = "main"')
        for item in value.values():
            check_manifest(item)
    elif isinstance(value, list):
        for item in value:
            check_manifest(item)


def metadata_issuer_selectors(metadata):
    """Validate original metadata owners with the same resolved-lock rule."""
    selected = []
    packages = metadata['packages']
    names = {p['name'] for p in packages if p['name'] in ORIGINAL_ISSUERS}
    names.update(d['name'] for p in packages for d in p['dependencies']
                 if d.get('name') in ORIGINAL_ISSUERS)
    for name in names:
        entries = [p for p in packages if p['name'] == name]
        if len(entries) != 1:
            raise ValueError(f'Missing, invalid or duplicated Corbet dependency: {name}')
        package = entries[0]
        check_lock([package])
        source = package['source']
        original = source.startswith(f'git+{ORIGINAL_ISSUERS[name][1]}?branch=v01#')
        declaration = source.split('#', 1)[0] if original else None
        for owner in packages:
            for dependency in owner['dependencies']:
                if dependency.get('name') != name:
                    continue
                raw = dependency.get('source') or ''
                if raw == declaration:
                    continue
                query = parse_qs(urlsplit(raw.removeprefix('git+')).query,
                                 keep_blank_values=True)
                if not FIRST_PARTY.match(raw) or query != {'branch': ['main']}:
                    raise ValueError(f'Invalid first-party source selector for {name}')
        selected.append({'name': name, 'resolved': source if original else None,
                         'declaration': declaration})
    return selected


def rejects(function, value):
    try:
        function(value)
    except ValueError:
        return
    raise AssertionError(f'Invalid input accepted: {value!r}')


def self_test_for(repo):
    source = 'git+' + repo + '?branch=main#' + 'a' * 40
    package = {'name': 'example', 'source': source}
    check_lock([package])
    check_lock([{'name': 'local'}])
    rejects(check_lock, [dict(package, source='git+' + repo + '?rev=' + 'a' * 40 + '#' + 'a' * 40)])
    for packages in ([package, package], [package, {'name': 'example'}],
                     [package, dict(package, source=source[:-1] + 'b')],
                     [dict(package, source=source.replace('main', 'develop'))],
                     [dict(package, source=source.replace('branch=main', 'tag=v1'))],
                     [dict(package, source=source.replace('branch=main', 'rev=' + 'b' * 40))],
                     [dict(package, source=source.replace('#' + 'a' * 40, '#short'))],
                     [dict(package, source=source.replace('branch=main', 'branch=main&branch=main'))]):
        rejects(check_lock, packages)
    for declaration in ({'git': repo}, {'git': repo, 'rev': 'a' * 40},
                        {'git': repo, 'branch': 'other'},
                        {'git': repo, 'branch': 'main', 'rev': 'a' * 40},
                        {'git': repo, 'branch': 'main', 'tag': 'v1'}):
        rejects(check_manifest, {'target': {'cfg(wasm)': {'dependencies': {'alias': declaration}}}})
    check_manifest({'workspace': {'dependencies': {'alias': {'git': repo, 'package': 'example', 'branch': 'main'}}}})


def check_original_issuer_fixtures():
    sha = 'a' * 40
    for name, (version, repo) in ORIGINAL_ISSUERS.items():
        source = f'git+{repo}?branch=v01#{sha}'
        package = {'name': name, 'version': version, 'source': source}
        check_lock([package])
        check_lock([dict(package, source=source.replace('branch=v01', 'branch=main'))])
        for bad in (
            dict(package, version='0.2.0'),
            {'name': name, 'source': source},
            dict(package, name='other'),
            dict(package, name='cmmr' if name == 'cmbl' else 'cmbl'),
            {'name': name},
            dict(package, source=f'registry+https://example.test/index#{sha}'),
            dict(package, source=source.replace('git.corbet.ch', 'github.com')),
            dict(package, source=source.replace('corbet-foss', 'corbet-libs')),
            dict(package, source=source.replace('git.corbet.ch', 'git.corbet.ch.evil.test')),
            dict(package, source=source.replace('git.corbet.ch', 'user@git.corbet.ch')),
            dict(package, source=source.replace('git.corbet.ch', 'git.corbet.ch:443')),
            dict(package, source=source.replace('.git?', '?')),
            dict(package, source=source.removeprefix('git+')),
            dict(package, source=source.replace('v01', 'v02')),
            dict(package, source=source.replace('v01', 'v%30%31')),
            dict(package, source=source.replace('branch=v01', 'tag=v01')),
            dict(package, source=source.replace('branch=v01', f'rev={sha}')),
            dict(package, source=source.replace('branch=v01', 'branch=v01&branch=v01')),
            dict(package, source=source.replace('branch=v01', 'branch=v01&extra=')),
            dict(package, source=source.replace(f'#{sha}', '#short')),
            dict(package, source=source.replace(f'#{sha}', f'#{sha.upper()}')),
        ):
            rejects(check_lock, [bad])
        rejects(check_lock, [package, package])
        rejects(check_lock, [package, {'name': name}])
        # This exception does not allow local product manifests to choose v01.
        rejects(check_manifest, {'dependencies': {name: {'git': repo, 'branch': 'v01'}}})
    check_lock([
        {'name': name, 'version': version, 'source': f'git+{repo}?branch=v01#{sha}'}
        for name, (version, repo) in ORIGINAL_ISSUERS.items()
    ])


def self_test():
    for domain in ('git.corbet.ch', 'github.com'):
        for organization in ('corbet-foss', 'corbet-fsl', 'corbet-libre', 'cmtymt'):
            self_test_for(f'https://{domain}/{organization}/example')
    check_original_issuer_fixtures()


if __name__ == '__main__':
    if '--metadata-issuers' in sys.argv:
        print(json.dumps(metadata_issuer_selectors(json.load(sys.stdin))))
    else:
        self_test()
    if '--self-test' not in sys.argv and '--metadata-issuers' not in sys.argv:
        paths = subprocess.check_output(['git', 'ls-files', '-z'], text=True).split('\0')
        for name in paths:
            path = Path(name)
            if path.name == 'Cargo.toml':
                check_manifest(tomllib.loads(path.read_text()))
            elif path.name == 'Cargo.lock':
                check_lock(tomllib.loads(path.read_text())['package'])
        print('First-party declarations follow main; locked crate revisions are unique')
