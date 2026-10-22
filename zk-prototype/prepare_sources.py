"""Download pinned public Noir libraries into this isolated prototype only."""
from pathlib import Path, PurePosixPath
import hashlib
import io
import json
import re
import tarfile
import tomllib

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ROOT = Path(__file__).resolve().parent
session = requests.Session()
session.mount('https://', HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.5)))
seen = {}
lock = []
expected_rows = json.loads((ROOT / 'sources-lock.json').read_text(encoding='utf-8'))
expected = {(r['repository'], r['tag'], r['directory']): r['archive_sha256'] for r in expected_rows}


def dependency(spec):
    repo = spec['git'].removesuffix('.git').removesuffix('/')
    if not re.fullmatch(r'https://github.com/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+', repo):
        raise RuntimeError('invalid_dependency_repository')
    tag = spec['tag']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', tag):
        raise RuntimeError('unpinned_or_invalid_tag')
    subdir = spec.get('directory', '')
    key = (repo, tag, subdir)
    if key not in expected:
        raise RuntimeError('dependency_missing_from_reviewed_lock')
    if key in seen:
        return seen[key]
    owner, name = repo.removeprefix('https://github.com/').split('/')
    target = ROOT / 'vendor' / (owner + '__' + name + '__' + tag)
    package = target / subdir
    seen[key] = package
    if not (target / '.archive-sha256').exists():
        url = f'https://codeload.github.com/{owner}/{name}/tar.gz/{tag}'
        response = session.get(url, timeout=(10, 30))
        response.raise_for_status()
        raw = response.content
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected[key]:
            raise RuntimeError('dependency_archive_digest_mismatch')
        target.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for member in archive.getmembers():
                parts = PurePosixPath(member.name).parts[1:]
                if '..' in parts:
                    raise RuntimeError('escaping_dependency_archive_member')
                if not member.isfile() or not parts:
                    continue
                namepart = parts[-1]
                if not (namepart.endswith('.nr') or namepart == 'Nargo.toml' or namepart.startswith('LICENSE')):
                    continue
                destination = target.joinpath(*parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.extractfile(member).read())
        (target / '.archive-sha256').write_text(digest, encoding='ascii')
        print('downloaded', owner + '/' + name, tag, flush=True)
    if (target / '.archive-sha256').read_text().strip() != expected[key]:
        raise RuntimeError('cached_dependency_archive_digest_mismatch')
    lock.append(key)
    rewrite(package / 'Nargo.toml')
    return package


def rewrite(manifest):
    original = manifest.with_suffix('.upstream.toml')
    if not original.exists():
        original.write_bytes(manifest.read_bytes())
    text = original.read_text(encoding='utf-8')
    data = tomllib.loads(text)
    for name, spec in data.get('dependencies', {}).items():
        if 'git' not in spec:
            continue
        package = dependency(spec)
        relative = Path(__import__('os').path.relpath(package, manifest.parent)).as_posix()
        text, count = re.subn(r'(?m)^' + re.escape(name) + r'\s*=.*$',
                             name + ' = { path = "' + relative + '" }', text)
        if count != 1:
            raise RuntimeError('dependency_manifest_rewrite_mismatch')
    manifest.write_text(text, encoding='utf-8')


rewrite(ROOT / 'circuit' / 'Nargo.toml')
if set(lock) != set(expected):
    raise RuntimeError('dependency_lock_coverage_mismatch')
print('pinned libraries', len(lock))
