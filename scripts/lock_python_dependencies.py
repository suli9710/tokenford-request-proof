"""Maintainer-only: pin the Python packages used by the build and synthetic fixtures."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib, json, urllib.request

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = {'requests':'2.34.2','cryptography':'50.0.0','paramiko':'5.0.0','cffi':'2.0.0',
            'certifi':'2026.5.20','charset-normalizer':'3.4.9','idna':'3.18','urllib3':'2.7.0',
            'bcrypt':'5.0.0','invoke':'3.0.3','pynacl':'1.6.2','pycparser':'3.0'}

def package(item):
    name, version = item
    url = f'https://pypi.org/pypi/{name}/{version}/json'
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise RuntimeError('package_metadata_limit')
    data = json.loads(raw)
    hashes = sorted({row['digests']['sha256'] for row in data['urls'] if not row.get('yanked')})
    if not hashes or any(len(value) != 64 for value in hashes):
        raise RuntimeError('missing_distribution_hashes')
    return name, version, hashes

if __name__ == '__main__':
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(package, sorted(VERSIONS.items())))
    text = '# Fixed Python 3.12 build/fixture dependencies; hashes from each pinned PyPI release.\n'
    for name, version, hashes in rows:
        text += name + '==' + version + ''.join(' \\\n    --hash=sha256:' + value for value in hashes) + '\n'
    path = ROOT / 'requirements.lock'
    path.write_text(text, encoding='utf-8')
    print(json.dumps({'packages':len(rows),'requirements_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}))
