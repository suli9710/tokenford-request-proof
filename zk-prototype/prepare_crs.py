"""Cache public proving parameters from the backend's official HTTPS source."""
from pathlib import Path
import hashlib
import json
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

root = Path(__file__).resolve().parent
points = json.loads((root / 'artifacts/circuit-stats.json').read_text())['points']
if points > 2**23 + 1:
    raise RuntimeError('public_parameter_limit')
target = root / 'crs'
target.mkdir(exist_ok=True)
session = requests.Session()
session.mount('https://', HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.5)))
manifest = []
expected = {row['url']: row for row in json.loads((target / 'sources.json').read_text(encoding='utf-8'))}
for remote, name, size in [('g1.dat', 'bn254_g1.dat', points * 64), ('g2.dat', 'bn254_g2.dat', 128)]:
    path = target / name
    url = 'https://crs.aztec.network/' + remote
    if url not in expected or expected[url]['bytes'] != size:
        raise RuntimeError('public_parameter_size_not_in_reviewed_lock')
    if not path.exists() or path.stat().st_size != size:
        headers = {'Range': f'bytes=0-{size-1}'} if remote == 'g1.dat' else {}
        with session.get(url, headers=headers, stream=True, timeout=(10, 30)) as response:
            response.raise_for_status()
            if remote == 'g1.dat':
                if response.status_code != 206 or not response.headers.get('Content-Range', '').startswith(f'bytes 0-{size-1}/'):
                    raise RuntimeError('parameter_range_response_mismatch')
            count = 0
            with path.open('wb') as file:
                for block in response.iter_content(1024 * 1024):
                    count += len(block)
                    if count > size:
                        raise RuntimeError('unexpected_parameter_response_size')
                    file.write(block)
            if count != size:
                raise RuntimeError('parameter_response_length_mismatch')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected[url]['sha256']:
        raise RuntimeError('public_parameter_digest_mismatch')
    manifest.append({'url':url, 'bytes':size, 'sha256':digest})
    print('cached public CRS', name, size, flush=True)
