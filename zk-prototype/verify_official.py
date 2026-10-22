"""Verify public proofs using public keys fetched directly from OpenAI."""
from pathlib import Path
import json
import subprocess
import sys
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

root = Path(__file__).resolve().parent
# A reviewer must independently accept the hash of this manifest/code release.
# A manifest delivered by an untrusted publisher cannot authenticate itself.
subprocess.run([sys.executable, '-B', 'check_integrity.py'], cwd=root, check=True)
compiled = subprocess.run(['node', '--max-old-space-size=16384', 'compile.mjs'],
                          cwd=root, capture_output=True, text=True, timeout=180)
if compiled.returncode != 0:
    raise RuntimeError('reviewed_source_recompile_failed')
subprocess.run([sys.executable, '-B', 'check_integrity.py', '--compiled'], cwd=root, check=True)
stats = json.loads((root / 'artifacts/circuit-stats.json').read_text(encoding='utf-8'))
if not (root / 'crs/bn254_g1.dat').exists() or (root / 'crs/bn254_g1.dat').stat().st_size < stats['points'] * 64:
    subprocess.run([sys.executable, '-B', 'prepare_crs.py'], cwd=root, check=True)
subprocess.run([sys.executable, '-B', 'prepare_crs.py'], cwd=root, check=True)
session = requests.Session()
session.mount('https://', HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.5)))
response = session.get('https://auth.openai.com/.well-known/jwks.json', timeout=(10, 15), allow_redirects=False)
if response.status_code != 200:
    raise RuntimeError('official_jwks_http_failure')
keys = response.json()
if not isinstance(keys.get('keys'), list):
    raise RuntimeError('invalid_official_jwks')
(root / 'artifacts/official-jwks.json').write_text(json.dumps(keys), encoding='utf-8')
rebuilt = subprocess.run(['node', '--max-old-space-size=16384', 'rebuild_vk.mjs'],
                         cwd=root, capture_output=True, text=True, timeout=120)
if rebuilt.returncode != 0:
    raise RuntimeError('expected_circuit_key_rebuild_failed')
rebuilt_result = json.loads(rebuilt.stdout.strip().splitlines()[-1])
results = []
for path in sorted((root / 'artifacts').glob('official-account-*-proof.json')):
    p = subprocess.run(['node', 'verify.mjs', path.name], cwd=root, capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError('public_proof_verification_failed')
    record = json.loads(p.stdout.strip().splitlines()[-1])
    if record.get('verified') is not True or record.get('official_openai_evidence') is not True:
        raise RuntimeError('public_proof_not_verified')
    results.append(record)
if not results:
    raise RuntimeError('no_public_proofs')
output = {'direct_official_jwks_fetch': True, 'verified': len(results),
          'verification_key_rebuilt': rebuilt_result,
          'unique_accounts': len({r['account_hash'] for r in results}),
          'requires_private_tokens': False, 'results': results}
(root / 'artifacts/independent-verification.json').write_text(json.dumps(output, indent=2), encoding='utf-8')
print(json.dumps(output, ensure_ascii=True, indent=2))
