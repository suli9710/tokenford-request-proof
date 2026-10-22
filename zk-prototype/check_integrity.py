"""Check files against a release manifest independently accepted by the reviewer."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent
manifest = json.loads((ROOT / 'reviewed-build.json').read_text(encoding='utf-8'))
bootstrap = '--bootstrap' in sys.argv
if bootstrap and '--compiled' in sys.argv:
    raise RuntimeError('bootstrap_cannot_check_an_installed_runtime')
external_prefixes = ('vendor/noir-lang__keccak256__v0.1.1/',
                     'vendor/noir-lang__sha256__v0.2.1/',
                     'vendor/olehmisar__nodash__v0.42.0/')
missing_external = 0
for name, expected in manifest['files'].items():
    path = (ROOT / name).resolve()
    if not path.is_relative_to(ROOT):
        raise RuntimeError('missing_or_escaping_reviewed_file')
    if not path.is_file():
        if bootstrap and name.startswith(external_prefixes):
            missing_external += 1
            continue
        raise RuntimeError('missing_or_escaping_reviewed_file')
    # Treat a text checkout's line endings consistently on all operating systems.
    raw = path.read_bytes().replace(b'\r\n', b'\n')
    if hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError('reviewed_file_digest_mismatch: ' + name)
if '--compiled' in sys.argv:
    import base64
    artifact = json.loads((ROOT / 'artifacts/circuit.json').read_text(encoding='utf-8'))
    if hashlib.sha256(base64.b64decode(artifact['bytecode'], validate=True)).hexdigest() != manifest['bytecode_sha256']:
        raise RuntimeError('reviewed_source_bytecode_mismatch')
print(json.dumps({'reviewed_files_match': True, 'compiled_checked': '--compiled' in sys.argv,
                  'bootstrap_only': bootstrap, 'missing_external_source_files': missing_external,
                  'external_audit': False}))
