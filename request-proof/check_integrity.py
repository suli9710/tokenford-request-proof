"""Fail if this independently accepted source/build release changes."""
from pathlib import Path
import base64,hashlib,json,sys

ROOT=Path(__file__).resolve().parent
PACKAGE=ROOT.parent
manifest=json.loads((ROOT/'reviewed-build.json').read_text(encoding='utf-8'))
for name,expected in manifest['files'].items():
    path=(PACKAGE/name).resolve()
    if not path.is_relative_to(PACKAGE) or not path.is_file():
        raise RuntimeError('missing_or_escaping_reviewed_file')
    if hashlib.sha256(path.read_bytes().replace(b'\r\n',b'\n')).hexdigest()!=expected:
        raise RuntimeError('reviewed_file_digest_mismatch: '+name)
if '--compiled' in sys.argv:
    c=json.loads((ROOT/'artifacts/circuit.json').read_text())
    if hashlib.sha256(base64.b64decode(c['bytecode'],validate=True)).hexdigest()!=manifest['bytecode_sha256']:
        raise RuntimeError('reviewed_bytecode_mismatch')
    if hashlib.sha256((ROOT/'artifacts/verification-key.bin').read_bytes()).hexdigest()!=manifest['verification_key_sha256']:
        raise RuntimeError('reviewed_verification_key_mismatch')
    for parameter in json.loads((ROOT/'crs/sources.json').read_text()):
        name='bn254_g1.dat' if parameter['url'].endswith('/g1.dat') else 'bn254_g2.dat'
        path=ROOT/'crs'/name
        if not path.is_file() or path.stat().st_size!=parameter['bytes']:
            raise RuntimeError('reviewed_parameter_missing_or_wrong_size')
        digest=hashlib.sha256()
        with path.open('rb') as file:
            while block:=file.read(1024*1024):digest.update(block)
        if digest.hexdigest()!=parameter['sha256']:
            raise RuntimeError('reviewed_parameter_hash_mismatch')
print(json.dumps({'reviewed_request_bridge_files_match':True,'external_audit':False,'compiled_checked':'--compiled' in sys.argv}))
