"""Maintainer-only baseline creation; generated hashes are NOT independent endorsement."""
from pathlib import Path
import hashlib, importlib.util, json, sys

ROOT = Path(__file__).resolve().parents[1]
parser = __import__('argparse').ArgumentParser(description=__doc__)
parser.add_argument('--acknowledge-new-unreviewed-release', action='store_true', required=True)
parser.parse_args()
spec = importlib.util.spec_from_file_location('review', ROOT / 'review.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)
# Preserve the inherited cryptographic identity; only list source changes explicitly.
for folder in ('zk-prototype', 'request-proof'):
    path = ROOT / folder / 'reviewed-build.json'
    value = json.loads(path.read_text(encoding='utf-8'))
    base = ROOT / folder if folder == 'zk-prototype' else ROOT
    for name in value['files']:
        source = base / name
        if not source.is_file():
            raise RuntimeError('cannot_freeze_missing_previously_reviewed_source: ' + name)
        value['files'][name] = hashlib.sha256(source.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8', newline='\n')
files = review.source_files()
manifest = {'schema': 1, 'external_audit': False,
            'kind': 'maintainer_source_baseline_requires_independent_acceptance',
            'license_for_original_code': 'Apache-2.0',
            'files': {name: value for name, value in files.items() if not review.external(name)},
            'external_files': {name: value for name, value in files.items() if review.external(name)},
            'external_material_policy': 'not_redistributed_fetch_exact_pinned_source_and_compile_locally_license_clarification_pending'}
path = ROOT / 'source-manifest.json'
path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
digest = review.digest(path)
(ROOT / 'SOURCE_MANIFEST_SHA256').write_text(digest + '  source-manifest.json\n', encoding='ascii', newline='\n')
print(json.dumps({'source_files': len(manifest['files']), 'source_manifest_sha256': digest, 'external_audit': False}))
