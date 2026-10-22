"""Deterministic source-only distribution. Never includes local builds or credentials."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('review', ROOT / 'review.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

def package(output):
    review.check()
    output = output.resolve()
    if not output.is_relative_to((ROOT / 'build').resolve()) or output.exists():
        raise RuntimeError('choose_a_new_output_under_build')
    manifest = json.loads((ROOT / 'source-manifest.json').read_text(encoding='utf-8'))
    # Hash-bound final sanitation/release reports stay outside their own archive.
    # VALIDATION describes source/build scope only and must never embed this ZIP's hash.
    names = sorted(set(manifest['files']) | {'source-manifest.json', 'SOURCE_MANIFEST_SHA256'} |
                   ({'VALIDATION.md'} if (ROOT / 'VALIDATION.md').is_file() else set()))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            path = (ROOT / name).resolve()
            if not path.is_relative_to(ROOT) or not path.is_file() or review.external(name):
                raise RuntimeError('unsafe_distribution_member')
            raw = path.read_bytes()
            if path.suffix.lower() in {'.py', '.rs', '.nr', '.json', '.toml', '.md', '.yml', '.yaml', '.sh', '.mjs', '.js', '.txt', '.lock', '.example'} or path.name.startswith('.'):
                raw = raw.replace(b'\r\n', b'\n')
            item = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            item.create_system = 3
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = (0o100755 if name.endswith('.sh') else 0o100644) << 16
            archive.writestr(item, raw)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('source_archive_crc_failed')
    result = {'schema': 1, 'files': len(names), 'sha256': review.digest(output),
              'bytes': output.stat().st_size, 'source_manifest_sha256': review.digest(ROOT / 'source-manifest.json'),
              'scope': 'source_only_original_code_and_redistributable_dependencies',
              'unclarified_dependencies_included': False, 'compiled_circuits_included': False,
              'production_credentials_included': False, 'external_audit': False}
    output.with_suffix('.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    package(parser.parse_args().out)
