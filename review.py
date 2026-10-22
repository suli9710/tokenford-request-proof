"""Local review/build entry point. A local record is not third-party attestation."""
from pathlib import Path
import argparse, base64, hashlib, importlib.metadata, json, os, re, shutil, subprocess, sys, time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / 'build'
MANIFEST = ROOT / 'source-manifest.json'
LOCAL_BUILD = BUILD / 'installation.json'
EXCLUDED_PARTS = {'.git', 'node_modules', 'target', '__pycache__', '.venv', 'build'}
REPORTS = {'FORK_REPORT.md', 'SANITIZATION_REPORT.md', 'VALIDATION.md', 'RELEASE_REPORT.md'}
COMPILED = {'circuit.json', 'circuit-stats.json', 'verification-key.bin'}
EXTERNAL_PREFIXES = ('zk-prototype/vendor/noir-lang__keccak256__v0.1.1/',
                     'zk-prototype/vendor/noir-lang__sha256__v0.2.1/',
                     'zk-prototype/vendor/olehmisar__nodash__v0.42.0/')


def external(name):
    return name.startswith(EXTERNAL_PREFIXES) or ('/artifacts/' in name and name.rsplit('/', 1)[1] in COMPILED)


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as file:
        while block := file.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def source_files():
    result = {}
    for path in sorted(ROOT.rglob('*')):
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDED_PARTS for part in rel.parts):
            continue
        if rel.as_posix().startswith(('request-proof/fixture/', 'zk-prototype/fixtures/', 'zk-prototype/outputs/')):
            continue
        if rel.as_posix() in {'source-manifest.json', 'SOURCE_MANIFEST_SHA256'} | REPORTS:
            continue
        if path.is_symlink():
            raise RuntimeError('source_symlink_not_supported: ' + rel.as_posix())
        if not path.is_file() or path.suffix == '.dat':
            continue
        if 'artifacts' in rel.parts and path.name not in COMPILED:
            continue
        # Text is normalized like the inherited source manifests; binary is exact.
        raw = path.read_bytes()
        if path.suffix.lower() in {'.py', '.rs', '.nr', '.json', '.toml', '.md', '.yml', '.yaml', '.sh', '.mjs', '.js', '.txt', '.lock', '.example'} or path.name.startswith('.'):
            raw = raw.replace(b'\r\n', b'\n')
        result[rel.as_posix()] = hashlib.sha256(raw).hexdigest()
    return result


def run(command, cwd=ROOT, log=None, timeout=900):
    env = os.environ.copy()
    env['PROOF_PYTHON'] = sys.executable
    if log is None:
        subprocess.run(command, cwd=cwd, env=env, check=True, timeout=timeout)
    else:
        with log.open('w', encoding='utf-8') as file:
            subprocess.run(command, cwd=cwd, env=env, stdout=file, stderr=subprocess.STDOUT, check=True, timeout=timeout)


def check(expected=None):
    if (ROOT / 'SOURCE_MANIFEST_SHA256').read_text(encoding='ascii').strip() != digest(MANIFEST) + '  source-manifest.json':
        raise RuntimeError('published_manifest_digest_file_mismatch')
    if expected and (len(expected) != 64 or digest(MANIFEST) != expected.lower()):
        raise RuntimeError('independently_expected_manifest_does_not_match')
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    if manifest.get('schema') != 1 or manifest.get('external_audit') is not False:
        raise RuntimeError('unsupported_source_manifest')
    all_files = source_files()
    actual = {name: value for name, value in all_files.items() if not external(name)}
    if actual != manifest['files']:
        changed = sorted(name for name in actual.keys() | manifest['files'].keys()
                         if actual.get(name) != manifest['files'].get(name))
        raise RuntimeError('source_manifest_changed: ' + ', '.join(changed[:12]))
    external_expected = manifest.get('external_files', {})
    if any(not external(name) for name in external_expected):
        raise RuntimeError('unexpected_external_material_classification')
    if any(external(name) and name not in external_expected for name in all_files):
        raise RuntimeError('unexpected_local_external_source_file')
    for name, value in external_expected.items():
        if name in all_files and all_files[name] != value:
            raise RuntimeError('local_external_material_changed: ' + name)
    # Both source checkers work before the public CRS parameters are installed.
    for folder in ('zk-prototype', 'request-proof'):
        run([sys.executable, '-B', 'check_integrity.py', '--bootstrap'], ROOT / folder)
    return digest(MANIFEST)


def tools():
    node = shutil.which('node')
    ssh = shutil.which('ssh')
    if not node or not ssh:
        raise RuntimeError('node_and_openssh_required')
    actual_node = subprocess.check_output([node, '-p', 'process.execPath'], text=True).strip()
    paths = {'python': Path(sys.executable).resolve(), 'node_launcher': Path(node).resolve(),
             'node': Path(actual_node).resolve(), 'ssh': Path(ssh).resolve()}
    return {name: {'path': str(path), 'sha256': digest(path)} for name, path in paths.items()}


def runtime_files():
    folder = ROOT / 'zk-prototype/node_modules'
    exe = ROOT / 'request-proof/client/target/release' / ('tokenford-user-verifier-prototype.exe' if os.name == 'nt' else 'tokenford-user-verifier-prototype')
    if not folder.is_dir() or not exe.is_file():
        raise RuntimeError('run_review_build_first')
    files = {exe.relative_to(ROOT).as_posix(): digest(exe)}
    for path in sorted(folder.rglob('*')):
        if path.is_file():
            if not path.resolve().is_relative_to(folder.resolve()):
                raise RuntimeError('dependency_symlink_escapes_installation')
            files[path.relative_to(ROOT).as_posix()] = digest(path)
    return files


def check_runtime():
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    if any(not (ROOT / name).is_file() for name in manifest.get('external_files', {})):
        raise RuntimeError('local_external_material_incomplete_run_build')
    record = json.loads(LOCAL_BUILD.read_text(encoding='utf-8'))
    if record.get('source_manifest_sha256') != digest(MANIFEST):
        raise RuntimeError('installation_belongs_to_different_source_release')
    if record.get('tools') != tools() or record.get('files') != runtime_files():
        raise RuntimeError('local_runtime_changed_rebuild_and_review')
    for folder in ('zk-prototype', 'request-proof'):
        run([sys.executable, '-B', 'check_integrity.py', '--compiled'], ROOT / folder)
    return record


def build():
    expected = check()
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError('reviewed_python_family_is_3_12')
    node_version = subprocess.check_output(['node', '--version'], text=True).strip()
    cargo_version = subprocess.check_output(['cargo', '--version'], text=True).strip()
    if node_version != 'v24.11.1' or not cargo_version.startswith('cargo 1.95.0 '):
        raise RuntimeError('use_pinned_node_24_11_1_and_rust_1_95_0')
    for name, version in re.findall(r'^([a-zA-Z0-9_-]+)==([^\s\\]+)', (ROOT / 'requirements.lock').read_text(), re.M):
        if importlib.metadata.version(name) != version:
            raise RuntimeError('install_python_packages_from_requirements_lock: ' + name)
    BUILD.mkdir(exist_ok=True)
    run([sys.executable, '-B', 'setup.py'], ROOT / 'request-proof', timeout=3600)
    # The source package excludes both circuit keys; rebuild the legacy key too.
    run(['node', '--max-old-space-size=16384', 'rebuild_vk.mjs'], ROOT / 'zk-prototype')
    if check() != expected:
        raise RuntimeError('source_changed_during_build')
    record = {'schema': 1, 'kind': 'local_installation_record_not_independent_attestation',
              'source_manifest_sha256': expected, 'tools': tools(), 'files': runtime_files(),
              'node_version': node_version, 'cargo_version': cargo_version,
              'python_version': sys.version.split()[0], 'platform': sys.platform,
              'built_at': datetime.now(timezone.utc).isoformat(), 'external_audit': False,
              'native_binary_reproducibility_demonstrated': False}
    LOCAL_BUILD.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'built': True, 'source_manifest_sha256': expected,
                      'runtime_files_recorded': len(record['files']), 'external_audit': False}))


def compiled_pair():
    folder = ROOT / 'request-proof/artifacts'
    circuit = json.loads((folder / 'circuit.json').read_text())
    return {'bytecode_sha256': hashlib.sha256(base64.b64decode(circuit['bytecode'], validate=True)).hexdigest(),
            'verification_key_sha256': digest(folder / 'verification-key.bin')}


def reproduce():
    check(); check_runtime()
    before = compiled_pair()
    run(['node', '--max-old-space-size=16384', 'compile.mjs', '--request'], ROOT / 'zk-prototype')
    run(['node', '--max-old-space-size=16384', 'rebuild_vk.mjs', '--request'], ROOT / 'zk-prototype')
    after = compiled_pair()
    if before != after:
        raise RuntimeError('rebuilt_circuit_or_verification_key_differs')
    check(); check_runtime()
    report = {'schema': 1, 'scope': 'same_machine_fresh_process_circuit_and_vk_recompilation',
              'matched': True, **after, 'native_binary_reproducibility_demonstrated': False,
              'cross_machine_tested': False, 'external_audit': False}
    (BUILD / 'recompile-result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))


def audit():
    check(); check_runtime()
    folder = BUILD / ('audit-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    checks = []
    def trial(name, command, cwd, output, required):
        path = cwd / output
        if path.exists():
            path.unlink()  # This exact generated synthetic receipt must be recreated.
        run(command, cwd, folder / (name + '.log'), timeout=240)
        data = json.loads(path.read_text(encoding='utf-8'))
        for key, value in required.items():
            if data.get(key) != value:
                raise RuntimeError(name + '_unexpected_result_' + key)
        (folder / (name + '.json')).write_text(json.dumps(data, indent=2), encoding='utf-8')
        checks.append({'name': name, 'passed': True})
        print(json.dumps(checks[-1]), flush=True)
        return data
    trial('ssh_positive', [sys.executable, '-B', 'fixture_trial.py', '--ssh'], ROOT / 'request-proof',
          'artifacts/ssh-fixture-result.json', {'synthetic_only': True, 'official_openai_request_verified': False,
          'ssh_public_key_auth': True, 'ssh_forced_command': True, 'response_metadata_privacy_check': True,
          'verified_output_text': 'Synthetic authenticated fixture output'})
    for attack, reason in [('wrong-model', 'response_model_or_status_mismatch'),
                          ('changed-body', 'request_or_nonce_changed'), ('wrong-account', 'credential_bridge_failed')]:
        data = trial(attack, [sys.executable, '-B', 'fixture_trial.py', '--' + attack], ROOT / 'request-proof',
                     'artifacts/' + attack + '-result.json', {'synthetic_only': True, 'rejected': True, 'attack': attack})
        if reason not in (data.get('verifier_error', '') + data.get('prover_error', '')):
            raise RuntimeError(attack + '_failed_for_unexpected_reason')
    trial('bad_host_key', [sys.executable, '-B', 'fixture_trial.py', '--bad-host-key'], ROOT / 'request-proof',
          'artifacts/ssh-bad-host-key-result.json', {'synthetic_only': True, 'wrong_host_key_rejected': True,
          'credentials_provider_started': False, 'real_upstream_calls': 0})
    data = trial('metadata_constraints', ['node', 'check_metadata_attack.mjs'], ROOT / 'zk-prototype',
                 '../request-proof/artifacts/metadata-attack-checks.json',
                 {'synthetic_only': True, 'valid_ascii_witness_passed': True, 'real_upstream_calls': 0})
    if len(data.get('checks', [])) != 4 or any(row.get('rejected') is not True for row in data['checks']):
        raise RuntimeError('metadata_negative_case_missing')
    run(['node', 'scripts/check_official_key_source.mjs'], ROOT,
        folder / 'official_key_source.log', timeout=60)
    checks.append({'name': 'official_key_source_negative', 'passed': True,
                   'scope': 'controlled key-selection regression, not a real upstream request'})
    runtime = check_runtime()
    exe = next(name for name in runtime['files'] if '/target/release/' in name)
    for name, relative in [('binary_drift', exe), ('dependency_drift', 'zk-prototype/node_modules/@noir-lang/noir_js/package.json')]:
        path = ROOT / relative
        original = path.read_bytes()
        try:
            path.write_bytes(original + b'\n')
            process = subprocess.run([sys.executable, '-B', str(ROOT / 'review.py'), 'verify',
                                     '--ssh-config', str(folder / 'nonexistent-ssh.json'),
                                     '--request', str(folder / 'nonexistent-request.json'),
                                     '--out', str(folder / (name + '-must-not-exist.json'))],
                                     cwd=ROOT, capture_output=True, text=True, timeout=90)
            if process.returncode == 0 or 'local_runtime_changed_rebuild_and_review' not in process.stderr:
                raise RuntimeError(name + '_not_rejected_at_runtime_gate')
        finally:
            path.write_bytes(original)
        checks.append({'name': name, 'passed': True, 'scope': 'real_verify_entry_refused_at_runtime_gate'})
    check(); check_runtime()
    report = {'schema': 1, 'synthetic_only': True, 'real_upstream_calls': 0, 'production_changed': False,
              'external_audit': False, 'checks': checks, 'seconds': round(time.monotonic() - started, 3),
              'source_manifest_sha256': digest(MANIFEST), 'negative_case_limit':
              'wrong-account checks the bridge failure boundary, not a separately classified constraint error'}
    (folder / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'audit_completed': True, 'report': str(folder.relative_to(ROOT) / 'summary.json'), **report}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check', 'build', 'runtime', 'audit', 'reproduce', 'verify'])
    parser.add_argument('--expected-manifest', help='SHA256 independently accepted by the user, not copied blindly from this package')
    parser.add_argument('--ssh-config', type=Path)
    parser.add_argument('--request', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if args.expected_manifest:
        check(args.expected_manifest)
    if args.command == 'check':
        value = check()
        manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
        ready = all((ROOT / name).is_file() for name in manifest.get('external_files', {}))
        print(json.dumps({'source_manifest_sha256': value, 'distributed_source_matched': True,
                          'external_material_ready': ready, 'external_audit': False}))
    elif args.command == 'build': build()
    elif args.command == 'runtime':
        check(); check_runtime(); print(json.dumps({'local_runtime_matches_build_record': True, 'external_audit': False}))
    elif args.command == 'reproduce': reproduce()
    elif args.command == 'audit': audit()
    else:
        if not all((args.ssh_config, args.request, args.out)):
            parser.error('verify requires --ssh-config, --request and --out')
        check(); check_runtime()
        run([sys.executable, '-B', 'verify_request.py', '--ssh-config', str(args.ssh_config.resolve()),
             '--request', str(args.request.resolve()), '--out', str(args.out.resolve())], ROOT / 'request-proof', timeout=200)


if __name__ == '__main__':
    main()
