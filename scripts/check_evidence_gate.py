"""Necessary negative checks for stale/overstated public evidence; no networking."""
from pathlib import Path
import copy
import importlib.util

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('review', root / 'review.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

expected = 'a' * 64
pair = {'bytecode_sha256': 'b' * 64, 'verification_key_sha256': 'c' * 64}
installation = {'source_manifest_sha256': expected, 'platform': 'controlled-fixture',
                'python_version': 'fixture', 'node_version': 'fixture', 'cargo_version': 'fixture',
                'files': {}, 'python_packages': {}}
identity = review.installation_identity(installation)
recompiled = {'source_manifest_sha256': expected, 'installation_sha256': identity,
              'executed_at': 'controlled-fixture', 'matched': True, **pair,
              'scope': 'same_machine_fresh_process_circuit_and_vk_recompilation'}
audited = {'source_manifest_sha256': expected, 'installation_sha256': identity,
           'executed_at': 'controlled-fixture', 'synthetic_only': True, 'real_upstream_calls': 0,
           'production_changed': False, 'external_audit': False, 'seconds': 0,
           'checks': [{'name': name, 'passed': True} for name in review.AUDIT_CHECKS]}

def payload(compiled=recompiled, audit=audited):
    return review.evidence_payload(expected, installation, compiled, audit, pair)

valid = payload()
if valid['scope']['external_audit'] is not False or valid['scope']['real_upstream_calls'] != 0:
    raise RuntimeError('bounded_positive_evidence_failed')
cases = []
for name, target, key, value, reason in (
    ('old-audit', 'audit', 'source_manifest_sha256', 'd' * 64, 'different_source_release'),
    ('old-recompile', 'compiled', 'source_manifest_sha256', 'd' * 64, 'different_source_release'),
    ('old-installation-audit', 'audit', 'installation_sha256', 'd' * 64, 'different_installation'),
    ('old-installation-recompile', 'compiled', 'installation_sha256', 'd' * 64, 'different_installation'),
    ('different-vk', 'compiled', 'verification_key_sha256', 'd' * 64, 'recompile_not_accepted'),
    ('missing-negative', 'audit', 'checks', audited['checks'][:-1], 'audit_incomplete_or_wrong_scope'),
    ('claimed-external-audit', 'audit', 'external_audit', True, 'audit_incomplete_or_wrong_scope'),
):
    compiled, audit = copy.deepcopy(recompiled), copy.deepcopy(audited)
    (audit if target == 'audit' else compiled)[key] = value
    try:
        payload(compiled, audit)
    except RuntimeError as error:
        if reason not in str(error):
            raise
    else:
        raise RuntimeError('evidence_attack_was_accepted: ' + name)
    cases.append(name)
print(review.json.dumps({'synthetic_only': True, 'evidence_gate_checks': cases,
                         'real_upstream_calls': 0, 'external_audit': False}))
