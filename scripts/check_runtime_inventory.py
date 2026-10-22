"""Check the directory-link blind spot using isolated fake package trees."""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('review', root / 'review.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

with tempfile.TemporaryDirectory(prefix='request-proof-inventory-') as name:
    prefix = Path(name).resolve()
    packages = prefix / 'site-packages'
    packages.mkdir()
    (packages / 'ordinary.py').write_text('# controlled fixture\n', encoding='ascii')
    before = review.python_package_files(prefix, [packages])
    hidden = prefix / 'hidden'
    hidden.mkdir()
    (hidden / '__init__.py').write_text('# controlled fixture\n', encoding='ascii')
    link = packages / 'injected_package'
    link_kind = 'symlink'
    def make_link(path, destination):
        global link_kind
        if os.name == 'nt':
            result = subprocess.run(['cmd', '/d', '/c', 'mklink', '/J', str(path), str(destination)],
                                    capture_output=True, timeout=10)
            if result.returncode != 0 or not path.is_junction():
                raise RuntimeError('cannot_create_isolated_junction_fixture')
            link_kind = 'junction'
        else:
            path.symlink_to(destination, target_is_directory=True)
    def remove_link(path):
        if path.is_junction():
            os.rmdir(path)  # Removes only the junction, never its target.
        else:
            path.unlink()
    make_link(link, hidden)
    if link.resolve() != hidden or not link.parent.resolve().is_relative_to(prefix):
        raise RuntimeError('isolated_link_fixture_target_mismatch')
    try:
        # Demonstrate why a plain rglob/is_file inventory overlooks this package.
        naive = {str(p.relative_to(prefix)) for p in packages.rglob('*') if p.is_file()}
        if link_kind == 'symlink' and any('injected_package' in p for p in naive):
            raise RuntimeError('fixture_did_not_reproduce_directory_link_blind_spot')
        try:
            review.python_package_files(prefix, [packages])
        except RuntimeError as error:
            if str(error) != 'python_package_link_not_supported':
                raise
        else:
            raise RuntimeError('python_directory_link_was_accepted')
        node = prefix / 'zk-prototype/node_modules'
        node.mkdir(parents=True)
        client = prefix / 'request-proof/client/target/release'
        client.mkdir(parents=True)
        (client / ('tokenford-user-verifier-prototype.exe' if os.name == 'nt' else
                   'tokenford-user-verifier-prototype')).write_bytes(b'controlled fixture')
        node_link = node / 'injected_package'
        make_link(node_link, hidden)
        saved_root = review.ROOT
        try:
            review.ROOT = prefix
            try:
                review.runtime_files()
            except RuntimeError as error:
                if str(error) != 'dependency_directory_link_or_escape_not_supported':
                    raise
            else:
                raise RuntimeError('node_directory_link_was_accepted')
        finally:
            review.ROOT = saved_root
            remove_link(node_link)
    finally:
        remove_link(link)
    if review.python_package_files(prefix, [packages]) != before:
        raise RuntimeError('fixture_restore_failed')
    print(json.dumps({'synthetic_only': True, 'directory_link_regression_executed': True, 'link_kind': link_kind,
                      'python_directory_link_rejected': True, 'node_directory_link_rejected': True,
                      'real_upstream_calls': 0}))
