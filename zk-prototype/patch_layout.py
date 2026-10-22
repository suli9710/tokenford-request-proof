"""Adapt module file locations to the pinned WASM compiler; no logic changes."""
from pathlib import Path
import json
import re

root = (Path(__file__).resolve().parent / 'vendor').resolve()
changes = []
for source in list(root.rglob('*.nr')):
    target = source.with_suffix('') / 'mod.nr'
    if source.stem not in ('lib', 'main', 'mod') and source.with_suffix('').is_dir() and not target.exists():
        assert source.resolve().is_relative_to(root)
        assert target.resolve().is_relative_to(root)
        source.rename(target)
        changes.append({'from': source.relative_to(root).as_posix(),
                        'to': target.relative_to(root).as_posix()})
print(json.dumps({'module_layout_changes': changes}))
parser = root / 'noir-lang__noir_json_parser__dc8ad05fd63ef7518bf3adf3e5b61a87feb143b8/src'
for name in ('json.nr', 'get_string.nr', 'get_object.nr', 'get_number.nr'):
    path = parser / name
    text = path.read_text(encoding='utf-8')
    text = re.sub(r'(?m)^(\s*)(?:pub\(crate\) )?fn (parse_json|get_string|get_object|get_number)<',
                  r'\1pub fn \2<', text)
    path.write_text(text, encoding='utf-8')
