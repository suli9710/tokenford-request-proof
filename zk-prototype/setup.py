"""Set up only this public prototype; never reads a production credential."""
from pathlib import Path
import os
import subprocess
import sys

root = Path(__file__).resolve().parent
def run(command):
    subprocess.run(command, cwd=root, check=True)
run([sys.executable, '-B', 'check_integrity.py', '--bootstrap'])
run(['npm.cmd' if os.name == 'nt' else 'npm', 'ci', '--ignore-scripts', '--no-fund', '--no-audit'])
run([sys.executable, '-B', 'prepare_sources.py'])
run([sys.executable, '-B', 'patch_layout.py'])
run(['node', '--max-old-space-size=16384', 'compile.mjs'])
run(['node', '--max-old-space-size=16384', 'size.mjs'])
run([sys.executable, '-B', 'prepare_crs.py'])
run([sys.executable, '-B', 'check_integrity.py', '--compiled'])
