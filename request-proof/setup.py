"""Build a reviewed experimental client locally, without reading account credentials."""
from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parent
def run(command,cwd=ROOT): subprocess.run(command,cwd=cwd,check=True)
run([sys.executable,'-B','check_integrity.py'])
run([sys.executable,'-B','setup.py'],ROOT.parent/'zk-prototype')
run(['node','--max-old-space-size=16384','compile.mjs','--request'],ROOT.parent/'zk-prototype')
run(['node','--max-old-space-size=16384','size.mjs','--request'],ROOT.parent/'zk-prototype')
run([sys.executable,'-B','prepare_parameters.py'])
run(['node','--max-old-space-size=16384','rebuild_vk.mjs','--request'],ROOT.parent/'zk-prototype')
run([sys.executable,'-B','check_integrity.py','--compiled'])
run(['cargo','build','--release','--locked'],ROOT/'client')
