"""Download public CRS for the isolated request bridge; lock subsequent runs."""
from pathlib import Path
import hashlib
import json
import requests

ROOT = Path(__file__).resolve().parent
points = json.loads((ROOT/'artifacts/circuit-stats.json').read_text())['points']
if points > 2**22 + 1:
    raise RuntimeError('parameter_limit')
folder = ROOT/'crs'
folder.mkdir(exist_ok=True)
lock = folder/'sources.json'
expected = {r['url']:r for r in json.loads(lock.read_text())} if lock.exists() else None
result = []
for remote, name, size in [('g1.dat','bn254_g1.dat',points*64),('g2.dat','bn254_g2.dat',128)]:
    url = 'https://crs.aztec.network/'+remote
    path = folder/name
    if not path.exists() or path.stat().st_size != size:
        headers = {'Range': f'bytes=0-{size-1}'} if remote=='g1.dat' else {}
        with requests.get(url,headers=headers,stream=True,timeout=(10,30)) as response:
            response.raise_for_status()
            if remote=='g1.dat' and (response.status_code!=206 or not response.headers.get('Content-Range','').startswith(f'bytes 0-{size-1}/')):
                raise RuntimeError('range_response_mismatch')
            count=0
            with path.open('wb') as file:
                for block in response.iter_content(1024*1024):
                    count+=len(block)
                    if count>size: raise RuntimeError('parameter_length_overflow')
                    file.write(block)
            if count!=size: raise RuntimeError('parameter_length_mismatch')
    row={'url':url,'bytes':size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    if expected is not None and row!=expected.get(url):
        raise RuntimeError('reviewed_parameter_digest_mismatch')
    result.append(row)
if expected is None:
    lock.write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({'public_parameters_ready':True,'previous_lock_checked':expected is not None}))
