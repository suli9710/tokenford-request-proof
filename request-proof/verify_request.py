"""User entry point: verify on this machine, then expose only authenticated text."""
from pathlib import Path
import argparse,base64,hashlib,json,os,subprocess,sys

ROOT=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description='Interactive verification through an independently pinned SSH endpoint')
parser.add_argument('--ssh-config',type=Path,required=True)
parser.add_argument('--request',type=Path,required=True)
parser.add_argument('--out',type=Path,required=True)
args=parser.parse_args()
if args.out.exists():raise RuntimeError('choose_a_new_receipt_path_do_not_reuse_an_old_result')
raw=args.request.read_bytes()
request=json.loads(raw)
exe=ROOT/'client/target/release'/('tokenford-user-verifier-prototype.exe' if os.name=='nt' else 'tokenford-user-verifier-prototype')
print('正在与证明端建立连接并独立验证；通过之前不会显示回复。',file=sys.stderr,flush=True)
process=subprocess.run([str(exe),'verify-ssh',str(args.ssh_config.resolve()),str(args.request.resolve())],
                       stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=185)
if process.returncode:
    print('本次请求未通过验证，不显示未验证回复。',file=sys.stderr)
    raise SystemExit(1)
result=json.loads(process.stdout)
required=['interactive_tls_verified','credential_bound_to_request','fresh_verifier_challenge','official_openai_request_verified']
if any(result.get(k) is not True for k in required) or result.get('synthetic_only') is not False or result.get('plan')!='plus':
    raise RuntimeError('official_interactive_proof_not_accepted')
if result.get('request_body_sha256')!=hashlib.sha256(raw).hexdigest():raise RuntimeError('local_request_changed')
view=base64.b64decode(result['response_body_base64'],validate=True)
if result.get('response_body_sha256')!=hashlib.sha256(view).hexdigest():raise RuntimeError('authenticated_response_view_changed')
if result.get('response_hash_scope')!='authenticated_view_with_redacted_metadata':raise RuntimeError('unsupported_response_view')
result.update(status='verified',requested_model=request['model'],receipt_kind='local_interactive_result_not_a_transferable_tls_certificate')
with args.out.open('x',encoding='utf-8') as file:json.dump(result,file,ensure_ascii=False,indent=2)
print(json.dumps({'status':'verified','plan':result['plan'],'model':request['model'],
    'text':result['verified_output_text'],'nonce':result['nonce'],'receipt':str(args.out.resolve()),
    'live_subscription_status_verified':False},ensure_ascii=False,indent=2))
