"""Actual local TLS + MPC-TLS + ZK; all identities, tokens and responses are synthetic."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from datetime import datetime,timedelta,timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes,serialization
import base64,json,ssl,subprocess,threading,time,socket,sys,os,tempfile

ROOT=Path(__file__).resolve().parent
FOLDER=ROOT/'fixture'
FOLDER.mkdir(exist_ok=True)
def b64(raw): return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')
def encode(value): return b64(json.dumps(value,separators=(',',':')).encode())
def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]

key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
public=key.public_key().public_numbers()
jwk={'kty':'RSA','kid':'fixture-only','e':b64(public.e.to_bytes(3,'big')),
     'n':b64(public.n.to_bytes(256,'big')),'alg':'RS256','use':'sig'}
(FOLDER/'jwks.json').write_text(json.dumps({'keys':[jwk]}),encoding='utf-8')
now=int(time.time())
account='SYNTHETIC-PRIVATE-ACCOUNT-ONLY'
claims={'iss':'https://auth.openai.com','iat':now-60,'exp':now+3600,
        'https://api.openai.com/auth':{'chatgpt_plan_type':'plus','chatgpt_account_id':account}}
signed=encode({'alg':'RS256','kid':'fixture-only','typ':'JWT'})+'.'+encode(claims)
token=signed+'.'+b64(key.sign(signed.encode(),padding.PKCS1v15(),hashes.SHA256()))
ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Local synthetic proof fixture CA')])
date=datetime.now(timezone.utc)
ca=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(date-timedelta(days=1)).not_valid_after(date+timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(ca_key,hashes.SHA256())
leafname=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'proof-fixture.invalid')])
cert=x509.CertificateBuilder().subject_name(leafname).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(date-timedelta(days=1)).not_valid_after(date+timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('proof-fixture.invalid')]),critical=False).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(ca_key,hashes.SHA256())
(FOLDER/'ca.der').write_bytes(ca.public_bytes(serialization.Encoding.DER))
cert_path=FOLDER/'temporary-synthetic-cert.pem'
key_path=FOLDER/'temporary-synthetic-key.pem'
cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2
context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
context.load_cert_chain(cert_path,key_path)
cert_path.unlink();key_path.unlink()

class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args): pass
    def do_POST(self):
        body=self.rfile.read(int(self.headers['Content-Length']))
        if self.path!='/backend-api/codex/responses' or self.headers.get('Authorization')!='Bearer '+token or ('--wrong-account' not in sys.argv and self.headers.get('Chatgpt-Account-Id')!=account):
            self.send_error(401); return
        model=json.loads(body)['model']
        if '--wrong-model' in sys.argv: model='substituted-model'
        event={'type':'response.completed','response':{'id':'fixture-response','status':'completed','model':model,
            'safety_identifier':'SYNTHETIC_IDENTITY_SECRET','prompt_cache_key':'SYNTHETIC_CACHE_SECRET',
            'output':[{'type':'message','content':[{'type':'output_text','text':'Synthetic authenticated fixture output'}]}]}}
        prefix=''
        if '--large-fixture' in sys.argv:
            prefix='event: response.output_text.delta\ndata: '+json.dumps({'type':'response.output_text.delta','delta':'S'*40000},separators=(',',':'))+'\n\n'
        raw=(prefix+'event: response.completed\ndata: '+json.dumps(event,separators=(',',':'))+'\n\n').encode()
        self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(raw)));self.send_header('Set-Cookie','SYNTHETIC_COOKIE_SECRET');self.send_header('Connection','close');self.end_headers();self.wfile.write(raw)
        self.wfile.flush();self.close_connection=True

server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
server.socket=context.wrap_socket(server.socket,server_side=True)
threading.Thread(target=server.serve_forever,daemon=True).start()
body={'model':'gpt-fixture-provenance','input':'Synthetic provenance check only','stream':True,'store':False}
body_path=FOLDER/'request.json'
body_path.write_text(json.dumps(body,separators=(',',':')),encoding='utf-8')
exe=ROOT/'client/target/release'/('tokenford-user-verifier-prototype.exe' if os.name=='nt' else 'tokenford-user-verifier-prototype')
if '--ssh' in sys.argv or '--bad-host-key' in sys.argv:
    import ssh_fixture
    try:
        report=ssh_fixture.run(ROOT,exe,body_path,{'token':token,'account_id':account,'fixture_port':server.server_port},'--bad-host-key' in sys.argv)
        (ROOT/'artifacts'/('ssh-bad-host-key-result.json' if '--bad-host-key' in sys.argv else 'ssh-fixture-result.json')).write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({k:v for k,v in report.items() if k!='response_body_base64'},indent=2))
    finally:server.shutdown();server.server_close()
    sys.exit(0)
port=free_port()
started=time.monotonic()
verifier=subprocess.Popen([str(exe),'verifier',str(port),str(body_path),'--fixture'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
    ready=verifier.stderr.readline().strip()
    if ready!='user_verifier_ready': raise RuntimeError('verifier_not_ready: '+ready)
    private={'token':token,'account_id':account,'fixture_port':server.server_port}
    if '--changed-body' in sys.argv: private['fixture_attack']='changed-body'
    if '--wrong-account' in sys.argv: private['account_id']='DIFFERENT-SYNTHETIC-ACCOUNT'
    p=subprocess.run([str(exe),'prover',str(port),'--fixture'],input=json.dumps(private),capture_output=True,text=True,timeout=175)
    out,err=verifier.communicate(timeout=175)
    attacks=[x for x in ('wrong-model','changed-body','wrong-account') if '--'+x in sys.argv]
    if attacks:
        if verifier.returncode==0: raise RuntimeError('attack_accepted')
        report={'synthetic_only':True,'attack':attacks[0],'rejected':True,'verifier_error':err.strip(),'prover_error':p.stderr.strip(),'prover_exit':p.returncode,'seconds':time.monotonic()-started}
    else:
        if p.returncode!=0 or verifier.returncode!=0:
            raise RuntimeError('synthetic_trial_failed: '+p.stderr.strip()+' | '+err.strip())
        report=json.loads(out)
        view=base64.b64decode(report['response_body_base64']).decode()
        if any(secret in view for secret in ('SYNTHETIC_IDENTITY_SECRET','SYNTHETIC_CACHE_SECRET','SYNTHETIC_COOKIE_SECRET')):
            raise RuntimeError('response_metadata_not_hidden')
        report['response_metadata_privacy_check']=True
        report.update(seconds=time.monotonic()-started,real_openai_credentials_used=False,production_changed=False,large_fixture='--large-fixture' in sys.argv)
        if report.get('official_openai_request_verified') is not False or report.get('synthetic_only') is not True:
            raise RuntimeError('fixture_mislabeled_as_official')
    (ROOT/'artifacts'/(attacks[0]+'-result.json' if attacks else 'large-fixture-result.json' if '--large-fixture' in sys.argv else 'fixture-result.json')).write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='response_body_base64'},indent=2))
finally:
    if verifier.poll() is None: verifier.kill();verifier.wait()
    server.shutdown();server.server_close()
