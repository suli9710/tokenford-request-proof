"""Real local SSH public-key auth + stdio + MPC-TLS fixture. No production credentials."""
from pathlib import Path
import base64,json,os,shutil,socket,subprocess,sys,tempfile,threading,time
import paramiko
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def run(root,exe,body_path,private,bad_host_key=False):
    with tempfile.TemporaryDirectory(prefix='proof-ssh-fixture-') as tmp:
        folder=Path(tmp)
        host=paramiko.RSAKey.generate(2048)
        user=ed25519.Ed25519PrivateKey.generate()
        key=folder/'client-key'
        key.write_bytes(user.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.OpenSSH,serialization.NoEncryption()))
        os.chmod(key,0o600)
        public=user.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
        if os.name=='nt':
            # Restrict only the temporary test key; never touches the user's SSH keys.
            p=subprocess.run(['icacls',str(key),'/inheritance:r','/grant:r',os.environ['USERNAME']+':F'],capture_output=True)
            if p.returncode:raise RuntimeError('temporary_fixture_key_acl_failed')
        provider=folder/'provider.py'
        provider.write_text('import os,sys\nsys.stdout.write(os.environ["SYNTHETIC_PROOF_PRIVATE"])\n',encoding='utf-8')
        policy=folder/'policy.json'
        policy.write_text(json.dumps({'allowed_models':['gpt-fixture-provenance'],'provider_executable':sys.executable,
            'provider_args':['-B',str(provider)],'busy_lock':str(folder/'busy.lock')}),encoding='utf-8')
        sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen(1);sock.settimeout(15)
        port=sock.getsockname()[1]
        known=folder/'known-hosts'
        trusted=paramiko.RSAKey.generate(2048) if bad_host_key else host
        known.write_text(f'[127.0.0.1]:{port} {trusted.get_name()} {trusted.get_base64()}\n',encoding='ascii')
        config=folder/'ssh.json'
        config.write_text(json.dumps({'host':'127.0.0.1','port':port,'user':'proof-fixture',
            'identity_file':str(key),'known_hosts_file':str(known)}),encoding='utf-8')
        state={'public_key_auth':False,'forced_command_started':False,'errors':[]}
        class Access(paramiko.ServerInterface):
            def get_allowed_auths(self,username):return 'publickey'
            def check_auth_publickey(self,username,received):
                if username=='proof-fixture' and received.get_name()+' '+received.get_base64()==public:
                    state['public_key_auth']=True;return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED
            def check_channel_request(self,kind,chanid):return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            def check_channel_exec_request(self,channel,command):
                if command!=b'tokenford-proof-stdio':return False
                def serve():
                    state['forced_command_started']=True
                    child=None
                    try:
                        env=os.environ.copy();env['SYNTHETIC_PROOF_PRIVATE']=json.dumps(private)
                        child=subprocess.Popen([str(exe),'serve-stdio',str(policy),'--fixture'],env=env,
                            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                        def incoming():
                            try:
                                while True:
                                    raw=channel.recv(65536)
                                    if not raw:break
                                    child.stdin.write(raw);child.stdin.flush()
                            except (OSError,EOFError):pass
                            finally:
                                try:child.stdin.close()
                                except OSError:pass
                        threading.Thread(target=incoming,daemon=True).start()
                        while True:
                            raw=child.stdout.read1(65536)
                            if not raw:break
                            channel.sendall(raw)
                        status=child.wait(timeout=175)
                        error=child.stderr.read().decode(errors='replace')
                        if error:state['errors'].append(error.strip())
                        channel.send_exit_status(status);channel.shutdown_write()
                    except Exception as error:
                        state['errors'].append(type(error).__name__)
                    finally:
                        if child is not None and child.poll() is None:child.kill();child.wait()
                        channel.close()
                threading.Thread(target=serve,daemon=True).start();return True
        def server():
            transport=None
            try:
                connection,_=sock.accept();transport=paramiko.Transport(connection);transport.add_server_key(host)
                transport.start_server(server=Access())
                channel=transport.accept(15)
                if channel is not None:
                    while transport.is_active() and not channel.closed:time.sleep(0.1)
            except (paramiko.SSHException,EOFError,OSError):pass
            finally:
                if transport is not None:transport.close()
        worker=threading.Thread(target=server,daemon=True);worker.start();start=time.monotonic()
        try:
            p=subprocess.run([str(exe),'verify-ssh-fixture',str(config),str(body_path),'--fixture'],capture_output=True,text=True,timeout=175)
            worker.join(timeout=10)
            if bad_host_key:
                if p.returncode==0 or state['forced_command_started']:raise RuntimeError('untrusted_ssh_host_was_accepted')
                return {'synthetic_only':True,'wrong_host_key_rejected':True,'credentials_provider_started':False,
                    'exit_code':p.returncode,'seconds':time.monotonic()-start,'real_upstream_calls':0}
            if p.returncode or not state['public_key_auth'] or not state['forced_command_started']:
                raise RuntimeError('ssh_fixture_failed: '+p.stderr.strip()+' | '+' | '.join(state['errors']))
            result=json.loads(p.stdout)
            view=base64.b64decode(result['response_body_base64']).decode()
            if any(secret in view for secret in ('SYNTHETIC_IDENTITY_SECRET','SYNTHETIC_CACHE_SECRET','SYNTHETIC_COOKIE_SECRET')):
                raise RuntimeError('ssh_response_identity_leak')
            result.update(seconds=time.monotonic()-start,ssh_public_key_auth=True,ssh_pinned_host_key=True,
                ssh_forced_command=True,response_metadata_privacy_check=True,real_openai_credentials_used=False,
                cross_machine_tested=False,actual_local_ssh_tested=True,production_changed=False)
            return result
        finally:sock.close()
