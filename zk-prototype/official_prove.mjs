// Private input arrives over stdin, stays in memory, and is never written out.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {Noir} from '@noir-lang/noir_js';
import {UltraHonkBackend} from '@aztec/bb.js';
const {generateInputs}=createRequire(import.meta.url)('noir-jwt');
const folder=new URL('./artifacts/',import.meta.url);
const rawCircuit=await readFile(new URL('circuit.json',folder));
const circuit=JSON.parse(rawCircuit);
const jwks=JSON.parse(await readFile(new URL('official-jwks.json',folder),'utf8'));
const hash=value=>createHash('sha256').update(value).digest('hex');
const chunks=[];
for await(const part of process.stdin) {chunks.push(part);if(chunks.reduce((n,p)=>n+p.length,0)>131072)throw new Error('private_input_limit');}
const rows=JSON.parse(Buffer.concat(chunks));
chunks.forEach(b=>b.fill(0));
if(!Array.isArray(rows)||rows.length<1||rows.length>4)throw new Error('account_limit');
const noir=new Noir(circuit);
const backend=new UltraHonkBackend(circuit.bytecode,{threads:4,backend:'wasm',crsPath:fileURLToPath(new URL('./crs/',import.meta.url))});
const options={keccakZK:true};
const reports=[];
let verificationKey;
try {
 for(let index=0;index<rows.length;index++) {
  const started=performance.now();
  const token=rows[index].access_token;
  const parts=token.split('.');
  const header=JSON.parse(Buffer.from(parts[0],'base64url'));
  const claims=JSON.parse(Buffer.from(parts[1],'base64url'));
  const jwk=jwks.keys.find(k=>k.kid===header.kid&&k.kty==='RSA');
  if(!jwk||header.alg!=='RS256'||jwk.e!=='AQAB'||Buffer.from(jwk.n,'base64url').length!==256)throw new Error('unsupported_official_key');
  if(!verifySignature('RSA-SHA256',Buffer.from(parts[0]+'.'+parts[1]),createPublicKey({key:jwk,format:'jwk'}),Buffer.from(parts[2],'base64url')))throw new Error('official_signature_invalid');
  const auth=claims['https://api.openai.com/auth'];
  const names=['free','plus','team','pro'];
  const planCode=names.indexOf(auth?.chatgpt_plan_type);
  const now=Math.floor(Date.now()/1000);
  if(claims.iss!=='https://auth.openai.com'||planCode<0||claims.iat>now||claims.exp<=now)throw new Error('invalid_credential_claims');
  if(typeof auth.chatgpt_account_id!=='string'||auth.chatgpt_account_id.length>64||auth.chatgpt_account_id.length<1)throw new Error('invalid_account_identity');
  const base=await generateInputs({jwt:token,pubkey:jwk,maxSignedDataLength:2048});
  const accountHash=createHash('sha256').update('TokenFord plan proof v1:').update(auth.chatgpt_account_id).digest();
  const input={data:base.data,payload_start:base.base64_decode_offset,signature_limbs:base.signature_limbs,
   modulus:base.pubkey_modulus_limbs,reduction:base.redc_params_limbs,plan_code:planCode,
   issued_at:String(claims.iat),expires_at:String(claims.exp),verification_time:String(now),account_hash:Array.from(accountHash)};
  console.log(JSON.stringify({stage:'official_witness',account:index+1,plan:names[planCode]}));
  const {witness}=await noir.execute(input);
  const beforeProof=performance.now();
  const proof=await backend.generateProof(witness,options);
  const proveSeconds=(performance.now()-beforeProof)/1000;
  witness.fill(0);
  if(!verificationKey) {
   verificationKey=await backend.getVerificationKey(options);
   await writeFile(new URL('verification-key.bin',folder),verificationKey);
  }
  if(!await backend.verifyProof(proof,options))throw new Error('proof_verification_failed');
  const bundle={schema_version:1,mode:'openai-signed-claims-prototype',official_openai_evidence:true,
   openai_endorsement:false,jwks_source:'https://auth.openai.com/.well-known/jwks.json',kid:header.kid,
   circuit_sha256:hash(Buffer.from(circuit.bytecode,'base64')),verification_key_sha256:hash(verificationKey),
   plan:names[planCode],issued_at:claims.iat,expires_at:claims.exp,verification_time:now,
   account_hash:accountHash.toString('hex'),proof_base64:Buffer.from(proof.proof).toString('base64'),public_inputs:proof.publicInputs};
  const serialized=JSON.stringify(bundle,null,2);
  const secretStrings=[token,parts[1],parts[2],claims.email,claims.sub,auth.chatgpt_account_id,auth.chatgpt_user_id];
  if(secretStrings.filter(v=>typeof v==='string'&&v.length>8).some(v=>serialized.includes(v)))throw new Error('private_data_in_export');
  const name='official-account-'+(index+1)+'-proof.json';
  await writeFile(new URL(name,folder),serialized+'\n');
  const report={account:index+1,plan:bundle.plan,account_hash:bundle.account_hash,
   verified:true,proofBytes:proof.proof.length,proveSeconds,elapsedSeconds:(performance.now()-started)/1000,
   issued_at:claims.iat,expires_at:claims.exp,verification_time:now,file:name,privacyCheck:true};
  reports.push(report);console.log(JSON.stringify({stage:'official_proof_ready',...report}));
  rows[index].access_token=null;
 }
 const summary={prototype:true,raw_tokens_saved:false,raw_tokens_logged:false,production_writes:0,
  accounts:reports,unique_accounts:new Set(reports.map(r=>r.account_hash)).size,
  limits:'Signed claims at issuance; does not attest current revocation status, pool completeness or request routing.'};
 await writeFile(new URL('official-result.json',folder),JSON.stringify(summary,null,2)+'\n');
 console.log(JSON.stringify({stage:'official_trial_complete',accounts:reports.length,unique_accounts:summary.unique_accounts}));
} catch(error) {
 console.log(JSON.stringify({stage:'official_trial_failed',error_type:error.name}));
 process.exitCode=1;
} finally {await backend.destroy();}
