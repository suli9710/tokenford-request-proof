// Independent verification process: needs only public artifacts, never a JWT.
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { UltraHonkVerifierBackend } from '@aztec/bb.js';
const artifact = new URL('./artifacts/',import.meta.url);
const filename=process.argv[2]??'demo-proof.json';
if(!/^(demo|official-account-[1-4])-proof\.json$/.test(filename))throw new Error('unexpected_proof_filename');
const bundle = JSON.parse(await readFile(new URL(filename,artifact),'utf8'));
const circuit = await readFile(new URL('circuit.json',artifact));
const vk = await readFile(new URL('verification-key.bin',artifact));
const hash = value=>createHash('sha256').update(value).digest('hex');
const reviewed=JSON.parse(await readFile(new URL('./reviewed-build.json',import.meta.url),'utf8'));
if(hash(Buffer.from(JSON.parse(circuit).bytecode,'base64'))!==reviewed.bytecode_sha256 || hash(vk)!==reviewed.verification_key_sha256)
    throw new Error('reviewed_artifact_mismatch');
if (bundle.circuit_sha256!==hash(Buffer.from(JSON.parse(circuit).bytecode,'base64')) || bundle.verification_key_sha256!==hash(vk)) throw new Error('artifact_hash_mismatch');
const official=bundle.mode==='openai-signed-claims-prototype';
if(!official&&(bundle.mode!=='synthetic-demo'||bundle.official_openai_evidence!==false))throw new Error('unexpected_proof_mode');
let jwk=bundle.jwk;
if(official) {
    if(bundle.jwks_source!=='https://auth.openai.com/.well-known/jwks.json')throw new Error('untrusted_jwks_source');
    // A file supplied with evidence is not an official trust anchor.
    const response=await fetch('https://auth.openai.com/.well-known/jwks.json',
        {redirect:'error',signal:AbortSignal.timeout(20000)});
    if(!response.ok)throw new Error('official_jwks_fetch_failed');
    const raw=await response.text();
    if(Buffer.byteLength(raw)>131072)throw new Error('jwks_too_large');
    const keys=JSON.parse(raw);
    const matches=keys.keys?.filter(key=>key.kid===bundle.kid&&key.kty==='RSA'&&
        (key.use===undefined||key.use==='sig')&&(key.alg===undefined||key.alg==='RS256'));
    if(matches?.length!==1)throw new Error('official_key_not_unique_or_missing');
    jwk=matches[0];
}
for(const name of ['issued_at','expires_at','verification_time'])
    if(!Number.isSafeInteger(bundle[name])||bundle[name]<0)throw new Error('invalid_time_metadata');
if(!Array.isArray(bundle.public_inputs)||bundle.public_inputs.some(v=>typeof v!=='string'||!/^0x[0-9a-f]{64}$/.test(v)))
    throw new Error('noncanonical_public_inputs');
if(!jwk||jwk.kty!=='RSA'||jwk.e!=='AQAB'||Buffer.from(jwk.n,'base64url').length!==256)throw new Error('untrusted_or_unsupported_key');
const fields=bundle.public_inputs.map(BigInt);
if (fields.length!==72) throw new Error('unexpected_public_input_count');
const n=BigInt('0x'+Buffer.from(jwk.n,'base64url').toString('hex'));
const reduction=(1n<<4100n)/n;
const mask=(1n<<120n)-1n;
for (let i=0;i<18;i++) {
    if (fields[i]!==((n>>(120n*BigInt(i)))&mask)) throw new Error('public_key_mismatch');
    if (fields[18+i]!==((reduction>>(120n*BigInt(i)))&mask)) throw new Error('reduction_mismatch');
}
const names=['free','plus','team','pro'];
if (names[Number(fields[36])]!==bundle.plan || fields[37]!==BigInt(bundle.issued_at) || fields[38]!==BigInt(bundle.expires_at)
    || fields[39]!==BigInt(bundle.verification_time)) throw new Error('public_claim_metadata_mismatch');
if(fields.slice(40).some(v=>v<0n||v>255n))throw new Error('invalid_account_commitment');
const anonymousAccount=Buffer.from(fields.slice(40).map(Number)).toString('hex');
if(official&&anonymousAccount!==bundle.account_hash)throw new Error('account_commitment_mismatch');
const start=performance.now();
const verifier=new UltraHonkVerifierBackend({threads:2,backend:'wasm',
    crsPath:fileURLToPath(new URL('./crs/',import.meta.url))});
try {
    const verified=await verifier.verifyProof({proof:Buffer.from(bundle.proof_base64,'base64'),
        publicInputs:bundle.public_inputs,verificationKey:vk},{keccakZK:true});
    const now=Math.floor(Date.now()/1000);
    const fresh=bundle.verification_time<=now+30 && now-bundle.verification_time<=300 && now<bundle.expires_at;
    console.log(JSON.stringify({mode:official?'OPENAI SIGNED CLAIMS PROTOTYPE':'SYNTHETIC DEMO',official_openai_evidence:official,
        verified,plan:bundle.plan,statement_time_within_5min:fresh,direct_official_jwks_fetch:official,
        live_subscription_status_verified:false,fresh_verifier_challenge:false,
        account_hash:anonymousAccount,seconds:(performance.now()-start)/1000,
        issued_at:bundle.issued_at,expires_at:bundle.expires_at,verification_time:bundle.verification_time,
        requires_private_token:false,trust:official?'OpenAI JWKS signature, through the expected local ZK circuit. No OpenAI endorsement.':'Demo key only; not an OpenAI account certificate.'}));
    if (!verified) process.exitCode=1;
} finally {await verifier.destroy();}
