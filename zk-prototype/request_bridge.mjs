// Experimental bridge for authenticated MPC-TLS commitments. Private input: stdin only.
import {readFile} from 'node:fs/promises';
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {Noir} from '@noir-lang/noir_js';
import {UltraHonkBackend,UltraHonkVerifierBackend} from '@aztec/bb.js';
const {generateInputs}=createRequire(import.meta.url)('noir-jwt');
const mode=process.argv[2],fixture=process.argv[3]==='--fixture';
if(!['prove','verify'].includes(mode))throw new Error('unsupported_mode');
const base=new URL('../request-proof/',import.meta.url);
const artifacts=new URL('artifacts/',base);
const circuit=JSON.parse(await readFile(new URL('circuit.json',artifacts),'utf8'));
const bytecodeHash=createHash('sha256').update(Buffer.from(circuit.bytecode,'base64')).digest('hex');
const vk=await readFile(new URL('verification-key.bin',artifacts));
const vkHash=createHash('sha256').update(vk).digest('hex');
const reviewed=JSON.parse(await readFile(new URL('reviewed-build.json',base),'utf8'));
if(bytecodeHash!==reviewed.bytecode_sha256||vkHash!==reviewed.verification_key_sha256)throw new Error('reviewed_bridge_artifact_mismatch');
const chunks=[];let count=0;
for await(const part of process.stdin){count+=part.length;if(count>131072)throw new Error('input_limit');chunks.push(part);}
const input=JSON.parse(Buffer.concat(chunks));chunks.forEach(x=>x.fill(0));
if(!Array.isArray(input.metadata)||input.metadata.length>8)throw new Error('metadata_count_limit');
for(const item of input.metadata)if(!Number.isInteger(item.bytes)||item.bytes<1||item.bytes>384||
    typeof item.commitment!=='string'||!/^[a-f0-9]{64}$/.test(item.commitment))throw new Error('invalid_metadata_descriptor');
let kid,header,claims;
if(mode==='prove') {
    const parts=input.token.split('.');if(parts.length!==3)throw new Error('bad_token');
    header=JSON.parse(Buffer.from(parts[0],'base64url'));claims=JSON.parse(Buffer.from(parts[1],'base64url'));
    kid=header.kid;
} else {kid=input.bundle.kid;}
let keys;
if(fixture){keys=JSON.parse(await readFile(new URL('fixture/jwks.json',base),'utf8'));}
else {
    const response=await fetch('https://auth.openai.com/.well-known/jwks.json',
        {redirect:'error',signal:AbortSignal.timeout(20000)});
    if(!response.ok)throw new Error('official_jwks_unavailable');
    const raw=await response.text();if(Buffer.byteLength(raw)>131072)throw new Error('jwks_limit');keys=JSON.parse(raw);
}
const matches=keys.keys?.filter(k=>k.kty==='RSA'&&k.kid===kid&&k.e==='AQAB'&&
    (k.alg===undefined||k.alg==='RS256')&&(k.use===undefined||k.use==='sig'));
if(matches?.length!==1)throw new Error('untrusted_signing_key');
const jwk=matches[0];if(Buffer.from(jwk.n,'base64url').length!==256)throw new Error('rsa_size');
for(const name of ['token_commitment','account_commitment'])
    if(typeof input[name]!=='string'||!/^([a-f0-9]{64})$/.test(input[name]))throw new Error('bad_commitment');
if(!Number.isSafeInteger(input.verification_time)||input.verification_time<0)throw new Error('bad_time');
const opts={keccakZK:true},crsPath=fileURLToPath(new URL('crs/',base));
const bytes=value=>Array.from(Buffer.from(value,'hex'));
if(mode==='prove') {
    if(header.alg!=='RS256'||claims.iss!=='https://auth.openai.com')throw new Error('issuer_or_algorithm');
    const parts=input.token.split('.');
    if(!verifySignature('RSA-SHA256',Buffer.from(parts[0]+'.'+parts[1]),createPublicKey({key:jwk,format:'jwk'}),Buffer.from(parts[2],'base64url')))
        throw new Error('bad_signature');
    const auth=claims['https://api.openai.com/auth'];
    const plan=['free','plus','team','pro'].indexOf(auth?.chatgpt_plan_type);
    if(plan<0||!Number.isSafeInteger(claims.iat)||!Number.isSafeInteger(claims.exp)||claims.iat>input.verification_time||input.verification_time>=claims.exp)
        throw new Error('invalid_signed_claims');
    const tokenBytes=Buffer.from(input.token),padded=Array(2400).fill(0);
    if(tokenBytes.length>2400)throw new Error('token_size');tokenBytes.forEach((v,i)=>padded[i]=v);
    const original=await generateInputs({jwt:input.token,pubkey:jwk,maxSignedDataLength:2048});
    const accountHash=createHash('sha256').update('TokenFord plan proof v1:').update(auth.chatgpt_account_id).digest();
    const values={data:original.data,payload_start:original.base64_decode_offset,signature_limbs:original.signature_limbs,
        full_token:{storage:padded,len:tokenBytes.length},token_blinder:bytes(input.token_blinder),account_blinder:bytes(input.account_blinder),
        modulus:original.pubkey_modulus_limbs,reduction:original.redc_params_limbs,plan_code:plan,
        issued_at:String(claims.iat),expires_at:String(claims.exp),verification_time:String(input.verification_time),
        account_hash:Array.from(accountHash),token_commitment:bytes(input.token_commitment),account_commitment:bytes(input.account_commitment)};
    values.metadata_values=Array.from({length:8},(_,i)=>{
        const raw=i<input.metadata.length?Buffer.from(input.metadata[i].value_base64,'base64'):Buffer.alloc(0);
        if(i<input.metadata.length && raw.length!==input.metadata[i].bytes)throw new Error('metadata_value_length');
        return {storage:[...raw,...Array(384-raw.length).fill(0)],len:raw.length};
    });
    values.metadata_blinders=Array.from({length:8},(_,i)=>i<input.metadata.length?bytes(input.metadata[i].blinder):Array(16).fill(0));
    values.metadata_count=input.metadata.length;
    values.metadata_lengths=Array.from({length:8},(_,i)=>i<input.metadata.length?input.metadata[i].bytes:0);
    values.metadata_commitments=Array.from({length:8},(_,i)=>i<input.metadata.length?bytes(input.metadata[i].commitment):Array(32).fill(0));
    const noir=new Noir(circuit);const {witness}=await noir.execute(values);
    const backend=new UltraHonkBackend(circuit.bytecode,{threads:4,backend:'wasm',crsPath});
    try {
        const proof=await backend.generateProof(witness,opts);
        if(!await backend.verifyProof(proof,opts))throw new Error('generated_proof_invalid');
        console.log(JSON.stringify({mode:fixture?'synthetic-tls-bridge-v2':'openai-tls-bridge-v2',kid,
            circuit_sha256:bytecodeHash,verification_key_sha256:vkHash,
            public_inputs:proof.publicInputs,proof_base64:Buffer.from(proof.proof).toString('base64')}));
    }finally{witness.fill(0);tokenBytes.fill(0);await backend.destroy();}
} else {
    const bundle=input.bundle;
    if(bundle.mode!==(fixture?'synthetic-tls-bridge-v2':'openai-tls-bridge-v2')||bundle.circuit_sha256!==bytecodeHash||bundle.verification_key_sha256!==vkHash)
        throw new Error('untrusted_bridge_artifact');
    if(!Array.isArray(bundle.public_inputs)||bundle.public_inputs.length!==401||
        bundle.public_inputs.some(x=>typeof x!=='string'||!/^0x[0-9a-f]{64}$/.test(x)))throw new Error('bad_public_input_encoding');
    const f=bundle.public_inputs.map(BigInt);
    const n=BigInt('0x'+Buffer.from(jwk.n,'base64url').toString('hex')),red=(1n<<4100n)/n,mask=(1n<<120n)-1n;
    for(let i=0;i<18;i++)if(f[i]!==((n>>(120n*BigInt(i)))&mask)||f[18+i]!==((red>>(120n*BigInt(i)))&mask))throw new Error('signing_key_mismatch');
    if(f[39]!==BigInt(input.verification_time)||f[37]>f[39]||f[39]>=f[38])throw new Error('verifier_time_not_bound');
    if(f.slice(40,136).some(x=>x<0n||x>255n)||f.slice(145).some(x=>x<0n||x>255n))throw new Error('invalid_commitment_bytes');
    const publicHex=(start,end)=>Buffer.from(f.slice(start,end).map(Number)).toString('hex');
    if(publicHex(72,104)!==input.token_commitment||publicHex(104,136)!==input.account_commitment)
        throw new Error('tls_credential_commitment_mismatch');
    if(f[136]!==BigInt(input.metadata.length))throw new Error('tls_metadata_count_mismatch');
    for(let i=0;i<8;i++){
        const expected=input.metadata[i];
        if(f[137+i]!==BigInt(expected?.bytes??0)||publicHex(145+i*32,177+i*32)!==(expected?.commitment??'0'.repeat(64)))
            throw new Error('tls_metadata_descriptor_mismatch');
    }
    const backend=new UltraHonkVerifierBackend({threads:2,backend:'wasm',crsPath});
    try {
        const verified=await backend.verifyProof({proof:Buffer.from(bundle.proof_base64,'base64'),publicInputs:bundle.public_inputs,verificationKey:vk},opts);
        if(!verified)throw new Error('invalid_credential_proof');
        console.log(JSON.stringify({verified:true,plan:['free','plus','team','pro'][Number(f[36])],account_hash:publicHex(40,72),
            synthetic_only:fixture,requires_private_token:false}));
    }finally{await backend.destroy();}
}
