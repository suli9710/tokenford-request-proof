// Synthetic-only regression for cross-field JSON hiding. No upstream requests.
import {generateKeyPairSync,sign,createHash,randomBytes} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {Noir} from '@noir-lang/noir_js';
const {generateInputs}=createRequire(import.meta.url)('noir-jwt');
const artifacts=new URL('../request-proof/artifacts/',import.meta.url);
const circuit=JSON.parse(await readFile(new URL('circuit.json',artifacts),'utf8'));
const noir=new Noir(circuit),now=Math.floor(Date.now()/1000);
const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
const jwk=publicKey.export({format:'jwk'}),account='SYNTHETIC-METADATA-TEST';
const claims={iss:'https://auth.openai.com',iat:now-30,exp:now+600,
    'https://api.openai.com/auth':{chatgpt_plan_type:'plus',chatgpt_account_id:account}};
const signed=Buffer.from('{"alg":"RS256","kid":"fixture-only"}').toString('base64url')+'.'+Buffer.from(JSON.stringify(claims)).toString('base64url');
const token=signed+'.'+sign('RSA-SHA256',Buffer.from(signed),privateKey).toString('base64url');
const original=await generateInputs({jwt:token,pubkey:jwk,maxSignedDataLength:2048});
const tokenBlinder=randomBytes(16),accountBlinder=randomBytes(16),metadataBlinder=randomBytes(16);
const digest=(value,blinder)=>Array.from(createHash('sha256').update(value).update(blinder).digest());
async function inputFor(value){
    const data=Buffer.from(value);
    return {data:original.data,payload_start:original.base64_decode_offset,signature_limbs:original.signature_limbs,
        full_token:{storage:[...Buffer.from(token),...Array(2400-Buffer.byteLength(token)).fill(0)],len:Buffer.byteLength(token)},
        token_blinder:Array.from(tokenBlinder),account_blinder:Array.from(accountBlinder),
        modulus:original.pubkey_modulus_limbs,reduction:original.redc_params_limbs,plan_code:1,
        issued_at:String(claims.iat),expires_at:String(claims.exp),verification_time:String(now),
        account_hash:Array.from(createHash('sha256').update('TokenFord plan proof v1:').update(account).digest()),
        token_commitment:digest(token,tokenBlinder),account_commitment:digest(account,accountBlinder),
        metadata_values:Array.from({length:8},(_,i)=>({storage:i===0?[...data,...Array(384-data.length).fill(0)]:Array(384).fill(0),len:i===0?data.length:0})),
        metadata_blinders:Array.from({length:8},(_,i)=>i===0?Array.from(metadataBlinder):Array(16).fill(0)),
        metadata_count:1,metadata_lengths:[data.length,0,0,0,0,0,0,0],
        metadata_commitments:[digest(data,metadataBlinder),...Array.from({length:7},()=>Array(32).fill(0))]};
}
const good=await inputFor('user-safe-identifier');const {witness}=await noir.execute(good);witness.fill(0);
const vector='{"type":"response.completed","response":{"safety_identifier":"OUTERSECRET","model":"wrong-model","status":"completed","output":[{"content":[{"type":"output_text","text":"actual"}]}],"metadata":{"safety_identifier":"INNERSECRET","model":"expected-model","status":"completed","output":[{"content":[{"type":"output_text","text":"other"}]}],"prompt_cache_key":"INNERTAIL"},"prompt_cache_key":"OUTERTAIL"}}';
const attack=vector.slice(vector.indexOf('OUTERSECRET'),vector.indexOf('INNERSECRET')+'INNERSECRET'.length);
const checks=[];
async function reject(label,input){let rejected=false;try{const {witness}=await noir.execute(input);witness.fill(0);}catch{rejected=true;}checks.push({label,rejected});if(!rejected)throw new Error('metadata_attack_accepted');}
await reject('cross_field_json_structure',await inputFor(attack));
await reject('hidden_json_escape',await inputFor('user\\u0022fake'));
const wrongLength=await inputFor('safe-value');wrongLength.metadata_lengths[0]++;
await reject('changed_authenticated_length',wrongLength);
const wrongCommit=await inputFor('safe-value');wrongCommit.metadata_commitments[0][0]^=1;
await reject('changed_authenticated_commitment',wrongCommit);
const result={synthetic_only:true,valid_ascii_witness_passed:true,checks,real_upstream_calls:0};
await writeFile(new URL('metadata-attack-checks.json',artifacts),JSON.stringify(result,null,2));
console.log(JSON.stringify(result));
