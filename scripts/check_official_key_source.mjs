// Controlled regression: real mode must select the fixed HTTPS key source.
// No network calls; this checks source selection, not OpenAI's signing service.
import {generateKeyPairSync} from 'node:crypto';
import {Readable} from 'node:stream';
import fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
let fetchCalls=0,localJwksReads=0;
const {publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const officialTestKey={...publicKey.export({format:'jwk'}),kid:'official-source-test-key',alg:'RS256',use:'sig'};
const original=fs.promises.readFile;
fs.promises.readFile=async function(path,...args){
    if(String(path).replaceAll('\\','/').endsWith('/fixture/jwks.json'))localJwksReads++;
    return original.call(this,path,...args);
};
syncBuiltinESMExports();
globalThis.fetch=async (url,options)=>{
    fetchCalls++;
    if(url!=='https://auth.openai.com/.well-known/jwks.json'||options.redirect!=='error')
        throw new Error('unexpected_key_source');
    return new Response(JSON.stringify({keys:[officialTestKey]}),{status:200});
};
process.argv[2]='verify';process.argv.length=3;
Object.defineProperty(process,'stdin',{value:Readable.from([Buffer.from(JSON.stringify({metadata:[],
    token_commitment:'0'.repeat(64),account_commitment:'0'.repeat(64),verification_time:1,
    bundle:{kid:'fixture-only'}}))])});
let reason;
try{await import('../zk-prototype/request_bridge.mjs');}catch(error){reason=error.message;}
if(reason!=='untrusted_signing_key'||fetchCalls!==1||localJwksReads!==0)
    throw new Error('official_key_source_regression_failed: '+JSON.stringify({reason,fetchCalls,localJwksReads}));
console.log(JSON.stringify({synthetic_only:true,real_upstream_calls:0,untrusted_key_rejected:true,
    fixed_https_source_calls:fetchCalls,local_jwks_reads:localJwksReads,
    scope:'controlled_key_selection_not_full_proof_forgery'}));
