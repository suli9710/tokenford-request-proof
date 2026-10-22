// Rebuild the verifier key from the expected local circuit, never from a proof.
import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {UltraHonkBackend} from '@aztec/bb.js';
const requestBridge=process.argv[2]==='--request';
const artifacts=new URL(requestBridge?'../request-proof/artifacts/':'./artifacts/',import.meta.url);
const circuit=JSON.parse(await readFile(new URL('circuit.json',artifacts),'utf8'));
const backend=new UltraHonkBackend(circuit.bytecode,{threads:4,backend:'wasm',crsPath:fileURLToPath(new URL(requestBridge?'../request-proof/crs/':'./crs/',import.meta.url))});
const start=performance.now();
try {
 const key=await backend.getVerificationKey({keccakZK:true});
 await writeFile(new URL('verification-key.bin',artifacts),key);
 console.log(JSON.stringify({verification_key_rebuilt:true,seconds:(performance.now()-start)/1000,
  sha256:createHash('sha256').update(key).digest('hex')}));
} finally {await backend.destroy();}
