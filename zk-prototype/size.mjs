import {readFile,writeFile} from 'node:fs/promises';
import {gunzipSync} from 'node:zlib';
import {Barretenberg} from '@aztec/bb.js';
const artifacts=new URL(process.argv[2]==='--request'?'../request-proof/artifacts/':'./artifacts/',import.meta.url);
const c=JSON.parse(await readFile(new URL('circuit.json',artifacts),'utf8'));
const bb=await Barretenberg.new({threads:4,backend:'wasm'});
try {
    const [gates,dyadic]=await bb.acirGetCircuitSizes(gunzipSync(Buffer.from(c.bytecode,'base64')),false,true);
    const result={gates,dyadic,points:Math.max(dyadic,512)+1};
    await writeFile(new URL('circuit-stats.json',artifacts),JSON.stringify(result));
    console.log(JSON.stringify(result));
} finally {await bb.destroy();}
