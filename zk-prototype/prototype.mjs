// PROTOTYPE ONLY. Generates a real ZK proof using synthetic credentials.
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFile, writeFile } from 'node:fs/promises';
import { Noir } from '@noir-lang/noir_js';
import { fileURLToPath } from 'node:url';
import { UltraHonkBackend } from '@aztec/bb.js';
const require = createRequire(import.meta.url);
const { generateInputs } = require('noir-jwt');
const artifact = new URL('./artifacts/', import.meta.url);
const rawCircuit = await readFile(new URL('circuit.json', artifact));
const circuit = JSON.parse(rawCircuit);
const noir = new Noir(circuit);
const started = performance.now();
const now = Math.floor(Date.now() / 1000);
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
const jwk = publicKey.export({ format: 'jwk' });
const privateEmail = 'PROTOTYPE_PRIVATE_EMAIL@example.invalid';
const claims = {
    iss: 'https://auth.openai.com', sub: 'PROTOTYPE_PRIVATE_SUBJECT',
    email: privateEmail, iat: now - 60, exp: now + 3600,
    'https://api.openai.com/auth': { chatgpt_plan_type: 'plus', chatgpt_account_id: 'PROTOTYPE_PRIVATE_ACCOUNT' },
};
function issue(payload) {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'synthetic-demo-only' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const data = header + '.' + body;
    return data + '.' + sign('RSA-SHA256', Buffer.from(data), privateKey).toString('base64url');
}
async function inputs(token, planCode = 1, payload = claims, time = now) {
    const base = await generateInputs({ jwt: token, pubkey: jwk, maxSignedDataLength: 2048 });
    return { data: base.data, payload_start: base.base64_decode_offset,
        signature_limbs: base.signature_limbs, modulus: base.pubkey_modulus_limbs,
        reduction: base.redc_params_limbs, plan_code: planCode,
        issued_at: String(payload.iat), expires_at: String(payload.exp), verification_time: String(time),
        account_hash:Array.from(createHash('sha256').update('TokenFord plan proof v1:')
            .update(payload['https://api.openai.com/auth'].chatgpt_account_id??'PROTOTYPE_PRIVATE_ACCOUNT').digest()) };
}
const token = issue(claims);
const goodInputs = await inputs(token);
console.log(JSON.stringify({stage:'witness', mode:'SYNTHETIC DEMO', signedBytes:goodInputs.data.len}));
let witness;
try {
    ({ witness } = await noir.execute(goodInputs));
} catch (error) {
    console.log(JSON.stringify({stage:'witness_failed',message:String(error.message).slice(0,700)}));
    process.exit(1);
}
console.log(JSON.stringify({stage:'witness_ready',seconds:(performance.now()-started)/1000,compressedBytes:witness.length}));
const checks = [];
async function rejected(label, value) {
    try { await noir.execute(value); checks.push({label,rejected:false}); }
    catch { checks.push({label,rejected:true}); }
    console.log(JSON.stringify(checks.at(-1)));
}
// These adversarial examples answer whether the claimed relation is enforced.
await rejected('changed_public_plan', { ...goodInputs, plan_code:2 });
const expired = {...claims, exp:now-1};
await rejected('expired_token', await inputs(issue(expired),1,expired));
const namespace = {...claims, 'https://api.openai.com/auth':{...claims['https://api.openai.com/auth'],chatgpt_plan_type:'free'}, fake:{chatgpt_plan_type:'plus'}};
await rejected('plus_in_wrong_json_object', await inputs(issue(namespace)));
const tampered = token.split('.');
tampered[1] = Buffer.from(JSON.stringify({...claims,'https://api.openai.com/auth':{...claims['https://api.openai.com/auth'],chatgpt_plan_type:'team'}})).toString('base64url');
await rejected('changed_signed_payload', await inputs(tampered.join('.'),2));
if (checks.some(c=>!c.rejected)) throw new Error('prototype_relation_failed');
const backend = new UltraHonkBackend(circuit.bytecode, { threads:4, backend:'wasm',
    crsPath:fileURLToPath(new URL('./crs/',import.meta.url)) });
// Explicit ZK mode. Do not replace with keccak:true, which disables ZK here.
const options = {keccakZK:true};
try {
    console.log(JSON.stringify({stage:'proving',elapsedSeconds:(performance.now()-started)/1000}));
    const proofStarted = performance.now();
    const proofData = await backend.generateProof(witness, options);
    const proveSeconds = (performance.now()-proofStarted)/1000;
    console.log(JSON.stringify({stage:'proof_ready',proveSeconds,proofBytes:proofData.proof.length}));
    const verificationKey = await backend.getVerificationKey(options);
    const verified = await backend.verifyProof(proofData,options);
    const changed = {...proofData, publicInputs:[...proofData.publicInputs]};
    changed.publicInputs[36] = '0x' + '2'.padStart(64,'0');
    const tamperedPlanRejected = !await backend.verifyProof(changed,options);
    const bundle = {schema_version:1,mode:'synthetic-demo',official_openai_evidence:false,
        circuit_sha256:createHash('sha256').update(Buffer.from(circuit.bytecode,'base64')).digest('hex'),
        verification_key_sha256:createHash('sha256').update(verificationKey).digest('hex'),
        jwk, plan:'plus', issued_at:claims.iat, expires_at:claims.exp, verification_time:now,
        proof_base64:Buffer.from(proofData.proof).toString('base64'), public_inputs:proofData.publicInputs};
    const serialized = JSON.stringify(bundle,null,2);
    const privacyCheck = ![token,token.split('.')[1],privateEmail,claims.sub,claims['https://api.openai.com/auth'].chatgpt_account_id]
        .some(secret=>serialized.includes(secret));
    if (!verified || !tamperedPlanRejected || !privacyCheck) throw new Error('proof_or_privacy_check_failed');
    await writeFile(new URL('demo-proof.json',artifact),serialized+'\n');
    await writeFile(new URL('verification-key.bin',artifact),verificationKey);
    const report = {synthetic_only:true,official_openai_proof_generated:false,
        verified,tamperedPlanRejected,privacyCheck,checks,
        proveSeconds,proofBytes:proofData.proof.length,publicInputs:proofData.publicInputs.length,
        elapsedSeconds:(performance.now()-started)/1000};
    await writeFile(new URL('demo-result.json',artifact),JSON.stringify(report,null,2)+'\n');
    console.log(JSON.stringify(report));
} finally { await backend.destroy(); }
