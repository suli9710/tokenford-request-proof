// Experimental bridge: one signed credential equals the hidden bytes in MPC-TLS.
use jwt::JWT;
use base64::BASE64_URL_DECODER;
use json_parser::JSON2kb;
use sha256::sha256_var;

global MAX_DATA: u32 = 2048;
global MAX_TOKEN: u32 = 2400;

fn main(
    data: BoundedVec<u8, MAX_DATA>,
    payload_start: u32,
    signature_limbs: [u128; 18],
    full_token: BoundedVec<u8, MAX_TOKEN>,
    token_blinder: [u8; 16],
    account_blinder: [u8; 16],
    metadata_values: [BoundedVec<u8, 384>; 8],
    metadata_blinders: [[u8; 16]; 8],
    modulus: pub [u128; 18],
    reduction: pub [u128; 18],
    plan_code: pub u8,
    issued_at: pub u64,
    expires_at: pub u64,
    verification_time: pub u64,
    account_hash: pub [u8; 32],
    token_commitment: pub [u8; 32],
    account_commitment: pub [u8; 32],
    metadata_count: pub u8,
    metadata_lengths: pub [u32; 8],
    metadata_commitments: pub [[u8; 32]; 8],
) {
    // Hidden response values cannot contain JSON terminators/escapes or HTTP
    // controls. Their exact plaintext, lengths and order come from MPC-TLS.
    assert(metadata_count <= 8);
    for slot in 0..8 {
        if slot < metadata_count as u32 {
            let value = metadata_values[slot];
            assert(value.len() > 0);
            assert(value.len() <= 384);
            assert(value.len() == metadata_lengths[slot]);
            let mut preimage: [u8; 400] = [0; 400];
            for i in 0..384 {
                if i < value.len() {
                    let c = value.storage()[i];
                    assert((c >= 32) & (c <= 126) & (c != 34) & (c != 92));
                    preimage[i] = c;
                }
            }
            for i in 0..16 { preimage[value.len() + i] = metadata_blinders[slot][i]; }
            assert(sha256_var(preimage, (value.len() + 16) as u64) == metadata_commitments[slot]);
        } else {
            assert(metadata_lengths[slot] == 0);
            assert(metadata_commitments[slot] == [0; 32]);
        }
    }
    assert(payload_start > 0);
    assert(payload_start < data.len());
    let signed = data.storage();
    for i in 0..MAX_DATA {
        if i < data.len() {
            let c = signed[i];
            if i == payload_start - 1 {
                assert(c == 46);
            } else {
                assert(((c >= 65) & (c <= 90)) | ((c >= 97) & (c <= 122))
                    | ((c >= 48) & (c <= 57)) | (c == 45) | (c == 95));
            }
        }
    }
    JWT::init(data, payload_start, modulus, reduction, signature_limbs).verify();

    // Bind the ENTIRE Authorization JWT, including its RSA signature.
    assert(full_token.len() == data.len() + 343);
    let token = full_token.storage();
    for i in 0..MAX_DATA { if i < data.len() { assert(token[i] == signed[i]); } }
    assert(token[data.len()] == 46);
    let mut encoded_signature: [u8; 342] = [0; 342];
    for i in 0..342 { encoded_signature[i] = token[data.len() + 1 + i]; }
    let signature: BoundedVec<u8, 256> = BASE64_URL_DECODER::decode_var::<342, 256>(
        BoundedVec::<u8, 342>::from_array(encoded_signature),
    );
    assert(signature.len() == 256);
    let sig = signature.storage();
    for i in 0..18 {
        let mut limb: u128 = 0;
        for j in 0..15 {
            if i * 15 + j < 256 {
                limb = limb + ((sig[255 - (i * 15 + j)] as u128) << ((8 * j) as u128));
            }
        }
        assert(limb == signature_limbs[i]);
    }
    let mut token_preimage: [u8; 2416] = [0; 2416];
    for i in 0..MAX_TOKEN { if i < full_token.len() { token_preimage[i] = token[i]; } }
    for i in 0..16 { token_preimage[full_token.len() + i] = token_blinder[i]; }
    // TLSNotary alpha.14 uses SHA256(plaintext || random 16-byte blinder).
    assert(sha256_var(token_preimage, (full_token.len() + 16) as u64) == token_commitment);

    let mut encoded: [u8; MAX_DATA] = [0; MAX_DATA];
    for i in 0..MAX_DATA {
        if i < data.len() - payload_start { encoded[i] = signed[i + payload_start]; }
    }
    let payload: BoundedVec<u8, 1536> = BASE64_URL_DECODER::decode_var(
        BoundedVec::from_parts(encoded, data.len() - payload_start),
    );
    let mut padded: [u8; 2048] = [32; 2048];
    for i in 0..1536 { if i < payload.len() { padded[i] = payload.storage()[i]; } }
    let json = JSON2kb::parse_json(padded);
    let issuer: BoundedVec<u8, 64> = json.get_string("iss".as_bytes()).unwrap();
    assert(issuer == BoundedVec::from_array("https://auth.openai.com".as_bytes()));
    let auth = json.get_object("https://api.openai.com/auth".as_bytes()).unwrap();
    let account: BoundedVec<u8, 64> = auth.get_string("chatgpt_account_id".as_bytes()).unwrap();
    assert(account.len() > 0);
    let domain = "TokenFord plan proof v1:".as_bytes();
    let mut account_preimage: [u8; 96] = [0; 96];
    for i in 0..24 { account_preimage[i] = domain[i]; }
    for i in 0..64 { if i < account.len() { account_preimage[24 + i] = account.storage()[i]; } }
    assert(sha256_var(account_preimage, (24 + account.len()) as u64) == account_hash);
    let mut hidden_account: [u8; 80] = [0; 80];
    for i in 0..64 { if i < account.len() { hidden_account[i] = account.storage()[i]; } }
    for i in 0..16 { hidden_account[account.len() + i] = account_blinder[i]; }
    assert(sha256_var(hidden_account, (account.len() + 16) as u64) == account_commitment);

    let plan: BoundedVec<u8, 32> = auth.get_string("chatgpt_plan_type".as_bytes()).unwrap();
    assert(plan_code <= 3);
    if plan_code == 0 { assert(plan == BoundedVec::from_array("free".as_bytes())); }
    else if plan_code == 1 { assert(plan == BoundedVec::from_array("plus".as_bytes())); }
    else if plan_code == 2 { assert(plan == BoundedVec::from_array("team".as_bytes())); }
    else { assert(plan == BoundedVec::from_array("pro".as_bytes())); }
    assert(json.get_number("iat".as_bytes()).unwrap() == issued_at);
    assert(json.get_number("exp".as_bytes()).unwrap() == expires_at);
    assert(issued_at <= verification_time);
    assert(verification_time < expires_at);
}
