// PROTOTYPE: prove signed plan claims while keeping the JWT private.
use jwt::JWT;
use base64::BASE64_URL_DECODER;
use json_parser::JSON2kb;
use sha256::sha256_var;

global MAX_DATA: u32 = 2048;

fn main(
    data: BoundedVec<u8, MAX_DATA>,
    payload_start: u32,
    signature_limbs: [u128; 18],
    modulus: pub [u128; 18],
    reduction: pub [u128; 18],
    plan_code: pub u8,
    issued_at: pub u64,
    expires_at: pub u64,
    verification_time: pub u64,
    account_hash: pub [u8; 32],
) {
    assert(payload_start > 0);
    assert(payload_start < data.len());
    let signed = data.storage();
    // Require one separator, preventing a prover from decoding another segment.
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
    let mut encoded: [u8; MAX_DATA] = [0; MAX_DATA];
    for i in 0..MAX_DATA {
        if i < data.len() - payload_start {
            encoded[i] = signed[i + payload_start];
        }
    }
    let payload: BoundedVec<u8, 1536> = BASE64_URL_DECODER::decode_var(
        BoundedVec::from_parts(encoded, data.len() - payload_start),
    );
    let mut padded: [u8; 2048] = [32; 2048];
    for i in 0..1536 {
        if i < payload.len() {
            padded[i] = payload.storage()[i];
        }
    }
    let json = JSON2kb::parse_json(padded);
    let issuer: BoundedVec<u8, 64> = json.get_string("iss".as_bytes()).unwrap();
    assert(issuer == BoundedVec::from_array("https://auth.openai.com".as_bytes()));
    let auth = json.get_object("https://api.openai.com/auth".as_bytes()).unwrap();
    let account: BoundedVec<u8, 64> = auth.get_string("chatgpt_account_id".as_bytes()).unwrap();
    assert(account.len() > 0);
    let domain = "TokenFord plan proof v1:".as_bytes();
    let mut account_preimage: [u8; 96] = [0; 96];
    for i in 0..24 { account_preimage[i] = domain[i]; }
    for i in 0..64 {
        if i < account.len() { account_preimage[24 + i] = account.storage()[i]; }
    }
    assert(sha256_var(account_preimage, (24 + account.len()) as u64) == account_hash);
    let plan: BoundedVec<u8, 32> = auth.get_string("chatgpt_plan_type".as_bytes()).unwrap();
    assert(plan_code <= 3);
    if plan_code == 0 {
        assert(plan == BoundedVec::from_array("free".as_bytes()));
    } else if plan_code == 1 {
        assert(plan == BoundedVec::from_array("plus".as_bytes()));
    } else if plan_code == 2 {
        assert(plan == BoundedVec::from_array("team".as_bytes()));
    } else {
        assert(plan == BoundedVec::from_array("pro".as_bytes()));
    }
    assert(json.get_number("iat".as_bytes()).unwrap() == issued_at);
    assert(json.get_number("exp".as_bytes()).unwrap() == expires_at);
    assert(issued_at <= verification_time);
    assert(verification_time < expires_at);
}
