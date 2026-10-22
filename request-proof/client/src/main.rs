//! Isolated, interactive user verifier. Never trusts a serialized "verified" flag.
#[cfg(tlsn_insecure)]
compile_error!("Insecure TLSNotary builds must never produce a verification result");
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use rangeset::set::RangeSet;
mod privacy;
mod transport;
use std::{env, ops::Range, path::PathBuf, process::Stdio, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::{io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, process::Command};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tlsn::{
    config::{prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig, TlsCommitProtocolConfig}, verifier::VerifierConfig},
    connection::ServerName, hash::HashAlgId,
    transcript::{Direction, PartialTranscript, TranscriptCommitConfig, TranscriptCommitment,
        TranscriptCommitmentKind, TranscriptSecret},
    verifier::VerifierOutput, webpki::{CertificateDer, RootCertStore}, Session,
};
const MAX_SENT: usize = 4096;
const MAX_RECV: usize = 65536;
const MAX_FRAME: usize = 131072;
const PATH: &str = "/backend-api/codex/responses";

#[derive(Serialize, Deserialize, Clone)]
struct Challenge { nonce: String, issued_at: u64, body_base64: String, model: String }
#[derive(Deserialize)]
struct PrivateInput { token: String, account_id: String, fixture_port: Option<u16>, fixture_attack: Option<String>,
    #[serde(skip)]server_policy:Option<transport::ServerPolicy> }

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }
fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_owned() }
fn domain(fixture: bool) -> &'static str { if fixture { "proof-fixture.invalid" } else { "chatgpt.com" } }
fn roots(fixture: bool) -> Result<RootCertStore> {
    if fixture { Ok(RootCertStore { roots: vec![CertificateDer(std::fs::read(root().join("fixture/ca.der"))?)] }) }
    else { Ok(RootCertStore::mozilla()) }
}
async fn send_json<T: AsyncWrite+Unpin>(socket: &mut T, value: &impl Serialize) -> Result<()> {
    let raw = serde_json::to_vec(value)?; ensure!(raw.len() <= MAX_FRAME, "frame_limit");
    socket.write_u32(raw.len() as u32).await?; socket.write_all(&raw).await?; socket.flush().await?; Ok(())
}
async fn recv_json<T: for<'a> Deserialize<'a>,S:AsyncRead+Unpin>(socket: &mut S) -> Result<T> {
    let size = socket.read_u32().await? as usize; ensure!(size <= MAX_FRAME, "frame_limit");
    let mut raw = vec![0; size]; socket.read_exact(&mut raw).await?; Ok(serde_json::from_slice(&raw)?)
}
fn request(c: &Challenge, host: &str, token: &[u8], account: &[u8]) -> Result<Vec<u8>> {
    ensure!(c.nonce.len() == 64 && c.nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "invalid_challenge_nonce");
    ensure!(!token.iter().chain(account).any(|b|*b==b'\r'||*b==b'\n'),"header_injection");
    let body = B64.decode(&c.body_base64)?;
    let mut out = format!("POST {PATH} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\nauthorization: Bearer ").into_bytes();
    out.extend_from_slice(token); out.extend_from_slice(b"\r\nchatgpt-account-id: ");
    out.extend_from_slice(account);
    out.extend_from_slice(format!("\r\ncontent-type: application/json\r\naccept: text/event-stream\r\nx-tokenford-proof-nonce: {}\r\ncontent-length: {}\r\n\r\n", c.nonce, body.len()).as_bytes());
    out.extend_from_slice(&body); ensure!(out.len() <= MAX_SENT, "request_limit"); Ok(out)
}
fn hidden_range(data: &[u8], prefix: &[u8]) -> Result<Range<usize>> {
    let matches: Vec<_> = data.windows(prefix.len()).enumerate().filter(|(_, x)| *x == prefix).map(|(i, _)|i).collect();
    ensure!(matches.len() == 1, "header_not_unique"); let start = matches[0] + prefix.len();
    let len = data[start..].windows(2).position(|x| x == b"\r\n").context("missing_header_end")?;
    ensure!(len > 0, "empty_credential"); Ok(start..start+len)
}
fn commitment(commits: &[TranscriptCommitment], range: Range<usize>) -> Result<String> {
    range_commitment(commits,Direction::Sent,&RangeSet::from(range))
}
fn range_commitment(commits:&[TranscriptCommitment],direction:Direction,range:&RangeSet<usize>)->Result<String>{
    let matches: Vec<_> = commits.iter().filter_map(|c| match c {
        TranscriptCommitment::Hash(h) if h.direction == direction && &h.idx == range
            && h.hash.alg == HashAlgId::SHA256 => Some(hex::encode(h.hash.value.as_bytes())), _ => None }).collect();
    ensure!(matches.len() == 1, "authenticated_commitment_missing_or_not_unique"); Ok(matches[0].clone())
}
fn blinder(secrets: &[TranscriptSecret], range: Range<usize>) -> Result<String> {
    range_blinder(secrets,Direction::Sent,&RangeSet::from(range))
}
fn range_blinder(secrets:&[TranscriptSecret],direction:Direction,range:&RangeSet<usize>)->Result<String>{
    for s in secrets { let TranscriptSecret::Hash(h) = s else { continue; };
        if h.direction == direction && &h.idx == range && h.alg == HashAlgId::SHA256 {
            return Ok(hex::encode(h.blinder.as_bytes()));
        }
    } bail!("commitment_blinder_missing")
}
#[cfg(test)]
fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let end = input.windows(2).position(|x|x==b"\r\n").context("truncated_chunk_header")?;
        let size = std::str::from_utf8(&input[..end])?;
        ensure!(!size.is_empty() && size.len() <= 8 && size.bytes().all(|b|b.is_ascii_hexdigit()), "unsupported_chunk_header");
        let n = usize::from_str_radix(size,16)?; input=&input[end+2..];
        if n == 0 { ensure!(input==b"\r\n", "unsupported_trailers_or_trailing_data"); break; }
        ensure!(n <= MAX_RECV && n+2 <= input.len() && &input[n..n+2]==b"\r\n", "truncated_chunk_data");
        output.extend_from_slice(&input[..n]); input=&input[n+2..];
        ensure!(output.len() <= MAX_RECV, "decoded_body_limit");
    }
    Ok(output)
}
async fn bridge(mode: &str, fixture: bool, value: Value) -> Result<Value> {
    let script = root().parent().unwrap().join("zk-prototype/request_bridge.mjs");
    let mut command = Command::new("node");
    command.arg("--max-old-space-size=16384").arg(script).arg(mode);
    if fixture { command.arg("--fixture"); }
    let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true).spawn()?;
    let mut input = child.stdin.take().context("bridge_stdin")?;
    input.write_all(&serde_json::to_vec(&value)?).await?; input.shutdown().await?; drop(input);
    let output = tokio::time::timeout(Duration::from_secs(150), child.wait_with_output()).await??;
    ensure!(output.status.success(), "credential_bridge_failed");
    // WASM dependencies may print diagnostics; only the final JSON record is data.
    let text = std::str::from_utf8(&output.stdout).context("invalid_bridge_utf8")?;
    let record = text.lines().rev().find(|l| l.starts_with('{')).context("bridge_result_missing")?;
    Ok(serde_json::from_str(record).context("invalid_bridge_result")?)
}
fn validate_transcript(t: &PartialTranscript, c: &Challenge, host: &str,
    commits: &[TranscriptCommitment]) -> Result<(String, String, Vec<u8>,Vec<Value>)> {
    let sent = t.sent_unsafe();
    let token = hidden_range(sent, b"\r\nauthorization: Bearer ")?;
    let account = hidden_range(sent, b"\r\nchatgpt-account-id: ")?;
    ensure!(token.len() <= 2400 && account.len() <= 64 && token.end < account.start, "credential_bounds");
    ensure!(t.sent_unauthed() == RangeSet::from([token.clone(), account.clone()]), "unexpected_request_redaction");
    ensure!(sent == request(c, host, &vec![0;token.len()], &vec![0;account.len()])?, "request_or_nonce_changed");
    let(body,groups)=privacy::authenticated_view(t.received_unsafe(),&t.received_unauthed())?;
    let mut metadata=Vec::new();
    for group in groups{metadata.push(json!({"bytes":group.iter().map(|r|r.len()).sum::<usize>(),
        "commitment":range_commitment(commits,Direction::Received,&group)?}));}
    let text = std::str::from_utf8(&body)?;
    let mut completed = false;
    for event in text.replace("\r\n", "\n").split("\n\n").filter(|x| !x.trim().is_empty()) {
        let values: Vec<_> = event.lines().filter_map(|l| l.strip_prefix("data: ")).collect();
        ensure!(values.len() == 1, "unsupported_sse_frame");
        if values[0] == "[DONE]" { ensure!(completed, "done_before_completion"); continue; }
        ensure!(!completed, "events_after_completion");
        let data: Value = serde_json::from_str(values[0])?;
        ensure!(!matches!(data["type"].as_str(), Some("error"|"response.failed"|"response.incomplete")), "upstream_failure_event");
        if data["type"] == "response.completed" {
            ensure!(data["response"]["status"] == "completed" && data["response"]["model"] == c.model, "response_model_or_status_mismatch");
            completed = true;
        }
    }
    ensure!(completed && text.ends_with("\n\n"), "missing_complete_terminal_event");
    Ok((commitment(commits, token)?, commitment(commits, account)?, body,metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunked_framing_is_complete_and_unambiguous() {
        assert_eq!(decode_chunked(b"2\r\nOK\r\n0\r\n\r\n").unwrap(), b"OK");
        assert!(decode_chunked(b"2\r\nO\r\n0\r\n\r\n").is_err());
        assert!(decode_chunked(b"2\r\nOK\r\n0\r\n\r\nextra").is_err());
        assert!(decode_chunked(b"2\r\nOK\r\n").is_err());
    }
    #[test]
    fn challenge_cannot_inject_headers() {
        let c=Challenge{nonce:"\r\n".to_owned()+&"a".repeat(62), issued_at:0, body_base64:B64.encode(b"{}"), model:"fixture".into()};
        assert!(request(&c,"proof-fixture.invalid",b"token",b"account").is_err());
    }
}

async fn prover<T:AsyncRead+AsyncWrite+Send+Unpin+'static>(mut socket: T, private: PrivateInput, fixture: bool) -> Result<Value> {
    let mut c: Challenge = recv_json(&mut socket).await?;
    ensure!(now().abs_diff(c.issued_at) <= 120 && c.nonce.len() == 64, "stale_challenge");
    ensure!(B64.decode(&c.body_base64)?.len()<=1024,"prototype_body_limit");
    if let Some(policy)=&private.server_policy{policy.authorize(&c)?;}
    ensure!(!private.token.contains(['\r','\n']) && !private.account_id.contains(['\r','\n']), "header_injection");
    ensure!(fixture || private.fixture_attack.is_none(), "fixture_attack_forbidden_in_official_mode");
    if private.fixture_attack.as_deref() == Some("changed-body") {
        let mut body: Value = serde_json::from_slice(&B64.decode(&c.body_base64)?)?;
        body["input"] = json!("Substituted prompt, not the user's request");
        c.body_base64 = B64.encode(serde_json::to_vec(&body)?);
    }
    socket.write_u8(1).await?;socket.flush().await?;
    let sent = request(&c, domain(fixture), private.token.as_bytes(), private.account_id.as_bytes())?;
    let token_range = hidden_range(&sent, b"\r\nauthorization: Bearer ")?;
    let account_range = hidden_range(&sent, b"\r\nchatgpt-account-id: ")?;
    let session = Session::new(socket.compat()); let (driver, mut handle) = session.split(); let task = tokio::spawn(driver);
    let p = handle.new_prover(ProverConfig::builder().build()?)?.commit(TlsCommitConfig::builder()
        .protocol(MpcTlsConfig::builder().max_sent_data(MAX_SENT).max_recv_data(MAX_RECV).build()?).build()?).await?;
    let target = if fixture { format!("127.0.0.1:{}", private.fixture_port.context("fixture_port_missing")?) }
        else { "chatgpt.com:443".to_owned() };
    let upstream = TcpStream::connect(target).await?;
    let (mut tls, future) = p.connect(TlsClientConfig::builder()
        .server_name(ServerName::Dns(domain(fixture).try_into()?)).root_store(roots(fixture)?).build()?, upstream.compat()).await?;
    let tls_task = tokio::spawn(future);
    futures::io::AsyncWriteExt::write_all(&mut tls, &sent).await?;
    futures::io::AsyncWriteExt::flush(&mut tls).await?;
    let mut received = Vec::new(); futures::io::AsyncReadExt::read_to_end(&mut tls, &mut received).await?; drop(tls);
    let mut p = tls_task.await??; let transcript = p.transcript().clone();
    let mut config = ProveConfig::builder(&transcript); config.server_identity();
    config.reveal_sent(&(0..token_range.start))?; config.reveal_sent(&(token_range.end..account_range.start))?;
    config.reveal_sent(&(account_range.end..sent.len()))?;
    let groups=privacy::hidden_groups(&received)?;
    let hidden=privacy::hidden_ranges(&received)?;let mut cursor=0;
    for range in hidden.iter(){if cursor<range.start{config.reveal_recv(&(cursor..range.start))?;}cursor=range.end;}
    if cursor<received.len(){config.reveal_recv(&(cursor..received.len()))?;}
    let mut commit = TranscriptCommitConfig::builder(&transcript);
    commit.default_kind(TranscriptCommitmentKind::Hash { alg: HashAlgId::SHA256 });
    commit.commit_sent(&token_range)?; commit.commit_sent(&account_range)?;
    for group in &groups{commit.commit_recv(group)?;}
    config.transcript_commit(commit.build()?);
    let output = p.prove(&config.build()?).await?; p.close().await?; handle.close();
    let mut socket = task.await??;
    let mut accepted = [0;1]; futures::io::AsyncReadExt::read_exact(&mut socket, &mut accepted).await?;
    ensure!(accepted == [1], "user_rejected_transcript");
    let mut metadata=Vec::new();
    for group in groups {
        let value:Vec<u8>=group.iter().flat_map(|r|received[r].to_vec()).collect();
        metadata.push(json!({"bytes":value.len(),"value_base64":B64.encode(value),
            "commitment":range_commitment(&output.transcript_commitments,Direction::Received,&group)?,
            "blinder":range_blinder(&output.transcript_secrets,Direction::Received,&group)?}));
    }
    let bundle = bridge("prove", fixture, json!({"token":private.token, "verification_time":c.issued_at,
        "token_blinder":blinder(&output.transcript_secrets, token_range.clone())?,
        "account_blinder":blinder(&output.transcript_secrets, account_range.clone())?,
        "token_commitment":commitment(&output.transcript_commitments, token_range)?,
        "account_commitment":commitment(&output.transcript_commitments, account_range)?,"metadata":metadata})).await?;
    let raw = serde_json::to_vec(&bundle)?; ensure!(raw.len() <= MAX_FRAME, "proof_frame_limit");
    futures::io::AsyncWriteExt::write_all(&mut socket, &(raw.len() as u32).to_be_bytes()).await?;
    futures::io::AsyncWriteExt::write_all(&mut socket, &raw).await?;
    futures::io::AsyncWriteExt::close(&mut socket).await?;
    Ok(json!({"proof_delivered":true,"synthetic_only":fixture}))
}
async fn verifier<T:AsyncRead+AsyncWrite+Send+Sync+Unpin+'static>(mut socket: T, c: Challenge, fixture: bool) -> Result<Value> {
    send_json(&mut socket, &c).await?;
    let ready=tokio::time::timeout(Duration::from_secs(15),socket.read_u8()).await??;
    ensure!(ready==1,"prover_not_ready");
    let session = Session::new(socket.compat()); let (driver, mut handle) = session.split(); let task = tokio::spawn(driver);
    let v = handle.new_verifier(VerifierConfig::builder().root_store(roots(fixture)?).build()?)?.commit().await?;
    match v.request().protocol() {
        TlsCommitProtocolConfig::Mpc(config) if config.max_sent_data() <= MAX_SENT && config.max_recv_data() <= MAX_RECV => (),
        _ => { v.reject(Some("MPC-TLS and resource limits required")).await?; bail!("tls_protocol_rejected"); }
    }
    let v = v.accept().await?.run().await?.verify().await?;
    ensure!(v.request().server_identity() && v.request().reveal().is_some(), "identity_or_transcript_not_disclosed");
    let (VerifierOutput {server_name, transcript, transcript_commitments, ..}, v) = v.accept().await?;
    v.close().await?; handle.close(); let mut socket = task.await??;
    let ServerName::Dns(name) = server_name.context("missing_authenticated_server")?;
    ensure!(name.as_str() == domain(fixture), "wrong_authenticated_domain");
    let (token, account, response_body,metadata) = validate_transcript(&transcript.context("no_authenticated_transcript")?, &c,
        domain(fixture), &transcript_commitments)?;
    futures::io::AsyncWriteExt::write_all(&mut socket, &[1]).await?;
    futures::io::AsyncWriteExt::flush(&mut socket).await?;
    let mut size = [0;4]; futures::io::AsyncReadExt::read_exact(&mut socket, &mut size).await?;
    let len = u32::from_be_bytes(size) as usize; ensure!(len <= MAX_FRAME, "proof_frame_limit");
    let mut raw = vec![0;len]; futures::io::AsyncReadExt::read_exact(&mut socket, &mut raw).await?;
    let bundle: Value = serde_json::from_slice(&raw)?;
    let result = bridge("verify", fixture, json!({"bundle":bundle,"verification_time":c.issued_at,
        "token_commitment":token,"account_commitment":account,"metadata":metadata})).await?;
    ensure!(result["verified"] == true && result["plan"] == "plus", "credential_not_verified_or_not_plus");
    ensure!(now().saturating_sub(c.issued_at) <= 120, "verification_deadline_exceeded");
    let mut output_text=String::new();
    for event in std::str::from_utf8(&response_body)?.replace("\r\n","\n").split("\n\n") {
        for line in event.lines().filter_map(|l|l.strip_prefix("data: ")).filter(|l|*l!="[DONE]"){
            let data:Value=serde_json::from_str(line)?;
            if data["type"]=="response.completed" {
                if let Some(items)=data["response"]["output"].as_array(){for item in items {
                    if let Some(parts)=item["content"].as_array(){for part in parts {
                        if part["type"]=="output_text" {output_text.push_str(part["text"].as_str().context("invalid_output_text")?);}
                    }}
                }}
            }
        }
    }
    Ok(json!({"interactive_tls_verified":true,"credential_bound_to_request":true,"plan":result["plan"],
        "synthetic_only":fixture,"official_openai_request_verified":!fixture,"live_subscription_status_verified":false,
        "nonce":c.nonce,"account_hash":result["account_hash"],"request_body_sha256":hex::encode(Sha256::digest(B64.decode(c.body_base64)?)),
        "response_body_sha256":hex::encode(Sha256::digest(&response_body)),"response_body_base64":B64.encode(response_body),
        "response_hash_scope":"authenticated_view_with_redacted_metadata","response_metadata_redacted":true,"verified_output_text":output_text,
        "fresh_verifier_challenge":true,"standalone_replay_verifiable":false}))
}

#[tokio::main]
async fn main() {
    let serving=env::args().nth(1).as_deref()==Some("serve-stdio");
    let result = tokio::time::timeout(Duration::from_secs(180), run()).await;
    match result { Ok(Ok(value)) => {if !serving {println!("{}", value);}},
        Ok(Err(e)) => { eprintln!("verification_or_proving_failed: {}", e.to_string().lines().next().unwrap_or("failure")); std::process::exit(1); },
        Err(_) => { eprintln!("interactive_deadline_exceeded"); std::process::exit(1); } }
}
async fn run() -> Result<Value> {
    let args: Vec<_> = env::args().collect(); ensure!(args.len() >= 2, "mode_required");
    let integrity = Command::new(env::var("PROOF_PYTHON").unwrap_or("python".to_owned()))
        .arg("-B").arg(root().join("check_integrity.py")).arg("--compiled")
        .stdin(Stdio::null()).stderr(Stdio::null()).output().await?;
    ensure!(integrity.status.success(), "reviewed_release_integrity_check_failed");
    let fixture = args.iter().any(|x| x == "--fixture");
    if args[1]=="serve-stdio" {
        let policy=transport::ServerPolicy::load(args.get(2).context("operator_server_policy_missing")?)?;
        let _lease=policy.acquire()?;
        let mut private=transport::load_private(&policy).await?;private.server_policy=Some(policy);
        let socket=transport::framed(tokio::io::stdin(),tokio::io::stdout());
        return prover(socket,private,fixture).await;
    }
    if args[1]=="verify-ssh" || args[1]=="verify-ssh-fixture" {
        let fixture_mode=args[1]=="verify-ssh-fixture";
        ensure!(fixture==fixture_mode,"fixture_ssh_mode_mismatch");
        let config:transport::SshConfig=serde_json::from_slice(&std::fs::read(args.get(2).context("ssh_config_missing")?)?)?;
        ensure!(!fixture || matches!(config.host.as_str(),"127.0.0.1"|"::1"|"localhost"),"fixture_ssh_must_use_loopback");
        let c=challenge(args.get(3).context("body_file_missing")?)?;
        let mut child=transport::ssh(&config)?;
        let socket=transport::framed(child.stdout.take().context("ssh_stdout_missing")?,child.stdin.take().context("ssh_stdin_missing")?);
        let pending=verifier(socket,c,fixture);tokio::pin!(pending);
        let result=tokio::select!{
            result=&mut pending=>result,
            status=child.wait()=>{ensure!(status?.success(),"ssh_remote_prover_failed");pending.await}
        };
        if result.is_err(){let _=child.kill().await;}
        let status=child.wait().await?;ensure!(status.success(),"ssh_remote_prover_failed");return result;
    }
    if args[1]=="verify-stdio-child" {
        ensure!(fixture,"child_mode_is_local_fixture_only");
        let config:transport::ChildConfig=serde_json::from_slice(&std::fs::read(args.get(2).context("child_config_missing")?)?)?;
        let c=challenge(args.get(3).context("body_file_missing")?)?;
        let mut child=transport::child(&config)?;
        let socket=transport::framed(child.stdout.take().context("child_stdout_missing")?,child.stdin.take().context("child_stdin_missing")?);
        let result=verifier(socket,c,true).await;
        if result.is_err(){let _=child.kill().await;}
        let status=child.wait().await?;ensure!(status.success(),"child_prover_failed");return result;
    }
    let port: u16 = args.get(2).context("port_missing")?.parse()?;
    let address = format!("127.0.0.1:{port}");
    match args[1].as_str() {
        "verifier" => {
            let c=challenge(args.get(3).context("request_body_file_missing")?)?;
            let listener = TcpListener::bind(address).await?; eprintln!("user_verifier_ready");
            let (socket, _) = listener.accept().await?; verifier(socket, c, fixture).await
        },
        "prover" => {
            let mut raw = Vec::new(); tokio::io::stdin().take(MAX_FRAME as u64).read_to_end(&mut raw).await?;
            let private: PrivateInput = serde_json::from_slice(&raw)?; raw.fill(0);
            prover(TcpStream::connect(address).await?, private, fixture).await
        },
        _ => bail!("unsupported_mode"),
    }
}
fn challenge(path:&str)->Result<Challenge>{
    let body=std::fs::read(path)?;ensure!(body.len()<=1024,"prototype_body_limit");
    let request:Value=serde_json::from_slice(&body)?;
    let model=request["model"].as_str().context("model_missing")?.to_owned();
    Ok(Challenge{nonce:hex::encode(rand::random::<[u8;32]>()),issued_at:now(),body_base64:B64.encode(body),model})
}
