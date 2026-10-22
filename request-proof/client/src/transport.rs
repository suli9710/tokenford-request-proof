//! SSH carries the interactive protocol; it never decides whether proof is valid.
use anyhow::{ensure,Context,Result};
use serde::Deserialize;
use std::{process::Stdio,time::Duration};
use tokio::{io::{AsyncRead,AsyncWrite,AsyncReadExt,AsyncWriteExt},process::{Child,Command}};
use crate::{PrivateInput,MAX_FRAME};
/// Stdio cannot signal a TCP-style half-close. Explicit bounded frames carry EOF.
pub fn framed<R:AsyncRead+Send+Unpin+'static,W:AsyncWrite+Send+Unpin+'static>(mut reader:R,mut writer:W)->tokio::io::DuplexStream{
    let(app,wire)=tokio::io::duplex(65536);let(mut outgoing,mut incoming)=tokio::io::split(wire);
    tokio::spawn(async move{
        let receive=async{
            let mut count=0usize;
            loop{
                let n=reader.read_u32().await? as usize;
                if n==0{incoming.shutdown().await?;break;}
                ensure!(n<=65536,"transport_frame_limit");count+=n;ensure!(count<=512*1024*1024,"transport_session_limit");
                let mut bytes=vec![0;n];reader.read_exact(&mut bytes).await?;incoming.write_all(&bytes).await?;
            }Ok::<_,anyhow::Error>(())
        };
        let send=async{
            let mut bytes=vec![0;65536];let mut count=0usize;
            loop{let n=outgoing.read(&mut bytes).await?;count+=n;ensure!(count<=512*1024*1024,"transport_session_limit");
                writer.write_u32(n as u32).await?;
                if n>0{writer.write_all(&bytes[..n]).await?;}
                writer.flush().await?;if n==0{break;}
            }Ok::<_,anyhow::Error>(())
        };
        let _=tokio::try_join!(receive,send);
    });app
}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
pub struct SshConfig{pub host:String,pub user:String,pub port:u16,pub identity_file:String,pub known_hosts_file:String}
pub fn ssh(config:&SshConfig)->Result<Child>{
    ensure!(!config.host.is_empty()&&!config.host.starts_with('-')&&config.host.bytes().all(|b|b.is_ascii_alphanumeric()||b".-:".contains(&b)),"invalid_ssh_host");
    ensure!(!config.user.is_empty()&&!config.user.starts_with('-')&&config.user.bytes().all(|b|b.is_ascii_alphanumeric()||b"_-".contains(&b)),"invalid_ssh_user");
    ensure!(config.port>0 && std::path::Path::new(&config.identity_file).is_file() && std::path::Path::new(&config.known_hosts_file).is_file(),"ssh_trust_files_required");
    let mut c=Command::new("ssh");
    c.arg("-F").arg(if cfg!(windows){"NUL"}else{"/dev/null"}).args(["-T","-p"]).arg(config.port.to_string())
        .args(["-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","IdentitiesOnly=yes",
            "-o","ForwardAgent=no","-o","ClearAllForwardings=yes","-o","ConnectTimeout=10",
            "-o","ServerAliveInterval=15","-o","ServerAliveCountMax=2","-o","PermitLocalCommand=no"])
        .arg("-o").arg(format!("UserKnownHostsFile={}",quote_ssh_path(&config.known_hosts_file)?))
        .arg("-o").arg(format!("GlobalKnownHostsFile={}",if cfg!(windows){"NUL"}else{"/dev/null"}))
        .arg("-i").arg(&config.identity_file).arg("-l").arg(&config.user).arg(&config.host).arg("tokenford-proof-stdio")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true);
    Ok(c.spawn()?)
}
fn quote_ssh_path(path:&str)->Result<String>{
    ensure!(!path.contains(['\r','\n','"','%']),"unsafe_ssh_trust_path");
    Ok(format!("\"{}\"",path.replace('\\',"/")))
}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
pub struct ChildConfig{pub executable:String,pub args:Vec<String>}
pub fn child(config:&ChildConfig)->Result<Child>{
    ensure!(config.args.len()<=8,"fixture_child_argument_limit");
    Ok(Command::new(&config.executable).args(&config.args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true).spawn()?)
}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
pub struct ServerPolicy{pub allowed_models:Vec<String>,pub provider_executable:String,
    pub provider_args:Vec<String>,pub busy_lock:String}
pub struct Lease{path:std::path::PathBuf}
impl Drop for Lease{fn drop(&mut self){let _=std::fs::remove_file(&self.path);}}
impl ServerPolicy {
    pub fn load(path:&str)->Result<Self>{
        let raw=std::fs::read(path)?;ensure!(raw.len()<=16384,"server_policy_limit");
        let policy:Self=serde_json::from_slice(&raw)?;
        ensure!(!policy.allowed_models.is_empty()&&policy.allowed_models.len()<=8&&policy.provider_args.len()<=8,"invalid_server_policy");
        ensure!(std::path::Path::new(&policy.provider_executable).is_absolute()&&std::path::Path::new(&policy.busy_lock).is_absolute(),"server_paths_must_be_absolute");Ok(policy)
    }
    pub fn acquire(&self)->Result<Lease>{
        use std::io::Write;
        let mut opts=std::fs::OpenOptions::new();opts.write(true).create_new(true);
        #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;opts.mode(0o600);}
        let mut file=opts.open(&self.busy_lock).context("server_busy_or_stale_lock_requires_operator_review")?;
        writeln!(file,"{}",std::process::id())?;Ok(Lease{path:self.busy_lock.clone().into()})
    }
    pub fn authorize(&self,c:&crate::Challenge)->Result<()> {
        use base64::Engine;
        ensure!(self.allowed_models.iter().any(|m|m==&c.model),"model_not_allowed_by_server");
        let body=base64::engine::general_purpose::STANDARD.decode(&c.body_base64)?;
        ensure!(body.len()<=1024,"prototype_body_limit");
        let value:serde_json::Value=serde_json::from_slice(&body)?;
        let object=value.as_object().context("request_must_be_object")?;
        ensure!(object.keys().all(|k|matches!(k.as_str(),"model"|"input"|"instructions"|"stream"|"store"|"reasoning"|"text")),"request_field_not_allowed_by_server");
        ensure!(value["model"].as_str()==Some(&c.model)&&value["stream"]==true&&value["store"]==false,"request_policy_mismatch");Ok(())
    }
}
pub async fn load_private(policy:&ServerPolicy)->Result<PrivateInput>{
    // Administrator-owned executable; no client-controlled executable or args.
    let mut child=Command::new(&policy.provider_executable).args(&policy.provider_args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true).spawn()?;
    let mut stdout=child.stdout.take().context("provider_stdout_missing")?;let mut raw=Vec::new();
    tokio::time::timeout(Duration::from_secs(10),(&mut stdout).take(MAX_FRAME as u64+1).read_to_end(&mut raw)).await??;
    ensure!(raw.len()<=MAX_FRAME,"provider_response_limit");
    let status=tokio::time::timeout(Duration::from_secs(10),child.wait()).await??;ensure!(status.success(),"credential_provider_failed");
    let parsed=serde_json::from_slice(&raw).context("invalid_private_provider_response");raw.fill(0);parsed
}

#[cfg(test)]mod tests{
    use super::*;
    #[tokio::test]async fn framing_peer_failure_reaches_caller(){
        let(peer,wire)=tokio::io::duplex(64);let(read,write)=tokio::io::split(wire);drop(peer);
        let mut app=framed(read,write);let mut byte=[0];
        let outcome=tokio::time::timeout(Duration::from_millis(500),app.read(&mut byte)).await;
        assert!(matches!(outcome,Ok(Ok(0))|Ok(Err(_))));
    }
}
