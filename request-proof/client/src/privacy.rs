//! Selectively hide only allowlisted metadata values, never response content.
use anyhow::{ensure, Context, Result};
use rangeset::set::RangeSet;
use serde_json::Value;
use std::{collections::HashSet, ops::Range};
const LIMIT: usize=65536;

fn parse_body(raw: &[u8]) -> Result<(Vec<u8>, Vec<usize>, Vec<Range<usize>>)> {
    ensure!(raw.len()<=LIMIT,"response_limit");
    let end=raw.windows(4).position(|w|w==b"\r\n\r\n").context("response_headers_missing")?+4;
    let headers=std::str::from_utf8(&raw[..end])?;
    ensure!(headers.starts_with("HTTP/1.1 200 "),"upstream_status_not_200");
    let mut length=None;let mut chunked=false;let mut metadata=Vec::new();let mut cursor=0;
    for (i,line) in headers.split("\r\n").enumerate() {
        if i>0 && !line.is_empty() {
            let (key,value)=line.split_once(':').context("malformed_response_header")?;
            ensure!(!key.is_empty() && key.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'),"invalid_header_name");
            match key.to_ascii_lowercase().as_str() {
                "content-length"=> {ensure!(length.is_none(),"duplicate_content_length");length=Some(value.trim().parse::<usize>()?);},
                "transfer-encoding"=> {ensure!(!chunked && value.trim().eq_ignore_ascii_case("chunked"),"unsupported_transfer_encoding");chunked=true;},
                "content-encoding"=>anyhow::bail!("unsupported_response_compression"),
                "set-cookie"|"openai-organization"|"openai-project"=> {
                    if !value.is_empty(){metadata.push(cursor+key.len()+1..cursor+line.len());}
                },
                _=>(),
            }
        }
        cursor+=line.len()+2;
    }
    ensure!(!(chunked&&length.is_some()),"ambiguous_response_framing");
    if let Some(n)=length {ensure!(n==raw.len()-end,"truncated_response");}
    if !chunked {return Ok((raw[end..].to_vec(),(end..raw.len()).collect(),metadata));}
    let mut body=Vec::new();let mut mapping=Vec::new();let mut pos=end;
    loop {
        let n=raw[pos..].windows(2).position(|w|w==b"\r\n").context("truncated_chunk_header")?;
        let size=std::str::from_utf8(&raw[pos..pos+n])?;
        ensure!(!size.is_empty()&&size.len()<=8&&size.bytes().all(|b|b.is_ascii_hexdigit()),"unsupported_chunk_header");
        let count=usize::from_str_radix(size,16)?;pos+=n+2;
        if count==0 {ensure!(&raw[pos..]==b"\r\n","unsupported_trailers_or_trailing_data");break;}
        ensure!(count<=LIMIT && pos+count+2<=raw.len() && &raw[pos+count..pos+count+2]==b"\r\n","truncated_chunk_data");
        body.extend_from_slice(&raw[pos..pos+count]);mapping.extend(pos..pos+count);pos+=count+2;
    }
    Ok((body,mapping,metadata))
}

struct JsonFields<'a>{data:&'a[u8],pos:usize,hidden:Vec<Range<usize>>}
impl JsonFields<'_> {
    fn ws(&mut self){while self.pos<self.data.len()&&self.data[self.pos].is_ascii_whitespace(){self.pos+=1;}}
    fn string(&mut self)->Result<(String,Range<usize>)>{
        ensure!(self.data.get(self.pos)==Some(&b'"'),"json_string_expected");let start=self.pos;self.pos+=1;
        loop {
            let b=*self.data.get(self.pos).context("unterminated_json_string")?;self.pos+=1;
            if b==b'"'{break;}
            if b==b'\\'{ensure!(self.pos<self.data.len(),"truncated_json_escape");self.pos+=1;}
        }
        let value:String=serde_json::from_slice(&self.data[start..self.pos])?;
        Ok((value,start+1..self.pos-1))
    }
    fn value(&mut self,context:u8,depth:usize)->Result<()> {
        ensure!(depth<=32,"json_nesting_limit");self.ws();
        match self.data.get(self.pos).copied().context("truncated_json_value")? {
            b'{'=>{
                self.pos+=1;self.ws();let mut keys=HashSet::new();
                if self.data.get(self.pos)==Some(&b'}'){self.pos+=1;return Ok(());}
                loop {
                    self.ws();let(key,_)=self.string()?;ensure!(keys.insert(key.clone()),"duplicate_json_key");
                    self.ws();ensure!(self.data.get(self.pos)==Some(&b':'),"json_colon_expected");self.pos+=1;self.ws();
                    if context==1 && matches!(key.as_str(),"safety_identifier"|"prompt_cache_key") {
                        if self.data.get(self.pos)==Some(&b'"') {let(_,range)=self.string()?;if !range.is_empty(){self.hidden.push(range);}}
                        else {ensure!(self.data.get(self.pos..self.pos+4)==Some(b"null"),"metadata_must_be_string_or_null");self.pos+=4;}
                    } else {self.value(if context==0&&key=="response"{1}else{2},depth+1)?;}
                    self.ws();match self.data.get(self.pos){Some(b',')=>self.pos+=1,Some(b'}')=>{self.pos+=1;break;},_=>anyhow::bail!("json_object_not_terminated")}
                }
            },
            b'['=>{
                self.pos+=1;self.ws();if self.data.get(self.pos)==Some(&b']'){self.pos+=1;return Ok(());}
                loop{self.value(2,depth+1)?;self.ws();match self.data.get(self.pos){Some(b',')=>self.pos+=1,Some(b']')=>{self.pos+=1;break;},_=>anyhow::bail!("json_array_not_terminated")}}
            },
            b'"'=>{self.string()?;},
            _=>{let start=self.pos;while self.pos<self.data.len()&&!b",]} \r\n\t".contains(&self.data[self.pos]){self.pos+=1;}ensure!(self.pos>start,"invalid_json_scalar");},
        }
        Ok(())
    }
}
fn json_ranges(raw:&[u8])->Result<Vec<Range<usize>>>{
    let _:Value=serde_json::from_slice(raw)?;
    let mut fields=JsonFields{data:raw,pos:0,hidden:Vec::new()};fields.value(0,0)?;fields.ws();
    ensure!(fields.pos==raw.len(),"trailing_json_data");Ok(fields.hidden)
}

/// Ranges can only cover response-level allowlisted JSON string interiors and
/// allowlisted HTTP header values. Framing, keys, quotes and content stay visible.
pub fn hidden_groups(raw:&[u8])->Result<Vec<RangeSet<usize>>>{
    let(body,mapping,metadata)=parse_body(raw)?;
    let mut groups:Vec<RangeSet<usize>>=metadata.into_iter().map(RangeSet::from).collect();let mut offset=0;
    for line in body.split_inclusive(|b|*b==b'\n') {
        let mut end=line.len();if end>0&&line[end-1]==b'\n'{end-=1;}if end>0&&line[end-1]==b'\r'{end-=1;}
        if line.starts_with(b"data: ") && &line[6..end]!=b"[DONE]" {
            for range in json_ranges(&line[6..end])? {
                let ranges:Vec<_>=(offset+6+range.start..offset+6+range.end).map(|i|mapping[i]..mapping[i]+1).collect();
                groups.push(RangeSet::from(ranges));
            }
        }
        offset+=line.len();
    }
    ensure!(groups.len()<=8&&groups.iter().all(|g|g.iter().map(|r|r.len()).sum::<usize>()<=384),"response_metadata_limit");
    Ok(groups)
}
pub fn hidden_ranges(raw:&[u8])->Result<RangeSet<usize>>{
    let ranges:Vec<_>=hidden_groups(raw)?.into_iter().flat_map(|g|g.iter().collect::<Vec<_>>()).collect();Ok(RangeSet::from(ranges))
}

pub fn authenticated_view(raw:&[u8],unauthenticated:&RangeSet<usize>)->Result<(Vec<u8>,Vec<RangeSet<usize>>)>{
    let mut sanitized=raw.to_vec();
    for range in unauthenticated.iter(){sanitized[range.clone()].fill(b'0');}
    ensure!(*unauthenticated==hidden_ranges(&sanitized)?,"unexpected_response_redaction");
    let groups=hidden_groups(&sanitized)?;
    let(body,_,_)=parse_body(&sanitized)?;Ok((body,groups))
}

#[cfg(test)]mod tests {
    use super::*;
    fn response(body:&[u8])->Vec<u8>{let mut out=format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nset-cookie: secret-cookie\r\n\r\n",body.len()).into_bytes();out.extend(body);out}
    #[test]fn metadata_hidden_without_hiding_output(){
        let body=br#"data: {"type":"response.completed","response":{"safety_identifier":"user-secret","prompt_cache_key":"cache-secret","model":"gpt","output":[{"content":[{"text":"visible"}]}]}}

"#;
        let raw=response(body);let ranges=hidden_ranges(&raw).unwrap();let mut partial=raw.clone();for range in ranges.iter(){partial[range.clone()].fill(0);}
        let(view,_)=authenticated_view(&partial,&ranges).unwrap();let text=String::from_utf8(view).unwrap();
        assert!(!text.contains("user-secret"));assert!(!text.contains("cache-secret"));assert!(text.contains("visible"));
        let model=partial.windows(3).position(|x|x==b"gpt").unwrap();let mut malicious:Vec<_>=ranges.iter().collect();malicious.push(model..model+3);
        assert!(authenticated_view(&partial,&RangeSet::from(malicious)).is_err());
    }
    #[test]fn duplicates_and_false_keys_are_rejected(){
        assert!(json_ranges(br#"{"response":{"model":"gpt","model":"fake"}}"#).is_err());
        assert!(json_ranges(br#"{"response":{"safety_identifier":{"text":"secret"}}}"#).is_err());
        assert!(json_ranges(br#"{"text":"safety_identifier: secret"}"#).unwrap().is_empty());
    }
    #[test]fn chunk_boundaries_do_not_hide_framing(){
        let body=b"data: {\"response\":{\"safety_identifier\":\"SECRET\"}}\n\n";
        let mut raw=b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
        for part in body.chunks(5){raw.extend(format!("{:x}\r\n",part.len()).as_bytes());raw.extend(part);raw.extend(b"\r\n");}raw.extend(b"0\r\n\r\n");
        let ranges=hidden_ranges(&raw).unwrap();let mut partial=raw.clone();for r in ranges.iter(){partial[r.clone()].fill(0);}
        assert!(!String::from_utf8(authenticated_view(&partial,&ranges).unwrap().0).unwrap().contains("SECRET"));
        raw.push(b'x');assert!(hidden_ranges(&raw).is_err());
    }
}
