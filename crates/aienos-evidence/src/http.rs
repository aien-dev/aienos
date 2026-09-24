//! Minimal HTTP/1.1 client for a local OpenAI-compatible inference endpoint.
//!
//! Plain `http://` only: the reference workload runs against a server on this
//! machine, so no TLS stack is pulled into the evidence path.

use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub base_path: String,
}

impl Endpoint {
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("only http:// endpoints are supported: {url}"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| format!("bad port in {url}"))?),
            None => (authority, 80),
        };
        if host.is_empty() {
            return Err(format!("missing host in {url}"));
        }
        Ok(Self {
            host: host.to_string(),
            port,
            base_path: path.trim_end_matches('/').to_string(),
        })
    }
}

/// Decodes a `Transfer-Encoding: chunked` body.
pub struct Dechunk<R: BufRead> {
    inner: R,
    remaining: usize,
    done: bool,
}

impl<R: BufRead> Dechunk<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            remaining: 0,
            done: false,
        }
    }
}

impl<R: BufRead> Read for Dechunk<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut line = String::new();
            if self.inner.read_line(&mut line)? == 0 {
                self.done = true;
                return Ok(0);
            }
            let size_text = line.trim().split(';').next().unwrap_or("");
            let size = usize::from_str_radix(size_text, 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                self.done = true;
                return Ok(0);
            }
            self.remaining = size;
        }
        let want = buf.len().min(self.remaining);
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "chunk truncated",
            ));
        }
        self.remaining -= n;
        if self.remaining == 0 {
            let mut crlf = String::new();
            self.inner.read_line(&mut crlf)?;
        }
        Ok(n)
    }
}

fn send(
    ep: &Endpoint,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<Box<dyn BufRead>, String> {
    let mut stream = TcpStream::connect((ep.host.as_str(), ep.port))
        .map_err(|e| format!("connect {}:{}: {e}", ep.host, ep.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();
    let body = body.unwrap_or("");
    let request = format!(
        "{method} {}{path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        ep.base_path,
        ep.host,
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status).map_err(|e| e.to_string())?;
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("bad status line: {}", status.trim()))?;
    let mut chunked = false;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).map_err(|e| e.to_string())? == 0
            || header.trim().is_empty()
        {
            break;
        }
        let lower = header.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }
    if !(200..300).contains(&code) {
        return Err(format!("{method} {path} returned HTTP {code}"));
    }
    Ok(if chunked {
        Box::new(BufReader::new(Dechunk::new(reader)))
    } else {
        Box::new(reader)
    })
}

pub fn model_ids(ep: &Endpoint) -> Result<Vec<String>, String> {
    let mut body = String::new();
    send(ep, "GET", "/models", None)?
        .read_to_string(&mut body)
        .map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&body).map_err(|e| format!("models JSON: {e}"))?;
    Ok(v["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["id"].as_str().map(str::to_string))
        .collect())
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub ttft_ms: f64,
    pub total_ms: f64,
    pub output_tokens: u64,
    /// Tokens after the first, divided by the time after the first token.
    pub decode_tokens_per_second: f64,
}

/// Pulls timing and token counts out of an SSE chat-completion stream.
/// `clock` returns milliseconds since the request was sent.
pub fn read_stream(body: impl BufRead, mut clock: impl FnMut() -> f64) -> Result<Sample, String> {
    let mut first: Option<f64> = None;
    let mut chunks = 0u64;
    let mut usage: Option<u64> = None;
    for line in body.lines() {
        let line = line.map_err(|e| e.to_string())?;
        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };
        if data.trim() == "[DONE]" {
            break;
        }
        let chunk: Value = serde_json::from_str(data).map_err(|e| format!("stream JSON: {e}"))?;
        if let Some(n) = chunk["usage"]["completion_tokens"].as_u64() {
            usage = Some(n);
        }
        let has_content = chunk["choices"].as_array().into_iter().flatten().any(|c| {
            c["delta"]["content"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        });
        if has_content {
            chunks += 1;
            if first.is_none() {
                first = Some(clock());
            }
        }
    }
    let total_ms = clock();
    let ttft_ms = first.ok_or("stream produced no content")?;
    let output_tokens = usage.unwrap_or(chunks);
    let decode_ms = total_ms - ttft_ms;
    let decode_tokens_per_second = if output_tokens > 1 && decode_ms > 0.0 {
        (output_tokens - 1) as f64 / (decode_ms / 1000.0)
    } else {
        0.0
    };
    Ok(Sample {
        ttft_ms,
        total_ms,
        output_tokens,
        decode_tokens_per_second,
    })
}

pub fn chat_sample(
    ep: &Endpoint,
    model: &str,
    prompt: &str,
    max_tokens: u32,
) -> Result<Sample, String> {
    let body = json!({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": max_tokens,
        "stream": true,
        "stream_options": {"include_usage": true}
    })
    .to_string();
    let started = Instant::now();
    let reader = send(ep, "POST", "/chat/completions", Some(&body))?;
    read_stream(reader, || started.elapsed().as_secs_f64() * 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_endpoints() {
        let ep = Endpoint::parse("http://127.0.0.1:18094/v1/").unwrap();
        assert_eq!(
            (ep.host.as_str(), ep.port, ep.base_path.as_str()),
            ("127.0.0.1", 18094, "/v1")
        );
        assert!(Endpoint::parse("https://example.com/v1").is_err());
    }

    #[test]
    fn dechunks_bodies_with_extensions() {
        let raw = "5;x=1\r\nhello\r\n7\r\n, world\r\n0\r\n\r\n";
        let mut out = String::new();
        Dechunk::new(Cursor::new(raw))
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, "hello, world");
    }

    #[test]
    fn stream_timing_uses_first_content_and_usage() {
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"completion_tokens\":11}}\n\n",
            "data: [DONE]\n\n"
        );
        let mut t = 0.0;
        let s = read_stream(Cursor::new(sse), || {
            t += 100.0;
            t
        })
        .unwrap();
        assert_eq!(s.ttft_ms, 100.0);
        assert_eq!(s.total_ms, 200.0);
        assert_eq!(s.output_tokens, 11);
        assert!((s.decode_tokens_per_second - 100.0).abs() < 1e-9);
    }

    #[test]
    fn empty_stream_is_an_error() {
        assert!(read_stream(Cursor::new("data: [DONE]\n"), || 1.0).is_err());
    }
}
