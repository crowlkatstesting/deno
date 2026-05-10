// Copyright 2018-2026 the Deno authors. MIT license.

//! Minimal client-side ZMTP 3.1 helpers used by `jupyter_tests.rs` in place
//! of the upstream `zeromq` crate. Only the operations the tests need are
//! implemented: REQ (heartbeat), DEALER (shell/control), and SUB (iopub).

use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::time::timeout;

const FLAG_MORE: u8 = 0x01;
const FLAG_LONG: u8 = 0x02;
const FLAG_COMMAND: u8 = 0x04;

#[derive(Debug, Clone, Copy)]
pub enum ClientSocketType {
  Req,
  Dealer,
  Sub,
}

impl ClientSocketType {
  fn name(self) -> &'static str {
    match self {
      ClientSocketType::Req => "REQ",
      ClientSocketType::Dealer => "DEALER",
      ClientSocketType::Sub => "SUB",
    }
  }
}

async fn read_frame(
  r: &mut OwnedReadHalf,
) -> Result<(Bytes, bool, bool)> {
  let flags = r.read_u8().await?;
  let more = flags & FLAG_MORE != 0;
  let long = flags & FLAG_LONG != 0;
  let command = flags & FLAG_COMMAND != 0;
  let size = if long {
    r.read_u64().await? as usize
  } else {
    r.read_u8().await? as usize
  };
  let mut buf = vec![0u8; size];
  r.read_exact(&mut buf).await?;
  Ok((Bytes::from(buf), more, command))
}

async fn write_frame(
  w: &mut OwnedWriteHalf,
  body: &[u8],
  more: bool,
  command: bool,
) -> Result<()> {
  let mut flags = 0u8;
  if more {
    flags |= FLAG_MORE;
  }
  if command {
    flags |= FLAG_COMMAND;
  }
  if body.len() > 255 {
    flags |= FLAG_LONG;
    w.write_all(&[flags]).await?;
    w.write_all(&(body.len() as u64).to_be_bytes()).await?;
  } else {
    w.write_all(&[flags, body.len() as u8]).await?;
  }
  w.write_all(body).await?;
  Ok(())
}

async fn greet(
  r: &mut OwnedReadHalf,
  w: &mut OwnedWriteHalf,
) -> Result<()> {
  let mut out = [0u8; 64];
  out[0] = 0xFF;
  out[9] = 0x7F;
  out[10] = 3;
  out[11] = 1;
  out[12..16].copy_from_slice(b"NULL");
  // as-server = 0 (client)
  out[32] = 0;
  w.write_all(&out).await?;

  let mut peer = [0u8; 64];
  r.read_exact(&mut peer).await?;
  if peer[0] != 0xFF || peer[9] != 0x7F {
    return Err(anyhow!("bad zmtp greeting"));
  }
  Ok(())
}

fn build_ready_command(metadata: &[(&str, &str)]) -> Vec<u8> {
  let mut body = Vec::new();
  let name = b"READY";
  body.push(name.len() as u8);
  body.extend_from_slice(name);
  for (k, v) in metadata {
    body.push(k.len() as u8);
    body.extend_from_slice(k.as_bytes());
    body.extend_from_slice(&(v.len() as u32).to_be_bytes());
    body.extend_from_slice(v.as_bytes());
  }
  body
}

async fn handshake(
  r: &mut OwnedReadHalf,
  w: &mut OwnedWriteHalf,
  socket_type: ClientSocketType,
) -> Result<()> {
  let body = build_ready_command(&[("Socket-Type", socket_type.name())]);
  write_frame(w, &body, false, true).await?;
  let (_body, _more, is_cmd) = read_frame(r).await?;
  if !is_cmd {
    return Err(anyhow!("expected READY command from server"));
  }
  Ok(())
}

pub struct ClientSocket {
  pub r: OwnedReadHalf,
  pub w: OwnedWriteHalf,
  pub kind: ClientSocketType,
  /// REQ uses an implicit empty delimiter on send/recv. We track that here.
  req_envelope: Option<Vec<Bytes>>,
}

impl ClientSocket {
  pub async fn connect(
    addr: &str,
    kind: ClientSocketType,
  ) -> Result<Self> {
    let addr = addr.trim_start_matches("tcp://");
    let stream = match timeout(Duration::from_secs(5), TcpStream::connect(addr))
      .await
    {
      Ok(Ok(s)) => s,
      Ok(Err(e)) => return Err(e.into()),
      Err(_) => return Err(anyhow!("timed out connecting to {addr}")),
    };
    let (mut r, mut w) = stream.into_split();
    greet(&mut r, &mut w).await?;
    handshake(&mut r, &mut w, kind).await?;
    Ok(Self {
      r,
      w,
      kind,
      req_envelope: None,
    })
  }

  /// SUB-only: subscribe to a topic. Empty topic means "all".
  pub async fn subscribe(&mut self, topic: &str) -> Result<()> {
    assert!(matches!(self.kind, ClientSocketType::Sub));
    // ZMTP 3.1 SUBSCRIBE command: name = "SUBSCRIBE", body = filter bytes.
    let mut body = Vec::new();
    let name = b"SUBSCRIBE";
    body.push(name.len() as u8);
    body.extend_from_slice(name);
    body.extend_from_slice(topic.as_bytes());
    write_frame(&mut self.w, &body, false, true).await?;
    Ok(())
  }

  pub async fn send_multipart(&mut self, parts: Vec<Bytes>) -> Result<()> {
    let parts = match self.kind {
      ClientSocketType::Req => {
        // REQ socket prepends an empty delimiter frame.
        let mut out = Vec::with_capacity(parts.len() + 1);
        out.push(Bytes::new());
        out.extend(parts);
        out
      }
      _ => parts,
    };
    for (i, p) in parts.iter().enumerate() {
      let more = i + 1 < parts.len();
      write_frame(&mut self.w, p, more, false).await?;
    }
    self.w.flush().await?;
    Ok(())
  }

  pub async fn recv_multipart(&mut self) -> Result<Vec<Bytes>> {
    let mut parts = Vec::new();
    loop {
      let (body, more, is_cmd) = read_frame(&mut self.r).await?;
      if is_cmd {
        continue;
      }
      parts.push(body);
      if !more {
        break;
      }
    }
    // REQ socket strips the leading empty delimiter.
    if matches!(self.kind, ClientSocketType::Req) {
      let mut idx = 0;
      while idx < parts.len() && parts[idx].is_empty() {
        idx += 1;
      }
      let _ = self.req_envelope.replace(parts.drain(..idx).collect());
    }
    Ok(parts)
  }

  /// REQ-specific convenience: send a single frame body.
  pub async fn send_single(&mut self, body: Bytes) -> Result<()> {
    self.send_multipart(vec![body]).await
  }
}
