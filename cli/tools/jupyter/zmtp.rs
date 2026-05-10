// Copyright 2018-2026 the Deno authors. MIT license.

//! Minimal ZMTP 3.1 implementation, kernel-side only.
//!
//! Supports the subset of ZeroMQ semantics that the Jupyter protocol needs:
//! `REP` (heartbeat), `ROUTER` (shell/control/stdin), and `PUB` (iopub).
//! Only the `NULL` security mechanism is supported, and the kernel always
//! binds (never connects).

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use deno_core::parking_lot::Mutex;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;

const SIGNATURE: [u8; 10] = [0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0x7F];
const VERSION_MAJOR: u8 = 3;
const VERSION_MINOR: u8 = 1;

const FLAG_MORE: u8 = 0x01;
const FLAG_LONG: u8 = 0x02;
const FLAG_COMMAND: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
  Rep,
  Router,
  Pub,
}

impl SocketType {
  fn name(self) -> &'static str {
    match self {
      SocketType::Rep => "REP",
      SocketType::Router => "ROUTER",
      SocketType::Pub => "PUB",
    }
  }
}

/// Read a single ZMTP frame from `r`. Returns `(body, more, is_command)`.
async fn read_frame(r: &mut OwnedReadHalf) -> io::Result<(Bytes, bool, bool)> {
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

/// Encode a frame's header (flags + size). Body is written separately.
fn frame_header(size: usize, more: bool, command: bool) -> Vec<u8> {
  let mut flags = 0u8;
  if more {
    flags |= FLAG_MORE;
  }
  if command {
    flags |= FLAG_COMMAND;
  }
  if size > 255 {
    flags |= FLAG_LONG;
    let mut out = Vec::with_capacity(9);
    out.push(flags);
    out.extend_from_slice(&(size as u64).to_be_bytes());
    out
  } else {
    vec![flags, size as u8]
  }
}

async fn write_frame(
  w: &mut OwnedWriteHalf,
  body: &[u8],
  more: bool,
  command: bool,
) -> io::Result<()> {
  let hdr = frame_header(body.len(), more, command);
  w.write_all(&hdr).await?;
  w.write_all(body).await?;
  Ok(())
}

/// Exchange the 64-byte ZMTP greeting with the peer.
async fn greet(
  r: &mut OwnedReadHalf,
  w: &mut OwnedWriteHalf,
  _socket_type: SocketType,
) -> io::Result<()> {
  // Write our greeting first.
  let mut out = [0u8; 64];
  out[..SIGNATURE.len()].copy_from_slice(&SIGNATURE);
  out[10] = VERSION_MAJOR;
  out[11] = VERSION_MINOR;
  // Mechanism "NULL"
  let mech = b"NULL";
  out[12..12 + mech.len()].copy_from_slice(mech);
  // as-server flag: kernel side always binds, so it's the ZMTP "server".
  out[32] = 1;
  w.write_all(&out).await?;

  let mut peer = [0u8; 64];
  r.read_exact(&mut peer).await?;
  if peer[0] != 0xFF || peer[9] != 0x7F {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "bad zmtp greeting",
    ));
  }
  Ok(())
}

/// Build a ZMTP `READY` command body with the given metadata fields.
fn build_ready_command(metadata: &[(&str, &str)]) -> Vec<u8> {
  let mut body = Vec::new();
  // command-name: short-string (length-prefixed by one byte)
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

/// Parse a `READY` command body into a metadata map (ignores unknown commands).
fn parse_command(body: &[u8]) -> Option<(String, HashMap<String, Vec<u8>>)> {
  if body.is_empty() {
    return None;
  }
  let name_len = body[0] as usize;
  if body.len() < 1 + name_len {
    return None;
  }
  let name = String::from_utf8_lossy(&body[1..1 + name_len]).into_owned();
  let mut p = 1 + name_len;
  let mut map = HashMap::new();
  while p < body.len() {
    let klen = body[p] as usize;
    p += 1;
    if p + klen > body.len() {
      return None;
    }
    let key = String::from_utf8_lossy(&body[p..p + klen]).into_owned();
    p += klen;
    if p + 4 > body.len() {
      return None;
    }
    let vlen =
      u32::from_be_bytes([body[p], body[p + 1], body[p + 2], body[p + 3]])
        as usize;
    p += 4;
    if p + vlen > body.len() {
      return None;
    }
    let value = body[p..p + vlen].to_vec();
    p += vlen;
    map.insert(key, value);
  }
  Some((name, map))
}

/// Perform the NULL-mechanism handshake. Returns the peer's `Identity`
/// metadata field if it supplied one.
async fn handshake(
  r: &mut OwnedReadHalf,
  w: &mut OwnedWriteHalf,
  socket_type: SocketType,
  identity: &[u8],
) -> io::Result<Option<Vec<u8>>> {
  // Send our READY.
  let identity_str = String::from_utf8_lossy(identity).into_owned();
  let metadata: Vec<(&str, &str)> = vec![
    ("Socket-Type", socket_type.name()),
    ("Identity", identity_str.as_str()),
  ];
  let body = build_ready_command(&metadata);
  write_frame(w, &body, false, true).await?;

  // Read peer's READY.
  let (peer_body, _more, is_cmd) = read_frame(r).await?;
  if !is_cmd {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "expected command frame in handshake",
    ));
  }
  let parsed = parse_command(&peer_body);
  let peer_identity = parsed.and_then(|(name, map)| {
    if name == "READY" {
      map.get("Identity").cloned()
    } else {
      None
    }
  });
  Ok(peer_identity)
}

/// One direction of a parsed multipart message.
pub type Multipart = Vec<Bytes>;

/// Read a multipart application message (skipping SUBSCRIBE/UNSUBSCRIBE
/// commands, which only apply to `PUB`).
async fn read_multipart(r: &mut OwnedReadHalf) -> io::Result<Multipart> {
  loop {
    let mut parts = Vec::new();
    let (body, mut more, is_cmd) = read_frame(r).await?;
    if is_cmd {
      // Drop unknown commands silently. Most often these are SUBSCRIBE.
      continue;
    }
    parts.push(body);
    while more {
      let (b, m, c) = read_frame(r).await?;
      if c {
        // commands shouldn't appear mid-message; treat as protocol error
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "unexpected command frame mid-message",
        ));
      }
      parts.push(b);
      more = m;
    }
    return Ok(parts);
  }
}

async fn write_multipart(
  w: &mut OwnedWriteHalf,
  parts: &[Bytes],
) -> io::Result<()> {
  if parts.is_empty() {
    return Ok(());
  }
  for (i, p) in parts.iter().enumerate() {
    let more = i + 1 < parts.len();
    write_frame(w, p, more, false).await?;
  }
  w.flush().await?;
  Ok(())
}

/// Handle to a single accepted peer connection.
struct Peer {
  identity: Vec<u8>,
  out_tx: mpsc::UnboundedSender<Multipart>,
}

/// Bind a port as REP (heartbeat). Accepts an arbitrary number of peers
/// concurrently. Each peer's request is dispatched to the JS layer via
/// `in_tx`; the JS layer's reply on `in_rx` is routed back to whichever peer
/// the request came from.
pub async fn run_rep(
  listener: TcpListener,
  in_rx: mpsc::UnboundedReceiver<Multipart>,
  in_tx: mpsc::UnboundedSender<Multipart>,
) -> io::Result<()> {
  // Outgoing reply queue keyed by FIFO order of pending peer replies.
  let pending: Arc<
    Mutex<std::collections::VecDeque<mpsc::UnboundedSender<Multipart>>>,
  > = Arc::new(Mutex::new(std::collections::VecDeque::new()));

  let dispatch_pending = pending.clone();
  let mut in_rx = in_rx;
  tokio::spawn(async move {
    while let Some(reply) = in_rx.recv().await {
      let tx = dispatch_pending.lock().pop_front();
      if let Some(tx) = tx {
        let _ = tx.send(reply);
      }
    }
  });

  loop {
    let (stream, _) = listener.accept().await?;
    let pending = pending.clone();
    let in_tx = in_tx.clone();
    tokio::spawn(async move {
      let _ = serve_rep_peer(stream, pending, in_tx).await;
    });
  }
}

async fn serve_rep_peer(
  stream: TcpStream,
  pending: Arc<
    Mutex<std::collections::VecDeque<mpsc::UnboundedSender<Multipart>>>,
  >,
  in_tx: mpsc::UnboundedSender<Multipart>,
) -> io::Result<()> {
  let (mut rd, mut wr) = stream.into_split();
  greet(&mut rd, &mut wr, SocketType::Rep).await?;
  handshake(&mut rd, &mut wr, SocketType::Rep, b"").await?;
  loop {
    let parts = read_multipart(&mut rd).await?;
    // Strip leading empty frames (REQ envelope) before dispatch.
    let mut idx = 0;
    while idx < parts.len() && parts[idx].is_empty() {
      idx += 1;
    }
    let body: Multipart = parts[idx..].to_vec();
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel::<Multipart>();
    pending.lock().push_back(reply_tx);
    if in_tx.send(body).is_err() {
      return Ok(());
    }
    let reply = match reply_rx.recv().await {
      Some(m) => m,
      None => return Ok(()),
    };
    let mut out = Vec::with_capacity(reply.len() + 1);
    out.push(Bytes::new());
    out.extend(reply);
    write_multipart(&mut wr, &out).await?;
  }
}

/// Bind a port as ROUTER. Each incoming multipart message is delivered
/// prefixed with the originating peer's identity, and outgoing messages
/// are routed to a peer by matching the first frame against the known
/// identities.
pub async fn run_router(
  listener: TcpListener,
  mut out_rx: mpsc::UnboundedReceiver<Multipart>,
  in_tx: mpsc::UnboundedSender<Multipart>,
) -> io::Result<()> {
  let peers: Arc<Mutex<Vec<Peer>>> = Arc::new(Mutex::new(Vec::new()));

  // Spawn the accept loop.
  let accept_peers = peers.clone();
  let accept_in_tx = in_tx.clone();
  tokio::spawn(async move {
    loop {
      let (stream, _) = match listener.accept().await {
        Ok(s) => s,
        Err(_) => return,
      };
      let peers = accept_peers.clone();
      let in_tx = accept_in_tx.clone();
      tokio::spawn(async move {
        let _ = handle_router_peer(stream, peers, in_tx).await;
      });
    }
  });

  // Outgoing loop: route to the right peer.
  while let Some(msg) = out_rx.recv().await {
    if msg.is_empty() {
      continue;
    }
    let identity = msg[0].clone();
    let body: Multipart = msg[1..].to_vec();
    let tx = {
      let guard = peers.lock();
      guard
        .iter()
        .find(|p| p.identity.as_slice() == identity.as_ref())
        .map(|p| p.out_tx.clone())
    };
    if let Some(tx) = tx {
      let _ = tx.send(body);
    }
  }
  Ok(())
}

async fn handle_router_peer(
  stream: TcpStream,
  peers: Arc<Mutex<Vec<Peer>>>,
  in_tx: mpsc::UnboundedSender<Multipart>,
) -> io::Result<()> {
  let (mut rd, mut wr) = stream.into_split();
  greet(&mut rd, &mut wr, SocketType::Router).await?;
  // Assign a random identity if peer doesn't supply one.
  let mut assigned = [0u8; 5];
  assigned[0] = 0;
  for b in &mut assigned[1..] {
    *b = rand::random::<u8>();
  }
  let peer_identity =
    handshake(&mut rd, &mut wr, SocketType::Router, &assigned)
      .await?
      .unwrap_or_else(|| assigned.to_vec());

  let (peer_tx, mut peer_rx) = mpsc::unbounded_channel::<Multipart>();
  peers.lock().push(Peer {
    identity: peer_identity.clone(),
    out_tx: peer_tx,
  });

  // Writer task.
  let write_handle = tokio::spawn(async move {
    while let Some(parts) = peer_rx.recv().await {
      if write_multipart(&mut wr, &parts).await.is_err() {
        break;
      }
    }
  });

  // Reader loop.
  let read_result: io::Result<()> = async {
    loop {
      let parts = read_multipart(&mut rd).await?;
      let mut prefixed = Vec::with_capacity(parts.len() + 1);
      prefixed.push(Bytes::from(peer_identity.clone()));
      prefixed.extend(parts);
      if in_tx.send(prefixed).is_err() {
        return Ok(());
      }
    }
  }
  .await;

  // Remove the peer regardless of how we exited.
  peers
    .lock()
    .retain(|p| p.identity.as_slice() != peer_identity.as_slice());
  write_handle.abort();
  read_result
}

/// Bind a port as PUB. All outgoing messages are broadcast to every connected
/// subscriber. SUBSCRIBE commands from peers are accepted but their filter
/// values are ignored.
pub async fn run_pub(
  listener: TcpListener,
  mut out_rx: mpsc::UnboundedReceiver<Multipart>,
) -> io::Result<()> {
  let peers: Arc<Mutex<Vec<mpsc::UnboundedSender<Multipart>>>> =
    Arc::new(Mutex::new(Vec::new()));

  // Accept loop.
  let accept_peers = peers.clone();
  tokio::spawn(async move {
    loop {
      let (stream, _) = match listener.accept().await {
        Ok(s) => s,
        Err(_) => return,
      };
      let peers = accept_peers.clone();
      tokio::spawn(async move {
        let _ = handle_pub_peer(stream, peers).await;
      });
    }
  });

  // Outgoing broadcast loop.
  while let Some(msg) = out_rx.recv().await {
    let mut guard = peers.lock();
    guard.retain(|tx| tx.send(msg.clone()).is_ok());
  }
  Ok(())
}

async fn handle_pub_peer(
  stream: TcpStream,
  peers: Arc<Mutex<Vec<mpsc::UnboundedSender<Multipart>>>>,
) -> io::Result<()> {
  let (mut rd, mut wr) = stream.into_split();
  greet(&mut rd, &mut wr, SocketType::Pub).await?;
  handshake(&mut rd, &mut wr, SocketType::Pub, b"").await?;

  let (peer_tx, mut peer_rx) = mpsc::unbounded_channel::<Multipart>();
  let tx_id = {
    let mut guard = peers.lock();
    guard.push(peer_tx);
    guard.len() - 1
  };

  // Drain incoming SUBSCRIBE commands (ignore filters).
  tokio::spawn(async move {
    loop {
      match read_frame(&mut rd).await {
        Ok(_) => continue,
        Err(_) => break,
      }
    }
  });

  // Writer loop.
  while let Some(parts) = peer_rx.recv().await {
    if write_multipart(&mut wr, &parts).await.is_err() {
      break;
    }
  }

  // Remove ourselves on disconnect.
  let mut guard = peers.lock();
  if tx_id < guard.len() {
    guard.remove(tx_id);
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_frame_header_short() {
    let h = frame_header(5, false, false);
    assert_eq!(h, vec![0x00, 5]);
  }

  #[test]
  fn test_frame_header_more() {
    let h = frame_header(5, true, false);
    assert_eq!(h, vec![0x01, 5]);
  }

  #[test]
  fn test_frame_header_long() {
    let h = frame_header(256, false, false);
    assert_eq!(h[0], FLAG_LONG);
    assert_eq!(&h[1..], &(256u64).to_be_bytes());
  }

  #[test]
  fn test_frame_header_command() {
    let h = frame_header(5, false, true);
    assert_eq!(h[0], FLAG_COMMAND);
  }

  #[test]
  fn test_parse_ready_command() {
    let body =
      build_ready_command(&[("Socket-Type", "ROUTER"), ("Identity", "abc")]);
    let (name, map) = parse_command(&body).unwrap();
    assert_eq!(name, "READY");
    assert_eq!(map.get("Socket-Type").unwrap(), b"ROUTER");
    assert_eq!(map.get("Identity").unwrap(), b"abc");
  }
}
