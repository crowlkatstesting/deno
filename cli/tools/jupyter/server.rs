// Copyright 2018-2026 the Deno authors. MIT license.

//! Socket-level transport for the Jupyter kernel.
//!
//! The protocol layer (HMAC signing, message dispatch, completion, etc.) lives
//! in JS (`cli/js/jupyter_kernel.js`). This module owns the five ZMQ sockets
//! and forwards raw multipart frames between them and the JS layer via mpsc
//! channels. It also peeks at incoming control-channel messages so that it
//! can terminate user-code execution as soon as an `interrupt_request` is
//! seen — interrupts must work even while the JS event loop is blocked.

use std::io;

use bytes::Bytes;
use deno_core::serde::Deserialize;
use deno_core::serde::Serialize;
use deno_core::serde_json;
use deno_core::v8;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::zmtp;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConnectionInfo {
  pub ip: String,
  pub transport: String,
  #[serde(rename = "hb_port")]
  pub hb_port: u16,
  pub control_port: u16,
  pub shell_port: u16,
  pub stdin_port: u16,
  pub iopub_port: u16,
  #[serde(default)]
  pub signature_scheme: String,
  #[serde(default)]
  pub key: String,
  #[serde(default)]
  pub kernel_name: String,
}

/// Bidirectional channel handle for one socket.
pub struct ChannelHandle {
  pub incoming_rx: mpsc::UnboundedReceiver<Vec<Bytes>>,
  pub outgoing_tx: mpsc::UnboundedSender<Vec<Bytes>>,
}

/// Set of handles for all five Jupyter ZMQ sockets, plus the address actually
/// bound (in case the connection file requested an ephemeral port).
pub struct SocketHandles {
  pub heartbeat: ChannelHandle,
  pub control: ChannelHandle,
  pub shell: ChannelHandle,
  pub stdin: ChannelHandle,
  pub iopub: ChannelHandle,
}

async fn bind(transport: &str, ip: &str, port: u16) -> io::Result<TcpListener> {
  if transport != "tcp" {
    return Err(io::Error::other(format!(
      "unsupported transport '{transport}', only 'tcp' is supported",
    )));
  }
  TcpListener::bind((ip, port)).await
}

/// Bind all five Jupyter sockets and start forwarding tasks. Returns the
/// channel handles for the JS-side kernel to drive.
///
/// `isolate_handle` is the user-code isolate. If we detect an
/// `interrupt_request` on the control channel we call
/// `terminate_execution()` on it immediately, so that the interrupt fires
/// even while user code is blocking the event loop.
pub async fn start(
  info: &ConnectionInfo,
  isolate_handle: v8::IsolateHandle,
) -> io::Result<SocketHandles> {
  let hb = bind(&info.transport, &info.ip, info.hb_port).await?;
  let control = bind(&info.transport, &info.ip, info.control_port).await?;
  let shell = bind(&info.transport, &info.ip, info.shell_port).await?;
  let stdin = bind(&info.transport, &info.ip, info.stdin_port).await?;
  let iopub = bind(&info.transport, &info.ip, info.iopub_port).await?;

  let heartbeat = spawn_rep(hb);
  let control = spawn_router_with_interrupt(control, isolate_handle);
  let shell = spawn_router(shell);
  let stdin = spawn_router(stdin);
  let iopub = spawn_pub(iopub);

  Ok(SocketHandles {
    heartbeat,
    control,
    shell,
    stdin,
    iopub,
  })
}

fn spawn_rep(listener: TcpListener) -> ChannelHandle {
  let (in_tx, in_rx) = mpsc::unbounded_channel::<Vec<Bytes>>();
  let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<Bytes>>();
  tokio::spawn(async move {
    let _ = zmtp::run_rep(listener, out_rx, in_tx).await;
  });
  ChannelHandle {
    incoming_rx: in_rx,
    outgoing_tx: out_tx,
  }
}

fn spawn_router(listener: TcpListener) -> ChannelHandle {
  let (in_tx, in_rx) = mpsc::unbounded_channel::<Vec<Bytes>>();
  let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<Bytes>>();
  tokio::spawn(async move {
    let _ = zmtp::run_router(listener, out_rx, in_tx).await;
  });
  ChannelHandle {
    incoming_rx: in_rx,
    outgoing_tx: out_tx,
  }
}

fn spawn_router_with_interrupt(
  listener: TcpListener,
  isolate_handle: v8::IsolateHandle,
) -> ChannelHandle {
  let (raw_in_tx, mut raw_in_rx) = mpsc::unbounded_channel::<Vec<Bytes>>();
  let (in_tx, in_rx) = mpsc::unbounded_channel::<Vec<Bytes>>();
  let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<Bytes>>();
  tokio::spawn(async move {
    let _ = zmtp::run_router(listener, out_rx, raw_in_tx).await;
  });
  // Filter task: peek at every incoming message; if it's an `interrupt_request`
  // we terminate the user isolate immediately, then forward the message on.
  tokio::spawn(async move {
    while let Some(msg) = raw_in_rx.recv().await {
      if is_interrupt_request(&msg) {
        isolate_handle.terminate_execution();
      }
      if in_tx.send(msg).is_err() {
        break;
      }
    }
  });
  ChannelHandle {
    incoming_rx: in_rx,
    outgoing_tx: out_tx,
  }
}

fn spawn_pub(listener: TcpListener) -> ChannelHandle {
  // PUB never receives application messages.
  let (in_tx, in_rx) = mpsc::unbounded_channel::<Vec<Bytes>>();
  let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<Bytes>>();
  drop(in_tx);
  tokio::spawn(async move {
    let _ = zmtp::run_pub(listener, out_rx).await;
  });
  ChannelHandle {
    incoming_rx: in_rx,
    outgoing_tx: out_tx,
  }
}

const DELIMITER: &[u8] = b"<IDS|MSG>";

/// Returns true if `parts` is a Jupyter wire message whose header announces
/// `msg_type: "interrupt_request"`.
fn is_interrupt_request(parts: &[Bytes]) -> bool {
  // Layout: [router_identity?, ...zmq_identities, "<IDS|MSG>", signature,
  //          header, parent_header, metadata, content, ...buffers].
  // We look for the delimiter and pick the next-but-one frame (the header).
  let Some(idx) = parts.iter().position(|p| p.as_ref() == DELIMITER) else {
    return false;
  };
  let header_idx = idx + 2;
  if header_idx >= parts.len() {
    return false;
  }
  let Ok(header) =
    serde_json::from_slice::<serde_json::Value>(&parts[header_idx])
  else {
    return false;
  };
  header.get("msg_type").and_then(|v| v.as_str()) == Some("interrupt_request")
}

#[cfg(test)]
mod tests {
  use super::*;
  use deno_core::serde_json::json;

  #[test]
  fn detects_interrupt_request() {
    let parts = vec![
      Bytes::from_static(b"id"),
      Bytes::from_static(DELIMITER),
      Bytes::from_static(b"sig"),
      Bytes::from(
        serde_json::to_vec(&json!({"msg_type": "interrupt_request"})).unwrap(),
      ),
      Bytes::from_static(b"{}"),
      Bytes::from_static(b"{}"),
      Bytes::from_static(b"{}"),
    ];
    assert!(is_interrupt_request(&parts));
  }

  #[test]
  fn ignores_non_interrupt() {
    let parts = vec![
      Bytes::from_static(b"id"),
      Bytes::from_static(DELIMITER),
      Bytes::from_static(b"sig"),
      Bytes::from(
        serde_json::to_vec(&json!({"msg_type": "execute_request"})).unwrap(),
      ),
      Bytes::from_static(b"{}"),
      Bytes::from_static(b"{}"),
      Bytes::from_static(b"{}"),
    ];
    assert!(!is_interrupt_request(&parts));
  }
}
