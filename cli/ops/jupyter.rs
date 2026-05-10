// Copyright 2018-2026 the Deno authors. MIT license.

//! Ops backing the Jupyter kernel.
//!
//! The Jupyter protocol (HMAC signing, message dispatch, completion,
//! `is_complete`, etc.) lives in JS at `cli/js/jupyter_kernel.js`. These ops
//! provide the thin Rust surface the JS layer needs:
//!
//! * `op_jupyter_recv` / `op_jupyter_send` — bridge raw multipart frames to
//!   the ZMTP sockets owned by `tools::jupyter::server`.
//! * `op_jupyter_recv_stdio` — receive captured `console.log`/`stderr`
//!   output that the `op_print` middleware buffers during user-code
//!   evaluation.
//! * `op_jupyter_repl_*` — drive the REPL session that runs user code, via
//!   the existing `JupyterReplProxy` request/response channel pair.
//! * `op_jupyter_create_png_from_texture` / `op_jupyter_get_buffer` —
//!   unchanged display-data helpers.
//! * `op_jupyter_deno_version` / `op_jupyter_typescript_version` —
//!   convenience accessors used to populate `kernel_info_reply`.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use bytes::Bytes;
use deno_core::OpState;
use deno_core::op2;
use deno_core::serde::Deserialize;
use deno_core::serde_json;
use deno_core::serde_v8;
use deno_error::JsErrorBox;
use deno_lib::version::DENO_VERSION_INFO;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;

use crate::cdp;
use crate::tools::jupyter::JupyterReplProxy;
use crate::tools::jupyter::JupyterReplRequest;
use crate::tools::jupyter::JupyterReplResponse;
use crate::tools::jupyter::server::ChannelHandle;
use crate::tools::jupyter::server::SocketHandles;

/// Captured chunk of user-code output.
#[derive(Debug, Clone)]
pub struct StreamContent {
  pub name: &'static str,
  pub text: String,
}

impl StreamContent {
  pub fn stdout(s: &str) -> Self {
    Self {
      name: "stdout",
      text: s.to_string(),
    }
  }
  pub fn stderr(s: &str) -> Self {
    Self {
      name: "stderr",
      text: s.to_string(),
    }
  }
}

/// Per-channel send/receive handles, stored in the op state so async ops
/// can pull from / push to them.
pub struct JupyterSockets {
  pub heartbeat: ChannelState,
  pub control: ChannelState,
  pub shell: ChannelState,
  pub stdin: ChannelState,
  pub iopub: ChannelState,
}

pub struct ChannelState {
  pub recv: Arc<AsyncMutex<mpsc::UnboundedReceiver<Vec<Bytes>>>>,
  pub send: mpsc::UnboundedSender<Vec<Bytes>>,
}

impl ChannelState {
  fn from_handle(h: ChannelHandle) -> Self {
    Self {
      recv: Arc::new(AsyncMutex::new(h.incoming_rx)),
      send: h.outgoing_tx,
    }
  }
}

impl From<SocketHandles> for JupyterSockets {
  fn from(h: SocketHandles) -> Self {
    Self {
      heartbeat: ChannelState::from_handle(h.heartbeat),
      control: ChannelState::from_handle(h.control),
      shell: ChannelState::from_handle(h.shell),
      stdin: ChannelState::from_handle(h.stdin),
      iopub: ChannelState::from_handle(h.iopub),
    }
  }
}

deno_core::extension!(deno_jupyter,
  ops = [
    op_jupyter_recv,
    op_jupyter_send,
    op_jupyter_recv_stdio,
    op_jupyter_repl_evaluate,
    op_jupyter_repl_get_properties,
    op_jupyter_repl_global_lexical_scope_names,
    op_jupyter_repl_evaluate_expression,
    op_jupyter_repl_call_function_on_args,
    op_jupyter_repl_broadcast_result,
    op_jupyter_repl_cancel_terminate,
    op_jupyter_create_png_from_texture,
    op_jupyter_get_buffer,
    op_jupyter_deno_version,
    op_jupyter_typescript_version,
  ],
  options = {
    sender: mpsc::UnboundedSender<StreamContent>,
  },
  middleware = |op| match op.name {
    "op_print" => op_print(),
    _ => op,
  },
  state = |state, options| {
    state.put(options.sender);
  },
);

deno_core::extension!(deno_jupyter_for_test,
  ops = [
    op_jupyter_create_png_from_texture,
    op_jupyter_get_buffer,
  ],
  options = {
    sender: mpsc::UnboundedSender<StreamContent>,
  },
  state = |state, options| {
    state.put(options.sender);
  },
);

#[op2(fast)]
pub fn op_print(state: &mut OpState, #[string] msg: &str, is_err: bool) {
  let sender = state.borrow_mut::<mpsc::UnboundedSender<StreamContent>>();
  let item = if is_err {
    StreamContent::stderr(msg)
  } else {
    StreamContent::stdout(msg)
  };
  if let Err(err) = sender.send(item) {
    log::error!("Failed to send stdio chunk: {}", err);
  }
}

fn pick_channel<'a>(
  sockets: &'a JupyterSockets,
  name: &str,
) -> Option<&'a ChannelState> {
  match name {
    "heartbeat" => Some(&sockets.heartbeat),
    "control" => Some(&sockets.control),
    "shell" => Some(&sockets.shell),
    "stdin" => Some(&sockets.stdin),
    "iopub" => Some(&sockets.iopub),
    _ => None,
  }
}

#[op2]
#[serde]
pub async fn op_jupyter_recv(
  state: Rc<RefCell<OpState>>,
  #[string] channel: String,
) -> Result<Option<Vec<serde_v8::ToJsBuffer>>, JsErrorBox> {
  let recv = {
    let s = state.borrow();
    let sockets = s.borrow::<Arc<JupyterSockets>>();
    let ch = pick_channel(sockets, &channel).ok_or_else(|| {
      JsErrorBox::type_error(format!("unknown channel {channel}"))
    })?;
    ch.recv.clone()
  };
  let mut guard = recv.lock().await;
  let Some(parts) = guard.recv().await else {
    return Ok(None);
  };
  Ok(Some(
    parts
      .into_iter()
      .map(|b| serde_v8::ToJsBuffer::from(b.to_vec()))
      .collect(),
  ))
}

#[op2]
pub fn op_jupyter_send(
  state: &mut OpState,
  #[string] channel: String,
  #[serde] parts: Vec<serde_v8::JsBuffer>,
) -> Result<(), JsErrorBox> {
  let sockets = state.borrow::<Arc<JupyterSockets>>();
  let ch = pick_channel(sockets, &channel).ok_or_else(|| {
    JsErrorBox::type_error(format!("unknown channel {channel}"))
  })?;
  let bytes: Vec<Bytes> =
    parts.into_iter().map(|b| Bytes::from(b.to_vec())).collect();
  ch.send
    .send(bytes)
    .map_err(|e| JsErrorBox::generic(e.to_string()))?;
  Ok(())
}

#[op2]
#[serde]
pub async fn op_jupyter_recv_stdio(
  state: Rc<RefCell<OpState>>,
) -> Option<(String, String)> {
  let recv = {
    let s = state.borrow();
    s.borrow::<Arc<AsyncMutex<mpsc::UnboundedReceiver<StreamContent>>>>()
      .clone()
  };
  let mut guard = recv.lock().await;
  let item = guard.recv().await?;
  Some((item.name.to_string(), item.text))
}

#[op2]
#[serde]
pub async fn op_jupyter_repl_evaluate(
  state: Rc<RefCell<OpState>>,
  #[string] code: String,
) -> Result<serde_json::Value, JsErrorBox> {
  let proxy = repl_proxy(&state);
  let mut p = proxy.lock().await;
  let _ = p
    .tx
    .send(JupyterReplRequest::EvaluateLineWithObjectWrapping { line: code });
  let Some(JupyterReplResponse::EvaluateLineWithObjectWrapping(resp)) =
    p.rx.recv().await
  else {
    return Err(JsErrorBox::generic("REPL bridge closed"));
  };
  match resp {
    Ok(r) => Ok(serde_json::to_value(r.value).map_err(|e| {
      JsErrorBox::generic(format!("serialize EvaluateResponse: {e}"))
    })?),
    Err(e) => Err(JsErrorBox::generic(e.to_string())),
  }
}

#[op2]
#[serde]
pub async fn op_jupyter_repl_get_properties(
  state: Rc<RefCell<OpState>>,
  #[string] object_id: String,
) -> Option<serde_json::Value> {
  let proxy = repl_proxy(&state);
  let mut p = proxy.lock().await;
  let _ = p.tx.send(JupyterReplRequest::GetProperties { object_id });
  let Some(JupyterReplResponse::GetProperties(resp)) = p.rx.recv().await else {
    return None;
  };
  resp.and_then(|r| serde_json::to_value(r).ok())
}

#[op2]
#[serde]
pub async fn op_jupyter_repl_global_lexical_scope_names(
  state: Rc<RefCell<OpState>>,
) -> Vec<String> {
  let proxy = repl_proxy(&state);
  let mut p = proxy.lock().await;
  let _ = p.tx.send(JupyterReplRequest::GlobalLexicalScopeNames);
  let Some(JupyterReplResponse::GlobalLexicalScopeNames(resp)) =
    p.rx.recv().await
  else {
    return vec![];
  };
  resp.names
}

#[op2]
#[serde]
pub async fn op_jupyter_repl_evaluate_expression(
  state: Rc<RefCell<OpState>>,
  #[string] expr: String,
) -> Option<serde_json::Value> {
  let proxy = repl_proxy(&state);
  let mut p = proxy.lock().await;
  let _ = p.tx.send(JupyterReplRequest::Evaluate { expr });
  let Some(JupyterReplResponse::Evaluate(resp)) = p.rx.recv().await else {
    return None;
  };
  resp.and_then(|r| serde_json::to_value(r).ok())
}

#[derive(Deserialize)]
struct CallFunctionOnArgsParams {
  #[serde(rename = "functionDeclaration")]
  function_declaration: String,
  arguments: Vec<cdp::RemoteObject>,
}

#[op2]
#[serde]
pub async fn op_jupyter_repl_call_function_on_args(
  state: Rc<RefCell<OpState>>,
  #[serde] params: CallFunctionOnArgsParams,
) -> Result<serde_json::Value, JsErrorBox> {
  let proxy = repl_proxy(&state);
  let mut p = proxy.lock().await;
  let _ = p.tx.send(JupyterReplRequest::CallFunctionOnArgs {
    function_declaration: params.function_declaration,
    args: params.arguments,
  });
  let Some(JupyterReplResponse::CallFunctionOnArgs(resp)) = p.rx.recv().await
  else {
    return Err(JsErrorBox::generic("REPL bridge closed"));
  };
  let r = resp.map_err(|e| JsErrorBox::generic(e.to_string()))?;
  serde_json::to_value(r).map_err(|e| JsErrorBox::generic(e.to_string()))
}

#[op2]
pub async fn op_jupyter_repl_broadcast_result(
  state: Rc<RefCell<OpState>>,
  #[smi] execution_count: u32,
  #[serde] result: cdp::CallArgument,
) -> Result<(), JsErrorBox> {
  let count = cdp::CallArgument {
    value: Some(serde_json::Value::from(execution_count)),
    unserializable_value: None,
    object_id: None,
  };
  let proxy = repl_proxy(&state);
  let mut p = proxy.lock().await;
  let _ = p.tx.send(JupyterReplRequest::CallFunctionOn {
    arg0: count,
    arg1: result,
  });
  let Some(JupyterReplResponse::CallFunctionOn(_)) = p.rx.recv().await else {
    return Err(JsErrorBox::generic("REPL bridge closed"));
  };
  Ok(())
}

#[op2(fast)]
pub fn op_jupyter_repl_cancel_terminate(state: &mut OpState) {
  let proxy = state.borrow::<Arc<AsyncMutex<JupyterReplProxy>>>().clone();
  // Best-effort: try_lock so we don't await here. The cancel just flips
  // a flag on the isolate.
  if let Ok(p) = proxy.try_lock() {
    let _ = p.tx.send(JupyterReplRequest::CancelPendingTerminate);
  }
}

#[op2]
#[string]
pub fn op_jupyter_deno_version() -> String {
  DENO_VERSION_INFO.deno.to_string()
}

#[op2]
#[string]
pub fn op_jupyter_typescript_version() -> String {
  DENO_VERSION_INFO.typescript.to_string()
}

fn repl_proxy(
  state: &Rc<RefCell<OpState>>,
) -> Arc<AsyncMutex<JupyterReplProxy>> {
  state
    .borrow()
    .borrow::<Arc<AsyncMutex<JupyterReplProxy>>>()
    .clone()
}

#[op2]
#[string]
pub fn op_jupyter_create_png_from_texture(
  #[cppgc] texture: &deno_runtime::deno_webgpu::texture::GPUTexture,
) -> Result<String, JsErrorBox> {
  use deno_runtime::deno_image::image::ExtendedColorType;
  use deno_runtime::deno_image::image::ImageEncoder;
  use deno_runtime::deno_webgpu::error::GPUError;
  use deno_runtime::deno_webgpu::*;
  use texture::GPUTextureFormat;

  let (command_encoder, maybe_err) =
    texture.instance.device_create_command_encoder(
      texture.device_id,
      &wgpu_types::CommandEncoderDescriptor { label: None },
      None,
    );
  if let Some(maybe_err) = maybe_err {
    return Err(JsErrorBox::from_err::<GPUError>(maybe_err.into()));
  }

  let data = canvas::copy_texture_to_vec(
    &texture.instance,
    texture.device_id,
    texture.queue_id,
    command_encoder,
    texture.id,
    &texture.size,
  )?;

  let color_type = match texture.format {
    GPUTextureFormat::Rgba8unorm => ExtendedColorType::Rgba8,
    GPUTextureFormat::Rgba8unormSrgb => ExtendedColorType::Rgba8,
    GPUTextureFormat::Rgba8snorm => ExtendedColorType::Rgba8,
    GPUTextureFormat::Rgba8uint => ExtendedColorType::Rgba8,
    GPUTextureFormat::Rgba8sint => ExtendedColorType::Rgba8,
    GPUTextureFormat::Bgra8unorm => ExtendedColorType::Bgra8,
    GPUTextureFormat::Bgra8unormSrgb => ExtendedColorType::Bgra8,
    _ => {
      return Err(JsErrorBox::type_error(format!(
        "Unsupported texture format '{}'",
        texture.format.as_str()
      )));
    }
  };

  let mut out: Vec<u8> = vec![];
  let img =
    deno_runtime::deno_image::image::codecs::png::PngEncoder::new(&mut out);
  img
    .write_image(&data, texture.size.width, texture.size.height, color_type)
    .map_err(|e| JsErrorBox::type_error(e.to_string()))?;
  Ok(deno_runtime::deno_web::forgiving_base64_encode(&out))
}

#[op2]
pub fn op_jupyter_get_buffer(
  #[cppgc] buffer: &deno_runtime::deno_webgpu::buffer::GPUBuffer,
) -> Result<Vec<u8>, deno_runtime::deno_webgpu::error::GPUError> {
  use deno_runtime::deno_webgpu::*;
  let index = buffer.instance.buffer_map_async(
    buffer.id,
    0,
    None,
    wgpu_core::resource::BufferMapOperation {
      host: wgpu_core::device::HostMap::Read,
      callback: None,
    },
  )?;

  buffer
    .instance
    .device_poll(
      buffer.device,
      wgpu_types::PollType::Wait {
        submission_index: Some(index),
        timeout: None,
      },
    )
    .unwrap();

  let (slice_pointer, range_size) = buffer
    .instance
    .buffer_get_mapped_range(buffer.id, 0, None)?;

  let data = {
    // SAFETY: creating a slice from pointer and length provided by wgpu and
    // then dropping it before unmapping
    let slice = unsafe {
      std::slice::from_raw_parts(slice_pointer.as_ptr(), range_size as usize)
    };
    slice.to_vec()
  };

  buffer.instance.buffer_unmap(buffer.id)?;
  Ok(data)
}
