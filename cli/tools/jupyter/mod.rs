// Copyright 2018-2026 the Deno authors. MIT license.

use std::sync::Arc;

use deno_core::anyhow::Context;
use deno_core::anyhow::bail;
use deno_core::error::AnyError;
use deno_core::located_script_name;
use deno_core::serde_json;
use deno_core::serde_json::json;
use deno_core::url::Url;
use deno_path_util::resolve_url_or_path;
use deno_runtime::WorkerExecutionMode;
use deno_runtime::deno_io::Stdio;
use deno_runtime::deno_io::StdioPipe;
use deno_runtime::deno_permissions::PermissionsContainer;
use deno_terminal::colors;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::CliFactory;
use crate::args::Flags;
use crate::args::JupyterFlags;
use crate::cdp;
use crate::ops;
use crate::ops::jupyter::JupyterSockets;
use crate::ops::jupyter::StreamContent;
use crate::tools::repl;
use crate::tools::test::TestEventWorkerSender;
use crate::tools::test::TestFailureFormatOptions;
use crate::tools::test::create_single_test_event_channel;
use crate::tools::test::reporters::PrettyTestReporter;

mod install;
pub mod server;
mod zmtp;

pub async fn kernel(
  flags: Arc<Flags>,
  jupyter_flags: JupyterFlags,
) -> Result<(), AnyError> {
  log::info!(
    "{} \"deno jupyter\" is unstable and might change in the future.",
    colors::yellow("Warning"),
  );

  if !jupyter_flags.install && !jupyter_flags.kernel {
    install::status(jupyter_flags.name.as_deref())?;
    return Ok(());
  }

  if jupyter_flags.install {
    install::install(
      jupyter_flags.name.as_deref(),
      jupyter_flags.display.as_deref(),
      jupyter_flags.force,
    )?;
    return Ok(());
  }

  let connection_filepath = jupyter_flags.conn_file.unwrap();
  let conn_file =
    std::fs::read_to_string(&connection_filepath).with_context(|| {
      format!("Couldn't read connection file: {connection_filepath:?}")
    })?;
  let connection_info: server::ConnectionInfo =
    serde_json::from_str(&conn_file).with_context(|| {
      format!("Connection file is not a valid JSON: {connection_filepath:?}")
    })?;

  let factory = CliFactory::from_flags(flags);
  let cli_options = factory.cli_options()?;
  let main_module =
    resolve_url_or_path("./$deno$jupyter.mts", cli_options.initial_cwd())
      .unwrap();
  let permissions =
    PermissionsContainer::allow_all(factory.permission_desc_parser()?.clone());
  let npm_installer = factory.npm_installer_if_managed().await?.cloned();
  let compiler_options_resolver = factory.compiler_options_resolver()?;
  let resolver = factory.resolver().await?.clone();
  let worker_factory = factory.create_cli_main_worker_factory().await?;
  let (stdio_tx, stdio_rx) = mpsc::unbounded_channel::<StreamContent>();

  let (worker, test_event_receiver) = create_single_test_event_channel();
  let TestEventWorkerSender {
    sender: test_event_sender,
    stdout,
    stderr,
  } = worker;

  let mut worker = worker_factory
    .create_custom_worker(
      WorkerExecutionMode::Jupyter,
      main_module.clone(),
      vec![],
      vec![],
      permissions,
      vec![
        ops::jupyter::deno_jupyter::init(stdio_tx),
        ops::testing::deno_test::init(test_event_sender),
      ],
      Stdio {
        stdin: StdioPipe::inherit(),
        stdout: StdioPipe::file(stdout),
        stderr: StdioPipe::file(stderr),
      },
      None,
    )
    .await?;
  worker.setup_repl().await?;
  let worker = worker.into_main_worker();
  let mut repl_session = repl::ReplSession::initialize(
    cli_options,
    npm_installer,
    resolver,
    compiler_options_resolver,
    worker,
    main_module,
    test_event_receiver,
  )
  .await?;

  struct TestWriter(mpsc::UnboundedSender<StreamContent>);
  impl std::io::Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
      // SAFETY: write only sees UTF-8 since we got it from inspectArgs.
      let s = String::from_utf8_lossy(buf).into_owned();
      self.0.send(StreamContent::stdout(&s)).ok();
      Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
      Ok(())
    }
  }
  let cwd_url =
    Url::from_directory_path(cli_options.initial_cwd()).map_err(|_| {
      deno_core::anyhow::anyhow!(
        "Unable to construct URL from cwd: {}",
        cli_options.initial_cwd().to_string_lossy()
      )
    })?;
  // Re-derive a sender for the test writer. It feeds into the same stdio
  // pipeline that op_print uses.
  let stdio_writer_tx = {
    let op_state = repl_session.worker.js_runtime.op_state();
    let s = op_state.borrow();
    s.borrow::<mpsc::UnboundedSender<StreamContent>>().clone()
  };
  repl_session.set_test_reporter_factory(Box::new(move || {
    Box::new(
      PrettyTestReporter::new(
        false,
        true,
        false,
        true,
        cwd_url.clone(),
        TestFailureFormatOptions::default(),
      )
      .with_writer(Box::new(TestWriter(stdio_writer_tx.clone()))),
    )
  }));

  // Set up REPL bridge: ops on the JS side push requests here; this loop
  // serves them by calling REPL session methods.
  let (proxy_tx, proxy_rx) = mpsc::unbounded_channel::<JupyterReplRequest>();
  let (resp_tx, resp_rx) = mpsc::unbounded_channel::<JupyterReplResponse>();

  let proxy = Arc::new(AsyncMutex::new(JupyterReplProxy {
    tx: proxy_tx,
    rx: resp_rx,
  }));

  let isolate_handle = repl_session
    .worker
    .js_runtime
    .v8_isolate()
    .thread_safe_handle();

  // Bind sockets on a dedicated OS thread so that the interrupt detector
  // task can call terminate_execution() even while the user-code worker
  // is busy running synchronous JS.
  let (sockets_tx, sockets_rx) =
    oneshot::channel::<Result<JupyterSockets, AnyError>>();
  let info_for_thread = connection_info.clone();
  let isolate_handle_clone = isolate_handle.clone();
  std::thread::spawn(move || {
    let result: Result<(), AnyError> =
      deno_runtime::tokio_util::create_and_run_current_thread(async move {
        let handles =
          server::start(&info_for_thread, isolate_handle_clone).await?;
        let sockets: JupyterSockets = handles.into();
        if sockets_tx.send(Ok(sockets)).is_err() {
          return Ok(());
        }
        // Keep the runtime alive forever; the tasks spawned inside
        // `server::start` own all the work.
        std::future::pending::<()>().await;
        Ok(())
      });
    if let Err(err) = result {
      log::error!("Jupyter socket thread error: {err}");
    }
  });

  let sockets = match sockets_rx.await {
    Ok(Ok(s)) => Arc::new(s),
    Ok(Err(err)) => return Err(err),
    Err(_) => bail!("socket thread aborted before binding"),
  };

  // Stash everything the ops need.
  {
    let op_state = repl_session.worker.js_runtime.op_state();
    let mut s = op_state.borrow_mut();
    s.put(sockets);
    s.put(proxy);
    s.put(Arc::new(AsyncMutex::new(stdio_rx)));
    s.put(Arc::new(ConnectionInfoForJs::from(&connection_info)));
  }

  // Surface the connection info and version to JS, then start the kernel
  // main loop running on the worker's event loop. `enableJupyter` sets up
  // `Deno.jupyter`; `startJupyterKernel` kicks off the protocol loops.
  let bootstrap = format!(
    "Deno[Deno.internal].enableJupyter(); Deno[Deno.internal].startJupyterKernel({});",
    serde_json::to_string(&ConnectionInfoForJs::from(&connection_info))?,
  );
  repl_session
    .worker
    .js_runtime
    .execute_script(located_script_name!(), bootstrap)?;

  let mut session = JupyterReplSession {
    repl_session,
    rx: proxy_rx,
    tx: resp_tx,
  };
  session.start().await;

  Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
struct ConnectionInfoForJs {
  ip: String,
  transport: String,
  hb_port: u16,
  control_port: u16,
  shell_port: u16,
  stdin_port: u16,
  iopub_port: u16,
  signature_scheme: String,
  key: String,
  kernel_name: String,
}

impl From<&server::ConnectionInfo> for ConnectionInfoForJs {
  fn from(info: &server::ConnectionInfo) -> Self {
    Self {
      ip: info.ip.clone(),
      transport: info.transport.clone(),
      hb_port: info.hb_port,
      control_port: info.control_port,
      shell_port: info.shell_port,
      stdin_port: info.stdin_port,
      iopub_port: info.iopub_port,
      signature_scheme: info.signature_scheme.clone(),
      key: info.key.clone(),
      kernel_name: info.kernel_name.clone(),
    }
  }
}

pub enum JupyterReplRequest {
  GetProperties {
    object_id: String,
  },
  Evaluate {
    expr: String,
  },
  GlobalLexicalScopeNames,
  EvaluateLineWithObjectWrapping {
    line: String,
  },
  CallFunctionOnArgs {
    function_declaration: String,
    args: Vec<cdp::RemoteObject>,
  },
  CallFunctionOn {
    arg0: cdp::CallArgument,
    arg1: cdp::CallArgument,
  },
  CancelPendingTerminate,
}

pub enum JupyterReplResponse {
  GetProperties(Option<cdp::GetPropertiesResponse>),
  Evaluate(Option<cdp::EvaluateResponse>),
  GlobalLexicalScopeNames(cdp::GlobalLexicalScopeNamesResponse),
  EvaluateLineWithObjectWrapping(Result<repl::TsEvaluateResponse, AnyError>),
  CallFunctionOnArgs(Result<cdp::CallFunctionOnResponse, AnyError>),
  #[allow(
    dead_code,
    reason = "value carries no information; presence signals success"
  )]
  CallFunctionOn(Option<cdp::CallFunctionOnResponse>),
}

/// Shared handle used by ops to call into the REPL session.
pub struct JupyterReplProxy {
  pub tx: mpsc::UnboundedSender<JupyterReplRequest>,
  pub rx: mpsc::UnboundedReceiver<JupyterReplResponse>,
}

struct JupyterReplSession {
  repl_session: repl::ReplSession,
  rx: mpsc::UnboundedReceiver<JupyterReplRequest>,
  tx: mpsc::UnboundedSender<JupyterReplResponse>,
}

impl JupyterReplSession {
  pub async fn start(&mut self) {
    let mut poll_worker = true;
    loop {
      tokio::select! {
        biased;

        maybe_message = self.rx.recv() => {
          let Some(msg) = maybe_message else {
            break;
          };
          if self.handle_message(msg).await.is_err() {
            break;
          }
          poll_worker = true;
        },
        _ = self.repl_session.run_event_loop(), if poll_worker => {
          poll_worker = false;
        }
      }
    }
  }

  async fn handle_message(
    &mut self,
    msg: JupyterReplRequest,
  ) -> Result<(), AnyError> {
    let resp = match msg {
      JupyterReplRequest::GetProperties { object_id } => {
        JupyterReplResponse::GetProperties(self.get_properties(object_id).await)
      }
      JupyterReplRequest::Evaluate { expr } => {
        JupyterReplResponse::Evaluate(self.evaluate(expr).await)
      }
      JupyterReplRequest::GlobalLexicalScopeNames => {
        JupyterReplResponse::GlobalLexicalScopeNames(
          self.global_lexical_scope_names().await,
        )
      }
      JupyterReplRequest::EvaluateLineWithObjectWrapping { line } => {
        JupyterReplResponse::EvaluateLineWithObjectWrapping(
          self.evaluate_line_with_object_wrapping(&line).await,
        )
      }
      JupyterReplRequest::CallFunctionOnArgs {
        function_declaration,
        args,
      } => JupyterReplResponse::CallFunctionOnArgs(
        self
          .call_function_on_args(function_declaration, &args)
          .await,
      ),
      JupyterReplRequest::CallFunctionOn { arg0, arg1 } => {
        JupyterReplResponse::CallFunctionOn(
          self.call_function_on(arg0, arg1).await,
        )
      }
      JupyterReplRequest::CancelPendingTerminate => {
        self
          .repl_session
          .worker
          .js_runtime
          .v8_isolate()
          .cancel_terminate_execution();
        // No response expected.
        return Ok(());
      }
    };
    self.tx.send(resp).map_err(|e| e.into())
  }

  pub async fn get_properties(
    &mut self,
    object_id: String,
  ) -> Option<cdp::GetPropertiesResponse> {
    let r = self
      .repl_session
      .post_message_with_event_loop(
        "Runtime.getProperties",
        Some(cdp::GetPropertiesArgs {
          object_id,
          own_properties: None,
          accessor_properties_only: None,
          generate_preview: None,
          non_indexed_properties_only: Some(true),
        }),
      )
      .await;
    serde_json::from_value(r).ok()
  }

  pub async fn evaluate(
    &mut self,
    expr: String,
  ) -> Option<cdp::EvaluateResponse> {
    let r = self
      .repl_session
      .post_message_with_event_loop(
        "Runtime.evaluate",
        Some(cdp::EvaluateArgs {
          expression: expr,
          object_group: None,
          include_command_line_api: None,
          silent: None,
          context_id: Some(self.repl_session.context_id),
          return_by_value: None,
          generate_preview: None,
          user_gesture: None,
          await_promise: None,
          throw_on_side_effect: Some(true),
          timeout: Some(200),
          disable_breaks: None,
          repl_mode: None,
          allow_unsafe_eval_blocked_by_csp: None,
          unique_context_id: None,
        }),
      )
      .await;
    serde_json::from_value(r).ok()
  }

  pub async fn global_lexical_scope_names(
    &mut self,
  ) -> cdp::GlobalLexicalScopeNamesResponse {
    let r = self
      .repl_session
      .post_message_with_event_loop(
        "Runtime.globalLexicalScopeNames",
        Some(cdp::GlobalLexicalScopeNamesArgs {
          execution_context_id: Some(self.repl_session.context_id),
        }),
      )
      .await;
    serde_json::from_value(r).unwrap()
  }

  pub async fn evaluate_line_with_object_wrapping(
    &mut self,
    line: &str,
  ) -> Result<repl::TsEvaluateResponse, AnyError> {
    self
      .repl_session
      .worker
      .js_runtime
      .v8_isolate()
      .cancel_terminate_execution();
    self
      .repl_session
      .evaluate_line_with_object_wrapping(line)
      .await
  }

  pub async fn call_function_on_args(
    &mut self,
    function_declaration: String,
    args: &[cdp::RemoteObject],
  ) -> Result<cdp::CallFunctionOnResponse, AnyError> {
    self
      .repl_session
      .call_function_on_args(function_declaration, args)
      .await
  }

  pub async fn call_function_on(
    &mut self,
    arg0: cdp::CallArgument,
    arg1: cdp::CallArgument,
  ) -> Option<cdp::CallFunctionOnResponse> {
    let response = self
      .repl_session
      .post_message_with_event_loop(
        "Runtime.callFunctionOn",
        Some(json!({
          "functionDeclaration": r#"async function (execution_count, result) {
            await Deno[Deno.internal].jupyter.broadcastResult(execution_count, result);
          }"#,
          "arguments": [arg0, arg1],
          "executionContextId": self.repl_session.context_id,
          "awaitPromise": true,
        })),
      )
      .await;
    serde_json::from_value(response).ok()
  }
}
