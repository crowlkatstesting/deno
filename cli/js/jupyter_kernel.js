// Copyright 2018-2026 the Deno authors. MIT license.

// Jupyter kernel protocol layer (signing, multipart parse/build, dispatch).
// The transport (ZMTP, sockets) lives in Rust at `cli/tools/jupyter/zmtp.rs`
// and is bridged to this module via `op_jupyter_recv` / `op_jupyter_send`.

import { core, internals, primordials } from "ext:core/mod.js";

const {
  ArrayPrototypePush,
  Error,
  JSONParse,
  JSONStringify,
  ObjectEntries,
  ObjectKeys,
  ObjectPrototypeHasOwnProperty,
  PromisePrototypeThen,
  PromiseResolve,
  StringFromCharCode,
  StringPrototypeCharCodeAt,
  StringPrototypeSplit,
  TypedArrayPrototypeGetByteLength,
  Uint8Array,
} = primordials;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const DELIM_STR = "<IDS|MSG>";
const DELIM = encoder.encode(DELIM_STR);
const PROTOCOL_VERSION = "5.3";
const SESSION_ID = randomUuid();

let connectionInfo = null;
let signingKey = null;
let executionCount = 0;
let lastExecutionRequest = null;
let pendingStdinResolver = null;

function randomUuid() {
  // RFC4122 v4
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [];
  for (let i = 0; i < 16; i++) {
    h.push(b[i].toString(16).padStart(2, "0"));
  }
  return `${h.slice(0, 4).join("")}-${h.slice(4, 6).join("")}-${
    h.slice(6, 8).join("")
  }-${h.slice(8, 10).join("")}-${h.slice(10).join("")}`;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function hex(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s;
}

async function sign(parts) {
  if (!signingKey) return "";
  // HMAC over the concatenation of the four header/content frames.
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.byteLength;
  }
  const sig = await crypto.subtle.sign("HMAC", signingKey, buf);
  return hex(new Uint8Array(sig));
}

async function verify(signature, parts) {
  if (!signingKey) return true;
  const expected = await sign(parts);
  return expected === signature;
}

// Locate the `<IDS|MSG>` delimiter and split into identities + body.
function splitMessage(parts) {
  let idx = -1;
  for (let i = 0; i < parts.length; i++) {
    if (bytesEqual(parts[i], DELIM)) {
      idx = i;
      break;
    }
  }
  if (idx < 0) return null;
  const identities = parts.slice(0, idx);
  const sigBytes = parts[idx + 1] ?? new Uint8Array(0);
  const headerBytes = parts[idx + 2];
  const parentBytes = parts[idx + 3];
  const metadataBytes = parts[idx + 4];
  const contentBytes = parts[idx + 5];
  const buffers = parts.slice(idx + 6);
  return {
    identities,
    sigBytes,
    headerBytes,
    parentBytes,
    metadataBytes,
    contentBytes,
    buffers,
  };
}

async function parseMessage(parts) {
  const split = splitMessage(parts);
  if (!split) return null;
  const ok = await verify(
    decoder.decode(split.sigBytes),
    [split.headerBytes, split.parentBytes, split.metadataBytes, split.contentBytes],
  );
  if (!ok) {
    core.print("[jupyter] dropping message with bad signature\n", true);
    return null;
  }
  return {
    identities: split.identities,
    header: JSONParse(decoder.decode(split.headerBytes)),
    parentHeader: JSONParse(decoder.decode(split.parentBytes)),
    metadata: JSONParse(decoder.decode(split.metadataBytes)),
    content: JSONParse(decoder.decode(split.contentBytes)),
    buffers: split.buffers,
  };
}

function makeHeader(msgType) {
  return {
    msg_id: randomUuid(),
    session: SESSION_ID,
    username: "kernel",
    date: new Date().toISOString(),
    msg_type: msgType,
    version: PROTOCOL_VERSION,
  };
}

async function buildMessage(
  identities,
  msgType,
  content,
  { parent = null, metadata = {}, buffers = [] } = {},
) {
  const header = makeHeader(msgType);
  const parentHeader = parent ?? {};
  const hBytes = encoder.encode(JSONStringify(header));
  const pBytes = encoder.encode(JSONStringify(parentHeader));
  const mBytes = encoder.encode(JSONStringify(metadata));
  const cBytes = encoder.encode(JSONStringify(content));
  const sig = await sign([hBytes, pBytes, mBytes, cBytes]);
  const out = [];
  for (const id of identities) ArrayPrototypePush(out, id);
  ArrayPrototypePush(out, DELIM);
  ArrayPrototypePush(out, encoder.encode(sig));
  ArrayPrototypePush(out, hBytes);
  ArrayPrototypePush(out, pBytes);
  ArrayPrototypePush(out, mBytes);
  ArrayPrototypePush(out, cBytes);
  for (const b of buffers) ArrayPrototypePush(out, b);
  return out;
}

async function sendOn(channel, identities, msgType, content, opts = {}) {
  const parts = await buildMessage(identities, msgType, content, opts);
  core.ops.op_jupyter_send(channel, parts);
}

// IOPub messages don't have ZMTP routing identities, but Jupyter clients
// subscribe to topic prefixes. Convention is `kernel.<session>.<msg_type>`
// or just `<msg_type>`. Using the msg_type keeps things simple.
async function publishIoPub(msgType, content, opts = {}) {
  const topic = encoder.encode(msgType);
  await sendOn("iopub", [topic], msgType, content, opts);
}

function kernelInfo() {
  return {
    status: "ok",
    protocol_version: PROTOCOL_VERSION,
    implementation: "Deno kernel",
    implementation_version: core.ops.op_jupyter_deno_version(),
    language_info: {
      name: "typescript",
      version: core.ops.op_jupyter_typescript_version(),
      mimetype: "text/x.typescript",
      file_extension: ".ts",
      pygments_lexer: "typescript",
      codemirror_mode: { name: "typescript", mode: "typescript" },
      nbconvert_exporter: "script",
    },
    banner: "Welcome to Deno kernel",
    help_links: [
      { text: "Visit Deno manual", url: "https://docs.deno.com" },
    ],
    debugger: false,
  };
}

// --- is_complete heuristic --------------------------------------------------
// Mirrors the Rust implementation it replaces: balanced brackets, stripping
// strings and comments.
function checkIsComplete(code) {
  const stack = [];
  let i = 0;
  const n = code.length;
  while (i < n) {
    const ch = code[i];
    if (ch === "/" && code[i + 1] === "/") {
      while (i < n && code[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && code[i + 1] === "*") {
      i += 2;
      let closed = false;
      while (i < n) {
        if (code[i] === "*" && code[i + 1] === "/") {
          i += 2;
          closed = true;
          break;
        }
        i++;
      }
      if (!closed) return { status: "incomplete", indent: "" };
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      const quote = ch;
      i++;
      let closed = false;
      let escaped = false;
      while (i < n) {
        const c = code[i++];
        if (escaped) {
          escaped = false;
          continue;
        }
        if (c === "\\") {
          escaped = true;
          continue;
        }
        if (c === quote) {
          closed = true;
          break;
        }
      }
      if (!closed) return { status: "incomplete", indent: "" };
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") {
      stack.push(ch);
    } else if (ch === ")") {
      if (stack.pop() !== "(") return { status: "invalid" };
    } else if (ch === "]") {
      if (stack.pop() !== "[") return { status: "invalid" };
    } else if (ch === "}") {
      if (stack.pop() !== "{") return { status: "invalid" };
    }
    i++;
  }
  return stack.length === 0
    ? { status: "complete" }
    : { status: "incomplete", indent: "  " };
}

// --- completion helpers ----------------------------------------------------
function isWordBoundary(c) {
  if (c === "." || c === "_" || c === "$") return false;
  const code = StringPrototypeCharCodeAt(c, 0);
  // ASCII whitespace or ASCII punctuation
  if (code <= 32) return true;
  return (code >= 33 && code <= 47) || (code >= 58 && code <= 64) ||
    (code >= 91 && code <= 96) || (code >= 123 && code <= 126);
}

function exprAtCursor(line, cursorPos) {
  let start = 0;
  for (let i = cursorPos - 1; i >= 0; i--) {
    if (isWordBoundary(line[i])) {
      start = i + 1;
      break;
    }
  }
  let end = cursorPos;
  for (let i = cursorPos; i < line.length; i++) {
    if (isWordBoundary(line[i])) {
      end = i;
      break;
    }
    end = i + 1;
  }
  return line.slice(start, end);
}

async function getObjectExprProperties(expr) {
  const r = await core.ops.op_jupyter_repl_evaluate_expression(expr);
  if (!r) return null;
  const id = r?.result?.objectId;
  if (!id) return null;
  const props = await core.ops.op_jupyter_repl_get_properties(id);
  if (!props) return null;
  return (props.result ?? []).map((p) => p.name);
}

async function getExpressionPropertyNames(expr) {
  const direct = await getObjectExprProperties(expr);
  if (direct) return direct;
  const r = await core.ops.op_jupyter_repl_evaluate_expression(expr);
  const kind = r?.result?.type;
  const proto = {
    object: "Object.prototype",
    function: "Function.prototype",
    string: "String.prototype",
    boolean: "Boolean.prototype",
    bigint: "BigInt.prototype",
    number: "Number.prototype",
  }[kind];
  if (!proto) return [];
  return (await getObjectExprProperties(proto)) ?? [];
}

async function complete(code, cursorPos) {
  const expr = exprAtCursor(code, cursorPos);
  const dot = expr.lastIndexOf(".");
  if (dot >= 0) {
    const sub = expr.slice(0, dot);
    const prefix = expr.slice(dot + 1);
    const names = await getExpressionPropertyNames(sub);
    const matches = names.filter((n) =>
      !n.startsWith("Symbol(") && n.startsWith(prefix)
    );
    return {
      matches,
      cursor_start: prefix.length > cursorPos ? cursorPos : cursorPos - prefix.length,
      cursor_end: cursorPos,
    };
  }
  const globals = await getExpressionPropertyNames("globalThis");
  const lex = await core.ops.op_jupyter_repl_global_lexical_scope_names();
  const all = [...globals, ...lex].filter((n) => n.startsWith(expr));
  all.sort();
  const dedup = [];
  for (const x of all) if (dedup[dedup.length - 1] !== x) dedup.push(x);
  return {
    matches: dedup,
    cursor_start: expr.length > cursorPos ? cursorPos : cursorPos - expr.length,
    cursor_end: cursorPos,
  };
}

// --- shell / control / stdin / iopub / heartbeat loops ---------------------

async function heartbeatLoop() {
  while (true) {
    const parts = await core.ops.op_jupyter_recv("heartbeat");
    if (parts === null) return;
    core.ops.op_jupyter_send("heartbeat", parts);
  }
}

async function controlLoop() {
  while (true) {
    const parts = await core.ops.op_jupyter_recv("control");
    if (parts === null) return;
    const msg = await parseMessage(parts);
    if (!msg) continue;
    await handleControl(msg);
  }
}

async function handleControl(msg) {
  const t = msg.header.msg_type;
  if (t === "kernel_info_request") {
    await sendOn("control", msg.identities, "kernel_info_reply", kernelInfo(), {
      parent: msg.header,
    });
  } else if (t === "shutdown_request") {
    await sendOn("control", msg.identities, "shutdown_reply", {
      restart: !!msg.content.restart,
      status: "ok",
    }, { parent: msg.header });
    setTimeout(() => Deno.exit(0), 10);
  } else if (t === "interrupt_request") {
    // The Rust control-channel detector has already terminated user code.
    // Cancel the pending termination flag so the next evaluation can proceed.
    await sendOn("control", msg.identities, "interrupt_reply", { status: "ok" }, {
      parent: msg.header,
    });
  } else if (t === "debug_request") {
    core.print("[jupyter] debug_request not supported\n", true);
  }
}

async function shellLoop() {
  while (true) {
    const parts = await core.ops.op_jupyter_recv("shell");
    if (parts === null) return;
    const msg = await parseMessage(parts);
    if (!msg) continue;
    await handleShell(msg);
  }
}

async function handleShell(msg) {
  await publishIoPub("status", { execution_state: "busy" }, { parent: msg.header });
  try {
    const t = msg.header.msg_type;
    if (t === "execute_request") {
      await handleExecute(msg);
    } else if (t === "complete_request") {
      const r = await complete(msg.content.code, msg.content.cursor_pos);
      await sendOn("shell", msg.identities, "complete_reply", {
        ...r,
        metadata: {},
        status: "ok",
      }, { parent: msg.header });
    } else if (t === "is_complete_request") {
      await sendOn(
        "shell",
        msg.identities,
        "is_complete_reply",
        checkIsComplete(msg.content.code),
        { parent: msg.header },
      );
    } else if (t === "inspect_request") {
      // Not implemented; reply "not found".
      await sendOn("shell", msg.identities, "inspect_reply", {
        status: "ok",
        found: false,
        data: {},
        metadata: {},
      }, { parent: msg.header });
    } else if (t === "kernel_info_request") {
      await sendOn(
        "shell",
        msg.identities,
        "kernel_info_reply",
        kernelInfo(),
        { parent: msg.header },
      );
    } else if (t === "comm_open") {
      await sendOn("shell", msg.identities, "comm_close", {
        comm_id: msg.content.comm_id,
        data: {},
      }, { parent: msg.header });
    } else if (t === "comm_info_request") {
      await sendOn("shell", msg.identities, "comm_info_reply", {
        comms: {},
        status: "ok",
      }, { parent: msg.header });
    } else if (t === "history_request") {
      await sendOn("shell", msg.identities, "history_reply", {
        history: [],
        status: "ok",
      }, { parent: msg.header });
    } else if (t === "comm_msg" || t === "comm_close") {
      // ignore
    } else {
      core.print(`[jupyter] unknown shell msg_type ${t}\n`, true);
    }
  } finally {
    await publishIoPub("status", { execution_state: "idle" }, { parent: msg.header });
  }
}

async function handleExecute(msg) {
  const req = msg.content;
  if (!req.silent && req.store_history !== false) {
    executionCount++;
  }
  lastExecutionRequest = msg;

  await publishIoPub("execute_input", {
    execution_count: executionCount,
    code: req.code,
  }, { parent: msg.header });

  let response;
  try {
    response = await core.ops.op_jupyter_repl_evaluate(req.code);
  } catch (err) {
    const message = err?.message ?? String(err);
    await publishIoPub("error", {
      ename: message,
      evalue: message,
      traceback: [],
    }, { parent: msg.header });
    await sendOn("shell", msg.identities, "execute_reply", {
      execution_count: executionCount,
      status: "error",
      payload: [],
      user_expressions: {},
    }, { parent: msg.header });
    return;
  }

  const evalResult = response.result;
  const exceptionDetails = response.exceptionDetails;

  if (!exceptionDetails) {
    // Format and broadcast the result via the user-code worker so that any
    // `Symbol.for("Jupyter.display")` method gets honoured.
    await core.ops.op_jupyter_repl_broadcast_result(executionCount, {
      objectId: evalResult.objectId,
      value: evalResult.value,
      unserializableValue: evalResult.unserializableValue,
    });
    await sendOn("shell", msg.identities, "execute_reply", {
      execution_count: executionCount,
      status: "ok",
      payload: [],
      user_expressions: {},
    }, { parent: msg.header });
    // Give the stdio relay a chance to flush before the cell completes.
    await new Promise((r) => setTimeout(r, 5));
    return;
  }

  // Resolve the exception into name/message/stack via call_function_on_args.
  let name = "";
  let message = "";
  let stack = "";
  if (exceptionDetails.exception) {
    try {
      const r = await core.ops.op_jupyter_repl_call_function_on_args({
        functionDeclaration: `function(object) {
          if (object instanceof Error) {
            const name = "name" in object ? String(object.name) : "";
            const message = "message" in object ? String(object.message) : "";
            const stack = "stack" in object ? String(object.stack) : "";
            return JSON.stringify({ name, message, stack });
          } else {
            const m = String(object);
            return JSON.stringify({ name: "", message: m, stack: "" });
          }
        }`,
        arguments: [exceptionDetails.exception],
      });
      const v = r?.result?.value;
      if (typeof v === "string") {
        const o = JSONParse(v);
        name = o.name ?? "";
        message = o.message ?? "";
        stack = o.stack ?? "";
      }
    } catch (_) {
      // fall through with empty fields
    }
  }
  if (!stack) stack = `${JSONStringify(message)}\n    at <unknown>`;
  const traceback = StringPrototypeSplit(`Stack trace:\n${stack}`, "\n");
  const ename = name || "Unknown error";
  const evalue = message || "(none)";

  await publishIoPub("error", { ename, evalue, traceback }, { parent: msg.header });
  await sendOn("shell", msg.identities, "execute_reply", {
    execution_count: executionCount,
    status: "error",
    error: { ename, evalue, traceback },
    payload: [],
    user_expressions: {},
  }, { parent: msg.header });
}

async function stdinLoop() {
  while (true) {
    const parts = await core.ops.op_jupyter_recv("stdin");
    if (parts === null) return;
    const msg = await parseMessage(parts);
    if (!msg) continue;
    if (msg.header.msg_type === "input_reply") {
      const r = pendingStdinResolver;
      pendingStdinResolver = null;
      if (r) r(msg.content.value ?? "");
    }
  }
}

async function stdioRelayLoop() {
  while (true) {
    const item = await core.ops.op_jupyter_recv_stdio();
    if (item === null) return;
    const [name, text] = item;
    if (!lastExecutionRequest) continue;
    await publishIoPub("stream", { name, text }, {
      parent: lastExecutionRequest.header,
    });
  }
}

// --- user-facing helpers (called by 40_jupyter.js) -------------------------

async function kernelBroadcast(msgType, content, opts = {}) {
  if (!lastExecutionRequest) return;
  await publishIoPub(msgType, content, {
    parent: lastExecutionRequest.header,
    metadata: opts.metadata ?? {},
    buffers: opts.buffers ?? [],
  });
}

async function kernelInput(prompt, password) {
  if (!lastExecutionRequest) return "";
  const allow = lastExecutionRequest.content.allow_stdin;
  if (!allow) return "";
  await sendOn(
    "stdin",
    lastExecutionRequest.identities,
    "input_request",
    { prompt, password: !!password },
    { parent: lastExecutionRequest.header },
  );
  return await new Promise((resolve) => {
    pendingStdinResolver = resolve;
  });
}

internals.startJupyterKernel = async function (info) {
  connectionInfo = info;
  if (info.key) {
    signingKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(info.key),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
  }
  internals.jupyter = internals.jupyter ?? {};
  internals.jupyter.kernelBroadcast = kernelBroadcast;
  internals.jupyter.kernelInput = kernelInput;
  // Fire and forget: each loop runs forever.
  PromisePrototypeThen(heartbeatLoop(), null, logError);
  PromisePrototypeThen(controlLoop(), null, logError);
  PromisePrototypeThen(shellLoop(), null, logError);
  PromisePrototypeThen(stdinLoop(), null, logError);
  PromisePrototypeThen(stdioRelayLoop(), null, logError);
};

function logError(err) {
  core.print(`[jupyter] loop error: ${err?.stack ?? err}\n`, true);
}
