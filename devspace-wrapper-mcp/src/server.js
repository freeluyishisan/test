#!/usr/bin/env node
import express from "express";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const SERVER_NAME = "devspace-wrapper-mcp";
const SERVER_VERSION = "0.1.0";

const HOST = process.env.HOST || process.env.WRAPPER_HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || process.env.WRAPPER_PORT || 8931);
const MAX_OUTPUT_BYTES = Number(process.env.WRAPPER_MAX_OUTPUT_BYTES || 200_000);
const DEFAULT_TIMEOUT_SECONDS = Number(process.env.WRAPPER_DEFAULT_TIMEOUT_SECONDS || 30);
const MAX_TIMEOUT_SECONDS = Number(process.env.WRAPPER_MAX_TIMEOUT_SECONDS || 300);
const MAX_READ_BYTES = Number(process.env.WRAPPER_MAX_READ_BYTES || 1_500_000);

const workspaces = new Map();

function expandHome(input) {
  if (!input) return input;
  if (input === "~") return os.homedir();
  if (input.startsWith("~/")) return path.join(os.homedir(), input.slice(2));
  return input;
}

function normalizePathForDisplay(value) {
  return value.split(path.sep).join("/");
}

function isSubPath(parent, child) {
  const relative = path.relative(parent, child);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function loadAllowedRoots() {
  const raw = process.env.WRAPPER_ALLOWED_ROOTS || process.env.DEVSPACE_WRAPPER_ALLOWED_ROOTS || process.cwd();
  const roots = raw
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => path.resolve(expandHome(entry)))
    .map((entry) => {
      try {
        return fs.realpathSync(entry);
      } catch {
        throw new Error(`Allowed root does not exist: ${entry}`);
      }
    });

  if (roots.length === 0) throw new Error("No allowed roots configured");
  return Array.from(new Set(roots));
}

const allowedRoots = loadAllowedRoots();

function assertInsideAllowedRoots(realTarget) {
  if (!allowedRoots.some((root) => isSubPath(root, realTarget))) {
    throw new Error(`Path is outside allowed roots: ${realTarget}`);
  }
}

async function realpathIfExists(target) {
  try {
    return await fsp.realpath(target);
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
}

async function ensureDirectory(target) {
  const stat = await fsp.stat(target);
  if (!stat.isDirectory()) throw new Error(`Not a directory: ${target}`);
}

async function openWorkspace(input) {
  const requested = input?.path || allowedRoots[0];
  const absolute = path.resolve(expandHome(requested));
  const realRoot = await fsp.realpath(absolute);
  await ensureDirectory(realRoot);
  assertInsideAllowedRoots(realRoot);

  const workspaceId = randomUUID();
  workspaces.set(workspaceId, { id: workspaceId, root: realRoot, createdAt: new Date().toISOString() });

  return [
    `Opened workspace ${workspaceId}`,
    `Root: ${realRoot}`,
    `Allowed roots: ${allowedRoots.join(", ")}`,
    "Use this workspaceId for read, write, edit, ls, grep, and bash calls.",
  ].join("\n");
}

function getWorkspace(workspaceId) {
  const workspace = workspaces.get(workspaceId);
  if (!workspace) throw new Error(`Unknown workspaceId: ${workspaceId}`);
  return workspace;
}

async function resolveWorkspacePath(workspace, userPath = ".", options = {}) {
  if (typeof userPath !== "string" || userPath.length === 0) {
    throw new Error("path must be a non-empty string");
  }

  const base = workspace.root;
  const absolute = path.isAbsolute(expandHome(userPath))
    ? path.resolve(expandHome(userPath))
    : path.resolve(base, userPath);

  if (!isSubPath(base, absolute)) {
    throw new Error(`Path escapes workspace root: ${userPath}`);
  }

  const real = await realpathIfExists(absolute);
  if (real) {
    if (!isSubPath(base, real)) throw new Error(`Real path escapes workspace root: ${userPath}`);
    assertInsideAllowedRoots(real);
    return real;
  }

  if (options.mustExist) throw new Error(`Path does not exist: ${userPath}`);

  const parent = path.dirname(absolute);
  const realParent = await realpathIfExists(parent);
  if (!realParent) throw new Error(`Parent path does not exist: ${path.relative(base, parent)}`);
  if (!isSubPath(base, realParent)) throw new Error(`Parent real path escapes workspace root: ${userPath}`);
  assertInsideAllowedRoots(realParent);
  return absolute;
}

function truncateText(text, maxBytes = MAX_OUTPUT_BYTES) {
  const buffer = Buffer.from(text, "utf8");
  if (buffer.byteLength <= maxBytes) return text;
  return buffer.subarray(0, maxBytes).toString("utf8") + `\n...[truncated to ${maxBytes} bytes]`;
}

async function readTool(input) {
  const workspace = getWorkspace(input.workspaceId);
  const target = await resolveWorkspacePath(workspace, input.path, { mustExist: true });
  const stat = await fsp.stat(target);
  if (!stat.isFile()) throw new Error(`Not a file: ${input.path}`);
  if (stat.size > MAX_READ_BYTES && !input.limit) {
    throw new Error(`File is too large (${stat.size} bytes). Use offset/limit or raise WRAPPER_MAX_READ_BYTES.`);
  }

  const content = await fsp.readFile(target, "utf8");
  const lines = content.split(/\r?\n/);
  const offset = Math.max(1, Number(input.offset || 1));
  const limit = input.limit ? Math.max(1, Number(input.limit)) : undefined;
  const selected = limit ? lines.slice(offset - 1, offset - 1 + limit) : lines.slice(offset - 1);
  const numbered = selected.map((line, index) => `${offset + index}: ${line}`).join("\n");
  return truncateText(numbered);
}

async function writeTool(input) {
  const workspace = getWorkspace(input.workspaceId);
  if (typeof input.content !== "string") throw new Error("content must be a string");
  const target = await resolveWorkspacePath(workspace, input.path, { mustExist: false });
  await fsp.mkdir(path.dirname(target), { recursive: true });
  if (input.overwrite === false) {
    const existing = await realpathIfExists(target);
    if (existing) throw new Error(`File already exists and overwrite=false: ${input.path}`);
  }
  await fsp.writeFile(target, input.content, "utf8");
  return `Wrote ${Buffer.byteLength(input.content, "utf8")} bytes to ${normalizePathForDisplay(path.relative(workspace.root, target))}`;
}

async function editTool(input) {
  const workspace = getWorkspace(input.workspaceId);
  if (typeof input.oldText !== "string" || input.oldText.length === 0) throw new Error("oldText must be a non-empty string");
  if (typeof input.newText !== "string") throw new Error("newText must be a string");

  const target = await resolveWorkspacePath(workspace, input.path, { mustExist: true });
  const original = await fsp.readFile(target, "utf8");
  const first = original.indexOf(input.oldText);
  if (first === -1) throw new Error("oldText was not found");

  let updated;
  let replacements;
  if (input.replaceAll === true) {
    updated = original.split(input.oldText).join(input.newText);
    replacements = original.split(input.oldText).length - 1;
  } else {
    const last = original.lastIndexOf(input.oldText);
    if (first !== last) throw new Error("oldText appears multiple times. Set replaceAll=true or provide a more specific oldText.");
    updated = original.slice(0, first) + input.newText + original.slice(first + input.oldText.length);
    replacements = 1;
  }

  await fsp.writeFile(target, updated, "utf8");
  return `Edited ${normalizePathForDisplay(path.relative(workspace.root, target))}; replacements=${replacements}`;
}

async function lsTool(input) {
  const workspace = getWorkspace(input.workspaceId);
  const target = await resolveWorkspacePath(workspace, input.path || ".", { mustExist: true });
  const entries = await fsp.readdir(target, { withFileTypes: true });
  const rows = [];
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const full = path.join(target, entry.name);
    let stat;
    try {
      stat = await fsp.lstat(full);
    } catch {
      continue;
    }
    const type = entry.isDirectory() ? "dir" : entry.isFile() ? "file" : entry.isSymbolicLink() ? "symlink" : "other";
    rows.push(`${type.padEnd(7)} ${String(stat.size).padStart(10)} ${stat.mtime.toISOString()} ${entry.name}`);
  }
  return rows.join("\n") || "(empty)";
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function isProbablyTextFile(file) {
  const handle = await fsp.open(file, "r");
  try {
    const buffer = Buffer.alloc(4096);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return !buffer.subarray(0, bytesRead).includes(0);
  } finally {
    await handle.close();
  }
}

async function walkFiles(root, results = []) {
  const ignored = new Set([".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"]);
  const entries = await fsp.readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    if (ignored.has(entry.name)) continue;
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) await walkFiles(full, results);
    else if (entry.isFile()) results.push(full);
  }
  return results;
}

async function grepTool(input) {
  const workspace = getWorkspace(input.workspaceId);
  if (typeof input.pattern !== "string" || input.pattern.length === 0) throw new Error("pattern must be a non-empty string");
  const target = await resolveWorkspacePath(workspace, input.path || ".", { mustExist: true });
  const stat = await fsp.stat(target);
  const files = stat.isDirectory() ? await walkFiles(target) : [target];
  const flags = input.caseSensitive ? "g" : "gi";
  const regex = new RegExp(input.regex ? input.pattern : escapeRegExp(input.pattern), flags);
  const maxResults = Math.min(Number(input.maxResults || 200), 1000);
  const matches = [];

  for (const file of files) {
    if (matches.length >= maxResults) break;
    try {
      const fileStat = await fsp.stat(file);
      if (fileStat.size > 2_000_000) continue;
      if (!(await isProbablyTextFile(file))) continue;
      const content = await fsp.readFile(file, "utf8");
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length && matches.length < maxResults; i++) {
        regex.lastIndex = 0;
        if (regex.test(lines[i])) {
          matches.push(`${normalizePathForDisplay(path.relative(workspace.root, file))}:${i + 1}: ${lines[i]}`);
        }
      }
    } catch {
      continue;
    }
  }

  return matches.length ? matches.join("\n") : "No matches";
}

async function bashTool(input) {
  const workspace = getWorkspace(input.workspaceId);
  if (typeof input.command !== "string" || input.command.trim().length === 0) throw new Error("command must be a non-empty string");
  const cwd = await resolveWorkspacePath(workspace, input.workingDirectory || ".", { mustExist: true });
  await ensureDirectory(cwd);

  const timeoutSeconds = Math.min(Math.max(Number(input.timeout || DEFAULT_TIMEOUT_SECONDS), 1), MAX_TIMEOUT_SECONDS);
  const shell = process.env.WRAPPER_SHELL || "/bin/bash";

  return new Promise((resolve) => {
    const child = spawn(shell, ["-lc", input.command], {
      cwd,
      env: { ...process.env, PWD: cwd },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 1500).unref();
    }, timeoutSeconds * 1000);

    child.stdout.on("data", (chunk) => { stdout = truncateText(stdout + chunk.toString(), MAX_OUTPUT_BYTES); });
    child.stderr.on("data", (chunk) => { stderr = truncateText(stderr + chunk.toString(), MAX_OUTPUT_BYTES); });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      const parts = [
        `exitCode=${code ?? "null"}`,
        signal ? `signal=${signal}` : undefined,
        timedOut ? `timedOut=true timeout=${timeoutSeconds}s` : undefined,
        `cwd=${normalizePathForDisplay(path.relative(workspace.root, cwd) || ".")}`,
        "--- stdout ---",
        stdout || "(empty)",
        "--- stderr ---",
        stderr || "(empty)",
      ].filter(Boolean);
      resolve({ text: parts.join("\n"), isError: Boolean(code) || timedOut });
    });
  });
}

const tools = {
  open_workspace: {
    description: "Open an allowed local project folder and return a workspaceId.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Absolute or relative project path under WRAPPER_ALLOWED_ROOTS." } },
      required: ["path"],
    },
    handler: openWorkspace,
  },
  read: {
    description: "Read a UTF-8 text file inside an open workspace.",
    inputSchema: {
      type: "object",
      properties: {
        workspaceId: { type: "string" },
        path: { type: "string" },
        offset: { type: "number", description: "1-based line offset." },
        limit: { type: "number", description: "Maximum number of lines." },
      },
      required: ["workspaceId", "path"],
    },
    handler: readTool,
  },
  write: {
    description: "Create or overwrite a UTF-8 text file inside an open workspace.",
    inputSchema: {
      type: "object",
      properties: {
        workspaceId: { type: "string" },
        path: { type: "string" },
        content: { type: "string" },
        overwrite: { type: "boolean", default: true },
      },
      required: ["workspaceId", "path", "content"],
    },
    handler: writeTool,
  },
  edit: {
    description: "Edit one file by replacing exact text. Safer than shell redirection for code changes.",
    inputSchema: {
      type: "object",
      properties: {
        workspaceId: { type: "string" },
        path: { type: "string" },
        oldText: { type: "string" },
        newText: { type: "string" },
        replaceAll: { type: "boolean", default: false },
      },
      required: ["workspaceId", "path", "oldText", "newText"],
    },
    handler: editTool,
  },
  ls: {
    description: "List files and directories inside an open workspace.",
    inputSchema: {
      type: "object",
      properties: { workspaceId: { type: "string" }, path: { type: "string", default: "." } },
      required: ["workspaceId"],
    },
    handler: lsTool,
  },
  grep: {
    description: "Search text files inside an open workspace.",
    inputSchema: {
      type: "object",
      properties: {
        workspaceId: { type: "string" },
        pattern: { type: "string" },
        path: { type: "string", default: "." },
        regex: { type: "boolean", default: false },
        caseSensitive: { type: "boolean", default: false },
        maxResults: { type: "number", default: 200 },
      },
      required: ["workspaceId", "pattern"],
    },
    handler: grepTool,
  },
  bash: {
    description: "Run a shell command inside an open workspace. Powerful: expose only through GPT Secure MCP Tunnel or another trusted channel.",
    inputSchema: {
      type: "object",
      properties: {
        workspaceId: { type: "string" },
        command: { type: "string" },
        workingDirectory: { type: "string", default: "." },
        timeout: { type: "number", description: `Seconds, max ${MAX_TIMEOUT_SECONDS}.` },
      },
      required: ["workspaceId", "command"],
    },
    handler: bashTool,
  },
};

function jsonRpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function jsonRpcError(id, code, message, data) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data ? { data } : {}) } };
}

async function handleRpc(reqBody) {
  const { id, method, params } = reqBody || {};

  if (method === "initialize") {
    return jsonRpcResult(id, {
      protocolVersion: params?.protocolVersion || "2025-06-18",
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      instructions: [
        "Use open_workspace first, then pass workspaceId to all file and shell tools.",
        "All paths are jailed under WRAPPER_ALLOWED_ROOTS.",
        "This server intentionally has no OAuth. Bind it to 127.0.0.1 and expose only through a trusted tunnel.",
      ].join(" "),
    });
  }

  if (method === "notifications/initialized") return null;

  if (method === "tools/list") {
    return jsonRpcResult(id, {
      tools: Object.entries(tools).map(([name, tool]) => ({
        name,
        description: tool.description,
        inputSchema: tool.inputSchema,
      })),
    });
  }

  if (method === "tools/call") {
    const name = params?.name;
    const args = params?.arguments || {};
    const tool = tools[name];
    if (!tool) return jsonRpcError(id, -32602, `Unknown tool: ${name}`);

    try {
      const output = await tool.handler(args);
      const text = typeof output === "string" ? output : output.text;
      return jsonRpcResult(id, {
        content: [{ type: "text", text: truncateText(text) }],
        isError: typeof output === "object" ? Boolean(output.isError) : false,
      });
    } catch (error) {
      return jsonRpcResult(id, {
        content: [{ type: "text", text: error?.stack || String(error) }],
        isError: true,
      });
    }
  }

  return jsonRpcError(id, -32601, `Method not found: ${method}`);
}

const app = express();
app.use(express.json({ limit: process.env.WRAPPER_JSON_LIMIT || "20mb" }));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "content-type,mcp-session-id");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  return next();
});

app.get("/healthz", (_req, res) => {
  res.json({ ok: true, name: SERVER_NAME, version: SERVER_VERSION, allowedRoots });
});

app.get("/mcp", (_req, res) => {
  res.json({
    ok: true,
    name: SERVER_NAME,
    message: "Use POST /mcp with JSON-RPC MCP messages. This endpoint intentionally does not implement OAuth.",
    tools: Object.keys(tools),
  });
});

app.post("/mcp", async (req, res) => {
  try {
    const sessionId = req.header("mcp-session-id") || randomUUID();
    res.setHeader("Mcp-Session-Id", sessionId);

    const body = req.body;
    if (Array.isArray(body)) {
      const results = (await Promise.all(body.map(handleRpc))).filter(Boolean);
      if (results.length === 0) return res.sendStatus(202);
      return res.json(results);
    }

    const result = await handleRpc(body);
    if (!result) return res.sendStatus(202);
    return res.json(result);
  } catch (error) {
    return res.status(500).json(jsonRpcError(null, -32603, "Internal error", String(error?.stack || error)));
  }
});

app.listen(PORT, HOST, () => {
  console.log(`${SERVER_NAME} listening on http://${HOST}:${PORT}/mcp`);
  console.log(`allowedRoots=${allowedRoots.join(",")}`);
  console.log("auth=none; expose only via trusted local tunnel");
});
