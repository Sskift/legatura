import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer as createNodeServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createKernel } from "./core/index.mjs";
import { compileArchitectureProfileViewModel } from "./workbench-view-model.mjs";

export const LOOPBACK_HOST = "127.0.0.1";
export const DEFAULT_PORT = 4317;
export const DEFAULT_BODY_LIMIT_BYTES = 1024 * 1024;

const DEFAULT_PUBLIC_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "public"
);

const CONTENT_TYPES = new Map([
  [".css", "text/css; charset=utf-8"],
  [".gif", "image/gif"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".jpeg", "image/jpeg"],
  [".jpg", "image/jpeg"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
  [".webp", "image/webp"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"]
]);

const ERROR_STATUS_BY_CODE = new Map([
  ["CHANGE_NOT_FOUND", 404],
  ["GATE_NOT_FOUND", 404],
  ["NOT_FOUND", 404],
  ["PROJECT_MODEL_NOT_FOUND", 404],
  ["CONFLICT", 409],
  ["GATE_FAILED", 409],
  ["INVALID_STATE", 409],
  ["NOT_ACCEPTABLE", 409],
  ["MODEL_INVALID", 422],
  ["PROJECT_MODEL_INVALID", 422],
  ["VALIDATION_ERROR", 422],
  ["EACCES", 403],
  ["EPERM", 403],
  ["ENOENT", 404]
]);

export class HttpError extends Error {
  constructor(statusCode, code, message, details) {
    super(message);
    this.name = "HttpError";
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

/**
 * Create an unbound Legatura HTTP server. Tests may inject a kernel; normal
 * callers always get the repository-backed core through createKernel().
 */
export function createServer({
  repoPath,
  kernel: injectedKernel,
  publicDir = DEFAULT_PUBLIC_DIR,
  bodyLimitBytes = DEFAULT_BODY_LIMIT_BYTES
} = {}) {
  if (!injectedKernel && (typeof repoPath !== "string" || repoPath.length === 0)) {
    throw new TypeError("repoPath is required when no kernel is supplied.");
  }
  if (!Number.isSafeInteger(bodyLimitBytes) || bodyLimitBytes < 1) {
    throw new TypeError("bodyLimitBytes must be a positive safe integer.");
  }

  const kernel = injectedKernel ?? createKernel({ repoPath });
  const resolvedPublicDir = path.resolve(publicDir);
  const server = createNodeServer((request, response) => {
    void handleRequest({
      request,
      response,
      kernel,
      publicDir: resolvedPublicDir,
      bodyLimitBytes
    }).catch((error) => sendError(response, error));
  });

  return {
    kernel,
    server,
    async listen(port = DEFAULT_PORT) {
      validatePort(port);
      await listenOnLoopback(server, port);
      return readServerAddress(server);
    },
    async close() {
      if (!server.listening) {
        return;
      }
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
    address() {
      return readServerAddress(server);
    }
  };
}

export async function startServer(options = {}) {
  const app = createServer(options);
  const address = await app.listen(options.port ?? DEFAULT_PORT);
  return { ...app, address };
}

async function handleRequest({ request, response, kernel, publicDir, bodyLimitBytes }) {
  const requestUrl = parseRequestUrl(request.url);

  if (requestUrl.pathname === "/api" || requestUrl.pathname.startsWith("/api/")) {
    await handleApiRequest({ request, response, requestUrl, kernel, bodyLimitBytes });
    return;
  }

  await serveStaticFile({ request, response, requestUrl, publicDir });
}

async function handleApiRequest({ request, response, requestUrl, kernel, bodyLimitBytes }) {
  const method = request.method ?? "GET";
  const segments = decodePathSegments(requestUrl.pathname);

  if (segments.length === 2 && segments[0] === "api" && segments[1] === "project") {
    assertMethod(method, ["GET"]);
    sendJson(response, 200, await kernel.inspectProject());
    return;
  }

  if (
    segments.length === 2
    && segments[0] === "api"
    && segments[1] === "architecture-profile"
  ) {
    assertMethod(method, ["GET"]);
    const profile = await kernel.inspectArchitectureProfile();
    sendJson(response, 200, compileArchitectureProfileViewModel(profile));
    return;
  }

  if (segments.length === 2 && segments[0] === "api" && segments[1] === "workbench") {
    assertMethod(method, ["GET"]);
    sendJson(response, 200, await kernel.inspectWorkbenchProjection());
    return;
  }

  if (segments.length === 2 && segments[0] === "api" && segments[1] === "changes") {
    if (method === "GET") {
      sendJson(response, 200, await kernel.listChanges());
      return;
    }
    if (method === "POST") {
      const input = await readJsonObject(request, bodyLimitBytes);
      sendJson(response, 201, await kernel.createChange(input));
      return;
    }
    throw methodNotAllowed(["GET", "POST"]);
  }

  if (
    segments.length >= 3
    && segments[0] === "api"
    && segments[1] === "changes"
  ) {
    const changeId = requireIdentifier(segments[2], "change id");

    if (segments.length === 3) {
      assertMethod(method, ["GET"]);
      const change = await kernel.getChange(changeId);
      if (change == null) {
        throw new HttpError(404, "CHANGE_NOT_FOUND", `Change ${changeId} was not found.`);
      }
      sendJson(response, 200, change);
      return;
    }

    if (segments.length === 4 && segments[3] === "compile") {
      assertMethod(method, ["POST"]);
      const patch = await readJsonObject(request, bodyLimitBytes);
      sendJson(response, 200, await kernel.compileChange(changeId, patch));
      return;
    }

    if (segments.length === 4 && segments[3] === "accept") {
      assertMethod(method, ["POST"]);
      const decision = await readJsonObject(request, bodyLimitBytes);
      sendJson(response, 200, await kernel.acceptChange(changeId, decision));
      return;
    }

    if (
      segments.length === 6
      && segments[3] === "gates"
      && segments[5] === "run"
    ) {
      assertMethod(method, ["POST"]);
      const gateId = requireIdentifier(segments[4], "gate id");
      await readJsonObject(request, bodyLimitBytes);
      sendJson(response, 200, await kernel.runGate(changeId, gateId));
      return;
    }
  }

  throw new HttpError(404, "API_NOT_FOUND", `No API route matches ${requestUrl.pathname}.`);
}

async function serveStaticFile({ request, response, requestUrl, publicDir }) {
  const method = request.method ?? "GET";
  assertMethod(method, ["GET", "HEAD"]);

  let pathname;
  try {
    pathname = decodeURIComponent(requestUrl.pathname);
  } catch {
    throw new HttpError(400, "INVALID_PATH", "The request path is not valid UTF-8.");
  }

  if (pathname.includes("\0")) {
    throw new HttpError(400, "INVALID_PATH", "The request path contains a null byte.");
  }

  const relativePath = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const filePath = path.resolve(publicDir, relativePath);
  if (filePath !== publicDir && !filePath.startsWith(`${publicDir}${path.sep}`)) {
    throw new HttpError(403, "STATIC_PATH_FORBIDDEN", "The requested path is outside public assets.");
  }

  let fileStat;
  try {
    fileStat = await stat(filePath);
  } catch (error) {
    if (error?.code === "ENOENT" || error?.code === "ENOTDIR") {
      throw new HttpError(404, "STATIC_NOT_FOUND", `Asset ${pathname} was not found.`);
    }
    throw error;
  }

  if (!fileStat.isFile()) {
    throw new HttpError(404, "STATIC_NOT_FOUND", `Asset ${pathname} was not found.`);
  }

  response.writeHead(200, {
    "cache-control": "no-cache",
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "content-length": fileStat.size,
    "content-type": CONTENT_TYPES.get(path.extname(filePath).toLowerCase())
      ?? "application/octet-stream",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY"
  });

  if (method === "HEAD") {
    response.end();
    return;
  }

  await new Promise((resolve, reject) => {
    const stream = createReadStream(filePath);
    stream.once("error", reject);
    response.once("error", reject);
    response.once("finish", resolve);
    stream.pipe(response);
  });
}

function parseRequestUrl(value) {
  try {
    return new URL(value ?? "/", `http://${LOOPBACK_HOST}`);
  } catch {
    throw new HttpError(400, "INVALID_URL", "The request URL is invalid.");
  }
}

function decodePathSegments(pathname) {
  try {
    return pathname.split("/").filter(Boolean).map((segment) => decodeURIComponent(segment));
  } catch {
    throw new HttpError(400, "INVALID_PATH", "The request path is not valid UTF-8.");
  }
}

function requireIdentifier(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.includes("/")) {
    throw new HttpError(400, "INVALID_IDENTIFIER", `A valid ${label} is required.`);
  }
  return value;
}

function assertMethod(actual, allowed) {
  if (!allowed.includes(actual)) {
    throw methodNotAllowed(allowed);
  }
}

function methodNotAllowed(allowed) {
  return new HttpError(405, "METHOD_NOT_ALLOWED", "The HTTP method is not allowed for this route.", {
    allowed
  });
}

async function readJsonObject(request, bodyLimitBytes) {
  assertLocalJsonMutation(request);
  const value = await readJsonBody(request, bodyLimitBytes);
  if (value === undefined) {
    return {};
  }
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new HttpError(400, "JSON_OBJECT_REQUIRED", "The request body must be a JSON object.");
  }
  return value;
}

function assertLocalJsonMutation(request) {
  const contentType = String(request.headers["content-type"] ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/json") {
    throw new HttpError(415, "JSON_CONTENT_TYPE_REQUIRED", "Mutation requests require Content-Type: application/json.");
  }

  const fetchSite = String(request.headers["sec-fetch-site"] ?? "").toLowerCase();
  if (fetchSite === "cross-site") {
    throw new HttpError(403, "CROSS_SITE_REQUEST_FORBIDDEN", "Cross-site mutation requests are not allowed.");
  }

  const origin = request.headers.origin;
  if (origin === undefined) return;
  let parsed;
  try {
    parsed = new URL(String(origin));
  } catch {
    throw new HttpError(403, "ORIGIN_FORBIDDEN", "Mutation request Origin is invalid.");
  }
  const host = String(request.headers.host ?? "").toLowerCase();
  const loopbackOrigin = parsed.protocol === "http:"
    && ["127.0.0.1", "localhost"].includes(parsed.hostname.toLowerCase())
    && parsed.host.toLowerCase() === host;
  if (!loopbackOrigin) {
    throw new HttpError(403, "ORIGIN_FORBIDDEN", "Mutation requests must originate from this loopback workbench.");
  }
}

async function readJsonBody(request, bodyLimitBytes) {
  const declaredLength = Number(request.headers["content-length"]);
  if (Number.isFinite(declaredLength) && declaredLength > bodyLimitBytes) {
    request.resume();
    throw new HttpError(
      413,
      "BODY_TOO_LARGE",
      `The request body exceeds the ${bodyLimitBytes}-byte limit.`,
      { limitBytes: bodyLimitBytes }
    );
  }

  const body = await readBody(request, bodyLimitBytes);
  if (body.length === 0) {
    return undefined;
  }

  try {
    return JSON.parse(body.toString("utf8"));
  } catch {
    throw new HttpError(400, "INVALID_JSON", "The request body is not valid JSON.");
  }
}

function readBody(request, bodyLimitBytes) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let size = 0;
    const chunks = [];

    request.on("data", (chunk) => {
      if (settled) {
        return;
      }
      size += chunk.length;
      if (size > bodyLimitBytes) {
        settled = true;
        reject(new HttpError(
          413,
          "BODY_TOO_LARGE",
          `The request body exceeds the ${bodyLimitBytes}-byte limit.`,
          { limitBytes: bodyLimitBytes }
        ));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (!settled) {
        settled = true;
        resolve(Buffer.concat(chunks));
      }
    });
    request.on("aborted", () => {
      if (!settled) {
        settled = true;
        reject(new HttpError(400, "REQUEST_ABORTED", "The request was aborted before completion."));
      }
    });
    request.on("error", (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
  });
}

function sendJson(response, statusCode, payload) {
  if (response.headersSent || response.destroyed) {
    return;
  }
  const body = `${JSON.stringify(payload ?? null)}\n`;
  response.writeHead(statusCode, {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "content-length": Buffer.byteLength(body),
    "content-type": "application/json; charset=utf-8",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY"
  });
  response.end(body);
}

function sendError(response, error) {
  if (response.headersSent || response.destroyed) {
    response.destroy(error instanceof Error ? error : undefined);
    return;
  }

  const normalized = normalizeError(error);
  const payload = {
    error: {
      code: normalized.code,
      message: normalized.message,
      ...(normalized.details === undefined ? {} : { details: normalized.details })
    }
  };
  sendJson(response, normalized.statusCode, payload);
}

function normalizeError(error) {
  const statusCandidate = error?.statusCode ?? error?.status;
  const statusCode = Number.isInteger(statusCandidate) && statusCandidate >= 400 && statusCandidate <= 599
    ? statusCandidate
    : ERROR_STATUS_BY_CODE.get(error?.code) ?? 500;
  const code = typeof error?.code === "string" && error.code.length > 0
    ? error.code
    : statusCode === 500 ? "INTERNAL_ERROR" : "REQUEST_FAILED";
  const message = statusCode === 500 && code === "INTERNAL_ERROR"
    ? "The request could not be completed."
    : error instanceof Error && error.message.length > 0
      ? error.message
      : "The request could not be completed.";

  return {
    statusCode,
    code,
    message,
    details: error?.details
  };
}

function validatePort(port) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new TypeError("port must be an integer between 0 and 65535.");
  }
}

function listenOnLoopback(server, port) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, LOOPBACK_HOST);
  });
}

function readServerAddress(server) {
  const address = server.address();
  if (!address || typeof address === "string") {
    return undefined;
  }
  return {
    host: LOOPBACK_HOST,
    port: address.port,
    url: `http://${LOOPBACK_HOST}:${address.port}`
  };
}
