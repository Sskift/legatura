import { receiveArchitectureProfileViewModel } from "./workbench-adapter.js";

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const SOURCE_FIELDS = Object.freeze([
  "snapshotDigest",
  "projectModelDigest",
  "gitContentDigest",
  "changeStoreDigest",
]);
const WINDOW_FIELDS = Object.freeze([
  "ordering",
  "offset",
  "limit",
  "returned",
  "hasMore",
  "recordRefs",
]);
const ENVELOPE_FIELDS = Object.freeze([
  "schemaVersion",
  "proofVersion",
  "kind",
  "source",
  "window",
  "page",
  "windowDigest",
  "continuation",
  "viewModelDigest",
]);
const MAX_CURSOR_BYTES = 2048;

/**
 * Owns browser traversal of the Kernel's bounded Profile windows. Callers only
 * render the current page; cursor and successor semantics stay behind here.
 */
export function createProfileWindowController({
  fetchJson,
  renderPage,
  endpoint = "/api/architecture-profile",
  elements = {},
} = {}) {
  if (typeof fetchJson !== "function" || typeof renderPage !== "function") {
    throw controllerError(
      "PROFILE_WINDOW_CONTROLLER_INVALID",
      "Profile window controller requires fetchJson and renderPage functions.",
    );
  }

  let generation = 0;
  let current = null;
  let loading = false;
  let visibleError = null;

  async function refresh() {
    current = null;
    return requestWindow({ predecessor: null, cursor: null });
  }

  async function next() {
    if (loading || !current?.window?.hasMore || current.continuation === null) {
      return { status: "terminal", window: current };
    }
    return requestWindow({
      predecessor: current,
      cursor: current.continuation.cursor,
    });
  }

  function cancel() {
    generation += 1;
    loading = false;
    renderControls();
  }

  function snapshot() {
    return { current, loading, error: visibleError };
  }

  async function requestWindow({ predecessor, cursor }) {
    const requestGeneration = ++generation;
    loading = true;
    visibleError = null;
    renderControls();
    try {
      const value = await fetchJson(profileWindowUrl(endpoint, cursor));
      if (requestGeneration !== generation) return { status: "discarded", window: current };
      const received = receiveArchitectureProfileWindowViewModel(value, { predecessor });
      current = received;
      renderPage(received.page, received);
      return { status: "rendered", window: received };
    } catch (error) {
      if (requestGeneration !== generation) return { status: "discarded", window: current };
      visibleError = sanitizeStructuredError(error, cursor);
      return { status: "failed", error: visibleError, window: current };
    } finally {
      if (requestGeneration === generation) {
        loading = false;
        renderControls();
      }
    }
  }

  function renderControls() {
    const { status, error, next: nextButton } = elements;
    if (status) {
      status.textContent = loading
        ? "正在载入 Profile 窗口"
        : current
          ? profileWindowStatus(current.window)
          : "Profile 窗口尚未载入";
    }
    if (error) {
      error.hidden = visibleError === null;
      error.textContent = visibleError
        ? `${visibleError.code} · ${visibleError.message}`
        : "";
    }
    if (nextButton) {
      nextButton.disabled = loading || !current?.window?.hasMore;
      nextButton.hidden = !loading && current !== null && !current.window.hasMore;
    }
  }

  renderControls();
  return Object.freeze({ refresh, next, cancel, snapshot });
}

export function receiveArchitectureProfileWindowViewModel(value, { predecessor = null } = {}) {
  requireRecord(value, "Profile window");
  requireExactKeys(value, ENVELOPE_FIELDS, "Profile window");
  if (value.schemaVersion !== 1
    || value.proofVersion !== 1
    || value.kind !== "architecture-profile-window") {
    throw invalidWindow("Profile window identity");
  }
  requireDigest(value.windowDigest, "Profile window digest");
  requireDigest(value.viewModelDigest, "Profile window view-model digest");
  requireSource(value.source, "Profile window source");
  requireWindow(value.window);
  const page = receiveArchitectureProfileViewModel(value.page);
  requireSameSource(value.source, page.sourceRefs, "Profile page source");
  requirePageRecords(value.window, page);
  requireContinuation(value.continuation, value.window.hasMore);

  if (predecessor !== null) {
    requireRecord(predecessor, "Preceding Profile window");
    requireSameSource(predecessor.source, value.source, "Profile successor source");
    if (predecessor.window.hasMore !== true
      || predecessor.continuation === null
      || value.window.ordering !== predecessor.window.ordering
      || value.window.limit !== predecessor.window.limit
      || value.window.offset !== predecessor.window.offset + predecessor.window.returned) {
      throw invalidWindow("Profile window successor");
    }
  } else if (value.window.offset !== 0) {
    throw invalidWindow("Initial Profile window offset");
  }
  return value;
}

function profileWindowUrl(endpoint, cursor) {
  if (cursor === null) return endpoint;
  return `${endpoint}?cursor=${encodeURIComponent(cursor)}`;
}

function profileWindowStatus(window) {
  if (window.returned === 0) return "当前 Profile 窗口没有 Change";
  const first = window.offset + 1;
  const last = window.offset + window.returned;
  return `当前 Profile 窗口 ${first}–${last}`;
}

function requireWindow(value) {
  requireRecord(value, "Profile window descriptor");
  requireExactKeys(value, WINDOW_FIELDS, "Profile window descriptor");
  if (value.ordering !== "change-id-v1"
    || !Number.isSafeInteger(value.offset)
    || value.offset < 0
    || !Number.isSafeInteger(value.limit)
    || value.limit < 1
    || value.limit > 32
    || !Number.isSafeInteger(value.returned)
    || value.returned < 0
    || value.returned > value.limit
    || typeof value.hasMore !== "boolean"
    || !Array.isArray(value.recordRefs)
    || value.recordRefs.length !== value.returned) {
    throw invalidWindow("Profile window descriptor");
  }
  for (const reference of value.recordRefs) {
    requireRecord(reference, "Profile window record reference");
    requireExactKeys(reference, ["id"], "Profile window record reference");
    if (typeof reference.id !== "string" || reference.id.length === 0) {
      throw invalidWindow("Profile window record reference");
    }
  }
}

function requirePageRecords(window, page) {
  const changes = page?.context?.changes;
  if (!Array.isArray(changes) || changes.length !== window.recordRefs.length) {
    throw invalidWindow("Profile page Change references");
  }
  const expected = new Set(window.recordRefs.map((reference) => reference.id));
  const observed = new Set(changes.map((change) => change?.id));
  if (expected.size !== window.recordRefs.length
    || observed.size !== changes.length
    || observed.size !== expected.size
    || [...observed].some((changeRef) => !expected.has(changeRef))) {
    throw invalidWindow("Profile page Change references");
  }
}

function requireContinuation(value, hasMore) {
  if (!hasMore) {
    if (value !== null) throw invalidWindow("Terminal Profile continuation");
    return;
  }
  requireRecord(value, "Profile continuation");
  requireExactKeys(value, ["cursor", "expiresAt"], "Profile continuation");
  if (typeof value.cursor !== "string"
    || value.cursor.length === 0
    || utf8Bytes(value.cursor) > MAX_CURSOR_BYTES
    || typeof value.expiresAt !== "string"
    || utf8Bytes(value.expiresAt) > 64
    || !Number.isFinite(Date.parse(value.expiresAt))
    || new Date(Date.parse(value.expiresAt)).toISOString() !== value.expiresAt) {
    throw invalidWindow("Profile continuation");
  }
}

function utf8Bytes(value) {
  return new TextEncoder().encode(value).byteLength;
}

function requireSource(value, label) {
  requireRecord(value, label);
  requireExactKeys(value, SOURCE_FIELDS, label);
  for (const field of SOURCE_FIELDS) requireDigest(value[field], `${label}.${field}`);
}

function requireSameSource(expected, observed, label) {
  requireSource(expected, label);
  requireSource(observed, label);
  if (SOURCE_FIELDS.some((field) => expected[field] !== observed[field])) {
    throw invalidWindow(label);
  }
}

function requireExactKeys(value, expected, label) {
  const observed = Object.keys(value);
  if (observed.length !== expected.length
    || observed.some((key) => !expected.includes(key))
    || expected.some((key) => !Object.hasOwn(value, key))) {
    throw invalidWindow(`${label} shape`);
  }
}

function requireRecord(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidWindow(label);
}

function requireDigest(value, label) {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) throw invalidWindow(label);
}

function sanitizeStructuredError(error, cursor) {
  const code = redactContinuation(
    boundedErrorText(error?.code, "PROFILE_WINDOW_REQUEST_FAILED"),
    cursor,
  );
  const message = redactContinuation(
    boundedErrorText(error?.message, "Profile window request failed."),
    cursor,
  );
  return Object.freeze({ code, message });
}

function redactContinuation(value, cursor) {
  if (typeof cursor !== "string" || cursor.length === 0) return value;
  return value
    .replaceAll(cursor, "[opaque continuation]")
    .replaceAll(encodeURIComponent(cursor), "[opaque continuation]");
}

function boundedErrorText(value, fallback) {
  if (typeof value !== "string" && typeof value !== "number") return fallback;
  const text = String(value).replace(/[\u0000-\u001f\u007f]/gu, " ").trim();
  return text.length > 0 ? text.slice(0, 512) : fallback;
}

function invalidWindow(label) {
  return controllerError(
    "BROWSER_PROFILE_WINDOW_INVALID",
    `${label} is not a canonical Kernel Profile window.`,
  );
}

function controllerError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
