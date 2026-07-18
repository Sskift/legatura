import {
  architectureProfileDimension,
  compileWorkbenchAcceptanceRequest,
  receiveWorkbenchProjection,
  refreshAfterMutation,
  selectWorkbenchAction,
  selectWorkbenchAcceptanceInputRequirements,
  selectWorkbenchAuthoringModules,
  selectWorkbenchClaimOptions,
  selectWorkbenchChangeKinds,
  selectWorkbenchChangeKindAuthoring,
  selectWorkbenchPlanOutcomes,
} from "./workbench-adapter.js";
import { createProfileWindowController } from "./profile-window-controller.js";

const state = {
  project: null,
  workbench: null,
  architectureProfile: null,
  changes: [],
  selectedChangeId: null,
  selectedChange: null,
  projectLoading: true,
  changesLoading: true,
  changeLoading: false,
  projectError: null,
  workbenchError: null,
  architectureProfileError: null,
  changesError: null,
  changeError: null,
  runningGateId: null,
};

const requestGeneration = {
  workbench: 0,
  changeDetail: 0,
};

const $ = (selector) => document.querySelector(selector);

const CHANGE_KIND_LABELS = Object.freeze({
  implementation: "能力实现",
  "regression-repair": "回归修复",
  "security-containment": "安全遏制",
  "data-integrity-repair": "数据完整性修复",
  "acceptance-integrity-repair": "验收不变量修复",
  "entrypoint-restoration": "已发布入口恢复",
  "plan-amendment": "Development Plan 修订",
});

const elements = {
  connection: $("#connection-state"),
  globalMessage: $("#global-message"),
  projectLoading: $("#project-loading"),
  projectError: $("#project-error"),
  projectErrorMessage: $("#project-error-message"),
  projectEmpty: $("#project-empty"),
  projectContent: $("#project-content"),
  changesLoading: $("#changes-loading"),
  changesError: $("#changes-error"),
  changesErrorMessage: $("#changes-error-message"),
  changesEmpty: $("#changes-empty"),
  changeList: $("#change-list"),
  changeDetailLoading: $("#change-detail-loading"),
  changeDetailError: $("#change-detail-error"),
  changeDetailErrorMessage: $("#change-detail-error-message"),
  changeUnselected: $("#change-unselected"),
  changeDetailContent: $("#change-detail-content"),
  reviewUnselected: $("#review-unselected"),
  reviewContent: $("#review-content"),
  createDialog: $("#create-change-dialog"),
  createForm: $("#create-change-form"),
  createError: $("#create-change-error"),
  submitCreate: $("#submit-create-change"),
  acceptDialog: $("#accept-change-dialog"),
  acceptForm: $("#accept-change-form"),
  acceptError: $("#accept-change-error"),
  submitAccept: $("#submit-accept-change"),
  compileChange: $("#compile-change"),
  acceptChange: $("#accept-change"),
  toastRegion: $("#toast-region"),
};

const profileWindowController = createProfileWindowController({
  fetchJson: api,
  renderPage(page) {
    state.architectureProfile = page;
    state.architectureProfileError = null;
    renderProjectState();
  },
  clearPage() {
    state.architectureProfile = null;
    renderProjectState();
  },
  elements: {
    status: $("#profile-window-status"),
    error: $("#profile-window-error"),
    next: $("#profile-window-next"),
  },
});

function createElement(tag, options = {}, children = []) {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(options)) {
    if (value === undefined || value === null) continue;
    if (key === "className") element.className = value;
    else if (key === "text") element.textContent = String(value);
    else if (key === "dataset") Object.assign(element.dataset, value);
    else if (key === "attributes") {
      for (const [name, attributeValue] of Object.entries(value)) {
        element.setAttribute(name, String(attributeValue));
      }
    } else if (key.startsWith("on") && typeof value === "function") {
      element.addEventListener(key.slice(2).toLowerCase(), value);
    } else {
      element[key] = value;
    }
  }
  const childList = Array.isArray(children) ? children : [children];
  for (const child of childList) {
    if (child === undefined || child === null || child === false) continue;
    element.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return element;
}

function clear(element) {
  element.replaceChildren();
}

function isPresent(value) {
  if (value === undefined || value === null || value === "") return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

function asArray(value) {
  if (!isPresent(value)) return [];
  if (Array.isArray(value)) return value;
  if (value instanceof Set) return [...value];
  return [value];
}

function firstPresent(...values) {
  return values.find(isPresent);
}

function unwrap(payload, keys = []) {
  if (!payload || typeof payload !== "object") return payload;
  for (const key of keys) {
    if (Object.hasOwn(payload, key)) return payload[key];
  }
  if (payload.data !== undefined) {
    if (payload.data && typeof payload.data === "object") {
      for (const key of keys) {
        if (Object.hasOwn(payload.data, key)) return payload.data[key];
      }
    }
    return payload.data;
  }
  return payload;
}

function toDisplayText(value, preferredKeys = []) {
  if (!isPresent(value)) return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => toDisplayText(item, preferredKeys)).filter(Boolean).join("、");
  }
  if (typeof value === "object") {
    const keys = [
      ...preferredKeys,
      "text",
      "title",
      "name",
      "summary",
      "description",
      "detail",
      "statement",
      "request",
      "value",
      "id",
    ];
    for (const key of keys) {
      if (isPresent(value[key])) return toDisplayText(value[key], preferredKeys);
    }
  }
  return "";
}

function itemTitle(item, fallback = "未命名项目") {
  return toDisplayText(item, ["title", "name", "statement", "claim", "label", "id"]) || fallback;
}

function itemDetail(item) {
  if (!item || typeof item !== "object") return "";
  return toDisplayText(
    firstPresent(
      item.description,
      item.detail,
      item.reason,
      item.summary,
      item.trigger,
      item.rationale,
      item.interface?.description,
      item.scope,
      item.oracle,
    ),
  );
}

function humanizeKey(key) {
  const labels = {
    baseline: "基线",
    targetModule: "目标模块",
    primaryModule: "主要模块",
    module: "模块",
    factAuthority: "事实职责",
    authority: "事实职责",
    sources: "上下文来源",
    contracts: "公开契约",
    decisions: "相关决策",
    restrictions: "边界限制",
    readScope: "可读范围",
    writeScope: "可写范围",
    files: "文件",
    modules: "模块",
    consumers: "使用方",
    dependencies: "依赖",
    affectedModules: "受影响模块",
    affectedContracts: "受影响契约",
    contextSources: "上下文来源",
    modelAmendments: "模型修订",
    modelGaps: "模型缺口",
    ephemeral: "临时信息",
  };
  if (labels[key]) return labels[key];
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/^./, (character) => character.toUpperCase());
}

function normalizeStatus(status) {
  return String(status || "")
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, "$1-$2")
    .toLowerCase()
    .replace(/[\s_]+/g, "-");
}

function statusTone(status) {
  const normalized = normalizeStatus(status);
  if (
    normalized.includes("accept") ||
    normalized.includes("integrat") ||
    normalized.includes("pass") ||
    normalized.includes("complete") ||
    normalized.includes("ready") ||
    normalized.includes("success") ||
    normalized.includes("closed") ||
    normalized === "governed"
  ) return "success";
  if (
    normalized.includes("fail") ||
    normalized.includes("reject") ||
    normalized.includes("error") ||
    normalized.includes("block") ||
    normalized.includes("invalid") ||
    normalized.includes("denied")
  ) return "danger";
  if (
    normalized.includes("pending") ||
    normalized.includes("decision") ||
    normalized.includes("review") ||
    normalized.includes("provisional") ||
    normalized.includes("warning") ||
    normalized.includes("waiver") ||
    normalized.includes("running")
  ) return "warning";
  if (normalized.includes("draft") || normalized.includes("compile") || normalized.includes("proposed")) {
    return "info";
  }
  return "neutral";
}

function statusLabel(status) {
  if (!isPresent(status)) return "状态未提供";
  const normalized = normalizeStatus(status);
  const labels = {
    proposed: "待编译",
    draft: "草稿",
    framed: "已界定",
    compiled: "已编译",
    executing: "执行中",
    running: "运行中",
    submitted: "已提交",
    "evidence-ready": "证据就绪",
    "needs-decision": "需要决定",
    "decision-required": "需要决定",
    accepted: "已接纳",
    integrated: "已集成",
    rejected: "已拒绝",
    passed: "已通过",
    failed: "未通过",
    pending: "待处理",
    active: "进行中",
    achieved: "已达成",
    planned: "计划中",
    conditional: "条件式",
    retired: "已退役",
    ready: "就绪",
    configured: "已配置",
    blocked: "已阻断",
    governed: "已治理",
    provisional: "暂定",
    opaque: "不透明",
    complete: "已完成",
    completed: "已完成",
    open: "待处理",
  };
  return labels[normalized] || String(status).replace(/[_-]+/g, " ");
}

function setPill(element, value, tone = statusTone(value)) {
  if (!isPresent(value)) {
    element.hidden = true;
    element.textContent = "";
    delete element.dataset.tone;
    return;
  }
  element.hidden = false;
  element.textContent = statusLabel(value);
  element.dataset.tone = tone;
}

function formatDate(value) {
  if (!isPresent(value)) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("zh-CN", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function shortIdentifier(value, length = 12) {
  if (!isPresent(value)) return "";
  const string = String(value);
  return string.length > length ? string.slice(0, length) : string;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });

  const contentType = response.headers.get("content-type") || "";
  let payload = null;
  if (response.status !== 204) {
    if (contentType.includes("application/json")) {
      payload = await response.json().catch(() => null);
    } else {
      const text = await response.text().catch(() => "");
      payload = text ? { message: text } : null;
    }
  }

  if (!response.ok) {
    const errorPayload = payload?.error;
    const message =
      (typeof errorPayload === "string" ? errorPayload : errorPayload?.message) ||
      payload?.message ||
      `请求失败（${response.status}）`;
    const error = new Error(message);
    error.code = errorPayload?.code || payload?.code || response.status;
    error.details = errorPayload?.details || payload?.details;
    throw error;
  }

  return payload;
}

function errorMessage(error) {
  if (!error) return "发生未知错误。";
  return error.message || String(error);
}

function setConnection(mode, label) {
  elements.connection.classList.toggle("is-online", mode === "online");
  elements.connection.classList.toggle("is-error", mode === "error");
  elements.connection.querySelector("span:last-child").textContent = label;
}

function toast(message, tone = "success") {
  const toastElement = createElement("div", {
    className: "toast",
    text: message,
    dataset: { tone },
  });
  elements.toastRegion.append(toastElement);
  window.setTimeout(() => toastElement.remove(), 4200);
}

function setBusy(button, busy, busyText) {
  if (!button) return;
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.textContent = busyText || "处理中";
    button.classList.add("is-busy");
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalText || button.textContent;
    delete button.dataset.originalText;
    button.classList.remove("is-busy");
    button.disabled = false;
  }
}

async function loadProject() {
  state.projectLoading = true;
  state.projectError = null;
  renderProjectState();
  try {
    const payload = await api("/api/project");
    const isInspection = payload && typeof payload === "object" && (
      Object.hasOwn(payload, "repoPath") ||
      Object.hasOwn(payload, "git") ||
      Array.isArray(payload.modules) ||
      Object.hasOwn(payload, "validation")
    );
    state.project = isInspection ? payload : unwrap(payload, ["project"]);
    setConnection("online", "本地工作台已连接");
  } catch (error) {
    state.projectError = error;
    state.project = null;
  } finally {
    state.projectLoading = false;
    renderProjectState();
  }
}

async function loadWorkbench(changeRef = state.selectedChangeId) {
  const generation = ++requestGeneration.workbench;
  state.workbenchError = null;
  const selectedChangeRef = isPresent(changeRef) ? String(changeRef) : null;
  const requestPath = selectedChangeRef === null
    ? "/api/workbench"
    : `/api/workbench?changeRef=${encodeURIComponent(selectedChangeRef)}`;
  try {
    const payload = await api(requestPath);
    if (generation !== requestGeneration.workbench) return;
    const received = await receiveWorkbenchProjection(payload);
    if (generation !== requestGeneration.workbench) return;
    state.workbench = received;
  } catch (error) {
    if (generation !== requestGeneration.workbench) return;
    state.workbenchError = error;
    state.workbench = null;
  } finally {
    if (generation !== requestGeneration.workbench) return;
    renderCreateChangeKindOptions();
    renderCreateModuleOptions();
    renderChangeDetail();
  }
}

async function loadArchitectureProfile() {
  state.architectureProfileError = null;
  const result = await profileWindowController.refresh();
  if (result.status === "failed") state.architectureProfileError = result.error;
  renderProjectState();
  return result;
}

async function loadNextArchitectureProfile() {
  state.architectureProfileError = null;
  const result = await profileWindowController.next();
  if (result.status === "failed") state.architectureProfileError = result.error;
  renderProjectState();
  return result;
}

async function loadChanges({ preserveSelection = true } = {}) {
  state.changesLoading = true;
  state.changesError = null;
  renderChangesState();
  try {
    const payload = await api("/api/changes");
    const unwrapped = unwrap(payload, ["changes", "items"]);
    state.changes = Array.isArray(unwrapped) ? unwrapped : [];
    setConnection("online", "本地工作台已连接");
    renderChangesState();

    const requestedId = readRequestedChangeId();
    const currentStillExists = state.changes.some(
      (change) => String(change.id) === String(state.selectedChangeId),
    );
    const requestedExists = state.changes.some(
      (change) => String(change.id) === String(requestedId),
    );
    const nextId =
      (preserveSelection && currentStillExists && state.selectedChangeId) ||
      (requestedExists && requestedId) ||
      state.changes[0]?.id;
    if (nextId && String(nextId) !== String(state.selectedChangeId)) {
      await selectChange(nextId);
    } else if (!nextId) {
      state.selectedChangeId = null;
      state.selectedChange = null;
      await loadWorkbench(null);
      renderChangeDetail();
    }
  } catch (error) {
    state.changesError = error;
    state.changes = [];
    if (!state.project) setConnection("error", "本地服务不可用");
  } finally {
    state.changesLoading = false;
    renderChangesState();
  }
}

async function loadChangeDetail(id = state.selectedChangeId) {
  if (!id) return;
  const generation = ++requestGeneration.changeDetail;
  state.changeLoading = true;
  state.changeError = null;
  renderChangeDetail();
  try {
    const payload = await api(`/api/changes/${encodeURIComponent(id)}`);
    if (generation !== requestGeneration.changeDetail) return;
    state.selectedChange = unwrap(payload, ["change"]);
    if (!state.selectedChange || typeof state.selectedChange !== "object") {
      throw new Error("服务没有返回可读取的变更详情。");
    }
  } catch (error) {
    if (generation !== requestGeneration.changeDetail) return;
    state.changeError = error;
    state.selectedChange = null;
  } finally {
    if (generation !== requestGeneration.changeDetail) return;
    state.changeLoading = false;
    renderChangeDetail();
  }
}

function refreshCanonicalStateAfterMutation(options) {
  return refreshAfterMutation({
    loadChangeDetail,
    loadChanges,
    loadProject,
    loadWorkbench,
    loadArchitectureProfile,
  }, options);
}

async function selectChange(id) {
  if (!isPresent(id)) return;
  state.selectedChangeId = String(id);
  state.selectedChange = null;
  state.changeError = null;
  writeRequestedChangeId(state.selectedChangeId);
  renderChangesState();
  await Promise.allSettled([
    loadChangeDetail(state.selectedChangeId),
    loadWorkbench(state.selectedChangeId),
  ]);
}

function readRequestedChangeId() {
  return new URL(window.location.href).searchParams.get("change");
}

function writeRequestedChangeId(id) {
  const url = new URL(window.location.href);
  if (id) url.searchParams.set("change", id);
  else url.searchParams.delete("change");
  window.history.replaceState({}, "", url);
}

function hasProjectData(project) {
  return project && typeof project === "object" && Object.keys(project).length > 0;
}

function projectBaseline(project) {
  return firstPresent(
    project.governanceBaseline,
    project.baseline,
    project.currentBaseline,
    project.repository?.baseline,
    project.git?.baseline,
    project.git && project.digest ? {
      label: `${project.git.branch || "DETACHED"}@${shortIdentifier(project.git.head, 10)}`,
      sourceRevision: project.git.head,
      modelRevision: project.digest,
      description: `Project Model ${shortIdentifier(project.digest, 18)}${project.git.dirty ? " · 含未提交修改" : ""}`,
    } : null,
  );
}

function baselineParts(baseline) {
  if (!isPresent(baseline)) return { value: "未提供", detail: "项目模型尚未声明治理基线。" };
  if (typeof baseline !== "object") return { value: String(baseline), detail: "" };
  const explicitLabel = firstPresent(baseline.label, baseline.displayName);
  const sourceRevision = firstPresent(
    baseline.sourceRevision,
    baseline.revision,
    baseline.commit,
    baseline.sha,
    baseline.ref,
  );
  const modelRevision = firstPresent(
    baseline.modelRevision,
    baseline.projectModelRevision,
    baseline.model,
  );
  const digest = firstPresent(baseline.digest, baseline.hash, baseline.contentDigest);
  const pieces = [sourceRevision, modelRevision].filter(isPresent).map((value) => shortIdentifier(value));
  return {
    value: explicitLabel || pieces.join(" · ") || shortIdentifier(digest) || "已声明",
    detail: toDisplayText(firstPresent(baseline.description, baseline.detail)) ||
      (digest ? `内容摘要 ${shortIdentifier(digest, 16)}` : ""),
  };
}

function boundaryGroups(project) {
  const boundary = firstPresent(
    project.assuranceBoundary,
    project.projectDocument?.assuranceBoundary,
    project.assurance,
    project.boundary,
  );
  const groups = { governed: [], provisional: [], opaque: [] };
  let explicit = false;

  if (Array.isArray(boundary)) {
    explicit = true;
    for (const item of boundary) {
      const status = normalizeStatus(item?.status || item?.state || item?.classification);
      if (groups[status]) groups[status].push(item);
    }
  } else if (boundary && typeof boundary === "object") {
    for (const key of Object.keys(groups)) {
      const value = firstPresent(boundary[key], boundary[`${key}Areas`], boundary.counts?.[key]);
      if (value !== undefined) {
        explicit = true;
        groups[key] = typeof value === "number" ? Array.from({ length: value }, () => null) : asArray(value);
      }
    }
  }

  if (!explicit && Array.isArray(project.modules)) {
    for (const module of project.modules) {
      const status = normalizeStatus(module?.assurance || module?.status || module?.classification);
      if (groups[status]) groups[status].push(module);
    }
  }
  return { groups, explicit };
}

function projectModules(project) {
  const modules = firstPresent(project.modules, project.atlas?.modules, project.projectModel?.modules);
  return Array.isArray(modules) ? modules : [];
}

function projectRelationships(project, modules) {
  const explicit = firstPresent(
    project.relationships,
    project.moduleRelationships,
    project.atlas?.relationships,
  );
  if (Array.isArray(explicit)) return explicit;
  const relationships = [];
  const contracts = asArray(project.contracts);
  relationships.push(...contracts.flatMap((contract) => {
      const owner = firstPresent(contract.owner?.module, contract.owner?.id, contract.owner);
      return asArray(contract.consumers).map((consumer) => ({
        from: owner,
        to: firstPresent(consumer?.module, consumer?.moduleId, consumer?.id, consumer),
        contract: firstPresent(contract.id, contract.name),
        relation: "provides",
      }));
    }));
  for (const module of modules) {
    const from = firstPresent(module.id, module.name);
    for (const dependency of asArray(firstPresent(module.dependsOn, module.dependencies, module.consumes))) {
      relationships.push({
        from,
        to: firstPresent(dependency?.module, dependency?.moduleId, dependency?.target, dependency?.id, dependency?.name, dependency),
        relation: "depends",
      });
    }
  }
  return relationships;
}

function projectGaps() {
  return architectureProfileDimension(state.architectureProfile, "knowledgeGaps");
}

function projectGates(project) {
  const gates = Array.isArray(project?.gates)
    ? project.gates
    : project?.projectModel?.gates;
  return Array.isArray(gates) ? gates : [];
}

function projectPlan(project = state.project) {
  return firstPresent(project?.plan, project?.projectModel?.plan);
}

function atlasActivePlanOutcomes() {
  return architectureProfileDimension(state.architectureProfile, "outcomes")
    .filter((outcome) => outcome?.status === "active");
}

function selectedChangeKind() {
  return $("#new-change-kind")?.value || "implementation";
}

function selectedChangeKindAuthoring() {
  return selectWorkbenchChangeKindAuthoring(state.workbench, selectedChangeKind());
}

function selectedPlanRefs() {
  const select = $("#new-change-plan-ref");
  if (!select) return [];
  return [...select.selectedOptions].map((option) => option.value).filter(Boolean);
}

function createPlanSelectionSatisfied(authoring = selectedChangeKindAuthoring()) {
  if (!authoring?.selectable) return false;
  const selection = authoring.planSelection;
  const refs = selectedPlanRefs();
  return refs.length >= selection.minRefs
    && refs.length <= selection.maxRefs
    && refs.every((ref) => selection.selectableOutcomeRefs.includes(ref));
}

function createAuthoringAvailable() {
  return selectableAuthoringModules().length > 0
    && selectedChangeKindAuthoring()?.selectable === true
    && createPlanSelectionSatisfied();
}

function renderProjectState() {
  elements.projectLoading.hidden = !state.projectLoading;
  elements.projectError.hidden = !state.projectError;
  elements.projectEmpty.hidden = state.projectLoading || state.projectError || hasProjectData(state.project);
  elements.projectContent.hidden = state.projectLoading || state.projectError || !hasProjectData(state.project);
  if (state.projectError) elements.projectErrorMessage.textContent = errorMessage(state.projectError);
  if (hasProjectData(state.project) && !state.projectLoading) renderProject(state.project);
}

function renderProject(project) {
  const name = firstPresent(
    project.name,
    project.title,
    project.projectName,
    project.project?.name,
    project.project?.id,
    project.repository?.name,
  ) || "未命名项目";
  $("#project-name").textContent = name;
  $("#project-avatar").textContent = name.trim().charAt(0).toUpperCase() || "P";
  const path = firstPresent(project.root, project.path, project.repoPath, project.repository?.path, project.repositoryRoot);
  $("#project-path").textContent = path ? String(path) : "项目路径未提供";
  const modelStatus = $("#project-model-status");
  const modelValid = project.validation?.valid;
  modelStatus.hidden = typeof modelValid !== "boolean";
  modelStatus.textContent = modelValid === true ? "模型有效" : modelValid === false ? "模型无效" : "";
  if (typeof modelValid === "boolean") modelStatus.dataset.tone = modelValid ? "success" : "danger";
  else delete modelStatus.dataset.tone;

  const updatedAt = firstPresent(project.updatedAt, project.scannedAt, project.generatedAt);
  const updatedElement = $("#project-updated");
  updatedElement.hidden = !updatedAt;
  updatedElement.textContent = updatedAt ? `更新于 ${formatDate(updatedAt)}` : "";

  const baseline = baselineParts(projectBaseline(project));
  $("#baseline-value").textContent = baseline.value;
  $("#baseline-value").title = baseline.value;
  $("#baseline-detail").textContent = baseline.detail || "当前变更所依据的精确项目事实与源码版本。";
  $("#footer-baseline").textContent = baseline.value === "未提供" ? "" : `baseline ${baseline.value}`;

  renderBoundary(project);
  renderProjectGateConfiguration(project);
  renderDevelopmentPlan(project);
  renderModules(project);
  renderKnowledgeGaps(project);
  renderProjectGates(project);
  renderCreateModuleOptions(project);
  renderCreatePlanOptions();
}

function workbenchAuthoringModules() {
  return selectWorkbenchAuthoringModules(state.workbench);
}

function selectableAuthoringModules() {
  return workbenchAuthoringModules().filter((module) => module?.selectable === true);
}

function disabledReasonSummary(value) {
  return Array.isArray(value) && value.length > 0 ? value.join(" · ") : "语义投影未授权";
}

function renderCreateChangeKindOptions() {
  const select = $("#new-change-kind");
  if (!select) return;
  const previous = select.value;
  const kinds = selectWorkbenchChangeKinds(state.workbench);
  clear(select);
  if (kinds.length === 0) {
    select.append(createElement("option", { value: "", text: "Kernel 未投影 Change kind" }));
    select.disabled = true;
    renderCreatePlanOptions();
    return;
  }
  for (const kind of kinds) {
    select.append(createElement("option", {
      value: kind.id,
      text: `${CHANGE_KIND_LABELS[kind.id] || kind.id}${
        kind.selectable ? "" : ` · ${disabledReasonSummary(kind.disabledReasonCodes)}`
      }`,
      disabled: !kind.selectable,
      attributes: {
        title: kind.selectable ? "" : disabledReasonSummary(kind.disabledReasonCodes),
      },
    }));
  }
  const selectableKinds = kinds.filter((kind) => kind.selectable === true);
  const selected = selectableKinds.find((kind) => kind.id === previous) ?? selectableKinds[0];
  if (selected) select.value = selected.id;
  select.disabled = selectableKinds.length === 0;
  renderCreatePlanOptions();
}

function renderCreateModuleOptions() {
  const select = $("#new-change-module");
  if (!select) return;
  const previous = select.value;
  const modules = workbenchAuthoringModules();
  const selectableModules = selectableAuthoringModules();
  clear(select);
  select.append(
    createElement("option", {
      value: "",
      text: selectableModules.length ? "请选择主要修改区域" : "没有可用的受控模块",
    }),
  );
  for (const module of modules) {
    const id = module?.id;
    if (!id) continue;
    const selectable = module.selectable === true;
    select.append(
      createElement("option", {
        value: String(id),
        text: `${module.name || id} · ${id}${selectable ? "" : ` · ${disabledReasonSummary(module.disabledReasonCodes)}`}`,
        disabled: !selectable,
        attributes: { title: selectable ? "" : disabledReasonSummary(module.disabledReasonCodes) },
      }),
    );
  }
  if (selectableModules.some((module) => String(module.id) === previous)) {
    select.value = previous;
  }
  select.disabled = selectableModules.length === 0;
  $("#new-change-module-help").textContent = selectableModules.length
    ? "一个 Change 只选择一个主要职责边界；跨模块影响会在编译后显式展开。"
    : state.workbenchError
      ? `Workbench 语义投影不可用：${errorMessage(state.workbenchError)}`
      : "Kernel 没有授权可用于创建 Change 的模块。";
  renderCreateClaimOptions(select.value);
}

function renderCreatePlanOptions() {
  const select = $("#new-change-plan-ref");
  if (!select) return;
  const previous = new Set([...select.selectedOptions].map((option) => option.value));
  const authoring = selectedChangeKindAuthoring();
  const planSelection = authoring?.planSelection;
  const outcomesByRef = new Map(selectWorkbenchPlanOutcomes(state.workbench)
    .map((outcome) => [outcome.outcomeRef, outcome]));
  const selectableOutcomeRefs = planSelection?.selectableOutcomeRefs ?? [];
  const integrityRepair = authoring?.integrityIncident?.required === true;
  const failureField = $("#integrity-failure-field");
  const failureInput = $("#new-change-observed-failure");
  failureField.hidden = !integrityRepair;
  failureInput.required = integrityRepair;
  if (!integrityRepair) failureInput.value = "";
  clear(select);
  if (!planSelection) {
    select.append(createElement("option", { value: "", text: "Kernel 未投影 Plan 选择要求" }));
    select.disabled = true;
    $("#new-change-plan-ref-help").textContent = "等待有效的 Workbench authoring projection。";
    renderCreateClaimOptions($("#new-change-module")?.value);
    return;
  }
  select.multiple = planSelection.maxRefs > 1;
  select.required = planSelection.minRefs > 0;
  select.size = select.multiple ? Math.min(Math.max(selectableOutcomeRefs.length, 2), 6) : 1;
  if (planSelection.minRefs === 0 && !select.multiple) {
    select.append(createElement("option", { value: "", text: "不绑定长期 Outcome" }));
  }
  for (const outcomeRef of selectableOutcomeRefs) {
    const outcome = outcomesByRef.get(outcomeRef);
    const detail = String(outcome?.statement || "");
    select.append(createElement("option", {
      value: outcomeRef,
      text: detail ? `${outcomeRef} · ${detail}` : outcomeRef,
      selected: previous.has(outcomeRef),
    }));
  }
  select.disabled = planSelection.maxRefs === 0 || selectableOutcomeRefs.length === 0;
  $("#new-change-plan-ref-help").textContent = planSelection.maxRefs === 0
    ? "Kernel 声明此 Change kind 不接受 Outcome 引用。"
    : selectableOutcomeRefs.length === 0
      ? disabledReasonSummary(authoring.disabledReasonCodes)
      : `Kernel 要求选择 ${planSelection.minRefs}–${planSelection.maxRefs} 个 Outcome。`;
  renderCreateClaimOptions($("#new-change-module")?.value);
}

function renderCreateClaimOptions(moduleId) {
  const container = $("#new-change-known-claims");
  if (!container) return;
  clear(container);
  if (!moduleId) {
    container.append(createElement("div", { className: "claim-picker-empty", text: "先选择主要修改区域。" }));
    return;
  }
  const module = workbenchAuthoringModules().find((item) => String(item?.id) === String(moduleId));
  const claims = Array.isArray(module?.claims) ? module.claims : [];
  if (claims.length === 0) {
    container.append(createElement("div", {
      className: "claim-picker-empty",
      text: "Kernel 没有为这个模块投影可审查的契约主张。",
    }));
    return;
  }
  const claimOptions = selectWorkbenchClaimOptions(state.workbench, {
    changeKind: selectedChangeKind(),
    planRefs: selectedPlanRefs(),
    moduleRef: String(moduleId),
  });
  if (claimOptions === null) {
    container.append(createElement("div", {
      className: "claim-picker-empty",
      text: "先完成 Kernel 要求的 Outcome 选择。",
    }));
    return;
  }
  const claimOptionsByRef = new Map(claimOptions.map((option) => [option.claimRef, option]));
  for (const claim of claims) {
    const id = claim?.id;
    if (!id) continue;
    const claimOption = claimOptionsByRef.get(id);
    const statement = String(claim.statement || id);
    const selectable = claimOption.selectable === true;
    const routes = Array.isArray(claim.acceptanceRoutes) ? claim.acceptanceRoutes : [];
    const routeSummary = routes.map((route) => (
      `${route.gateId}/${route.commandId} · ${shortIdentifier(route.routeDigest, 18)}`
    )).join("；");
    const input = createElement("input", {
      type: "checkbox",
      name: "knownClaim",
      value: String(id),
      disabled: !selectable,
      dataset: {
        statement,
        contractId: String(claim.contractRef || ""),
        routeRefs: routes.map((route) => route.routeRef).join(","),
        routeDigests: routes.map((route) => route.routeDigest).join(","),
      },
    });
    container.append(
      createElement("label", { className: "claim-choice" }, [
        input,
        createElement("span", {}, [
          createElement("strong", { text: statement }),
          createElement("small", { text: `${claim.contractRef} · ${id}` }),
          ...(routeSummary ? [createElement("small", { text: routeSummary })] : []),
        ]),
        createElement("span", {
          className: `claim-oracle-state${selectable ? " has-gate" : ""}`,
          text: selectable
            ? `${routes.length} 条精确路由`
            : disabledReasonSummary(claimOption.disabledReasonCodes),
          attributes: {
            title: routeSummary || disabledReasonSummary(claimOption.disabledReasonCodes),
          },
        }),
      ]),
    );
  }
}

function renderBoundary(project) {
  const { groups, explicit } = boundaryGroups(project);
  const total = Object.values(groups).reduce((sum, items) => sum + items.length, 0);
  const bar = $("#boundary-bar");
  const legend = $("#boundary-legend");
  clear(bar);
  clear(legend);

  const config = [
    ["governed", "已治理"],
    ["provisional", "暂定"],
    ["opaque", "不透明"],
  ];
  if (total > 0) {
    for (const [key] of config) {
      if (groups[key].length === 0) continue;
      bar.append(
        createElement("span", {
          className: `boundary-segment ${key}`,
          attributes: { style: `width:${(groups[key].length / total) * 100}%` },
          title: `${key}: ${groups[key].length}`,
        }),
      );
    }
  } else {
    bar.append(createElement("span", { className: "boundary-segment opaque", attributes: { style: "width:100%" } }));
  }
  for (const [key, label] of config) {
    legend.append(
      createElement("div", { className: `legend-item ${key}` }, [
        createElement("span", { text: label }),
        createElement("strong", { text: explicit || total > 0 ? groups[key].length : "—" }),
      ]),
    );
  }
}

function renderProjectGateConfiguration(project) {
  const gates = projectGates(project);
  const value = $("#gate-configuration-value");
  value.querySelector("strong").textContent = `${gates.length} 项已声明`;
  $("#gate-configuration-detail").textContent = gates.length
    ? "这里只显示 Project Model 的 Gate 配置数量；运行事实属于各个 Change。"
    : "当前 Project Model 没有声明 Gate。";
}

function renderModules(project) {
  const modules = projectModules(project);
  const relationships = projectRelationships(project, modules);
  const container = $("#module-map");
  clear(container);
  $("#module-count").textContent = `${modules.length} 个模块`;
  $("#module-map-empty").hidden = modules.length > 0;

  for (const module of modules) {
    const id = String(firstPresent(module.id, module.name, ""));
    const outgoing = relationships.filter(
      (relationship) => String(firstPresent(relationship.from, relationship.source, relationship.producer)) === id,
    );
    const status = normalizeStatus(firstPresent(module.assurance, module.status, module.classification));
    const metadata = [];
    const authority = firstPresent(module.factAuthority, module.authority, module.owner);
    if (authority) metadata.push(createElement("span", { className: "mini-chip", text: toDisplayText(authority) }));
    if (status) metadata.push(createElement("span", { className: "mini-chip", text: statusLabel(status) }));

    const children = [
      createElement("div", { className: "module-card-header" }, [
        createElement("div", {}, [
          createElement("h4", { text: itemTitle(module, "未命名模块") }),
          createElement("p", { text: itemDetail(module) || "职责说明未提供" }),
        ]),
      ]),
      createElement("div", { className: "module-meta" }, metadata),
    ];

    if (outgoing.length) {
      const labels = outgoing
        .map((relationship) =>
          toDisplayText(firstPresent(relationship.to, relationship.target, relationship.consumer)),
        )
        .filter(Boolean);
      children.push(
        createElement("div", { className: "module-dependencies" }, [
          createElement("strong", {
            text: outgoing.every((relationship) => relationship.relation === "provides")
              ? "公开给 → "
              : outgoing.every((relationship) => relationship.relation === "depends")
                ? "依赖 → "
                : "关联 → ",
          }),
          document.createTextNode(labels.join("、")),
        ]),
      );
    }
    container.append(
      createElement("article", {
        className: "module-card",
        dataset: { state: ["governed", "provisional", "opaque"].includes(status) ? status : "unknown" },
      }, children),
    );
  }
}

function renderItemList(container, items, options = {}) {
  clear(container);
  items.forEach((item, index) => {
    const status = firstPresent(item?.status, item?.state, item?.result, options.defaultStatus);
    const marker = options.marker || (statusTone(status) === "success" ? "✓" : statusTone(status) === "danger" ? "!" : String(index + 1));
    container.append(
      createElement("div", { className: "list-item", dataset: { tone: statusTone(status) } }, [
        createElement("span", { className: "list-item-marker", text: marker }),
        createElement("div", { className: "list-item-content" }, [
          createElement("strong", { text: itemTitle(item, options.fallbackTitle || "未命名记录") }),
          ...(itemDetail(item) ? [createElement("p", { text: itemDetail(item) })] : []),
        ]),
      ]),
    );
  });
}

function renderKnowledgeGaps(project) {
  const gaps = projectGaps(project);
  $("#gap-count").textContent = String(gaps.length);
  const empty = $("#knowledge-gaps-empty");
  empty.hidden = gaps.length > 0;
  empty.textContent = state.architectureProfileError
    ? `Architecture Profile 不可用：${errorMessage(state.architectureProfileError)}`
    : "当前 Profile 没有登记的知识缺口。";
  const exactProfileGaps = architectureProfileDimension(state.architectureProfile, "knowledgeGaps");
  renderItemList(
    $("#knowledge-gaps"),
    state.architectureProfile
      ? gaps.map((gap) => ({
          title: gap.id,
          description: gap.statement,
          status: gap.status,
        }))
      : gaps,
    { fallbackTitle: "未命名缺口" },
  );
}

function renderProjectGates(project) {
  const gates = projectGates(project);
  $("#project-gates-empty").hidden = gates.length > 0;
  renderItemList($("#project-gates"), gates, { fallbackTitle: "未命名门禁" });
}

function renderDevelopmentPlan(project) {
  const plan = projectPlan(project);
  const outcomes = atlasActivePlanOutcomes(project);
  $("#plan-active-count").textContent = `${outcomes.length} active`;
  $("#plan-north-star").textContent = toDisplayText(plan?.northStar) || "尚未声明长期 North Star。";
  const empty = $("#active-plan-outcomes-empty");
  empty.hidden = outcomes.length > 0;
  empty.textContent = state.architectureProfileError
    ? `Architecture Profile 不可用：${errorMessage(state.architectureProfileError)}`
    : "当前 Profile 没有 active Outcome。";
  renderItemList(
    $("#active-plan-outcomes"),
    outcomes.map((outcome) => ({
      title: outcome.id,
      description: state.architectureProfile
        ? outcome.statement
        : outcome.outcome,
      status: outcome.status,
    })),
    { fallbackTitle: "未命名 Outcome" },
  );
}

function renderChangesState() {
  elements.changesLoading.hidden = !state.changesLoading;
  elements.changesError.hidden = !state.changesError;
  elements.changesEmpty.hidden = state.changesLoading || state.changesError || state.changes.length > 0;
  elements.changeList.hidden = state.changesLoading || state.changesError || state.changes.length === 0;
  if (state.changesError) elements.changesErrorMessage.textContent = errorMessage(state.changesError);
  renderChangeList();
}

function changeTitle(change) {
  return firstPresent(change.title, change.name, change.intent?.title, toDisplayText(change.intent)) || "未命名变更";
}

function changeIntent(change) {
  return toDisplayText(
    firstPresent(
      change.intent?.request,
      change.intent?.description,
      change.intent?.summary,
      change.request,
      change.description,
      change.intent,
    ),
  );
}

function workbenchChangeAction(kind, change = state.selectedChange) {
  return selectWorkbenchAction(state.workbench, change, kind);
}

function workbenchAcceptanceInputRequirements(change = state.selectedChange) {
  return selectWorkbenchAcceptanceInputRequirements(state.workbench, change);
}

function projectWorkbenchAction(button, action) {
  const enabled = action?.enabled === true;
  button.disabled = !enabled;
  button.title = enabled ? "" : disabledReasonSummary(action?.disabledReasonCodes);
}

function renderChangeList() {
  clear(elements.changeList);
  for (const change of state.changes) {
    const id = String(firstPresent(change.id, change.changeId, ""));
    const status = firstPresent(change.status, change.state, change.phase);
    const selected = id && id === String(state.selectedChangeId);
    const updated = formatDate(firstPresent(change.updatedAt, change.createdAt));
    const button = createElement("button", {
      className: `change-list-item${selected ? " is-selected" : ""}`,
      type: "button",
      attributes: { role: "listitem", "aria-current": selected ? "true" : "false" },
      onclick: () => selectChange(id),
    }, [
      createElement("div", { className: "change-list-meta" }, [
        createElement("span", { className: "change-list-state", dataset: { tone: statusTone(status) } }, [
          createElement("i", { className: "status-dot", attributes: { "aria-hidden": "true" } }),
          document.createTextNode(statusLabel(status)),
        ]),
        ...(updated ? [createElement("span", { text: updated })] : []),
      ]),
      createElement("h4", { text: changeTitle(change) }),
      createElement("p", { text: changeIntent(change) || "变更意图尚未提供" }),
    ]);
    elements.changeList.append(button);
  }
}

function renderChangeDetail() {
  elements.changeDetailLoading.hidden = !state.changeLoading;
  elements.changeDetailError.hidden = !state.changeError;
  elements.changeUnselected.hidden = state.changeLoading || state.changeError || Boolean(state.selectedChange);
  elements.changeDetailContent.hidden = state.changeLoading || state.changeError || !state.selectedChange;
  if (state.changeError) elements.changeDetailErrorMessage.textContent = errorMessage(state.changeError);
  renderChangeList();

  if (state.selectedChange && !state.changeLoading) {
    renderSelectedChange(state.selectedChange);
    renderReview(state.selectedChange);
  } else {
    elements.reviewUnselected.hidden = false;
    elements.reviewContent.hidden = true;
  }
}

function renderSelectedChange(change) {
  const id = firstPresent(change.id, change.changeId, state.selectedChangeId);
  $("#change-id").textContent = id ? `CHANGE · ${shortIdentifier(id, 18)}` : "";
  setPill($("#change-status"), firstPresent(change.status, change.state, change.phase));
  $("#change-title").textContent = changeTitle(change);
  const planRefs = asArray(firstPresent(change.planRefs, change.planRef)).map(toDisplayText).filter(Boolean);
  const planRef = $("#change-plan-ref");
  planRef.hidden = planRefs.length === 0;
  planRef.textContent = planRefs.length ? `OUTCOME · ${planRefs.join("、")}` : "";
  const summary = firstPresent(change.summary, change.intent?.detail);
  $("#change-summary").hidden = !summary;
  $("#change-summary").textContent = toDisplayText(summary);
  $("#change-intent").textContent = changeIntent(change) || "变更意图尚未提供。";

  renderStructuredList(
    $("#change-claims"),
    firstPresent(change.claims, change.acceptanceClaims, change.intent?.claims),
    "尚未冻结主张。",
  );
  renderStructuredList(
    $("#change-non-goals"),
    firstPresent(change.nonGoals, change.non_goals, change.intent?.nonGoals),
    "未声明非目标。",
  );
  renderContextCapsule(change);
  renderImpactSet(change);
  renderVerificationObligations(change);

  const currentStatus = normalizeStatus(firstPresent(change.status, change.state, change.phase));
  projectWorkbenchAction(elements.compileChange, workbenchChangeAction("compile", change));
  elements.compileChange.textContent = currentStatus === "proposed" || currentStatus === "draft" ? "编译变更" : "重新编译";
}

function renderStructuredList(container, value, emptyText) {
  clear(container);
  const items = asArray(value).filter(isPresent);
  if (items.length === 0) {
    container.append(createElement("span", { className: "muted", text: emptyText }));
    return;
  }
  for (const item of items) {
    container.append(
      createElement("div", { className: "structured-list-item" }, [
        createElement("span", { text: toDisplayText(item, ["statement", "claim", "text", "title"]) || "未提供内容" }),
      ]),
    );
  }
}

function contextCapsule(change) {
  return firstPresent(change.contextCapsule, change.context, change.compilation?.contextCapsule);
}

function renderContextCapsule(change) {
  const capsule = contextCapsule(change);
  const container = $("#context-capsule");
  clear(container);
  const empty = !isPresent(capsule);
  container.hidden = empty;
  $("#context-capsule-empty").hidden = !empty;
  if (empty) return;

  const entries = [];
  if (Array.isArray(capsule)) {
    capsule.forEach((item, index) => entries.push([`上下文 ${index + 1}`, item]));
  } else if (typeof capsule === "object") {
    const orderedKeys = [
      "baseline",
      "targetModule",
      "primaryModule",
      "module",
      "factAuthority",
      "authority",
      "sources",
      "contextSources",
      "contracts",
      "decisions",
      "readScope",
      "writeScope",
      "restrictions",
    ];
    const used = new Set();
    for (const key of orderedKeys) {
      if (isPresent(capsule[key]) && !used.has(key)) {
        entries.push([humanizeKey(key), capsule[key]]);
        used.add(key);
      }
    }
    if (entries.length === 0) {
      for (const [key, value] of Object.entries(capsule)) {
        if (isPresent(value) && key !== "status") entries.push([humanizeKey(key), value]);
      }
    }
  } else {
    entries.push(["上下文", capsule]);
  }

  for (const [label, value] of entries) {
    const display = toDisplayText(value);
    const count = Array.isArray(value) && value.length > 1 ? `${value.length} 项` : "";
    container.append(
      createElement("div", { className: "context-cell" }, [
        createElement("span", { text: label }),
        createElement("strong", { text: display || "已提供" }),
        ...(count ? [createElement("p", { text: count })] : []),
      ]),
    );
  }
}

function impactSet(change) {
  return firstPresent(change.impactSet, change.impact, change.compilation?.impactSet);
}

function renderImpactSet(change) {
  const impact = impactSet(change);
  const container = $("#impact-set");
  clear(container);
  const empty = !isPresent(impact);
  container.hidden = empty;
  $("#impact-set-empty").hidden = !empty;
  if (empty) return;

  const groups = [];
  if (Array.isArray(impact)) {
    groups.push(["影响对象", impact]);
  } else if (typeof impact === "object") {
    for (const [key, value] of Object.entries(impact)) {
      if (isPresent(value) && !["status", "summary"].includes(key)) groups.push([humanizeKey(key), asArray(value)]);
    }
    if (groups.length === 0 && impact.summary) groups.push(["影响范围", [impact.summary]]);
  } else {
    groups.push(["影响范围", [impact]]);
  }

  for (const [label, values] of groups) {
    const group = createElement("div", { className: "impact-group" }, [
      createElement("span", { className: "impact-group-label", text: label }),
    ]);
    for (const value of values) {
      group.append(createElement("span", { className: "impact-chip", text: toDisplayText(value) || "已声明" }));
    }
    container.append(group);
  }
}

function verificationObligations(change) {
  const obligations = firstPresent(
    change.verificationObligations,
    change.obligations,
    change.compilation?.verificationObligations,
  );
  return Array.isArray(obligations) ? obligations : [];
}

function renderVerificationObligations(change) {
  const obligations = verificationObligations(change);
  const container = $("#verification-obligations");
  clear(container);
  $("#verification-obligations-empty").hidden = obligations.length > 0;
  container.hidden = obligations.length === 0;

  obligations.forEach((obligation, index) => {
    const claimId = firstPresent(obligation.claimId, obligation.claim?.id, obligation.id);
    const claim = asArray(change.claims).find((item) => String(item?.id) === String(claimId));
    const status = firstPresent(obligation.status, obligation.state, obligation.result);
    const oracle = toDisplayText(firstPresent(obligation.oracle, obligation.evidenceRequired, obligation.method));
    const risk = toDisplayText(firstPresent(obligation.risk, obligation.riskLevel));
    container.append(
      createElement("div", { className: "obligation-item", dataset: { tone: statusTone(status) } }, [
        createElement("span", {
          className: "obligation-mark",
          text: status && statusTone(status) === "success" ? "✓" : String(index + 1),
        }),
        createElement("div", { className: "obligation-copy" }, [
          createElement("strong", {
            text: toDisplayText(claim, ["statement", "description"])
              || toDisplayText(obligation, ["claim", "title", "text"])
              || `证明义务 ${index + 1}`,
          }),
          ...(oracle ? [createElement("p", { text: `判断依据：${oracle}` })] : []),
        ]),
        ...(risk ? [createElement("span", { className: "obligation-risk", text: risk })] : []),
      ]),
    );
  });
}

function renderReview(change) {
  elements.reviewUnselected.hidden = true;
  elements.reviewContent.hidden = false;
  const reference = $("#review-change-reference");
  reference.hidden = false;
  reference.textContent = changeTitle(change);
  renderEvidence(change);
  renderResidualUncertainty(change);
  renderKnowledgeClosure(change);
  renderDecisions(change);
  renderChangeGates(change);
  renderAcceptance(change);
}

function evidenceRecords(change) {
  return Array.isArray(change?.evidence) ? change.evidence : [];
}

function evidenceCurrency(change, evidenceId) {
  const currency = change?.observation?.evidenceCurrency;
  if (!currency || !evidenceId) return null;
  if (Array.isArray(currency.invalidIds) && currency.invalidIds.includes(evidenceId)) return "invalid";
  if (Array.isArray(currency.staleIds) && currency.staleIds.includes(evidenceId)) return "stale";
  if (Array.isArray(currency.currentIds) && currency.currentIds.includes(evidenceId)) return "current";
  return null;
}

function evidenceCurrencyLabel(currency) {
  return {
    current: "当前证据",
    stale: "证据已过期",
    invalid: "证据无效",
    "sealed-historical": "封存历史证据",
  }[currency] || currency;
}

function evidenceCurrencyTone(currency) {
  if (currency === "invalid") return "danger";
  if (currency === "stale") return "warning";
  return "neutral";
}

function renderEvidence(change) {
  const evidence = evidenceRecords(change);
  const records = $("#evidence-records");
  clear(records);
  $("#evidence-empty").hidden = evidence.length > 0;

  for (const record of evidence) {
    const evidenceId = typeof record?.id === "string" ? record.id : "";
    const currency = evidenceCurrency(change, evidenceId);
    const observationStatus = typeof record?.observation?.status === "string"
      ? record.observation.status
      : null;
    const dimensions = [
      ["Claim", record.claim],
      ["Oracle", record.oracle],
      ["Observation", record.observation],
      ["Provenance", record.provenance],
      ["Applicability", record.applicability],
      ["Discriminatory Power", record.discriminatoryPower],
    ].filter(([, value]) => isPresent(value));
    records.append(
      createElement("div", { className: "evidence-record" }, [
        createElement("div", { className: "evidence-record-main" }, [
          createElement("strong", { text: itemTitle(record, "证据记录") }),
          ...(itemDetail(record) ? [createElement("p", { text: itemDetail(record) })] : []),
          createElement("div", { className: "evidence-record-details" }, dimensions.map(([label, value]) =>
            createElement("div", { className: "evidence-record-detail" }, [
              createElement("span", { text: label }),
              createElement("p", { text: summarizeStructured(value) || "已记录" }),
            ]),
          )),
        ]),
        ...(currency
          ? [createElement("span", {
              className: "status-pill",
              text: evidenceCurrencyLabel(currency),
              dataset: { tone: evidenceCurrencyTone(currency) },
            })]
          : observationStatus
            ? [createElement("span", {
                className: "status-pill",
                text: `Observation · ${statusLabel(observationStatus)}`,
                dataset: { tone: statusTone(observationStatus) },
              })]
            : []),
      ]),
    );
  }
  records.hidden = evidence.length === 0;
}

function summarizeStructured(value) {
  const direct = toDisplayText(value, ["statement", "description", "status", "kind", "name", "title"]);
  if (direct) return direct;
  if (Array.isArray(value)) {
    return value.map((item) => summarizeStructured(item)).filter(Boolean).slice(0, 3).join("；");
  }
  if (value && typeof value === "object") {
    return Object.entries(value)
      .filter(([, item]) => isPresent(item))
      .slice(0, 3)
      .map(([key, item]) => `${humanizeKey(key)}：${toDisplayText(item) || (Array.isArray(item) ? `${item.length} 项` : "已记录")}`)
      .join("；");
  }
  return toDisplayText(value);
}

function residualUncertainty(change) {
  const direct = firstPresent(
    change.residualUncertainty,
    change.uncertainties,
    change.review?.residualUncertainty,
    change.evidence?.residualUncertainty,
  );
  const fromEvidence = asArray(change.evidence).flatMap((item) => asArray(item?.residualUncertainty));
  const unique = new Map();
  for (const item of [...asArray(direct), ...fromEvidence].filter(isPresent)) {
    const key = toDisplayText(item) || JSON.stringify(item);
    if (!unique.has(key)) unique.set(key, item);
  }
  return [...unique.values()];
}

function renderResidualUncertainty(change) {
  const uncertainty = residualUncertainty(change);
  $("#residual-uncertainty-empty").hidden = uncertainty.length > 0;
  renderItemList($("#residual-uncertainty"), uncertainty, {
    fallbackTitle: "未说明的不确定性",
    defaultStatus: "pending",
  });
}

function closureData(change) {
  const closure = firstPresent(change.knowledgeClosure, change.closure, change.review?.knowledgeClosure);
  if (!closure) return { status: null, items: [] };
  if (Array.isArray(closure)) return { status: null, items: closure };
  if (typeof closure !== "object") return { status: closure, items: [] };
  if (closure.noNewKnowledge === true) {
    return {
      status: firstPresent(closure.status, closure.state),
      items: [{
        title: "没有需要长期写回的新知识",
        description: closure.rationale,
        status: "complete",
      }],
    };
  }
  const directItems = firstPresent(closure.items, closure.records, closure.entries);
  const items = Array.isArray(directItems) ? [...directItems] : [];
  const groups = ["modelAmendments", "amendments", "modelGaps", "gaps", "ephemeral", "provenance"];
  if (items.length === 0) {
    for (const key of groups) {
      for (const item of asArray(closure[key])) {
        if (isPresent(item)) items.push(typeof item === "object" ? { category: humanizeKey(key), ...item } : { title: item, category: humanizeKey(key) });
      }
    }
  }
  return { status: firstPresent(closure.status, closure.state), items };
}

function renderKnowledgeClosure(change) {
  const closure = closureData(change);
  setPill($("#closure-status"), closure.status);
  $("#knowledge-closure-empty").hidden = closure.items.length > 0;
  const decorated = closure.items.map((item) => {
    if (!item || typeof item !== "object" || !item.category) return item;
    return { ...item, description: firstPresent(item.description, item.detail, item.category) };
  });
  renderItemList($("#knowledge-closure"), decorated, {
    fallbackTitle: "Knowledge Closure 记录",
    defaultStatus: closure.status,
  });
}

function decisionItems(change) {
  const decisions = firstPresent(change.decisions, change.decisionQueue, change.review?.decisions);
  if (Array.isArray(decisions)) return decisions;
  if (change.authorityDecision && typeof change.authorityDecision === "object") {
    return [{
      title: `由 ${toDisplayText(firstPresent(change.authorityDecision.authority, change.authorityDecision.decidedBy)) || "Decision Authority"} 作出的决定`,
      description: change.authorityDecision.rationale,
      ...change.authorityDecision,
    }];
  }
  return [];
}

function renderDecisions(change) {
  const decisions = decisionItems(change);
  const pending = decisions.filter((decision) => !["accepted", "resolved", "closed", "approved"].includes(normalizeStatus(decision.status || decision.state)));
  if (
    pending.length === 0 &&
    decisions.length === 0 &&
    !["accepted", "integrated"].includes(normalizeStatus(firstPresent(change.state, change.status)))
  ) {
    pending.push({
      title: "尚未记录 Decision Authority 的决定",
      description: "接纳时需要由项目模型声明的决策职责说明理由与作用范围。",
      status: "pending",
    });
  }
  const container = $("#decision-queue");
  clear(container);
  $("#decision-queue-empty").hidden = pending.length > 0;
  for (const decision of pending) {
    const authority = toDisplayText(firstPresent(decision.decisionAuthority, decision.authority, decision.owner));
    container.append(
      createElement("div", { className: "decision-item" }, [
        createElement("div", {}, [
          createElement("strong", { text: itemTitle(decision, "待处理决定") }),
          createElement("p", { text: itemDetail(decision) || "需要具备相应决策权的人处理。" }),
        ]),
        ...(authority ? [createElement("span", { className: "status-pill", text: authority, dataset: { tone: "warning" } })] : []),
      ]),
    );
  }
}

function localGateObservation(change, gateId) {
  const runs = Array.isArray(change?.gateRuns) ? change.gateRuns : [];
  return runs.find((run) => String(run?.gateId) === String(gateId)) ?? null;
}

function renderChangeGates(change) {
  const gates = workbenchChangeAction("gates", change);
  const container = $("#change-gates");
  clear(container);
  for (const gate of Array.isArray(gates) ? gates : []) {
    const id = gate?.gateId;
    if (!id) continue;
    const observation = localGateObservation(change, id);
    const status = typeof observation?.status === "string" ? observation.status : null;
    const annotations = Array.isArray(gate.claimRouteAnnotations) ? gate.claimRouteAnnotations : [];
    const annotationSummary = annotations.map((annotation) => (
      `${annotation.sourceClaimRef}:${annotation.gateId}/${annotation.commandId} · ${shortIdentifier(annotation.routeDigest, 18)}`
    )).join("；");
    const button = createElement("button", {
      className: "gate-action-button",
      type: "button",
      disabled: gate.enabled !== true || state.runningGateId === String(id),
      text: state.runningGateId === String(id)
        ? "运行中…"
        : `${status ? "重跑" : "运行"} ${gate.name || id}`,
      onclick: () => runGate(id, button),
      dataset: {
        gateId: String(id),
        selectedCommandIds: Array.isArray(gate.selectedCommandIds) ? gate.selectedCommandIds.join(",") : "",
        routeDigests: annotations.map((annotation) => annotation.routeDigest).join(","),
      },
      attributes: {
        title: [
          ...(status ? [`Observation：${statusLabel(status)}`] : []),
          ...(gate.enabled === true ? [] : [disabledReasonSummary(gate.disabledReasonCodes)]),
          ...(annotationSummary ? [annotationSummary] : []),
        ].join("；"),
      },
    });
    container.append(button);
  }
}

function acceptanceData(change) {
  const acceptance = firstPresent(change.acceptance, change.acceptedChangePackage, change.review?.acceptance);
  if (!acceptance) return {};
  if (typeof acceptance !== "object") return { status: acceptance };
  return acceptance;
}

function renderAcceptance(change) {
  const acceptance = acceptanceData(change);
  const status = firstPresent(acceptance.status, change.status, change.state);
  const observedState = normalizeStatus(firstPresent(change.state, change.status, status));
  const accepted = ["accepted", "integrated"].includes(observedState);
  const action = workbenchChangeAction("accept", change);
  const allowed = action?.enabled === true;
  const title = $("#acceptance-title");
  const detail = $("#acceptance-detail");
  const seal = $("#acceptance-seal");

  if (accepted) {
    title.textContent = normalizeStatus(status) === "integrated" ? "这个变更包已经集成" : "这个变更包已经接纳";
    detail.textContent = toDisplayText(firstPresent(acceptance.reason, acceptance.detail))
      || (acceptance.digest ? `接纳记录已绑定内容摘要 ${shortIdentifier(acceptance.digest, 24)}。` : "接纳记录已绑定这一精确内容。");
    seal.textContent = "✓";
    elements.acceptChange.textContent = "已接纳";
    elements.acceptChange.disabled = true;
    elements.acceptChange.title = "";
  } else {
    title.textContent = allowed ? "准备接纳这个精确变更" : "当前还不能接纳";
    detail.textContent =
      toDisplayText(firstPresent(acceptance.reason, acceptance.detail, change.acceptanceBlocker)) ||
      (allowed
        ? "接纳会绑定当前基线、变更内容、证据与决策。内容变化后需要重新验证。"
        : disabledReasonSummary(action?.disabledReasonCodes));
    seal.textContent = "A";
    elements.acceptChange.textContent = "接纳变更包";
    elements.acceptChange.disabled = !allowed;
    elements.acceptChange.title = allowed ? "" : disabledReasonSummary(action?.disabledReasonCodes);
  }
}

async function compileSelectedChange() {
  const id = state.selectedChangeId;
  if (!id) return;
  const action = workbenchChangeAction("compile", state.selectedChange);
  if (action?.enabled !== true) {
    toast(disabledReasonSummary(action?.disabledReasonCodes), "danger");
    return;
  }
  setBusy(elements.compileChange, true, "正在编译");
  try {
    await api(`/api/changes/${encodeURIComponent(id)}/compile`, { method: "POST", body: "{}" });
    await refreshCanonicalStateAfterMutation({ detailId: id });
    toast("变更已编译，上下文与证明义务已刷新。", "success");
  } catch (error) {
    toast(errorMessage(error), "danger");
  } finally {
    setBusy(elements.compileChange, false);
    renderSelectedChange(state.selectedChange || {});
  }
}

async function runGate(gateId, button) {
  const id = state.selectedChangeId;
  if (!id || !gateId) return;
  const gateAction = workbenchChangeAction("gates", state.selectedChange)?.find(
    (gate) => String(gate?.gateId) === String(gateId),
  );
  if (gateAction?.enabled !== true) {
    toast(disabledReasonSummary(gateAction?.disabledReasonCodes), "danger");
    return;
  }
  const gateLabel = button.textContent.replace(/^(运行|重跑)\s+/u, "") || String(gateId);
  state.runningGateId = String(gateId);
  button.disabled = true;
  button.textContent = "运行中…";
  try {
    const result = await api(`/api/changes/${encodeURIComponent(id)}/gates/${encodeURIComponent(gateId)}/run`, {
      method: "POST",
      body: "{}",
    });
    await refreshCanonicalStateAfterMutation({ detailId: id });
    if (normalizeStatus(result?.status) === "passed" && result?.blocked !== true) {
      toast(`门禁“${gateLabel}”已通过。`, "success");
    } else {
      toast(`门禁“${gateLabel}”未通过，请查看证据与剩余不确定性。`, "danger");
    }
  } catch (error) {
    toast(errorMessage(error), "danger");
  } finally {
    state.runningGateId = null;
    if (state.selectedChange) renderChangeGates(state.selectedChange);
  }
}

function openAcceptDialog() {
  if (!state.selectedChange) return;
  const action = workbenchChangeAction("accept", state.selectedChange);
  if (action?.enabled !== true) {
    toast(disabledReasonSummary(action?.disabledReasonCodes), "danger");
    return;
  }
  const requirements = workbenchAcceptanceInputRequirements(state.selectedChange);
  if (requirements?.available !== true) {
    toast(disabledReasonSummary(requirements?.disabledReasonCodes), "danger");
    return;
  }
  elements.acceptError.hidden = true;
  elements.acceptError.textContent = "";
  $("#accept-dialog-change").textContent = changeTitle(state.selectedChange);
  projectWorkbenchAction(elements.submitAccept, action);
  renderAcceptanceRequirementForm(
    requirements,
    state.selectedChange.authorityDecision,
    state.selectedChange.knowledgeClosure,
  );
  $("#accept-confirmation").checked = false;
  if (typeof elements.acceptDialog.showModal === "function") elements.acceptDialog.showModal();
  else elements.acceptDialog.setAttribute("open", "");
}

function renderAcceptanceRequirementForm(requirements, existingDecision = {}, existingClosure = {}) {
  const decisionSelect = $("#accept-decision-option");
  clear(decisionSelect);
  requirements.authorityDecision.decisionOptions.forEach((option, index) => {
    decisionSelect.append(createElement("option", {
      value: String(index),
      text: `${option.authorityRef} · ${option.decisionType}`,
      selected: option.authorityRef === existingDecision?.authority
        && option.decisionType === existingDecision?.decisionType,
    }));
  });
  decisionSelect.disabled = requirements.authorityDecision.decisionOptions.length === 0;
  $("#accept-decided-by").value = existingDecision?.decidedBy || "";
  $("#accept-decision-reason").value = existingDecision?.rationale || existingDecision?.reason || "";
  $("#accept-amendment-refs").value = requirements.authorityDecision.requiredAmendmentRefs.length > 0
    ? requirements.authorityDecision.requiredAmendmentRefs.join("\n")
    : asArray(existingDecision?.amendmentRefs).join("\n");
  $("#accept-adopted-paths").value = requirements.authorityDecision.requiredAdoptedChangePaths.join("\n");
  $("#accept-approved-obligations").value = requirements.authorityDecision.requiredApprovedObligationIds.join("\n");
  $("#accept-waiver-expires-at").value = existingDecision?.expiresAt || "";
  $("#accept-waiver-scope").value = toDisplayText(existingDecision?.scope);
  $("#accept-waiver-controls").value = asArray(existingDecision?.compensatingControls).join("\n");

  const closureMode = $("#accept-closure-mode");
  clear(closureMode);
  const existingClosureMode = existingClosure?.noNewKnowledge === true
    ? "no-new-knowledge"
    : Array.isArray(existingClosure?.entries)
      ? "entries"
      : requirements.knowledgeClosure.allowedModes[0];
  for (const mode of requirements.knowledgeClosure.allowedModes) {
    closureMode.append(createElement("option", {
      value: mode,
      text: mode === "no-new-knowledge" ? "没有新增持久知识" : "逐项归档新增知识",
      selected: mode === existingClosureMode,
    }));
  }
  const closureEntries = Array.isArray(existingClosure?.entries) ? existingClosure.entries : [];
  $("#accept-closure-rationale").value = existingClosure?.rationale
    || closureEntries.find((entry) => isPresent(entry?.rationale))?.rationale
    || "";
  $("#accept-model-amendment-refs").value = requirements.knowledgeClosure.requiredModelAmendmentRefs.join("\n");
  const gapSelect = $("#accept-model-gap-refs");
  clear(gapSelect);
  const selectedGapRefs = new Set(closureEntries
    .filter((entry) => entry?.kind === "model-gap")
    .flatMap((entry) => asArray(entry?.refs).map(String)));
  for (const gapRef of requirements.knowledgeClosure.selectableKnowledgeGapRefs) {
    gapSelect.append(createElement("option", {
      value: gapRef,
      text: gapRef,
      selected: selectedGapRefs.has(gapRef),
    }));
  }
  $("#accept-ephemeral-statements").value = closureEntries
    .filter((entry) => entry?.kind === "ephemeral")
    .map((entry) => entry?.statement)
    .filter(isPresent)
    .join("\n");
  $("#accept-binding-summary").textContent = [
    `requirements ${shortIdentifier(requirements.requirementsDigest, 24)}`,
    ...requirements.confirmation.bindingFields.map((field) => (
      `${field} ${shortIdentifier(requirements.binding[field], 18)}`
    )),
  ].join(" · ");
  $("#accept-confirmation").required = requirements.confirmation.required === true;
  renderAcceptConditionalFields();
}

function selectedAcceptanceDecisionOption(requirements = workbenchAcceptanceInputRequirements()) {
  const index = Number.parseInt($("#accept-decision-option").value, 10);
  return Number.isSafeInteger(index) ? requirements?.authorityDecision?.decisionOptions?.[index] : null;
}

function renderAcceptConditionalFields() {
  const requirements = workbenchAcceptanceInputRequirements();
  if (!requirements) return;
  const option = selectedAcceptanceDecisionOption(requirements);
  const requiredFields = new Set(option?.requiredFields ?? []);
  const decisionReasonField = $("#accept-decision-reason-field");
  const decisionReason = $("#accept-decision-reason");
  const reasonRequired = requiredFields.has("rationale") || requiredFields.has("reason");
  decisionReasonField.hidden = !reasonRequired;
  decisionReason.required = reasonRequired;
  $("#accept-decision-reason-label").textContent = requiredFields.has("reason")
    ? "豁免理由 · reason"
    : "决定理由 · rationale";

  const amendmentRequired = requiredFields.has("amendmentRefs")
    || requirements.authorityDecision.requiredAmendmentRefs.length > 0;
  $("#accept-normative-fields").hidden = !amendmentRequired;
  $("#accept-amendment-refs").required = amendmentRequired;
  $("#accept-amendment-refs").readOnly = requirements.authorityDecision.requiredAmendmentRefs.length > 0;
  $("#accept-adoption-fields").hidden = requirements.authorityDecision.requiredAdoptedChangePaths.length === 0;
  $("#accept-obligation-fields").hidden = requirements.authorityDecision.requiredApprovedObligationIds.length === 0;

  const waiverFields = ["expiresAt", "scope", "compensatingControls"];
  const waiverRequired = waiverFields.some((field) => requiredFields.has(field));
  $("#accept-waiver-fields").hidden = !waiverRequired;
  $("#accept-waiver-expires-at").required = requiredFields.has("expiresAt");
  $("#accept-waiver-scope").required = requiredFields.has("scope");
  $("#accept-waiver-controls").required = requiredFields.has("compensatingControls");

  const entryMode = $("#accept-closure-mode").value === "entries";
  $("#accept-closure-entry-fields").hidden = !entryMode;
  $("#accept-model-amendment-field").hidden = !entryMode
    || requirements.knowledgeClosure.requiredModelAmendmentRefs.length === 0;
  $("#accept-model-gap-field").hidden = !entryMode
    || requirements.knowledgeClosure.selectableKnowledgeGapRefs.length === 0
    || !requirements.knowledgeClosure.entryKinds.includes("model-gap");
  $("#accept-ephemeral-field").hidden = !entryMode
    || !requirements.knowledgeClosure.entryKinds.includes("ephemeral");
}

function readLineValues(selector) {
  return $(selector).value.split("\n").map((line) => line.trim()).filter(Boolean);
}

function closeAcceptDialog() {
  if (typeof elements.acceptDialog.close === "function") elements.acceptDialog.close();
  else elements.acceptDialog.removeAttribute("open");
}

async function acceptSelectedChange(event) {
  event.preventDefault();
  const id = state.selectedChangeId;
  if (!id || !state.selectedChange) return;
  const requirements = workbenchAcceptanceInputRequirements(state.selectedChange);
  if (!requirements || requirements.available !== true || !$("#accept-confirmation").checked) {
    elements.acceptError.hidden = false;
    elements.acceptError.textContent = "验收输入要求不可用，或尚未确认 Kernel 绑定的精确范围。";
    return;
  }
  let acceptanceRequest;
  try {
    acceptanceRequest = compileWorkbenchAcceptanceRequest(requirements, {
      confirmed: $("#accept-confirmation").checked,
      decisionOptionIndex: Number.parseInt($("#accept-decision-option").value, 10),
      decidedBy: $("#accept-decided-by").value,
      decisionReason: $("#accept-decision-reason").value,
      amendmentRefs: readLineValues("#accept-amendment-refs"),
      expiresAt: $("#accept-waiver-expires-at").value,
      scope: $("#accept-waiver-scope").value,
      compensatingControls: readLineValues("#accept-waiver-controls"),
      closureMode: $("#accept-closure-mode").value,
      closureRationale: $("#accept-closure-rationale").value,
      knowledgeGapRefs: [...$("#accept-model-gap-refs").selectedOptions]
        .map((option) => option.value),
      ephemeralStatements: readLineValues("#accept-ephemeral-statements"),
    });
  } catch (error) {
    elements.acceptError.hidden = false;
    elements.acceptError.textContent = errorMessage(error);
    return;
  }

  elements.acceptError.hidden = true;
  setBusy(elements.submitAccept, true, "正在接纳");
  try {
    await api(`/api/changes/${encodeURIComponent(id)}/accept`, {
      method: "POST",
      body: JSON.stringify(acceptanceRequest),
    });
    closeAcceptDialog();
    await refreshCanonicalStateAfterMutation({ detailId: id, includeProject: true });
    toast("变更包已接纳。", "success");
  } catch (error) {
    elements.acceptError.hidden = false;
    elements.acceptError.textContent = errorMessage(error);
    await refreshCanonicalStateAfterMutation({ detailId: id, includeProject: true });
  } finally {
    setBusy(elements.submitAccept, false);
    projectWorkbenchAction(
      elements.submitAccept,
      workbenchChangeAction("accept", state.selectedChange),
    );
    if (state.selectedChange) renderAcceptance(state.selectedChange);
  }
}

function openCreateDialog() {
  elements.createError.hidden = true;
  elements.createError.textContent = "";
  renderCreateChangeKindOptions();
  renderCreateModuleOptions();
  renderCreatePlanOptions();
  const modulesAvailable = selectableAuthoringModules().length > 0;
  const kindAuthoring = selectedChangeKindAuthoring();
  const planAvailable = createPlanSelectionSatisfied(kindAuthoring);
  elements.submitCreate.disabled = !createAuthoringAvailable();
  if (!modulesAvailable) {
    elements.createError.hidden = false;
    elements.createError.textContent = state.workbenchError
      ? `Workbench 语义投影不可用：${errorMessage(state.workbenchError)}`
      : "Kernel 当前没有授权可用于创建 Change 的模块。";
  } else if (!planAvailable) {
    elements.createError.hidden = false;
    elements.createError.textContent = disabledReasonSummary(kindAuthoring?.disabledReasonCodes);
  }
  if (typeof elements.createDialog.showModal === "function") elements.createDialog.showModal();
  else elements.createDialog.setAttribute("open", "");
  window.setTimeout(() => $("#new-change-title").focus(), 0);
}

function closeCreateDialog() {
  if (typeof elements.createDialog.close === "function") elements.createDialog.close();
  else elements.createDialog.removeAttribute("open");
}

async function createChange(event) {
  event.preventDefault();
  const title = $("#new-change-title").value.trim();
  const intent = $("#new-change-intent").value.trim();
  const primaryModule = $("#new-change-module").value;
  const changeKind = selectedChangeKind();
  const kindAuthoring = selectedChangeKindAuthoring();
  const planRefs = selectedPlanRefs();
  const integrityIncidentRequired = kindAuthoring?.integrityIncident?.required === true;
  const observedFailure = $("#new-change-observed-failure").value.trim();
  const knownClaims = [...document.querySelectorAll('#new-change-known-claims input[name="knownClaim"]:checked')]
    .map((input) => ({ id: input.value, statement: input.dataset.statement }));
  const claims = knownClaims;
  const nonGoals = $("#new-change-non-goals").value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  if (!intent) {
    elements.createError.hidden = false;
    elements.createError.textContent = "请先写下变更意图。";
    $("#new-change-intent").focus();
    return;
  }
  if (!primaryModule) {
    elements.createError.hidden = false;
    elements.createError.textContent = "请选择一个已治理的主要修改区域。";
    $("#new-change-module").focus();
    return;
  }
  if (!createPlanSelectionSatisfied(kindAuthoring)) {
    elements.createError.hidden = false;
    elements.createError.textContent = "所选 Outcome 数量不符合 Kernel 投影的 Plan cardinality。";
    $("#new-change-plan-ref").focus();
    return;
  }
  if (integrityIncidentRequired && !observedFailure) {
    elements.createError.hidden = false;
    elements.createError.textContent = "完整性修复必须记录一条具体、可审查的失败 Observation。";
    $("#new-change-observed-failure").focus();
    return;
  }
  if (claims.length === 0) {
    elements.createError.hidden = false;
    elements.createError.textContent = "请选择一个已有门禁支持的契约主张；新语义需要先修订 Project Model。";
    $("#new-change-known-claims input:not(:disabled)")?.focus();
    return;
  }

  elements.createError.hidden = true;
  setBusy(elements.submitCreate, true, "正在创建");
  try {
    const payload = await api("/api/changes", {
      method: "POST",
      body: JSON.stringify({
        title: title || intent,
        request: intent,
        description: intent,
        primaryModule,
        changeKind,
        planRefs,
        integrityTarget: integrityIncidentRequired
          ? { claimRef: claims[0].id, failureEvidenceRef: "integrity-failure-observation" }
          : null,
        evidence: integrityIncidentRequired ? [{
          id: "integrity-failure-observation",
          claim: claims[0],
          oracle: {
            kind: "reported-incident",
            description: "A concrete pre-repair incident is reviewed against an existing protected Claim.",
          },
          observation: { status: "failed", detail: observedFailure },
          provenance: {
            kind: "reported-incident",
            source: "local-workbench",
            observedAt: new Date().toISOString(),
          },
          applicability: { module: primaryModule, phase: "pre-repair" },
          discriminatoryPower: {
            rejects: ["Using the integrity channel without naming an observed violation of an existing Claim."],
          },
          residualUncertainty: [
            "The incident report establishes repair intent but is not trusted proof that the repair succeeds.",
          ],
        }] : [],
        claims,
        nonGoals,
      }),
    });
    const created = unwrap(payload, ["change"]);
    const createdId = firstPresent(created?.id, created?.changeId, payload?.id);
    closeCreateDialog();
    elements.createForm.reset();
    renderCreatePlanOptions();
    await refreshCanonicalStateAfterMutation({ preserveSelection: false });
    if (createdId) await selectChange(createdId);
    document.querySelector("#workspace").scrollIntoView({ behavior: "smooth", block: "start" });
    toast("变更已创建，可以开始编译。", "success");
  } catch (error) {
    elements.createError.hidden = false;
    elements.createError.textContent = errorMessage(error);
  } finally {
    setBusy(elements.submitCreate, false);
    elements.submitCreate.disabled = !createAuthoringAvailable();
  }
}

function wireEvents() {
  [$("#open-create-change"), $("#open-create-change-secondary"), $("#create-first-change")].forEach((button) => {
    button?.addEventListener("click", openCreateDialog);
  });
  $("#close-create-change").addEventListener("click", closeCreateDialog);
  $("#cancel-create-change").addEventListener("click", closeCreateDialog);
  elements.createForm.addEventListener("submit", createChange);
  elements.createDialog.addEventListener("click", (event) => {
    if (event.target === elements.createDialog) closeCreateDialog();
  });
  $("#close-accept-change").addEventListener("click", closeAcceptDialog);
  $("#cancel-accept-change").addEventListener("click", closeAcceptDialog);
  $("#new-change-module").addEventListener("change", (event) => {
    renderCreateClaimOptions(event.target.value);
  });
  $("#new-change-kind").addEventListener("change", () => {
    renderCreatePlanOptions();
    elements.submitCreate.disabled = !createAuthoringAvailable();
  });
  $("#new-change-plan-ref").addEventListener("change", () => {
    renderCreateClaimOptions($("#new-change-module").value);
    elements.submitCreate.disabled = !createAuthoringAvailable();
  });
  elements.acceptForm.addEventListener("submit", acceptSelectedChange);
  $("#accept-decision-option").addEventListener("change", renderAcceptConditionalFields);
  $("#accept-closure-mode").addEventListener("change", renderAcceptConditionalFields);
  elements.acceptDialog.addEventListener("click", (event) => {
    if (event.target === elements.acceptDialog) closeAcceptDialog();
  });
  $("#refresh-project").addEventListener("click", () => {
    void Promise.allSettled([loadProject(), loadWorkbench(), loadArchitectureProfile()]);
  });
  $("#retry-project").addEventListener("click", () => {
    void Promise.allSettled([loadProject(), loadWorkbench(), loadArchitectureProfile()]);
  });
  $("#refresh-changes").addEventListener("click", () => {
    void Promise.allSettled([loadChanges({ preserveSelection: true }), loadWorkbench()]);
  });
  $("#retry-changes").addEventListener("click", () => {
    void Promise.allSettled([loadChanges({ preserveSelection: true }), loadWorkbench()]);
  });
  $("#retry-change-detail").addEventListener("click", () => {
    void Promise.allSettled([loadChangeDetail(), loadWorkbench()]);
  });
  $("#profile-window-next").addEventListener("click", () => {
    void loadNextArchitectureProfile();
  });
  elements.compileChange.addEventListener("click", compileSelectedChange);
  elements.acceptChange.addEventListener("click", openAcceptDialog);
}

function observeSections() {
  if (!("IntersectionObserver" in window)) return;
  const links = [...document.querySelectorAll("[data-nav]")];
  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (!visible) return;
      links.forEach((link) => link.classList.toggle("is-active", link.dataset.nav === visible.target.id));
    },
    { rootMargin: "-25% 0px -60%", threshold: [0.05, 0.25, 0.5] },
  );
  document.querySelectorAll("main > section[id]").forEach((section) => observer.observe(section));
}

async function initialize() {
  wireEvents();
  observeSections();
  setConnection("loading", "正在连接");
  const results = await Promise.allSettled([
    loadProject(),
    loadWorkbench(),
    loadArchitectureProfile(),
    loadChanges({ preserveSelection: false }),
  ]);
  if (results.every((result) => result.status === "rejected") || (state.projectError && state.changesError)) {
    setConnection("error", "本地服务不可用");
  }
}

initialize();
