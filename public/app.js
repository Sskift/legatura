const state = {
  project: null,
  changes: [],
  selectedChangeId: null,
  selectedChange: null,
  projectLoading: true,
  changesLoading: true,
  changeLoading: false,
  projectError: null,
  changesError: null,
  changeError: null,
  runningGateId: null,
};

const $ = (selector) => document.querySelector(selector);

const integrityChangeKinds = new Set([
  "regression-repair",
  "security-containment",
  "data-integrity-repair",
  "acceptance-integrity-repair",
  "entrypoint-restoration",
]);

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
    normalized === "healthy" ||
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
    healthy: "健康",
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
  state.changeLoading = true;
  state.changeError = null;
  renderChangeDetail();
  try {
    const payload = await api(`/api/changes/${encodeURIComponent(id)}`);
    state.selectedChange = unwrap(payload, ["change"]);
    if (!state.selectedChange || typeof state.selectedChange !== "object") {
      throw new Error("服务没有返回可读取的变更详情。");
    }
  } catch (error) {
    state.changeError = error;
    state.selectedChange = null;
  } finally {
    state.changeLoading = false;
    renderChangeDetail();
  }
}

async function selectChange(id) {
  if (!isPresent(id)) return;
  state.selectedChangeId = String(id);
  state.selectedChange = null;
  state.changeError = null;
  writeRequestedChangeId(state.selectedChangeId);
  renderChangesState();
  await loadChangeDetail(state.selectedChangeId);
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

function projectGaps(project) {
  const gaps = firstPresent(
    project.knowledgeGaps,
    project.gaps,
    project.knowledge?.gaps,
    project.atlas?.knowledgeGaps,
  );
  return Array.isArray(gaps) ? gaps : [];
}

function projectGates(project) {
  const gates = firstPresent(project.gates, project.gateHealth?.gates, project.projectModel?.gates);
  return Array.isArray(gates) ? gates : [];
}

function projectContracts(project = state.project) {
  const contracts = firstPresent(project?.contracts, project?.projectModel?.contracts);
  return Array.isArray(contracts) ? contracts : [];
}

function projectPlan(project = state.project) {
  return firstPresent(project?.plan, project?.projectModel?.plan);
}

function activePlanOutcomes(project = state.project) {
  return asArray(projectPlan(project)?.outcomes).filter(
    (outcome) => normalizeStatus(outcome?.status) === "active",
  );
}

function planRefsRequired(project = state.project) {
  return project?.projectDocument?.changePolicy?.requirePlanRefs === true;
}

function selectedChangeKind() {
  return $("#new-change-kind")?.value || "implementation";
}

function selectablePlanOutcomes(project = state.project, changeKind = selectedChangeKind()) {
  if (changeKind === "plan-amendment") return [];
  return activePlanOutcomes(project).filter((outcome) => {
    if (integrityChangeKinds.has(changeKind)) {
      return outcome.kind === "integrity-maintenance"
        && asArray(outcome.allowedChangeKinds).includes(changeKind);
    }
    return outcome.kind !== "integrity-maintenance";
  });
}

function outcomeRequired(project = state.project, changeKind = selectedChangeKind()) {
  return changeKind !== "plan-amendment"
    && (planRefsRequired(project) || integrityChangeKinds.has(changeKind));
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
  setPill(
    $("#project-model-status"),
    firstPresent(project.status, project.modelStatus, project.validation?.valid === true ? "healthy" : project.validation?.valid === false ? "failed" : null),
  );

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
  renderProjectGateHealth(project);
  renderDevelopmentPlan(project);
  renderModules(project);
  renderKnowledgeGaps(project);
  renderProjectGates(project);
  renderCreateModuleOptions(project);
  renderCreatePlanOptions(project);
}

function governedModules(project = state.project) {
  return projectModules(project || {}).filter(
    (module) => normalizeStatus(firstPresent(module.status, module.assurance, module.classification)) === "governed",
  );
}

function renderCreateModuleOptions(project = state.project) {
  const select = $("#new-change-module");
  if (!select) return;
  const previous = select.value;
  const modules = governedModules(project);
  clear(select);
  select.append(
    createElement("option", {
      value: "",
      text: modules.length ? "请选择主要修改区域" : "没有可用的已治理模块",
    }),
  );
  for (const module of modules) {
    const id = firstPresent(module.id, module.name);
    select.append(
      createElement("option", {
        value: String(id),
        text: `${itemTitle(module, String(id))} · ${id}`,
      }),
    );
  }
  if (modules.some((module) => String(firstPresent(module.id, module.name)) === previous)) {
    select.value = previous;
  }
  select.disabled = modules.length === 0;
  $("#new-change-module-help").textContent = modules.length
    ? "一个 Change 只选择一个主要职责边界；跨模块影响会在编译后显式展开。"
    : "项目模型中没有 Governed 模块，暂时无法创建受治理的变更。";
  renderCreateClaimOptions(select.value, project);
}

function renderCreatePlanOptions(project = state.project) {
  const select = $("#new-change-plan-ref");
  if (!select) return;
  const previous = select.value;
  const changeKind = selectedChangeKind();
  const integrityRepair = integrityChangeKinds.has(changeKind);
  const outcomes = selectablePlanOutcomes(project, changeKind);
  const required = outcomeRequired(project, changeKind);
  const failureField = $("#integrity-failure-field");
  const failureInput = $("#new-change-observed-failure");
  failureField.hidden = !integrityRepair;
  failureInput.required = integrityRepair;
  if (!integrityRepair) failureInput.value = "";
  clear(select);
  if (changeKind === "plan-amendment") {
    select.append(createElement("option", { value: "", text: "计划修订不引用 Outcome" }));
    select.disabled = true;
    $("#new-change-plan-ref-help").textContent = "计划修订由治理 Authority 授权，不能使用正在编辑的计划自我授权。";
    return;
  }
  select.append(createElement("option", {
    value: "",
    text: outcomes.length
      ? required ? "请选择本次 Change 推进的 Outcome" : "不绑定长期 Outcome"
      : "没有 active Outcome",
  }));
  for (const outcome of outcomes) {
    const id = String(outcome.id);
    const detail = String(firstPresent(outcome.outcome, outcome.summary, outcome.title, ""));
    select.append(createElement("option", {
      value: id,
      text: detail ? `${id} · ${detail}` : id,
    }));
  }
  if (outcomes.some((outcome) => String(outcome.id) === previous)) select.value = previous;
  select.disabled = outcomes.length === 0;
  $("#new-change-plan-ref-help").textContent = outcomes.length
    ? required
      ? "必须选择冻结 Governance Baseline 中的 active Outcome；planned Outcome 需先独立激活。"
      : "项目未强制对齐，但可以显式记录这次 Change 推进的 active Outcome。"
    : required
      ? "计划策略要求对齐，但当前没有 active Outcome；Project Model 应停止变更创建。"
      : "项目尚未声明可选的 active Outcome。";
}

function renderCreateClaimOptions(moduleId, project = state.project) {
  const container = $("#new-change-known-claims");
  if (!container) return;
  clear(container);
  if (!moduleId || !project) {
    container.append(createElement("div", { className: "claim-picker-empty", text: "先选择主要修改区域。" }));
    return;
  }
  const module = projectModules(project).find(
    (item) => String(firstPresent(item.id, item.name)) === String(moduleId),
  );
  const declaredContractIds = new Set(
    asArray(module?.publicContracts)
      .map((contract) => firstPresent(contract?.id, contract))
      .filter(isPresent)
      .map(String),
  );
  const contracts = projectContracts(project).filter((contract) => {
    const owner = String(firstPresent(contract.owner?.module, contract.owner?.moduleId, contract.owner?.id, contract.owner, ""));
    return owner === String(moduleId) || declaredContractIds.has(String(firstPresent(contract.id, contract.name)));
  });
  const gateClaimIds = new Set(
    projectGates(project)
      .filter((gate) => {
        const targets = asArray(gate.appliesTo).map(String);
        return targets.length === 0 || targets.includes(String(moduleId));
      })
      .flatMap((gate) => asArray(gate.commands).flatMap((command) => asArray(command?.claimRefs)))
      .map(String),
  );
  const claims = contracts.flatMap((contract) =>
    asArray(contract.claims).map((claim) => ({ claim, contract })),
  );
  if (claims.length === 0) {
    container.append(createElement("div", {
      className: "claim-picker-empty",
      text: "这个模块尚未声明公开契约主张；请先发起 Project Model 修订。",
    }));
    return;
  }
  for (const { claim, contract } of claims) {
    const id = firstPresent(claim.id, claim.claimId);
    const statement = toDisplayText(claim, ["statement", "description"]);
    const hasGate = gateClaimIds.has(String(id));
    const input = createElement("input", {
      type: "checkbox",
      name: "knownClaim",
      value: String(id),
      disabled: !hasGate,
      dataset: { statement, contractId: String(firstPresent(contract.id, contract.name, "")) },
    });
    container.append(
      createElement("label", { className: "claim-choice" }, [
        input,
        createElement("span", {}, [
          createElement("strong", { text: statement || String(id) }),
          createElement("small", { text: `${firstPresent(contract.name, contract.id)} · ${id}` }),
        ]),
        createElement("span", {
          className: `claim-oracle-state${hasGate ? " has-gate" : ""}`,
          text: hasGate ? "已有门禁" : "需先建 Oracle",
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

function renderProjectGateHealth(project) {
  const gates = projectGates(project);
  const health = firstPresent(project.gateHealth, project.health?.gates);
  const status = firstPresent(
    health?.status,
    health?.state,
    project.gateStatus,
    project.validation?.valid === false ? "failed" : gates.length ? "configured" : null,
    gates.length ? summarizeGateStatus(gates) : null,
  );
  const value = $("#gate-health-value");
  value.dataset.tone = statusTone(status);
  value.querySelector("strong").textContent = status ? statusLabel(status) : "尚未提供";
  $("#gate-health-detail").textContent =
    toDisplayText(firstPresent(health?.summary, health?.detail, health?.message)) ||
    (gates.length ? `${gates.length} 项已声明门禁；运行结果随所选变更记录。` : "门禁结果尚未载入。");
}

function summarizeGateStatus(gates) {
  const statuses = gates.map((gate) => statusTone(gate.status || gate.state || gate.result));
  if (statuses.includes("danger")) return "failed";
  if (statuses.includes("warning")) return "pending";
  if (statuses.length > 0 && statuses.every((tone) => tone === "success")) return "passed";
  return gates.length ? "pending" : null;
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
  $("#knowledge-gaps-empty").hidden = gaps.length > 0;
  renderItemList($("#knowledge-gaps"), gaps, { fallbackTitle: "未命名缺口" });
}

function renderProjectGates(project) {
  const gates = projectGates(project);
  $("#project-gates-empty").hidden = gates.length > 0;
  renderItemList($("#project-gates"), gates, { fallbackTitle: "未命名门禁" });
}

function renderDevelopmentPlan(project) {
  const plan = projectPlan(project);
  const outcomes = activePlanOutcomes(project);
  $("#plan-active-count").textContent = `${outcomes.length} active`;
  $("#plan-north-star").textContent = toDisplayText(plan?.northStar) || "尚未声明长期 North Star。";
  $("#active-plan-outcomes-empty").hidden = outcomes.length > 0;
  renderItemList(
    $("#active-plan-outcomes"),
    outcomes.map((outcome) => ({
      title: outcome.id,
      description: outcome.outcome,
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
  elements.compileChange.disabled = change.canCompile === false || ["accepted", "integrated", "rejected"].includes(currentStatus);
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
    const coveredClaimIds = new Set(asArray(change.readiness?.coverage?.coveredClaimIds).map(String));
    const derivedStatus = coveredClaimIds.has(String(claimId)) ? "passed" : "pending";
    const status = firstPresent(obligation.status, obligation.state, obligation.result, derivedStatus);
    const oracle = toDisplayText(firstPresent(obligation.oracle, obligation.evidenceRequired, obligation.method));
    const risk = toDisplayText(firstPresent(obligation.risk, obligation.riskLevel));
    container.append(
      createElement("div", { className: "obligation-item", dataset: { tone: statusTone(status) } }, [
        createElement("span", {
          className: "obligation-mark",
          text: statusTone(status) === "success" ? "✓" : String(index + 1),
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

function evidenceData(change) {
  const raw = firstPresent(change.evidence, change.assurance?.evidence, change.review?.evidence);
  if (Array.isArray(raw)) return { records: raw, dimensions: [], overall: null };
  if (!raw || typeof raw !== "object") return { records: [], dimensions: [], overall: null };
  const dimensions = firstPresent(raw.dimensions, raw.strength?.dimensions, change.evidenceStrength?.dimensions);
  const records = firstPresent(raw.records, raw.items, raw.results, raw.observations);
  return {
    dimensions: Array.isArray(dimensions) ? dimensions : normalizeDimensionObject(dimensions),
    records: Array.isArray(records) ? records : [],
    overall: firstPresent(raw.overall, raw.status, raw.strength?.overall, change.evidenceStrength?.overall),
  };
}

function normalizeDimensionObject(dimensions) {
  if (!dimensions || typeof dimensions !== "object") return [];
  return Object.entries(dimensions).map(([id, value]) =>
    typeof value === "object" ? { id, ...value } : { id, value },
  );
}

function scoreValue(dimension) {
  const raw = firstPresent(dimension.score, dimension.value, dimension.rating);
  if (typeof raw !== "number" || Number.isNaN(raw)) return null;
  return Math.max(0, Math.min(100, raw <= 1 ? raw * 100 : raw));
}

function dimensionLabel(dimension) {
  return firstPresent(dimension.label, dimension.name, dimension.title, dimension.id)
    ? humanizeKey(String(firstPresent(dimension.label, dimension.name, dimension.title, dimension.id)))
    : "证据维度";
}

function renderEvidence(change) {
  const evidence = evidenceData(change);
  const dimensions = $("#evidence-dimensions");
  const records = $("#evidence-records");
  clear(dimensions);
  clear(records);
  setPill($("#evidence-overall"), evidence.overall);
  const empty = evidence.dimensions.length === 0 && evidence.records.length === 0;
  $("#evidence-empty").hidden = !empty;

  for (const dimension of evidence.dimensions) {
    const score = scoreValue(dimension);
    const level = firstPresent(dimension.level, dimension.status, dimension.rating);
    const detail = toDisplayText(firstPresent(dimension.detail, dimension.description));
    const track = createElement("div", { className: "evidence-track" });
    if (score !== null) track.append(createElement("span", { attributes: { style: `width:${score}%` } }));
    else track.style.opacity = "0.35";
    dimensions.append(
      createElement("div", { className: "evidence-dimension" }, [
        createElement("div", { className: "evidence-dimension-label" }, [
          createElement("strong", { text: dimensionLabel(dimension) }),
          ...(detail ? [createElement("span", { text: detail })] : []),
        ]),
        track,
        createElement("span", {
          className: "evidence-level",
          text: level ? statusLabel(level) : score !== null ? `${Math.round(score)}/100` : "未评估",
        }),
      ]),
    );
  }

  for (const record of evidence.records) {
    const evidenceId = String(firstPresent(record.id, record.evidenceId, ""));
    const coverage = change.readiness?.coverage ?? {};
    const untrusted = asArray(coverage.untrustedEvidenceIds).map(String).includes(evidenceId);
    const stale = asArray(coverage.staleEvidenceIds).map(String).includes(evidenceId);
    const mismatched = asArray(coverage.mismatchedClaimEvidenceIds).map(String).includes(evidenceId);
    const status = untrusted
      ? "未被内核采信"
      : stale ? "已过期" : mismatched ? "主张语义不匹配"
        : firstPresent(record.status, record.result, record.outcome, record.observation?.status);
    const statusDisplayTone = untrusted || stale || mismatched ? "warning" : statusTone(status);
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
        ...(status
          ? [createElement("span", { className: "status-pill", text: statusLabel(status), dataset: { tone: statusDisplayTone } })]
          : []),
      ]),
    );
  }
  records.hidden = evidence.records.length === 0;
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

function changeGates(change) {
  const configured = asArray(firstPresent(change.gates, change.verificationGates, change.review?.gates));
  const projectConfigured = asArray(state.project?.gates);
  const runs = [
    ...asArray(change.gateRuns),
    ...asArray(change.integrationAssurance?.gateRuns),
  ];
  const byId = new Map();
  for (const gate of [...projectConfigured, ...configured]) {
    const id = firstPresent(gate?.id, gate?.gateId, gate?.name);
    if (id) byId.set(String(id), { ...gate });
  }
  for (const run of runs) {
    const id = firstPresent(run?.gateId, run?.id, run?.name);
    if (id === "project-model") continue;
    if (id) byId.set(String(id), { ...(byId.get(String(id)) || {}), ...run, id });
  }
  return [...byId.values()];
}

function renderChangeGates(change) {
  const gates = changeGates(change);
  const container = $("#change-gates");
  const lifecycle = normalizeStatus(firstPresent(change.state, change.status));
  const integrationGateIds = new Set(asArray(change.verificationPlan?.integrationGateIds).map(String));
  clear(container);
  for (const gate of gates) {
    const id = firstPresent(gate.id, gate.gateId, gate.name);
    if (!id) continue;
    const status = firstPresent(gate.status, gate.state, gate.result);
    const button = createElement("button", {
      className: "gate-action-button",
      type: "button",
      disabled: gate.runnable === false
        || state.runningGateId === String(id)
        || lifecycle === "integrated"
        || (lifecycle === "accepted" && !integrationGateIds.has(String(id))),
      text: state.runningGateId === String(id)
        ? "运行中…"
        : `${statusTone(status) === "success" ? "重跑" : "运行"} ${itemTitle(gate, "门禁")}`,
      onclick: () => runGate(id, button),
    });
    if (status) button.title = `当前状态：${statusLabel(status)}`;
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
  const lifecycle = normalizeStatus(firstPresent(change.state, change.status, status));
  const accepted = ["accepted", "integrated"].includes(lifecycle);
  const allowed = acceptance.allowed !== false && change.canAccept !== false && lifecycle === "evidence-ready" && !accepted;
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
  } else {
    title.textContent = allowed ? "准备接纳这个精确变更" : "当前还不能接纳";
    detail.textContent =
      toDisplayText(firstPresent(acceptance.reason, acceptance.detail, change.acceptanceBlocker)) ||
      (lifecycle === "evidence-ready"
        ? "接纳会绑定当前基线、变更内容、证据与决策。内容变化后需要重新验证。"
        : "先完成证明义务与必要门禁，变更进入 EvidenceReady 后才能接纳。");
    seal.textContent = "A";
    elements.acceptChange.textContent = "接纳变更包";
    elements.acceptChange.disabled = !allowed;
  }
}

async function compileSelectedChange() {
  const id = state.selectedChangeId;
  if (!id) return;
  setBusy(elements.compileChange, true, "正在编译");
  try {
    await api(`/api/changes/${encodeURIComponent(id)}/compile`, { method: "POST", body: "{}" });
    await Promise.all([loadChangeDetail(id), loadChanges({ preserveSelection: true })]);
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
  const gateLabel = button.textContent.replace(/^(运行|重跑)\s+/u, "") || String(gateId);
  state.runningGateId = String(gateId);
  button.disabled = true;
  button.textContent = "运行中…";
  try {
    const result = await api(`/api/changes/${encodeURIComponent(id)}/gates/${encodeURIComponent(gateId)}/run`, {
      method: "POST",
      body: "{}",
    });
    await loadChangeDetail(id);
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

function knowledgeClosureComplete(change = state.selectedChange) {
  const closure = firstPresent(change?.knowledgeClosure, change?.closure);
  if (!closure || typeof closure !== "object" || Array.isArray(closure)) return false;
  if (normalizeStatus(closure.status) !== "complete") return false;
  if (closure.noNewKnowledge === true) return Boolean(toDisplayText(closure.rationale));
  const entries = asArray(firstPresent(closure.entries, closure.dispositions, closure.items));
  if (entries.length === 0) return false;
  return entries.every((entry) => {
    const kind = normalizeStatus(firstPresent(entry?.kind, entry?.classification));
    const refs = asArray(entry?.refs).filter(isPresent);
    return ["model-amendment", "model-gap", "ephemeral"].includes(kind)
      && (refs.length > 0 || Boolean(toDisplayText(entry?.statement)))
      && Boolean(toDisplayText(entry?.rationale));
  });
}

function decisionAuthorities(project = state.project, change = state.selectedChange) {
  const governance = change?.governanceBaseline ?? project ?? {};
  const selectedOutcomeIds = new Set(asArray(change?.planRefs).map((ref) => String(ref)));
  const usesIntegrityOutcome = asArray(projectPlan(governance)?.outcomes).some((outcome) => (
    selectedOutcomeIds.has(String(outcome?.id)) && outcome?.kind === "integrity-maintenance"
  ));
  if (change?.changeKind === "plan-amendment" || usesIntegrityOutcome) {
    const planAuthority = toDisplayText(projectPlan(governance)?.authority);
    return planAuthority ? [planAuthority] : [];
  }
  const module = projectModules(governance).find(
    (item) => String(firstPresent(item.id, item.name)) === String(change?.primaryModule),
  );
  const moduleAuthority = firstPresent(module?.decisionAuthority, module?.authority);
  if (moduleAuthority) return [toDisplayText(moduleAuthority)];
  const declared = firstPresent(
    governance?.projectDocument?.authorities?.decision,
    governance?.project?.authorities?.decision,
    governance?.authorities?.decision,
  );
  return [...new Set(asArray(declared).map((authority) => toDisplayText(authority, ["id", "name"])).filter(Boolean))];
}

function modelAmendmentRefs(change = state.selectedChange) {
  const closure = firstPresent(change?.knowledgeClosure, change?.closure);
  if (!closure || typeof closure !== "object") return [];
  const entries = asArray(firstPresent(closure.entries, closure.dispositions, closure.items));
  return [...new Set(entries.flatMap((entry) => {
    const kind = normalizeStatus(firstPresent(entry?.kind, entry?.classification, entry?.type));
    if (kind !== "model-amendment") return [];
    return asArray(firstPresent(entry.refs, entry.references, entry.amendmentRefs))
      .map((ref) => toDisplayText(ref))
      .filter(Boolean);
  }))];
}

function requiredModelAmendmentRefs(change = state.selectedChange) {
  const observed = asArray(change?.scopeAnalysis?.modelAmendmentPaths)
    .map((ref) => toDisplayText(ref))
    .filter(Boolean);
  return [...new Set([...observed, ...modelAmendmentRefs(change)])];
}

function populateAuthorityOptions() {
  const select = $("#accept-authority");
  const authorities = decisionAuthorities();
  const existing = firstPresent(state.selectedChange?.authorityDecision?.authority, select.value);
  clear(select);
  select.append(createElement("option", { value: "", text: "请选择有权作出决定的职责" }));
  for (const authority of authorities) {
    select.append(createElement("option", { value: authority, text: authority }));
  }
  if (existing && authorities.includes(String(existing))) select.value = String(existing);
  else if (authorities.length === 1) select.value = authorities[0];
  select.disabled = authorities.length === 0;
}

function updateAmendmentField() {
  const normative = $("#accept-decision-type").value === "normative-amendment";
  $("#accept-amendment-field").hidden = !normative;
  $("#accept-amendment-refs").required = normative;
}

function openAcceptDialog() {
  if (!state.selectedChange) return;
  elements.acceptError.hidden = true;
  elements.acceptError.textContent = "";
  $("#accept-dialog-change").textContent = changeTitle(state.selectedChange);
  const closureComplete = knowledgeClosureComplete();
  const unresolvedModelClosure = !closureComplete && requiredModelAmendmentRefs().length > 0;
  $("#accept-closure-fields").hidden = closureComplete;
  $("#accept-closure-summary").required = !closureComplete;
  populateAuthorityOptions();

  const existingDecision = state.selectedChange.authorityDecision || {};
  const requiredAmendments = requiredModelAmendmentRefs();
  $("#accept-decision-type").value = ["case-decision", "normative-amendment"].includes(existingDecision.decisionType)
    ? existingDecision.decisionType
    : requiredAmendments.length > 0 ? "normative-amendment" : "case-decision";
  $("#accept-rationale").value = existingDecision.rationale || "";
  $("#accept-amendment-refs").value = firstPresent(
    asArray(existingDecision.amendmentRefs).join("\n"),
    requiredAmendments.join("\n"),
  ) || "";
  $("#accept-confirmation").checked = false;
  updateAmendmentField();

  if (unresolvedModelClosure) {
    elements.acceptError.hidden = false;
    elements.acceptError.textContent = "检测到 Project Model 变更，但 Knowledge Closure 尚未引用其版本化归宿；请先补全模型记录并重新编译。";
    elements.submitAccept.disabled = true;
  } else if (decisionAuthorities().length === 0) {
    elements.acceptError.hidden = false;
    elements.acceptError.textContent = "Project Model 没有为这个变更声明 Decision Authority，暂时无法接纳。";
    elements.submitAccept.disabled = true;
  } else {
    elements.submitAccept.disabled = false;
  }
  if (typeof elements.acceptDialog.showModal === "function") elements.acceptDialog.showModal();
  else elements.acceptDialog.setAttribute("open", "");
}

function closeAcceptDialog() {
  if (typeof elements.acceptDialog.close === "function") elements.acceptDialog.close();
  else elements.acceptDialog.removeAttribute("open");
}

async function acceptSelectedChange(event) {
  event.preventDefault();
  const id = state.selectedChangeId;
  if (!id || !state.selectedChange) return;
  const authority = $("#accept-authority").value;
  const decisionType = $("#accept-decision-type").value;
  const rationale = $("#accept-rationale").value.trim();
  const amendmentRefs = $("#accept-amendment-refs").value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const closureSummary = $("#accept-closure-summary").value.trim();
  const closureKind = $("#accept-closure-kind").value;

  if (!authority || !rationale || !$("#accept-confirmation").checked) {
    elements.acceptError.hidden = false;
    elements.acceptError.textContent = "请选择决策职责、填写决定理由，并确认接纳范围。";
    return;
  }
  if (decisionType === "normative-amendment" && amendmentRefs.length === 0) {
    elements.acceptError.hidden = false;
    elements.acceptError.textContent = "长期规范修订必须引用至少一个 Model Amendment。";
    return;
  }
  const missingAmendments = requiredModelAmendmentRefs().filter((ref) => !amendmentRefs.includes(ref));
  if (decisionType === "normative-amendment" && missingAmendments.length > 0) {
    elements.acceptError.hidden = false;
    elements.acceptError.textContent = `规范修订引用缺少 ${missingAmendments.length} 个实际变更文件。`;
    return;
  }
  if (!knowledgeClosureComplete() && !closureSummary) {
    elements.acceptError.hidden = false;
    elements.acceptError.textContent = "请说明本次新知识如何归档。";
    return;
  }

  elements.acceptError.hidden = true;
  setBusy(elements.submitAccept, true, "正在接纳");
  try {
    if (!knowledgeClosureComplete()) {
      const knowledgeClosure = closureKind === "ephemeral"
        ? { status: "complete", noNewKnowledge: true, rationale: closureSummary }
        : {
            status: "complete",
            entries: [{
              kind: closureKind,
              statement: closureSummary,
              rationale: closureSummary,
              ...(closureKind === "model-amendment" && amendmentRefs.length ? { refs: amendmentRefs } : {}),
            }],
          };
      await api(`/api/changes/${encodeURIComponent(id)}/compile`, {
        method: "POST",
        body: JSON.stringify({ knowledgeClosure }),
      });
    }
    await api(`/api/changes/${encodeURIComponent(id)}/accept`, {
      method: "POST",
      body: JSON.stringify({
        authorityDecision: {
          status: "approved",
          authority,
          decidedBy: authority,
          decisionType,
          rationale,
          amendmentRefs,
        },
      }),
    });
    closeAcceptDialog();
    await Promise.all([loadChangeDetail(id), loadChanges({ preserveSelection: true }), loadProject()]);
    toast("变更包已接纳。", "success");
  } catch (error) {
    elements.acceptError.hidden = false;
    elements.acceptError.textContent = errorMessage(error);
  } finally {
    setBusy(elements.submitAccept, false);
    if (decisionAuthorities().length === 0) elements.submitAccept.disabled = true;
    if (state.selectedChange) renderAcceptance(state.selectedChange);
  }
}

function openCreateDialog() {
  elements.createError.hidden = true;
  elements.createError.textContent = "";
  renderCreateModuleOptions();
  renderCreatePlanOptions();
  const modulesAvailable = governedModules().length > 0;
  const planAvailable = !outcomeRequired() || selectablePlanOutcomes().length > 0;
  elements.submitCreate.disabled = !modulesAvailable || !planAvailable;
  if (!modulesAvailable) {
    elements.createError.hidden = false;
    elements.createError.textContent = "当前项目没有可用于变更的 Governed 模块。请先完善 Project Model。";
  } else if (!planAvailable) {
    elements.createError.hidden = false;
    elements.createError.textContent = "当前计划策略要求对齐，但没有 active Outcome。请先修订 Development Plan。";
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
  const planRef = $("#new-change-plan-ref").value;
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
  if (outcomeRequired() && !planRef) {
    elements.createError.hidden = false;
    elements.createError.textContent = "请选择一个 active Development Outcome。";
    $("#new-change-plan-ref").focus();
    return;
  }
  if (integrityChangeKinds.has(changeKind) && !observedFailure) {
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
        planRefs: planRef ? [planRef] : [],
        integrityTarget: integrityChangeKinds.has(changeKind)
          ? { claimRef: claims[0].id, failureEvidenceRef: "integrity-failure-observation" }
          : null,
        evidence: integrityChangeKinds.has(changeKind) ? [{
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
    await loadChanges({ preserveSelection: false });
    if (createdId) await selectChange(createdId);
    document.querySelector("#workspace").scrollIntoView({ behavior: "smooth", block: "start" });
    toast("变更已创建，可以开始编译。", "success");
  } catch (error) {
    elements.createError.hidden = false;
    elements.createError.textContent = errorMessage(error);
  } finally {
    setBusy(elements.submitCreate, false);
    if (governedModules().length === 0 || (outcomeRequired() && selectablePlanOutcomes().length === 0)) {
      elements.submitCreate.disabled = true;
    }
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
  $("#accept-decision-type").addEventListener("change", updateAmendmentField);
  $("#new-change-module").addEventListener("change", (event) => {
    renderCreateClaimOptions(event.target.value);
  });
  $("#new-change-kind").addEventListener("change", () => {
    renderCreatePlanOptions();
    elements.submitCreate.disabled = governedModules().length === 0
      || (outcomeRequired() && selectablePlanOutcomes().length === 0);
  });
  elements.acceptForm.addEventListener("submit", acceptSelectedChange);
  elements.acceptDialog.addEventListener("click", (event) => {
    if (event.target === elements.acceptDialog) closeAcceptDialog();
  });
  $("#refresh-project").addEventListener("click", loadProject);
  $("#retry-project").addEventListener("click", loadProject);
  $("#refresh-changes").addEventListener("click", () => loadChanges({ preserveSelection: true }));
  $("#retry-changes").addEventListener("click", () => loadChanges({ preserveSelection: true }));
  $("#retry-change-detail").addEventListener("click", () => loadChangeDetail());
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
  const results = await Promise.allSettled([loadProject(), loadChanges({ preserveSelection: false })]);
  if (results.every((result) => result.status === "rejected") || (state.projectError && state.changesError)) {
    setConnection("error", "本地服务不可用");
  }
}

initialize();
