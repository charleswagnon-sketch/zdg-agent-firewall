const STORAGE_KEYS = { token: "zdg.console.adminToken", operator: "zdg.console.operator" };
const state = { token: "", operator: "", metrics: null, approvals: [], poller: null, activityLifecycles: [], selectedAttemptId: "", activityDrawerVisible: true, runsRows: [], runsCount: 0, runsLimit: 25, runsOffset: 0, replayData: null, replayAttemptId: "", licenseData: null };
const SAMPLE_INVESTIGATE_PAYLOAD = {
  agent_id: "agent-pilot-01",
  tool_family: "shell",
  action: "execute",
  args: { command: "echo safe" },
};

// ── Display-layer identity mapping ────────────────────────────────────────────
// Maps system-default and well-known demo fallback values to cleaner developer-
// facing labels. Canonical stored values in the DB are unchanged — this affects
// presentation only. Applied wherever agent_id or actor_id is rendered to a
// developer-visible surface.
const IDENTITY_DISPLAY_MAP = {
  "actor:unspecified": "local-developer",
  "test-agent": "demo-agent",
};
function displayIdentity(value) {
  if (!value) return null;
  return IDENTITY_DISPLAY_MAP[value] ?? value;
}

// ── Display-layer reason code mapping ─────────────────────────────────────────
// Maps canonical reason codes to human-readable labels for the developer surface.
// The raw canonical code is preserved in title/tooltip and in raw export; it is
// never discarded.
const REASON_LABELS = {
  "ALLOW":                    "Allowed by policy",
  "UNREGISTERED_TOOL_FAMILY": "Tool family not registered",
  "EXPLICIT_DENY":            "Blocked by policy",
  "AGENT_SUSPENDED":          "Agent suspended",
  "SESSION_SUSPENDED":        "Session suspended",
  "SESSION_CLOSED":           "Session closed",
  "CONTRACT_REVOKED":         "Contract revoked",
  "CONTRACT_EXPIRED":         "Contract expired",
  "BREACH_ESCALATED":         "Breach escalation block",
  "IDENTITY_FAILED":          "Identity mismatch",
  "APPROVAL_REQUIRED":        "Approval required",
};
function displayReasonCode(code) {
  if (!code) return null;
  return REASON_LABELS[code] ?? code;
}

const $ = (id) => document.getElementById(id);
const viewButtons = () => document.querySelectorAll(".nav button");
const views = () => document.querySelectorAll(".view");

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function formatCount(value) {
  return typeof value === "number" ? value.toLocaleString() : "-";
}

function pretty(value) {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function parseJsonOrEmpty(text) {
  const trimmed = (text || "").trim();
  return trimmed ? JSON.parse(trimmed) : {};
}

function parseJsonOrString(text) {
  const trimmed = (text || "").trim();
  if (!trimmed) throw new Error("Value is required.");
  try { return JSON.parse(trimmed); } catch (_error) { return trimmed; }
}

function summarizeObject(value) {
  if (!value || typeof value !== "object") return "-";
  const keys = Object.keys(value);
  if (!keys.length) return "{}";
  return keys.length > 3 ? keys.slice(0, 3).join(", ") + ", ..." : keys.join(", ");
}

function summarizeEventPayload(payload) {
  if (!payload || typeof payload !== "object") return "-";
  const parts = [];
  if (payload.agent_id) parts.push(`agent=${payload.agent_id}`);
  if (payload.tool_family) parts.push(`tool=${payload.tool_family}`);
  if (payload.reason_code) parts.push(`reason=${payload.reason_code}`);
  if (payload.operator) parts.push(`operator=${payload.operator}`);
  if (payload.scope) parts.push(`scope=${payload.scope}`);
  return parts.length ? parts.join(" | ") : summarizeObject(payload);
}

function pillClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized.includes("allow") || normalized.includes("complete") || normalized.includes("success") || normalized === "active" || normalized === "approved" || normalized === "trialing") return "allow";
  if (normalized.includes("approval") || normalized.includes("pending") || normalized.includes("reset")) return "approval";
  if (normalized.includes("block") || normalized.includes("fail") || normalized.includes("suspend") || normalized.includes("closed") || normalized.includes("deregister") || normalized.includes("deny") || normalized === "expired" || normalized === "revoked") return "block";
  return "info";
}

function makePill(value) {
  return `<span class="pill ${pillClass(value)}">${escapeHtml(value || "unknown")}</span>`;
}

function showStatus(message, kind = "") {
  const banner = $("status-banner");
  banner.classList.remove("ok", "error", "info", "warn");
  if (kind) banner.classList.add(kind);
  $("status-text").textContent = message;
}

function setConnectionState(label, tone = "info", detail = "") {
  const pill = $("connection-pill");
  pill.className = `pill ${tone}`;
  pill.textContent = label;
  $("connection-detail").textContent = detail;
}

function setLastRefresh() {
  const timestamp = new Date().toLocaleTimeString();
  $("last-refresh").textContent = timestamp;
  return timestamp;
}

function renderList(element, items, mapper, emptyMessage) {
  if (!items || !items.length) {
    element.innerHTML = `<li><span>${escapeHtml(emptyMessage)}</span><span class="pill info">idle</span></li>`;
    return;
  }
  element.innerHTML = items.map((item) => {
    const mapped = mapper(item);
    return `<li><span>${escapeHtml(mapped.left)}</span><span class="pill ${escapeHtml(mapped.pill || "info")}">${escapeHtml(mapped.right)}</span></li>`;
  }).join("");
}

function loadStoredCredentials() {
  state.token = localStorage.getItem(STORAGE_KEYS.token) || "";
  state.operator = localStorage.getItem(STORAGE_KEYS.operator) || "";
  $("admin-token").value = state.token;
  $("operator-name").value = state.operator;
  if (state.token) {
    showStatus("Credentials loaded. Refresh to pull run data.", "info");
    setConnectionState("Configured", "info", "Token saved locally. Refresh to verify live API connectivity.");
  } else {
    setConnectionState("Not connected", "error", "Add your API token and refresh to verify connectivity.");
  }
}

function saveCredentials(event) {
  event.preventDefault();
  state.token = $("admin-token").value.trim();
  state.operator = $("operator-name").value.trim();
  localStorage.setItem(STORAGE_KEYS.token, state.token);
  localStorage.setItem(STORAGE_KEYS.operator, state.operator);
  if (!state.token) {
    showStatus("API access required", "error");
    setConnectionState("Not connected", "error", "Enter a valid admin API token to load runs, replay, and admin data.");
    return;
  }
  showStatus("Credentials saved. Loading data...", "info");
  setConnectionState("Checking", "info", "Saved locally. Verifying API connectivity now.");
  refreshAll();
}

function clearCredentials() {
  state.token = "";
  state.operator = "";
  localStorage.removeItem(STORAGE_KEYS.token);
  localStorage.removeItem(STORAGE_KEYS.operator);
  $("admin-token").value = "";
  $("operator-name").value = "";
  showStatus("Credentials cleared. API sections are idle until a token is added.", "error");
  setConnectionState("Not connected", "error", "Credentials removed. API sections are idle until a token is added.");
}

function requireOperator() {
  const operator = ($("operator-name").value || state.operator || "").trim();
  if (!operator) throw new Error("Identity is required for mutating actions.");
  state.operator = operator;
  localStorage.setItem(STORAGE_KEYS.operator, operator);
  return operator;
}

async function apiFetch(path, options = {}) {
  if (!state.token) throw new Error("Admin token is required.");
  const headers = new Headers(options.headers || {});
  headers.set("X-ZDG-Admin-Token", state.token);
  headers.set("Accept", "application/json");
  let body = options.body;
  if (body && typeof body === "object" && !(body instanceof Blob) && !(body instanceof String)) {
    body = JSON.stringify(body);
    if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, { method: options.method || "GET", headers, body });
  const text = await response.text();
  const contentType = response.headers.get("content-type") || "";
  let payload = text;
  if (contentType.includes("application/json")) payload = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const detail = payload && typeof payload === "object" ? payload.detail || payload : null;
    const reason = detail && typeof detail === "object" ? detail.reason || detail.reason_code || response.statusText : response.statusText;
    throw new Error(String(reason));
  }
  return payload;
}

function renderOverviewSummary() {
  const summary = [];
  if (state.approvals.length) summary.push({ left: "Pending approval queue", right: `${state.approvals.length} waiting`, pill: "approval" });
  if (state.metrics) {
    summary.push({ left: "Current policy bundle", right: state.metrics.active_policy_bundle || "-", pill: "info" });
    if (state.metrics.kill_switch_global_active) {
      summary.push({ left: "Global halt is active", right: "All governed actions are blocked", pill: "block" });
    } else if ((state.metrics.kill_switch_scoped_active_count || 0) > 0) {
      summary.push({ left: "Scoped halts active", right: `${state.metrics.kill_switch_scoped_active_count} scoped switch(es)`, pill: "approval" });
    }
    if ((state.metrics.total_blocked || 0) > 0) {
      summary.push({ left: "Hard blocks observed", right: `${state.metrics.total_blocked} blocked attempt(s)`, pill: "block" });
    }
  }
  renderList($("overview-summary-list"), summary, (item) => item, "No signals yet.");
}

async function loadMetrics() {
  const metrics = await apiFetch("/v1/metrics");
  state.metrics = metrics;
  $("metric-total-attempts").textContent = formatCount(metrics.total_attempts);
  $("metric-total-allowed").textContent = formatCount(metrics.total_allowed);
  $("metric-total-blocked").textContent = formatCount(metrics.total_blocked);
  $("metric-total-approval").textContent = formatCount(metrics.total_approval_required);
  $("overview-policy-version").textContent = metrics.active_policy_bundle || "-";
  $("overview-global-killswitch").innerHTML = makePill(metrics.kill_switch_global_active ? "active" : "inactive");
  $("overview-scoped-killswitch").textContent = formatCount(metrics.kill_switch_scoped_active_count);
  $("policy-current-version").textContent = metrics.active_policy_bundle || "-";
  renderList($("top-rules-list"), metrics.top_triggered_rules || [], (item) => ({ left: item.rule, right: `${item.count} hits`, pill: "info" }), "No triggered rule data yet.");
  renderList($("top-reason-codes-list"), metrics.top_reason_codes || [], (item) => ({ left: item.reason_code, right: `${item.count} decisions`, pill: pillClass(item.reason_code) }), "No reason code data yet.");
  renderOverviewSummary();
}

async function loadApprovals() {
  const payload = await apiFetch("/v1/approvals");
  state.approvals = payload.approvals || [];
  $("approvals-count").textContent = `${payload.count || 0} pending approval(s)`;
  $("overview-pending-approvals").textContent = formatCount(payload.count || 0);
  $("approvals-table-body").innerHTML = state.approvals.length ? state.approvals.map((approval) => `
    <tr>
      <td><div class="mono">${escapeHtml(approval.approval_id)}</div><div class="meta">${escapeHtml(approval.decision_id)}</div></td>
      <td><div>${escapeHtml(approval.agent_id)}</div><div class="meta">${escapeHtml(approval.action)}</div></td>
      <td>${makePill(approval.tool_family)}</td>
      <td>${escapeHtml(approval.risk_score)}</td>
      <td><span class="truncate" title="${escapeHtml(approval.reason || "")}">${escapeHtml(approval.reason || "-")}</span></td>
      <td>${escapeHtml(formatDate(approval.expires_at))}</td>
      <td><div class="actions">
        <button class="small" data-approval-action="approve" data-approval-id="${escapeHtml(approval.approval_id)}" data-payload-hash="${escapeHtml(approval.payload_hash)}">Approve</button>
        <button class="small danger" data-approval-action="deny" data-approval-id="${escapeHtml(approval.approval_id)}" data-payload-hash="${escapeHtml(approval.payload_hash)}">Deny</button>
      </div></td>
    </tr>`).join("") : '<tr><td colspan="7" class="empty">No pending approvals.</td></tr>';
  renderOverviewSummary();
}

const DECISION_EVENT_TYPES = new Set(["ACTION_ALLOWED", "ACTION_BLOCKED", "APPROVAL_REQUIRED", "UNREGISTERED_TOOL_FAMILY"]);
const EXECUTION_EVENT_TYPES = new Set(["EXECUTION_COMPLETED", "EXECUTION_FAILED"]);

function eventTimestamp(value) {
  const time = value ? new Date(value).getTime() : 0;
  return Number.isNaN(time) ? 0 : time;
}

function uniqueValues(values) {
  return [...new Set(values.filter(Boolean))];
}

function summarizeLifecycleDetail(event) {
  if (!event) return "No matching lifecycle step in the current filter set.";
  const payload = event.payload;
  if (!payload || typeof payload !== "object") return "-";
  const parts = [];
  if (payload.reason_code) parts.push(payload.reason_code);
  if (payload.reason && payload.reason !== payload.reason_code) parts.push(payload.reason);
  if (payload.execution_status) parts.push(payload.execution_status);
  if (payload.blocked_reason) parts.push(payload.blocked_reason);
  if (payload.output_summary) parts.push(payload.output_summary);
  return parts.length ? parts.join(" | ") : summarizeEventPayload(payload);
}

function summarizeChains(chainIds) {
  if (!chainIds.length) return { primary: "-", detail: "No chain metadata" };
  if (chainIds.length === 1) return { primary: chainIds[0], detail: "Single chain view" };
  return { primary: chainIds[0], detail: `+${chainIds.length - 1} linked chain(s)` };
}

function deriveLifecycleTone(item) {
  const decisionType = item.decisionEvent?.event_type || "";
  const executionType = item.executionEvent?.event_type || "";
  if (executionType.includes("FAILED") || decisionType.includes("BLOCK") || decisionType.includes("UNREGISTERED")) return "block";
  if (decisionType.includes("APPROVAL") || item.lifecycle.some((value) => String(value).includes("APPROVAL"))) return "approval";
  if (executionType.includes("COMPLETED") || decisionType.includes("ALLOW")) return "allow";
  return "info";
}

function summarizeAttemptContext(item) {
  const parts = [];
  if (item.agents.length) parts.push(`Agents: ${item.agents.join(", ")}`);
  if (item.tools.length) parts.push(`Tools: ${item.tools.join(", ")}`);
  if (item.chainIds.length) parts.push(`Chains: ${item.chainIds.join(", ")}`);
  if (item.lifecycle.length) parts.push(`Lifecycle: ${item.lifecycle.join(" -> ")}`);
  return parts.length ? parts.join("\n") : "No additional context captured for this attempt.";
}

function summarizeAttemptGridMeta(item) {
  const parts = [];
  if (item.tools.length) parts.push(item.tools.join(", "));
  if (item.chainIds.length) parts.push(`${item.chainIds.length} chain${item.chainIds.length === 1 ? "" : "s"}`);
  if (item.eventCount) parts.push(`${item.eventCount} event${item.eventCount === 1 ? "" : "s"}`);
  return parts.join(" | ") || "No context";
}

function applyActivitySelectionVisuals() {
  const rows = $("events-table-body").querySelectorAll("tr[data-attempt-id]");
  rows.forEach((row) => row.classList.toggle("is-selected", row.dataset.attemptId === state.selectedAttemptId));
}

function setActivityDrawerVisibility(visible) {
  state.activityDrawerVisible = Boolean(visible);
  const layout = $("activity-layout");
  const toggle = $("toggle-activity-drawer");
  if (layout) layout.classList.toggle("drawer-hidden", !state.activityDrawerVisible);
  if (!toggle) return;
  toggle.textContent = state.activityDrawerVisible ? "Hide detail" : "Show detail";
  toggle.setAttribute("aria-pressed", state.activityDrawerVisible ? "true" : "false");
}

function toggleActivityDrawer() {
  setActivityDrawerVisibility(!state.activityDrawerVisible);
}

function updateActivitySelection(attemptId) {
  state.selectedAttemptId = attemptId || "";
  if (state.selectedAttemptId) setActivityDrawerVisibility(true);
  applyActivitySelectionVisuals();
  renderActivityDrawer();
}

function renderActivityDrawer() {
  const empty = $("activity-detail-empty");
  const card = $("activity-detail-card");
  const selected = state.activityLifecycles.find((item) => item.attemptId === state.selectedAttemptId);
  if (!selected) {
    empty.classList.remove("hidden");
    card.classList.add("hidden");
    return;
  }
  empty.classList.add("hidden");
  card.classList.remove("hidden");
  $("activity-detail-attempt").textContent = selected.attemptId;
  $("activity-detail-last-seen").textContent = formatDate(selected.latestEvent?.created_at);
  $("activity-detail-decision").innerHTML = `${makePill(selected.decisionEvent?.event_type || "no decision")}<div class="meta detail-meta">${escapeHtml(summarizeLifecycleDetail(selected.decisionEvent))}</div>`;
  $("activity-detail-execution").innerHTML = `${makePill(selected.executionEvent?.event_type || "no execution")}<div class="meta detail-meta">${escapeHtml(summarizeLifecycleDetail(selected.executionEvent))}</div>`;
  $("activity-detail-context").textContent = summarizeAttemptContext(selected);
  $("activity-detail-timeline").innerHTML = selected.events
    .slice()
    .sort((left, right) => eventTimestamp(left.created_at) - eventTimestamp(right.created_at))
    .map((event) => `
      <li class="timeline-item tone-${escapeHtml(pillClass(event.event_type))}">
        <div class="timeline-head">
          <span>${makePill(event.event_type)}</span>
          <span class="meta">${escapeHtml(formatDate(event.created_at))}</span>
        </div>
        <div class="timeline-body">${escapeHtml(summarizeLifecycleDetail(event))}</div>
      </li>`)
    .join("");
  $("activity-detail-payload").textContent = pretty(selected.summaryPayload || {});
}

function groupEventsByAttempt(events) {
  const groups = new Map();
  events.forEach((event, index) => {
    const attemptId = event.related_attempt_id || `event:${event.event_id || index}`;
    if (!groups.has(attemptId)) groups.set(attemptId, { attemptId, events: [] });
    groups.get(attemptId).events.push(event);
  });
  return [...groups.values()];
}

function summarizeAttemptLifecycle(group) {
  const sortedDesc = [...group.events].sort((left, right) => eventTimestamp(right.created_at) - eventTimestamp(left.created_at));
  const sortedAsc = [...sortedDesc].reverse();
  const latestEvent = sortedDesc[0];
  const decisionEvent = sortedDesc.find((event) => DECISION_EVENT_TYPES.has(event.event_type));
  const executionEvent = sortedDesc.find((event) => EXECUTION_EVENT_TYPES.has(event.event_type));
  const chainIds = uniqueValues(sortedDesc.map((event) => event.chain_id));
  const agents = uniqueValues(sortedDesc.map((event) => event.payload?.agent_id));
  const tools = uniqueValues(sortedDesc.map((event) => event.payload?.tool_family));
  const lifecycle = uniqueValues(sortedAsc.map((event) => event.event_type));
  const summaryPayload = latestEvent?.payload || decisionEvent?.payload || executionEvent?.payload || {};
  return {
    attemptId: group.attemptId,
    latestEvent,
    decisionEvent,
    executionEvent,
    chainIds,
    agents,
    tools,
    lifecycle,
    eventCount: group.events.length,
    summaryPayload,
    events: sortedAsc,
  };
}

async function loadEvents() {
  const params = new URLSearchParams({ limit: "40" });
  if ($("events-agent-filter").value.trim()) params.set("agent_id", $("events-agent-filter").value.trim());
  if ($("events-tool-filter").value.trim()) params.set("tool_family", $("events-tool-filter").value.trim());
  if ($("events-type-filter").value.trim()) params.set("event_type", $("events-type-filter").value.trim());
  const payload = await apiFetch(`/v1/events?${params.toString()}`);
  const events = payload.events || [];
  const lifecycles = groupEventsByAttempt(events)
    .map(summarizeAttemptLifecycle)
    .sort((left, right) => eventTimestamp(right.latestEvent?.created_at) - eventTimestamp(left.latestEvent?.created_at));
  state.activityLifecycles = lifecycles;
  if (state.selectedAttemptId && !lifecycles.some((item) => item.attemptId === state.selectedAttemptId)) state.selectedAttemptId = "";
  $("events-count").textContent = `${lifecycles.length} attempt lifecycle(s) in the current feed. Grouped from ${events.length} event(s).`;
  $("events-table-body").innerHTML = lifecycles.length ? lifecycles.map((item) => {
    const tone = deriveLifecycleTone(item);
    const decisionDetail = summarizeLifecycleDetail(item.decisionEvent);
    const executionDetail = summarizeLifecycleDetail(item.executionEvent);
    const agentLabel = item.agents.length ? item.agents.join(", ") : "-";
    const summaryLabel = summarizeEventPayload(item.summaryPayload);
    const gridMeta = summarizeAttemptGridMeta(item);
    return `
    <tr class="attempt-row tone-${escapeHtml(tone)}${state.selectedAttemptId === item.attemptId ? ' is-selected' : ''}" data-attempt-id="${escapeHtml(item.attemptId)}">
      <td><div>${escapeHtml(formatDate(item.latestEvent?.created_at))}</div><div class="meta">${escapeHtml(`${item.eventCount} event(s)`)}</div></td>
      <td><div class="mono">${escapeHtml(item.attemptId)}</div><div class="meta truncate" title="${escapeHtml(item.lifecycle.join(" -> "))}">${escapeHtml(item.lifecycle.join(" -> ") || "-")}</div></td>
      <td><div class="activity-stack compact">${makePill(item.decisionEvent?.event_type || "no decision")}<span class="meta truncate" title="${escapeHtml(decisionDetail)}">${escapeHtml(decisionDetail)}</span></div></td>
      <td><div class="activity-stack compact">${makePill(item.executionEvent?.event_type || "no execution")}<span class="meta truncate" title="${escapeHtml(executionDetail)}">${escapeHtml(executionDetail)}</span></div></td>
      <td><div>${escapeHtml(agentLabel)}</div><div class="meta truncate" title="${escapeHtml(gridMeta)}">${escapeHtml(gridMeta)}</div></td>
      <td class="activity-open-cell"><button type="button" class="small ghost detail-trigger" data-open-attempt="${escapeHtml(item.attemptId)}">Open</button><div class="meta truncate" title="${escapeHtml(summaryLabel)}">${escapeHtml(summaryLabel)}</div></td>
    </tr>`;
  }).join("") : (() => {
    const hasFilters = $("events-agent-filter").value.trim() || $("events-tool-filter").value.trim() || $("events-type-filter").value.trim();
    const msg = hasFilters ? 'No events matched the current filters.' : 'No activity yet — submit a governed action via <code>POST /v1/action</code> to see events here.';
    return `<tr><td colspan="6" class="empty">${msg}</td></tr>`;
  })();
  applyActivitySelectionVisuals();
  renderActivityDrawer();
}

function clearActivitySelection() {
  updateActivitySelection("");
}

function handleActivitySelection(event) {
  const row = event.target.closest("tr[data-attempt-id]");
  const trigger = event.target.closest("[data-open-attempt]");
  if (!row) return;
  updateActivitySelection(trigger?.dataset.openAttempt || row.dataset.attemptId || "");
  const drawer = $("activity-drawer");
  if (drawer && window.matchMedia("(max-width: 1500px)").matches) {
    drawer.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}
function renderAgentActions(agent) {
  const agentId = escapeHtml(agent.agent_id);
  const status = String(agent.status || "").toLowerCase();
  const actions = [];
  if (status === "active") {
    actions.push(`<button class="small" data-agent-action="suspend" data-agent-id="${agentId}">Suspend</button>`);
  }
  if (status === "suspended") {
    actions.push(`<button class="small" data-agent-action="unsuspend" data-agent-id="${agentId}">Unsuspend</button>`);
  }
  if (status !== "deregistered") {
    actions.push(`<button class="small danger" data-agent-action="deregister" data-agent-id="${agentId}">Deregister</button>`);
  }
  return actions.length ? `<div class="actions stack">${actions.join("")}</div>` : '<span class="meta">No actions available</span>';
}

function renderSessionActions(record) {
  const sessionId = escapeHtml(record.session_id);
  const status = String(record.status || "").toLowerCase();
  const actions = [];
  if (status === "active") {
    actions.push(`<button class="small" data-session-action="suspend" data-session-id="${sessionId}">Suspend</button>`);
  }
  if (status === "suspended") {
    actions.push(`<button class="small" data-session-action="unsuspend" data-session-id="${sessionId}">Unsuspend</button>`);
  }
  if (status !== "closed") {
    actions.push(`<button class="small danger" data-session-action="close" data-session-id="${sessionId}">Close</button>`);
  }
  return actions.length ? `<div class="actions stack">${actions.join("")}</div>` : '<span class="meta">No actions available</span>';
}

async function loadAgents() {
  const payload = await apiFetch("/v1/agents");
  const agents = payload.agents || [];
  $("agents-table-body").innerHTML = agents.length ? agents.map((agent) => `
    <tr>
      <td>
        <div class="mono">${escapeHtml(agent.agent_id)}</div>
        <div class="meta">${escapeHtml(agent.registered_by || "-")}</div>
      </td>
      <td>${makePill(agent.status)}</td>
      <td>
        <div class="detail-stack">
          <div><span class="detail-label">Type</span><span>${escapeHtml(agent.agent_type || "-")}</span></div>
          <div><span class="detail-label">Registered</span><span>${escapeHtml(formatDate(agent.registered_at))}</span></div>
          <div><span class="detail-label">Metadata</span><span class="truncate" title="${escapeHtml(JSON.stringify(agent.metadata || {}))}">${escapeHtml(summarizeObject(agent.metadata))}</span></div>
        </div>
      </td>
      <td class="actions-cell">${renderAgentActions(agent)}</td>
    </tr>`).join("") : '<tr><td colspan="4" class="empty">No registered agents yet.</td></tr>';
}

async function loadSessions() {
  const payload = await apiFetch("/v1/sessions");
  const sessions = payload.sessions || [];
  $("sessions-table-body").innerHTML = sessions.length ? sessions.map((record) => `
    <tr>
      <td>
        <div class="mono">${escapeHtml(record.session_id)}</div>
        <div class="meta">${escapeHtml(record.created_by || "-")}</div>
      </td>
      <td>${makePill(record.status)}</td>
      <td>
        <div class="detail-stack">
          <div><span class="detail-label">Agent</span><span>${escapeHtml(record.agent_id || "-")}</span></div>
          <div><span class="detail-label">Created</span><span>${escapeHtml(formatDate(record.created_at))}</span></div>
          <div><span class="detail-label">Source</span><span>${escapeHtml(record.creation_source || "-")}</span></div>
        </div>
      </td>
      <td class="actions-cell">${renderSessionActions(record)}</td>
    </tr>`).join("") : '<tr><td colspan="4" class="empty">No sessions created yet.</td></tr>';
}

async function loadKillSwitch() {
  const payload = await apiFetch("/v1/killswitch");
  const scoped = payload.scoped_halts || [];
  $("killswitch-status-card").innerHTML = `<div class="summary-line"><span>Global status</span>${makePill(payload.global_halt ? "active" : "inactive")}</div>${scoped.length ? `<div class="detail-box"><strong>Scoped halts</strong><ul class="list">${scoped.map((item) => `<li><span class="mono">${escapeHtml(item.scope + (item.scope_value ? `:${item.scope_value}` : ""))}</span><span class="pill block">active</span></li>`).join("")}</ul></div>` : '<div class="empty">No scoped halts are active.</div>'}`;
}

async function loadLicenseStatus() {
  const data = await apiFetch("/v1/license");
  state.licenseData = data;
  const plan = data.license?.plan_code || (data.unmanaged_mode ? "unmanaged" : "-");
  const status = data.license?.status || (data.unmanaged_mode ? "unmanaged" : "-");
  $("license-plan").textContent = plan;
  $("license-status-pill").innerHTML = makePill(status);
  $("license-status-message").textContent = data.status_message || "";

  const ents = data.entitlements || [];
  const KEY_FEATURES = ["debug_bundle_export", "replay_history_days", "advanced_filters"];
  const shown = ents.filter((e) => KEY_FEATURES.includes(e.feature_code));
  if (shown.length === 0 && !data.unmanaged_mode) {
    $("license-entitlements-summary").innerHTML = '<p class="help">No entitlements recorded — permissive defaults apply.</p>';
  } else if (data.unmanaged_mode) {
    $("license-entitlements-summary").innerHTML = '<p class="help">All features accessible in unmanaged mode. Activate a license via <code>POST /v1/license/activate</code> to enable plan enforcement.</p>';
  } else {
    $("license-entitlements-summary").innerHTML = `<ul class="list">${shown.map((e) => {
      const val = e.limit_value != null ? `limit: ${e.limit_value}` : (e.enabled ? "enabled" : "disabled");
      const tone = e.enabled ? "allow" : "block";
      return `<li><span class="mono">${escapeHtml(e.feature_code)}</span><span class="pill ${tone}">${escapeHtml(val)}</span></li>`;
    }).join("")}</ul>`;
  }

  const usage = data.usage_summary;
  if (usage) {
    const runsInfo = usage.max_monthly_runs;
    const exportsInfo = usage.max_monthly_exports;
    const fmtUsage = (info) => {
      if (!info) return "-";
      const used = info.used ?? 0;
      const limit = info.limit != null ? info.limit : "∞";
      const tone = info.exceeded ? "block" : "allow";
      return `<span class="pill ${tone}">${escapeHtml(String(used))} / ${escapeHtml(String(limit))}</span>`;
    };
    $("license-usage-summary").innerHTML = `
      <div class="section-tag" style="margin-top:0.5rem">Usage — ${escapeHtml(usage.window || "")}</div>
      <div class="meta-pair"><span>Runs this month</span>${fmtUsage(runsInfo)}</div>
      <div class="meta-pair"><span>Exports this month</span>${fmtUsage(exportsInfo)}</div>`;
  } else {
    $("license-usage-summary").innerHTML = "";
  }

  // Billing actions — show if admin token is set (we can make the API calls)
  const accountId = data.license?.account_id || null;
  const hasStripeCustomer = !!(data.license?.stripe_customer_id);
  if (accountId) {
    $("billing-actions").style.display = "";
    $("billing-portal-btn").style.display = hasStripeCustomer ? "" : "none";
    $("billing-status-msg").textContent = "";
  } else {
    $("billing-actions").style.display = "none";
  }
}

async function startBillingCheckout() {
  const accountId = state.licenseData?.license?.account_id;
  if (!accountId) { showStatus("No active license account found.", "error"); return; }
  const planCode = $("billing-plan-select").value;
  $("billing-status-msg").textContent = "Creating checkout session…";
  try {
    const data = await apiFetch("/v1/billing/checkout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ account_id: accountId, plan_code: planCode }),
    });
    if (data.checkout_url) {
      $("billing-status-msg").textContent = "Redirecting to Stripe…";
      window.location.href = data.checkout_url;
    }
  } catch (_err) {
    $("billing-status-msg").textContent = "Checkout failed — check Stripe configuration.";
  }
}

async function openBillingPortal() {
  const accountId = state.licenseData?.license?.account_id;
  if (!accountId) { showStatus("No active license account found.", "error"); return; }
  $("billing-status-msg").textContent = "Opening billing portal…";
  try {
    const data = await apiFetch("/v1/billing/portal", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ account_id: accountId }),
    });
    if (data.portal_url) {
      $("billing-status-msg").textContent = "Redirecting to Stripe portal…";
      window.location.href = data.portal_url;
    }
  } catch (_err) {
    $("billing-status-msg").textContent = "Portal failed — check Stripe configuration.";
  }
}

async function refreshAll() {
  if (!state.token) {
    showStatus("API access required", "error");
    setConnectionState("Not connected", "error", "Enter a valid admin API token to load runs, replay, and admin data.");
    return;
  }
  showStatus("Refreshing...", "info");
  setConnectionState("Checking", "info", "Verifying API and refreshing data.");
  const results = await Promise.allSettled([loadMetrics(), loadApprovals(), loadEvents(), loadAgents(), loadSessions(), loadKillSwitch(), loadLicenseStatus(), loadRuns()]);
  const failure = results.find((result) => result.status === "rejected");
  if (failure) {
    showStatus(`Some sections failed to refresh: ${failure.reason.message}`, "error");
    setConnectionState("Degraded", "approval", `Some sections failed to refresh. ${failure.reason.message}`);
  } else {
    const refreshedAt = setLastRefresh();
    showStatus("Data refreshed successfully.", "ok");
    setConnectionState("Connected", "allow", `API verified at ${refreshedAt}.`);
  }
}

async function resolveApproval(event) {
  const button = event.target.closest("button[data-approval-action]");
  if (!button) return;
  const approvalId = button.dataset.approvalId;
  const payloadHash = button.dataset.payloadHash;
  const approved = button.dataset.approvalAction === "approve";
  const operator = requireOperator();
  const comment = window.prompt(`${approved ? "Approve" : "Deny"} ${approvalId}? Optional comment:`, "") || null;
  await apiFetch(`/v1/approval/${encodeURIComponent(approvalId)}`, { method: "POST", body: { approve: approved, operator, payload_hash: payloadHash, comment } });
  showStatus(`Approval ${approvalId} resolved.`, "ok");
  await loadApprovals();
  await loadEvents();
}

async function updateAgent(event) {
  const button = event.target.closest("button[data-agent-action]");
  if (!button) return;
  const operator = requireOperator();
  const reason = window.prompt(`Reason for ${button.dataset.agentAction} on ${button.dataset.agentId}:`, "Operator console action");
  if (!reason) return;
  await apiFetch(`/v1/agents/${encodeURIComponent(button.dataset.agentId)}/${button.dataset.agentAction}`, { method: "POST", body: { operator, reason } });
  showStatus(`Agent ${button.dataset.agentId} updated.`, "ok");
  await loadAgents();
  await loadEvents();
}

async function updateSession(event) {
  const button = event.target.closest("button[data-session-action]");
  if (!button) return;
  const operator = requireOperator();
  const reason = window.prompt(`Reason for ${button.dataset.sessionAction} on ${button.dataset.sessionId}:`, "Operator console action");
  if (!reason) return;
  await apiFetch(`/v1/sessions/${encodeURIComponent(button.dataset.sessionId)}/${button.dataset.sessionAction}`, { method: "POST", body: { operator, reason } });
  showStatus(`Session ${button.dataset.sessionId} updated.`, "ok");
  await loadSessions();
  await loadEvents();
}

async function registerAgent(event) {
  event.preventDefault();
  const operator = requireOperator();
  await apiFetch("/v1/agents", {
    method: "POST",
    body: {
      agent_id: $("agent-id-input").value.trim(),
      agent_type: $("agent-type-input").value.trim(),
      metadata: parseJsonOrEmpty($("agent-metadata-input").value),
      operator,
    },
  });
  event.target.reset();
  showStatus("Agent registered.", "ok");
  await loadAgents();
  await loadEvents();
}

async function createSession(event) {
  event.preventDefault();
  const operator = requireOperator();
  await apiFetch("/v1/sessions", {
    method: "POST",
    body: {
      agent_id: $("session-agent-input").value.trim() || null,
      metadata: parseJsonOrEmpty($("session-metadata-input").value),
      operator,
      creation_source: $("session-source-input").value.trim() || "console",
    },
  });
  event.target.reset();
  $("session-source-input").value = "console";
  showStatus("Session created.", "ok");
  await loadSessions();
  await loadEvents();
}

async function updateKillSwitch(event) {
  event.preventDefault();
  const operator = requireOperator();
  const action = $("killswitch-action-input").value;
  const scope = $("killswitch-scope-input").value;
  const scopeValue = $("killswitch-scope-value-input").value.trim() || null;
  const comment = $("killswitch-comment-input").value.trim() || null;
  await apiFetch(`/v1/killswitch/${action}`, { method: "POST", body: { operator, scope, scope_value: scope === "global" ? null : scopeValue, comment } });
  showStatus("Kill switch action applied.", "ok");
  await loadKillSwitch();
  await loadEvents();
}

async function reloadPolicy() {
  const payload = await apiFetch("/v1/policy/reload", { method: "POST" });
  $("policy-output").textContent = pretty(payload);
  $("policy-reload-state").textContent = payload.reloaded ? "Reloaded" : "No change";
  showStatus(payload.reloaded ? "Policy bundle reloaded." : "Policy bundle unchanged.", "ok");
  await loadMetrics();
  await loadEvents();
}

async function investigatePayload() {
  const payload = parseJsonOrEmpty($("investigate-input").value);
  const response = await apiFetch("/v1/investigate", { method: "POST", body: payload });
  $("investigate-output").textContent = pretty(response);
  const cells = $("investigate-summary-grid").children;
  cells[0].querySelector("span").innerHTML = makePill(response.final_decision?.decision || "-");
  cells[1].querySelector("span").textContent = response.final_decision?.reason_code || "-";
  cells[2].querySelector("span").textContent = response.total_risk_score ?? "-";
  cells[3].querySelector("span").textContent = response.payload_hash || "-";
  showStatus("Investigate trace generated.", "ok");
}

async function exportAudit() {
  const chainId = $("audit-export-chain").value.trim();
  const format = $("audit-export-format").value;
  if (!chainId) throw new Error("Chain ID is required for export.");
  const response = await fetch(`/v1/audit/export?chain_id=${encodeURIComponent(chainId)}&format=${encodeURIComponent(format)}`, { headers: { "X-ZDG-Admin-Token": state.token } });
  const text = await response.text();
  if (!response.ok) throw new Error(text || "Audit export failed.");
  const content = format === "json" ? pretty(JSON.parse(text)) : text;
  $("audit-export-output").textContent = content;
  $("audit-verify-input").value = content;
  showStatus("Audit export ready.", "ok");
}

async function verifyAudit() {
  const raw = $("audit-verify-input").value.trim();
  if (!raw) throw new Error("Paste a chain export to verify.");
  const isJson = raw.startsWith("{");
  const payload = await apiFetch("/v1/audit/verify", {
    method: "POST",
    headers: isJson ? { "Content-Type": "application/json" } : { "Content-Type": "text/plain" },
    body: isJson ? JSON.parse(raw) : raw,
  });
  $("audit-verify-output").textContent = pretty(payload);
  showStatus(payload.ok ? "Chain verification passed." : "Chain verification reported a problem.", payload.ok ? "ok" : "error");
}

async function diffAudit() {
  const payload = await apiFetch("/v1/audit/diff", {
    method: "POST",
    body: {
      left_export: parseJsonOrString($("audit-diff-left").value),
      right_export: parseJsonOrString($("audit-diff-right").value),
    },
  });
  $("audit-diff-output").textContent = pretty(payload);
  showStatus("Audit diff generated.", "ok");
}

async function copyAudit() {
  const text = $("audit-export-output").textContent;
  if (!text || text === "Export output will appear here.") throw new Error("Nothing to copy yet.");
  await navigator.clipboard.writeText(text);
  showStatus("Audit export copied to clipboard.", "ok");
}

function selectView(name) {
  viewButtons().forEach((button) => button.classList.toggle("active", button.dataset.view === name));
  views().forEach((section) => section.classList.toggle("active", section.id === `view-${name}`));
}

function startPolling() {
  if (state.poller) clearInterval(state.poller);
  state.poller = window.setInterval(() => {
    if (!state.token) return;
    Promise.allSettled([loadMetrics(), loadApprovals(), loadEvents(), loadKillSwitch()]).then(() => setLastRefresh());
  }, 20000);
}

function withHandler(handler) {
  return async (event) => {
    try { await handler(event); } catch (error) { showStatus(error.message || String(error), "error"); }
  };
}

function wireEvents() {
  $("auth-form").addEventListener("submit", withHandler(saveCredentials));
  $("clear-auth").addEventListener("click", clearCredentials);
  $("refresh-all").addEventListener("click", withHandler(refreshAll));
  $("toggle-activity-drawer").addEventListener("click", toggleActivityDrawer);
  $("refresh-activity").addEventListener("click", withHandler(loadEvents));
  $("clear-activity-selection").addEventListener("click", clearActivitySelection);
  $("events-table-body").addEventListener("click", handleActivitySelection);
  $("apply-event-filters").addEventListener("click", withHandler(loadEvents));
  $("clear-event-filters").addEventListener("click", () => {
    $("events-agent-filter").value = "";
    $("events-tool-filter").value = "";
    $("events-type-filter").value = "";
    withHandler(loadEvents)();
  });
  $("refresh-approvals").addEventListener("click", withHandler(loadApprovals));
  $("refresh-agents").addEventListener("click", withHandler(loadAgents));
  $("refresh-sessions").addEventListener("click", withHandler(loadSessions));
  $("refresh-killswitch").addEventListener("click", withHandler(loadKillSwitch));
  $("reload-policy").addEventListener("click", withHandler(reloadPolicy));
  $("run-investigate").addEventListener("click", withHandler(investigatePayload));
  $("run-audit-export").addEventListener("click", withHandler(exportAudit));
  $("copy-audit-export").addEventListener("click", withHandler(copyAudit));
  $("run-audit-verify").addEventListener("click", withHandler(verifyAudit));
  $("run-audit-diff").addEventListener("click", withHandler(diffAudit));
  $("agent-form").addEventListener("submit", withHandler(registerAgent));
  $("session-form").addEventListener("submit", withHandler(createSession));
  $("killswitch-form").addEventListener("submit", withHandler(updateKillSwitch));
  $("approvals-table-body").addEventListener("click", withHandler(resolveApproval));
  $("agents-table-body").addEventListener("click", withHandler(updateAgent));
  $("sessions-table-body").addEventListener("click", withHandler(updateSession));
  viewButtons().forEach((button) => button.addEventListener("click", () => selectView(button.dataset.view)));
  $("refresh-runs").addEventListener("click", withHandler(loadRuns));
  $("apply-runs-filters").addEventListener("click", withHandler(runsApplyFilters));
  $("clear-runs-filters").addEventListener("click", runsClearFilters);
  $("runs-next-page").addEventListener("click", withHandler(runsNextPage));
  $("runs-prev-page").addEventListener("click", withHandler(runsPrevPage));
  $("runs-table-body").addEventListener("click", handleRunsTableClick);
  $("export-replay-snapshot").addEventListener("click", withHandler(exportReplaySnapshot));
  $("export-replay-json").addEventListener("click", withHandler(exportReplayJson));
  $("back-to-runs").addEventListener("click", backToRuns);
  $("back-to-runs-from-error").addEventListener("click", backToRuns);
  $("billing-checkout-btn").addEventListener("click", withHandler(startBillingCheckout));
  $("billing-portal-btn").addEventListener("click", withHandler(openBillingPortal));
  $("load-replay-manual").addEventListener("click", withHandler(() => {
    const id = $("replay-manual-id").value.trim();
    if (!id) throw new Error("Enter an attempt ID.");
    return openReplay(id);
  }));
}

async function init() {
  loadStoredCredentials();
  wireEvents();
  $("investigate-input").value = pretty(SAMPLE_INVESTIGATE_PAYLOAD);
  setActivityDrawerVisibility(state.activityDrawerVisible);
  renderActivityDrawer();
  startPolling();
  if (state.token) await refreshAll();
}

// ── Runs view ─────────────────────────────────────────────────────────────────

async function loadRuns() {
  const params = new URLSearchParams({ limit: String(state.runsLimit), offset: String(state.runsOffset) });
  const decision = $("runs-decision-filter").value.trim();
  const agentId = $("runs-agent-filter").value.trim();
  const sessionId = $("runs-session-filter").value.trim();
  const toolFamily = $("runs-tool-filter").value.trim();
  if (decision) params.set("decision", decision);
  if (agentId) params.set("agent_id", agentId);
  if (sessionId) params.set("session_id", sessionId);
  if (toolFamily) params.set("tool_family", toolFamily);
  const payload = await apiFetch(`/v1/audit/runs?${params.toString()}`);
  state.runsRows = payload.runs || [];
  state.runsCount = payload.count || 0;
  renderRunsTable();
}

function renderRunsTable() {
  const { runsRows: rows, runsCount: count, runsLimit: limit, runsOffset: offset } = state;
  $("runs-count-label").textContent = `${count} run(s) total`;
  $("runs-page-label").textContent = rows.length ? `Showing ${offset + 1}–${offset + rows.length}` : "";
  $("runs-page-info").textContent = rows.length ? `${offset + 1}–${offset + rows.length} of ${count}` : "0 results";
  $("runs-prev-page").disabled = offset === 0;
  $("runs-next-page").disabled = offset + rows.length >= count;
  if (!rows.length) {
    const decision = $("runs-decision-filter").value.trim();
    const agentId = $("runs-agent-filter").value.trim();
    const sessionId = $("runs-session-filter").value.trim();
    const toolFamily = $("runs-tool-filter").value.trim();
    const hasFilters = decision || agentId || sessionId || toolFamily;
    const emptyMsg = count === 0 && !hasFilters
      ? '<strong>No runs yet</strong><br>Submit your first governed action from <code>/docs</code> or your local agent integration to see replay artifacts here.<br><small>Quick start: open <code>/docs</code>, call <code>POST /v1/action</code>, then return here to inspect the run.</small>'
      : 'No runs matched the current filters.';
    $("runs-table-body").innerHTML = `<tr><td colspan="7" class="empty">${emptyMsg}</td></tr>`;
    return;
  }
  $("runs-table-body").innerHTML = rows.map((row) => {
    const execStatus = row.mock
      ? `${escapeHtml(row.execution_status || "-")} <span class="pill info" style="font-size:0.72rem">mock</span>`
      : escapeHtml(row.execution_status || "-");
    return `
    <tr class="runs-row tone-${escapeHtml(pillClass(row.final_decision))}" data-attempt-id="${escapeHtml(row.attempt_id)}">
      <td>
        <div>${escapeHtml(formatDate(row.started_at))}</div>
        <div class="mono meta truncate" title="${escapeHtml(row.attempt_id)}">${escapeHtml(row.attempt_id)}</div>
      </td>
      <td>
        <div>${escapeHtml(displayIdentity(row.agent_id) || "-")}</div>
        <div class="meta">${escapeHtml(row.tool_family || "-")} / ${escapeHtml(row.action || "-")}</div>
      </td>
      <td>${row.duration_ms != null ? `${row.duration_ms} ms` : "-"}</td>
      <td>${makePill(row.final_decision || "—")}</td>
      <td><span class="truncate" title="${escapeHtml(row.terminal_reason_code || "")}">${escapeHtml(displayReasonCode(row.terminal_reason_code) || "-")}</span></td>
      <td>${execStatus}</td>
      <td><button type="button" class="small ghost open-btn" data-open-replay="${escapeHtml(row.attempt_id)}">↗</button></td>
    </tr>`;
  }).join("");
}

function handleRunsTableClick(event) {
  const btn = event.target.closest("[data-open-replay]");
  if (btn) { openReplay(btn.dataset.openReplay); return; }
  const row = event.target.closest("tr[data-attempt-id]");
  if (row) openReplay(row.dataset.attemptId);
}

async function runsApplyFilters() {
  state.runsOffset = 0;
  await loadRuns();
}

function runsClearFilters() {
  $("runs-decision-filter").value = "";
  $("runs-agent-filter").value = "";
  $("runs-session-filter").value = "";
  $("runs-tool-filter").value = "";
  state.runsOffset = 0;
  loadRuns().catch((error) => showStatus(error.message, "error"));
}

async function runsNextPage() {
  state.runsOffset += state.runsLimit;
  await loadRuns();
}

async function runsPrevPage() {
  state.runsOffset = Math.max(0, state.runsOffset - state.runsLimit);
  await loadRuns();
}

// ── Replay view ───────────────────────────────────────────────────────────────

function renderSummaryCard(title, entries, modifierClass = "") {
  const rows = entries.map(([label, value]) => {
    const displayValue = value == null
      ? `<span style="color:var(--muted)">—</span>`
      : typeof value === "boolean"
        ? makePill(String(value))
        : `<span class="truncate" title="${escapeHtml(String(value))}">${escapeHtml(String(value))}</span>`;
    return `<div class="replay-card-row"><span class="detail-label">${escapeHtml(label)}</span>${displayValue}</div>`;
  }).join("");
  const cls = ["panel", "replay-card", modifierClass].filter(Boolean).join(" ");
  return `<div class="${cls}"><strong class="replay-card-title">${escapeHtml(title)}</strong><div>${rows}</div></div>`;
}

function renderReplayView(snapshot) {
  $("replay-attempt-heading").textContent = snapshot.attempt_id;
  const rs = snapshot.run_summary || {};
  const as_ = snapshot.authority_summary || {};
  const cs = snapshot.contract_summary || {};
  const hs = snapshot.handoff_summary || {};
  const gs = snapshot.guardrail_summary || {};
  const cr = snapshot.credential_summary || {};
  const es = snapshot.execution_summary || {};
  const us = snapshot.usage_summary || {};

  // Hero strip: key facts at a glance
  const toolAction = rs.tool_family != null && rs.action != null ? `${rs.tool_family} / ${rs.action}` : null;
  $("replay-hero").innerHTML = `
    <div class="replay-hero-kv">
      <span class="replay-hero-label">Decision</span>
      ${makePill(rs.final_decision || "—")}
    </div>
    <div class="replay-hero-kv">
      <span class="replay-hero-label">Reason</span>
      <span class="replay-hero-val" title="${escapeHtml(rs.terminal_reason_code || "")}">${escapeHtml(displayReasonCode(rs.terminal_reason_code) || "—")}</span>
    </div>
    <div class="replay-hero-kv">
      <span class="replay-hero-label">Tool / Action</span>
      <span class="replay-hero-val">${escapeHtml(toolAction || "—")}</span>
    </div>
    <div class="replay-hero-kv">
      <span class="replay-hero-label">Duration</span>
      <span class="replay-hero-val">${rs.duration_ms != null ? `${rs.duration_ms} ms` : "—"}</span>
    </div>`;
  $("replay-hero").classList.remove("hidden");

  // Primary card: Run summary
  $("replay-summary-primary").innerHTML = renderSummaryCard("Run", [
    ["Agent", displayIdentity(rs.agent_id)],
    ["Tool / Action", toolAction],
    ["Started", rs.start_time ? formatDate(rs.start_time) : null],
    ["Session", rs.session_id],
  ]);

  // Secondary cards: detailed context
  $("replay-summary-grid").innerHTML = [
    renderSummaryCard("Authority", [
      ["Actor", displayIdentity(as_.actor_id)],
      ["Delegation", as_.delegation_chain_id],
    ], "replay-card--secondary"),
    renderSummaryCard("Contract", [
      ["Contract ID", cs.contract_id],
      ["State", cs.contract_state],
      ["Bound at", cs.bound_at ? formatDate(cs.bound_at) : null],
      ["Expires at", cs.expires_at ? formatDate(cs.expires_at) : null],
    ], "replay-card--secondary"),
    renderSummaryCard("Handoff", [
      ["Handoff ID", hs.handoff_id],
      ["Validation", hs.validation_state],
      ["Disposition", hs.disposition],
    ], "replay-card--secondary"),
    renderSummaryCard("Guardrail", [
      ["Blocked", gs.guardrail_blocked],
      ["Checks triggered", gs.checks_triggered],
    ], "replay-card--secondary"),
    renderSummaryCard("Credential", [
      ["Issued", cr.issued],
      ["Grant ID", cr.grant_id],
      ["Subject", displayIdentity(cr.subject_id)],
      ["Expires at", cr.expires_at ? formatDate(cr.expires_at) : null],
    ], "replay-card--secondary"),
    renderSummaryCard("Execution", [
      ["Executed", es.executed],
      ["Mock", es.mock],
      ["Status", es.execution_status],
      ["Output", es.output_summary],
    ], "replay-card--secondary"),
    renderSummaryCard("Usage", [
      ["Invocations", us.invocation_count],
      ["Elapsed", us.elapsed_ms != null ? `${us.elapsed_ms} ms` : null],
    ], "replay-card--secondary"),
  ].join("");

  const timeline = snapshot.timeline || [];
  $("replay-timeline-list").innerHTML = timeline.length
    ? timeline.map((ev) => `
        <div class="replay-timeline-item tone-${escapeHtml(pillClass(ev.event_type))}">
          <div class="replay-timeline-head">
            <span class="meta replay-seq">${escapeHtml(String(ev.seq ?? ""))}</span>
            ${makePill(ev.event_type)}
            <span class="replay-timeline-label">${escapeHtml(ev.label || ev.event_type)}</span>
            <span class="meta replay-timeline-time">${escapeHtml(formatDate(ev.created_at))}</span>
          </div>
          <details class="replay-payload-details">
            <summary>View raw payload</summary>
            <pre class="output">${escapeHtml(JSON.stringify(ev.event_payload || {}, null, 2))}</pre>
          </details>
        </div>`).join("")
    : '<p class="empty">No timeline events for this attempt.</p>';

  $("replay-empty-state").classList.add("hidden");
  $("replay-error-state").classList.add("hidden");
  $("replay-content").classList.remove("hidden");
}

async function openReplay(attemptId) {
  selectView("replay");
  state.replayAttemptId = attemptId;
  state.replayData = null;
  $("replay-content").classList.add("hidden");
  $("replay-error-state").classList.add("hidden");
  $("replay-empty-state").classList.add("hidden");
  $("replay-hero").classList.add("hidden");
  try {
    const snapshot = await apiFetch(`/v1/audit/replay?attempt_id=${encodeURIComponent(attemptId)}`);
    state.replayData = snapshot;
    renderReplayView(snapshot);
  } catch (error) {
    $("replay-error-message").textContent = `Unable to load replay for ${attemptId}: ${error.message}`;
    $("replay-error-state").classList.remove("hidden");
  }
}

function backToRuns() {
  selectView("runs");
}

function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

async function exportReplaySnapshot() {
  if (!state.replayData) throw new Error("No replay data loaded.");
  downloadJson(state.replayData, `replay-snapshot-${state.replayAttemptId}.json`);
  showStatus("Snapshot exported.", "ok");
}

async function exportReplayJson() {
  if (!state.replayAttemptId) throw new Error("No attempt loaded.");
  const raw = await apiFetch(`/v1/audit/replay?attempt_id=${encodeURIComponent(state.replayAttemptId)}&format=json`);
  downloadJson(raw, `replay-raw-${state.replayAttemptId}.json`);
  showStatus("Raw JSON trace exported.", "ok");
}

window.addEventListener("DOMContentLoaded", () => {
  init().catch((error) => showStatus(error.message || String(error), "error"));
});








