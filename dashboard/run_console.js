/**
 * ZDG-FR Developer Edition — Run Console
 *
 * Client-side logic for /run-console. Submits governed actions via POST /v1/action,
 * fetches replay via GET /v1/audit/replay, renders the decision output and event
 * timeline, and handles event inspector + export.
 */

"use strict";

// ── State ─────────────────────────────────────────────────────────────────────
const STORAGE_KEY = "zdg.console.adminToken";

const state = {
  token: "",
  runsRows: [],
  activeFilter: "all",
  currentAttemptId: null,
  currentReplay: null,
  selectedEventSeq: null,
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function esc(v) {
  return String(v ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function fmt(v) {
  if (!v) return "—";
  const d = new Date(v);
  return isNaN(d.getTime()) ? String(v) : d.toLocaleTimeString();
}

function fmtMs(v) {
  if (v == null) return "—";
  return v < 1000 ? `${Math.round(v)} ms` : `${(v / 1000).toFixed(2)} s`;
}

function decisionClass(d) {
  if (!d) return "";
  const m = { ALLOW: "allow", BLOCK: "block", APPROVAL_REQUIRED: "approval" };
  return m[d] ?? "";
}

function eventTypeClass(t) {
  if (!t) return "";
  if (t === "ACTION_ATTEMPTED") return "action";
  if (t === "ACTION_ALLOWED" || t === "EXECUTION_COMPLETED") return "allow";
  if (t === "ACTION_BLOCKED") return "block";
  if (t === "EXECUTION_FAILED") return "failed";
  if (t === "APPROVAL_REQUIRED") return "approval";
  return "";
}

function eventIcon(t) {
  const icons = {
    ACTION_ATTEMPTED: "→",
    ACTION_ALLOWED: "✓",
    ACTION_BLOCKED: "✗",
    EXECUTION_COMPLETED: "▶",
    EXECUTION_FAILED: "!",
    APPROVAL_REQUIRED: "?",
    CONTRACT_BOUND: "⚙",
    CREDENTIAL_ISSUED: "🔑",
    CREDENTIAL_ACTIVATED: "🔑",
    CONTRACT_USAGE_UPDATED: "∞",
    SESSION_CREATED: "◎",
  };
  return icons[t] ?? "·";
}

// ── API ───────────────────────────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers ?? {}) };
  if (state.token) headers["X-ZDG-Admin-Token"] = state.token;
  const res = await fetch(path, { ...opts, headers });
  return res;
}

// ── Token persistence ─────────────────────────────────────────────────────────
function loadToken() {
  state.token = localStorage.getItem(STORAGE_KEY) ?? "";
  const inp = document.getElementById("rc-token-input");
  if (inp && state.token) inp.value = state.token;
}

function saveToken() {
  const inp = document.getElementById("rc-token-input");
  state.token = (inp?.value ?? "").trim();
  if (state.token) localStorage.setItem(STORAGE_KEY, state.token);
  else localStorage.removeItem(STORAGE_KEY);
}

// ── Status bar ────────────────────────────────────────────────────────────────
function setStatus(mode, text) {
  const dot = document.getElementById("rc-status-dot");
  const txt = document.getElementById("rc-status-text");
  if (dot) {
    dot.className = `rc-status-dot ${mode}`;
  }
  if (txt) txt.textContent = text;
}

// ── Runs sidebar ──────────────────────────────────────────────────────────────
async function loadRuns() {
  const list = document.getElementById("rc-runs-list");
  if (!list) return;
  list.innerHTML = `<div style="padding:1rem;color:var(--muted);font-size:0.82rem;">Loading…</div>`;
  try {
    const res = await apiFetch("/v1/audit/runs?limit=50");
    if (!res.ok) {
      list.innerHTML = `<div style="padding:1rem;color:var(--danger);font-size:0.82rem;">HTTP ${res.status} — check token</div>`;
      return;
    }
    const data = await res.json();
    state.runsRows = data.runs ?? [];
    renderRunsList(/* fromLoad */ true);
  } catch (e) {
    list.innerHTML = `<div style="padding:1rem;color:var(--danger);font-size:0.82rem;">${esc(e.message)}</div>`;
  }
}

function filterRuns(rows) {
  if (state.activeFilter === "all") return rows;
  if (state.activeFilter === "block") return rows.filter(r => r.final_decision === "BLOCK");
  if (state.activeFilter === "error") return rows.filter(r => r.execution_status === "failed" || r.final_decision === null);
  return rows;
}

function renderRunsList(fromLoad = false) {
  const list = document.getElementById("rc-runs-list");
  if (!list) return;
  const rows = filterRuns(state.runsRows);
  if (!rows.length) {
    if (fromLoad && state.runsRows.length === 0) {
      // Genuinely empty — no runs exist yet
      list.innerHTML = `<div class="rc-zero-sidebar">
        <div class="rc-zero-sidebar-step"><strong>No runs yet.</strong></div>
        <div class="rc-zero-sidebar-step">Use the form below to submit your first governed action. Try <code style="font-size:0.72rem;color:var(--accent)">shell / execute</code> with <code style="font-size:0.72rem;color:var(--accent)">{"command":"echo hello"}</code>.</div>
        <div class="rc-zero-sidebar-step">Runs appear here once submitted.</div>
      </div>`;
    } else {
      list.innerHTML = `<div style="padding:1rem;color:var(--muted);font-size:0.82rem;">No runs match the current filter.</div>`;
    }
    return;
  }
  list.innerHTML = rows.map(row => {
    const dc = decisionClass(row.final_decision ?? "");
    const active = state.currentAttemptId === row.attempt_id ? " active" : "";
    const shortId = (row.attempt_id ?? "").slice(-14);
    return `<div class="rc-run-item${active}" data-attempt="${esc(row.attempt_id)}">
      <div class="rc-run-item-top">
        <span class="rc-run-item-id" title="${esc(row.attempt_id)}">${esc(shortId)}</span>
        <span class="pill ${dc}" style="font-size:0.68rem;padding:0.2rem 0.5rem;">${esc(row.final_decision ?? "open")}</span>
      </div>
      <div class="rc-run-item-meta">
        <span class="rc-run-item-tool">${esc(row.tool_family ?? "")} / ${esc(row.action ?? "")}</span>
      </div>
      <div class="rc-run-item-time">${fmt(row.started_at)} · ${esc(row.agent_id ?? "")}</div>
    </div>`;
  }).join("");

  list.querySelectorAll(".rc-run-item").forEach(el => {
    el.addEventListener("click", () => {
      const id = el.dataset.attempt;
      if (id) loadReplay(id);
    });
  });
}

// ── Submit action ─────────────────────────────────────────────────────────────
async function submitAction(e) {
  e.preventDefault();
  const agentId = document.getElementById("rc-agent-id")?.value.trim();
  const toolFamily = document.getElementById("rc-tool-family")?.value.trim();
  const action = document.getElementById("rc-action")?.value.trim();
  const argsRaw = document.getElementById("rc-args")?.value.trim();
  const sessionId = document.getElementById("rc-session-id")?.value.trim() || undefined;

  let args;
  try {
    args = argsRaw ? JSON.parse(argsRaw) : {};
  } catch {
    renderFailureCard("Invalid JSON in Args field.", null);
    return;
  }

  if (!agentId || !toolFamily || !action) {
    renderFailureCard("Agent ID, tool family, and action are required.", null);
    return;
  }

  const payload = { agent_id: agentId, tool_family: toolFamily, action, args };
  if (sessionId) payload.session_id = sessionId;

  setStatus("running", "Submitting action…");
  clearOutput();
  clearTimeline();
  document.getElementById("rc-export-strip").style.display = "none";
  document.getElementById("rc-attempt-id-display").textContent = "";
  state.currentAttemptId = null;
  state.currentReplay = null;

  const btn = document.getElementById("rc-submit-btn");
  if (btn) btn.disabled = true;

  try {
    const res = await apiFetch("/v1/action", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    if (res.status === 402) {
      const body = await res.json().catch(() => ({}));
      const reason = body?.detail?.reason ?? "Feature limit reached";
      setStatus("failed", "Blocked by license gate");
      renderFailureCard(`HTTP 402 — ${reason}`, null);
      if (btn) btn.disabled = false;
      return;
    }

    if (!res.ok) {
      const text = await res.text();
      setStatus("failed", `HTTP ${res.status}`);
      renderFailureCard(`HTTP ${res.status} — ${text}`, null);
      if (btn) btn.disabled = false;
      return;
    }

    const body = await res.json();
    const attemptId = body.attempt_id;
    state.currentAttemptId = attemptId;

    const display = document.getElementById("rc-attempt-id-display");
    if (display) display.textContent = attemptId ?? "";

    setStatus("running", "Fetching replay…");
    await loadReplay(attemptId, body);
  } catch (err) {
    setStatus("failed", "Network error");
    renderFailureCard(err.message, null);
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── Load replay ───────────────────────────────────────────────────────────────
async function loadReplay(attemptId, actionResponse = null) {
  if (!attemptId) return;
  state.currentAttemptId = attemptId;

  // Mark active in sidebar
  document.querySelectorAll(".rc-run-item").forEach(el => {
    el.classList.toggle("active", el.dataset.attempt === attemptId);
  });
  document.getElementById("rc-attempt-id-display").textContent = attemptId;

  if (!actionResponse) {
    setStatus("running", "Loading replay…");
    clearOutput();
    clearTimeline();
  }

  try {
    // Snapshot format (no format=json) returns run_summary, timeline, execution_summary
    const res = await apiFetch(`/v1/audit/replay?attempt_id=${encodeURIComponent(attemptId)}`);
    if (res.status === 402) {
      const body = await res.json().catch(() => ({}));
      setStatus("blocked", "Replay access limited");
      renderFailureCard(`Replay not available: ${body?.detail?.reason ?? "feature gate"}`, null);
      return;
    }
    if (!res.ok) {
      setStatus("failed", `Replay fetch failed — HTTP ${res.status}`);
      renderFailureCard(`Could not load replay for ${attemptId}.`, null);
      return;
    }

    const replay = await res.json();
    state.currentReplay = replay;
    renderReplay(replay, actionResponse);
  } catch (err) {
    setStatus("failed", "Replay fetch error");
    renderFailureCard(err.message, null);
  }
}

// ── Render replay ─────────────────────────────────────────────────────────────
function renderReplay(replay, actionResponse) {
  const summary = replay.run_summary ?? {};
  const execSummary = replay.execution_summary ?? {};
  const timeline = replay.timeline ?? [];

  const decision = summary.final_decision ?? actionResponse?.decision ?? "—";
  const dc = decisionClass(decision);

  // Status bar
  if (decision === "ALLOW" && execSummary.execution_status !== "failed") {
    setStatus("done", `ALLOW — ${summary.terminal_reason_code ?? ""}`);
  } else if (decision === "BLOCK") {
    setStatus("blocked", `BLOCK — ${summary.terminal_reason_code ?? ""}`);
  } else if (execSummary.execution_status === "failed") {
    setStatus("failed", "Execution failed");
  } else {
    setStatus("done", decision);
  }

  const area = document.getElementById("rc-output-area");
  if (!area) return;

  let html = "";

  // Decision hero
  const heroClass = execSummary.execution_status === "failed" ? "failed" : dc;
  const badgeText = execSummary.execution_status === "failed" ? "FAILED" : decision;
  html += `<div class="rc-decision-hero ${heroClass}">
    <div class="rc-decision-badge ${heroClass}">${esc(badgeText)}</div>
    <div class="rc-decision-meta">
      <div class="rc-decision-field">
        <span class="label">Reason</span>
        <span class="value">${esc(summary.terminal_reason_code ?? actionResponse?.decision_reason ?? "—")}</span>
      </div>
      <div class="rc-decision-field">
        <span class="label">Tool / Action</span>
        <span class="value">${esc(summary.tool_family ?? "")} / ${esc(summary.action ?? "")}</span>
      </div>
      <div class="rc-decision-field">
        <span class="label">Duration</span>
        <span class="value">${fmtMs(summary.duration_ms)}</span>
      </div>
      <div class="rc-decision-field">
        <span class="label">Agent</span>
        <span class="value">${esc(summary.agent_id ?? "")}</span>
      </div>
      <div class="rc-decision-field">
        <span class="label">Attempt</span>
        <span class="value" style="font-size:0.75rem;">${esc((state.currentAttemptId ?? "").slice(-18))}</span>
      </div>
      <div class="rc-decision-field">
        <span class="label">Mock</span>
        <span class="value">${execSummary.mock ? "yes" : "no"}</span>
      </div>
    </div>
  </div>`;

  // Failure card for EXECUTION_FAILED
  const failedEvent = timeline.find(e => e.event_type === "EXECUTION_FAILED");
  if (failedEvent) {
    const errMsg = failedEvent.event_payload?.error ?? failedEvent.event_payload?.error_message ?? JSON.stringify(failedEvent.event_payload);
    html += `<div class="rc-failure-card">
      <div class="rc-failure-head">⚠ Execution failed</div>
      <pre>${esc(errMsg)}</pre>
    </div>`;
  }

  // [1] Block posture — explicit "not executed" when blocked and no execution
  if (decision === "BLOCK" && !execSummary.executed) {
    html += `<div class="rc-not-executed-card">
      <div class="rc-not-executed-icon">✗</div>
      <div class="rc-not-executed-body">
        <div class="rc-not-executed-head">Not executed</div>
        <div class="rc-not-executed-reason">Action blocked before execution. Reason: <span class="rc-not-executed-code">${esc(summary.terminal_reason_code ?? "—")}</span></div>
      </div>
    </div>`;
  }

  // [1] Execution output — prominently rendered for mock and real runs
  if (execSummary.output_summary) {
    const isMock = execSummary.mock;
    html += `<div class="rc-exec-output${isMock ? " rc-exec-output-mock" : ""}">
      <div class="rc-exec-label">${isMock ? "Mock execution output" : "Execution output"}</div>
      <pre>${esc(execSummary.output_summary)}</pre>
    </div>`;
  }

  // Inline tool event cards from timeline
  const keyEvents = timeline.filter(e =>
    ["ACTION_ATTEMPTED", "ACTION_ALLOWED", "ACTION_BLOCKED", "EXECUTION_COMPLETED", "EXECUTION_FAILED", "APPROVAL_REQUIRED"].includes(e.event_type)
  );

  if (keyEvents.length) {
    html += keyEvents.map(ev => {
      const ec = eventTypeClass(ev.event_type);
      return `<div class="rc-tool-event">
        <div class="rc-tool-event-icon" style="${ec === "failed" ? "background:rgba(255,110,103,0.12);color:var(--danger);" : ec === "allow" ? "background:rgba(67,215,178,0.12);color:var(--accent);" : ec === "block" ? "background:rgba(255,180,84,0.12);color:var(--warn);" : ""}">${esc(eventIcon(ev.event_type))}</div>
        <div class="rc-tool-event-body">
          <div class="rc-tool-event-type">${esc(ev.event_type)}</div>
          <div class="rc-tool-event-label">${esc(ev.label ?? "")}</div>
          <div class="rc-tool-event-meta">${fmt(ev.created_at)}</div>
        </div>
      </div>`;
    }).join("");
  }

  area.innerHTML = html;

  // Timeline
  renderTimeline(timeline);

  // Export strip
  document.getElementById("rc-export-strip").style.display = "flex";
}

// ── Timeline ──────────────────────────────────────────────────────────────────
function renderTimeline(timeline) {
  const list = document.getElementById("rc-timeline-list");
  const count = document.getElementById("rc-tl-count");
  if (!list) return;

  if (!timeline.length) {
    list.innerHTML = `<div style="padding:1rem;color:var(--muted);font-size:0.82rem;">No events.</div>`;
    if (count) count.textContent = "0 events";
    return;
  }

  if (count) count.textContent = `${timeline.length} event${timeline.length !== 1 ? "s" : ""}`;

  list.innerHTML = timeline.map(ev => {
    const ec = eventTypeClass(ev.event_type);
    const active = state.selectedEventSeq === ev.seq ? " active" : "";
    return `<div class="rc-tl-item${active}" data-seq="${ev.seq}">
      <div class="rc-tl-seq">${ev.seq}</div>
      <div class="rc-tl-body">
        <div class="rc-tl-type ${ec}">${esc(ev.event_type)}</div>
        <div class="rc-tl-label">${esc(ev.label ?? "")}</div>
        <div class="rc-tl-time">${fmt(ev.created_at)}</div>
      </div>
    </div>`;
  }).join("");

  list.querySelectorAll(".rc-tl-item").forEach(el => {
    el.addEventListener("click", () => {
      const seq = Number(el.dataset.seq);
      const ev = (state.currentReplay?.timeline ?? []).find(e => e.seq === seq);
      if (ev) openInspector(ev);
    });
  });
}

function clearTimeline() {
  const list = document.getElementById("rc-timeline-list");
  if (list) list.innerHTML = `<div style="padding:1rem;color:var(--muted);font-size:0.82rem;">Run an action to see the event timeline.</div>`;
  const count = document.getElementById("rc-tl-count");
  if (count) count.textContent = "—";
  closeInspector();
}

// ── Inspector ─────────────────────────────────────────────────────────────────
function openInspector(ev) {
  state.selectedEventSeq = ev.seq;

  // Highlight in timeline
  document.querySelectorAll(".rc-tl-item").forEach(el => {
    el.classList.toggle("active", Number(el.dataset.seq) === ev.seq);
  });

  const inspector = document.getElementById("rc-inspector");
  const title = document.getElementById("rc-inspector-title");
  const metrics = document.getElementById("rc-inspector-metrics");
  const payload = document.getElementById("rc-inspector-payload");

  if (!inspector) return;
  inspector.classList.add("visible");

  if (title) title.textContent = ev.event_type ?? "Event";

  // Metrics grid: timestamp, seq, event_id, any top-level numeric/string fields
  const metricRows = [
    { label: "Seq", value: ev.seq },
    { label: "Timestamp", value: ev.created_at ? new Date(ev.created_at).toLocaleString() : "—" },
    { label: "Event ID", value: (ev.event_id ?? "").slice(-14) || "—" },
    { label: "Type", value: ev.event_type ?? "—" },
  ];

  // Pull latency/duration from payload if available
  const p = ev.event_payload ?? {};
  if (p.duration_ms != null) metricRows.push({ label: "Duration", value: fmtMs(p.duration_ms) });
  if (p.elapsed_ms  != null) metricRows.push({ label: "Elapsed", value: fmtMs(p.elapsed_ms) });
  if (p.risk_score  != null) metricRows.push({ label: "Risk score", value: p.risk_score });
  if (p.decision    != null) metricRows.push({ label: "Decision", value: p.decision });
  if (p.reason_code != null) metricRows.push({ label: "Reason", value: p.reason_code });

  if (metrics) {
    metrics.innerHTML = metricRows.map(m =>
      `<div class="rc-inspector-metric"><span class="label">${esc(m.label)}</span><span class="value">${esc(m.value)}</span></div>`
    ).join("");
  }

  if (payload) payload.textContent = JSON.stringify(ev.event_payload ?? {}, null, 2);
}

function closeInspector() {
  const inspector = document.getElementById("rc-inspector");
  if (inspector) inspector.classList.remove("visible");
  state.selectedEventSeq = null;
}

// ── Output helpers ────────────────────────────────────────────────────────────
function clearOutput() {
  const area = document.getElementById("rc-output-area");
  if (area) area.innerHTML = "";
}

function renderFailureCard(message, detail) {
  const area = document.getElementById("rc-output-area");
  if (!area) return;
  area.innerHTML = `<div class="rc-failure-card">
    <div class="rc-failure-head">⚠ Error</div>
    <pre>${esc(message)}${detail ? "\n\n" + esc(detail) : ""}</pre>
  </div>`;
}

// ── Export ────────────────────────────────────────────────────────────────────
function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function exportSnapshot() {
  if (!state.currentAttemptId) return;
  try {
    const res = await apiFetch(`/v1/audit/replay?attempt_id=${encodeURIComponent(state.currentAttemptId)}`);
    if (!res.ok) { alert(`HTTP ${res.status}`); return; }
    const data = await res.json();
    downloadJson(data, `replay_snapshot_${state.currentAttemptId}.json`);
  } catch (e) {
    alert(e.message);
  }
}

async function exportRaw() {
  if (!state.currentAttemptId) return;
  try {
    const res = await apiFetch(`/v1/audit/replay?attempt_id=${encodeURIComponent(state.currentAttemptId)}&format=json`);
    if (!res.ok) { alert(`HTTP ${res.status}`); return; }
    const data = await res.json();
    downloadJson(data, `replay_raw_${state.currentAttemptId}.json`);
  } catch (e) {
    alert(e.message);
  }
}

function copySummary() {
  const replay = state.currentReplay;
  if (!replay) return;
  const s = replay.run_summary ?? {};
  const lines = [
    `Attempt:  ${state.currentAttemptId}`,
    `Decision: ${s.final_decision ?? "—"}`,
    `Reason:   ${s.terminal_reason_code ?? "—"}`,
    `Tool:     ${s.tool_family ?? ""}/${s.action ?? ""}`,
    `Agent:    ${s.agent_id ?? ""}`,
    `Duration: ${fmtMs(s.duration_ms)}`,
    `Events:   ${(replay.timeline ?? []).length}`,
  ];
  // [2] Copy confirmation feedback
  const btn = document.getElementById("rc-copy-summary");
  navigator.clipboard?.writeText(lines.join("\n")).then(() => {
    if (!btn) return;
    const prev = btn.textContent;
    btn.textContent = "Copied ✓";
    btn.style.color = "var(--accent)";
    btn.style.borderColor = "rgba(67,215,178,0.4)";
    setTimeout(() => {
      btn.textContent = prev;
      btn.style.color = "";
      btn.style.borderColor = "";
    }, 1800);
  }).catch(() => {});
}

// ── Filter chips ──────────────────────────────────────────────────────────────
function setupFilterChips() {
  document.querySelectorAll(".chip[data-filter]").forEach(chip => {
    chip.addEventListener("click", () => {
      state.activeFilter = chip.dataset.filter;
      document.querySelectorAll(".chip[data-filter]").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      renderRunsList(false);
    });
  });
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  loadToken();
  setupFilterChips();

  document.getElementById("rc-token-save")?.addEventListener("click", () => {
    saveToken();
    loadRuns();
  });

  document.getElementById("rc-token-input")?.addEventListener("keydown", e => {
    if (e.key === "Enter") { saveToken(); loadRuns(); }
  });

  document.getElementById("rc-refresh-runs")?.addEventListener("click", loadRuns);

  document.getElementById("rc-submit-form")?.addEventListener("submit", submitAction);

  document.getElementById("rc-inspector-close")?.addEventListener("click", closeInspector);

  document.getElementById("rc-export-snapshot")?.addEventListener("click", exportSnapshot);
  document.getElementById("rc-export-raw")?.addEventListener("click", exportRaw);
  document.getElementById("rc-copy-summary")?.addEventListener("click", copySummary);

  // Auto-load runs if token already saved
  if (state.token) loadRuns();
});
