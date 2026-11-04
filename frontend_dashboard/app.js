// ─── Your Warden Dashboard Application ─────────────────────────────────────
// Handles auth state, real-time incident streaming, and admin actions.
// ────────────────────────────────────────────────────────────────────────────

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getAuth,
  onAuthStateChanged,
  signOut,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  getDatabase,
  ref,
  onValue,
  update,
  serverTimestamp,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-database.js";
import { firebaseConfig } from "./config.js";

// ── Initialise Firebase ─────────────────────────────────────────────────────
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getDatabase(app);

// ── DOM Elements ────────────────────────────────────────────────────────────
const userEmailEl = document.getElementById("user-email");
const logoutBtn = document.getElementById("logout-btn");
const statusDot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
const incidentsList = document.getElementById("incidents-list");
const emptyState = document.getElementById("empty-state");
const statTotal = document.getElementById("stat-total");
const statQuarantined = document.getElementById("stat-quarantined");
const statResolved = document.getElementById("stat-resolved");

// ── Auth State Observer ─────────────────────────────────────────────────────
onAuthStateChanged(auth, (user) => {
  if (!user) {
    window.location.href = "login.html";
    return;
  }
  userEmailEl.textContent = user.email;
  connectToDatabase();
});

// ── Logout ──────────────────────────────────────────────────────────────────
logoutBtn.addEventListener("click", () => {
  signOut(auth).then(() => {
    window.location.href = "login.html";
  });
});

// ── Real-time Database Listener ─────────────────────────────────────────────
function connectToDatabase() {
  const incidentsRef = ref(db, "incidents");

  statusDot.classList.remove("bg-amber-400");
  statusDot.classList.add("bg-emerald-500");
  statusText.textContent = "Connected";

  onValue(
    incidentsRef,
    (snapshot) => {
      const data = snapshot.val();
      renderIncidents(data);
    },
    (error) => {
      console.error("Database listener error:", error);
      statusDot.classList.remove("bg-emerald-500");
      statusDot.classList.add("bg-rose-500");
      statusText.textContent = "Disconnected";
    }
  );
}

// ── Render Incidents ────────────────────────────────────────────────────────
function renderIncidents(data) {
  if (!data) {
    incidentsList.innerHTML = "";
    emptyState.classList.remove("hidden");
    updateStats(0, 0, 0);
    return;
  }

  emptyState.classList.add("hidden");

  const entries = Object.entries(data).sort((a, b) => {
    const ta = a[1].created_at || "";
    const tb = b[1].created_at || "";
    return tb.localeCompare(ta);
  });

  let total = entries.length;
  let quarantined = 0;
  let resolved = 0;

  entries.forEach(([, v]) => {
    if (v.status === "QUARANTINED") quarantined++;
    else resolved++;
  });

  updateStats(total, quarantined, resolved);

  incidentsList.innerHTML = entries
    .map(([id, incident]) => buildIncidentCard(id, incident))
    .join("");

  // Attach action button listeners
  document.querySelectorAll("[data-action]").forEach((btn) => {
    btn.addEventListener("click", handleAction);
  });

  // Attach collapsible toggles
  document.querySelectorAll("[data-toggle]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = document.getElementById(btn.getAttribute("data-toggle"));
      if (target) target.classList.toggle("hidden");
      const arrow = btn.querySelector(".toggle-arrow");
      if (arrow) arrow.classList.toggle("rotate-90");
    });
  });
}

function updateStats(total, quarantined, resolved) {
  statTotal.textContent = total;
  statQuarantined.textContent = quarantined;
  statResolved.textContent = resolved;
}

// ── Plain English Explanations for Non-Technical Users ─────────────────────
function getThreatExplanation(threat, inc) {
  const t = (threat || "").toUpperCase();
  const heuristics = inc.heuristic_details || {};
  const threats = [];

  if (t === "OVERRIDE" || heuristics.has_override_triggers) {
    threats.push({
      badge: "AI Hijacking Attempt",
      icon: "🤖",
      title: "Prompt Injection (Instruction Override)",
      summary: "This document contains deceptive commands pretending to be system directives (such as 'Ignore previous instructions', 'reveal system prompt', or fake header markers like '### Instruction').",
      danger: "If approved raw, these hidden attacker commands will override Claude's safety guidelines and force Claude to act on behalf of the attacker rather than you.",
      recommendation: "Allow Sanitized"
    });
  }

  if (t === "EXFILTRATION" || heuristics.has_exfiltration_patterns) {
    threats.push({
      badge: "Data Leak & Tracking",
      icon: "🕵️",
      title: "Data Exfiltration (Webhook / External Beacon)",
      summary: "This document contains an external tracking image or link (e.g. webhook.site beacon) designed to silently send data out.",
      danger: "When Claude processes or renders this document, sensitive chat context, private tokens, or answers could be quietly leaked to an external third-party server.",
      recommendation: "Allow Sanitized or Reject"
    });
  }

  if (t === "JAILBREAK") {
    threats.push({
      badge: "Guardrail Bypass",
      icon: "🔓",
      title: "Safety Guardrail Bypass (Jailbreak)",
      summary: "This file attempts to coerce the AI into breaking out of its safety, ethical, and operational boundaries.",
      danger: "The AI could be manipulated into producing malicious code, revealing protected internal secrets, or bypassing system constraints.",
      recommendation: "Reject & Drop"
    });
  }

  if (heuristics.has_invisible_chars) {
    threats.push({
      badge: "Hidden Steganography",
      icon: "👻",
      title: "Invisible Unicode Characters",
      summary: "This file hides zero-width invisible characters that cannot be seen by human eyes on screen, but are read and parsed by AI models.",
      danger: "Attackers can hide secret instructions in plain sight that you cannot see, but Claude will quietly execute.",
      recommendation: "Allow Sanitized"
    });
  }

  if (threats.length === 0) {
    threats.push({
      badge: "Suspicious Pattern",
      icon: "⚠️",
      title: "Suspicious Document Pattern",
      summary: "This file contains flagged structural or semantic patterns that could pose an AI security risk.",
      danger: "Could cause unintended AI behavior or safety rule bypass if loaded uninspected.",
      recommendation: "Allow Sanitized"
    });
  }

  return threats;
}

// ── Build Incident Card HTML ────────────────────────────────────────────────
function buildIncidentCard(id, inc) {
  const risk = Math.round((inc.risk_score || 0) * 100);
  const severity = inc.severity || "LOW";
  const threat = (inc.threat_type || "none").toUpperCase();
  const status = inc.status || "QUARANTINED";
  const source = inc.source_filename || "inline content";
  const createdAt = inc.created_at
    ? new Date(inc.created_at).toLocaleString()
    : "—";

  const explanationItems = getThreatExplanation(threat, inc);
  const explanationCardsHTML = explanationItems
    .map(
      (item) => `
      <div class="bg-amber-50/80 border border-amber-200/90 rounded-xl p-3.5 text-xs text-slate-800 space-y-2 mb-2">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-1.5 font-bold text-amber-950">
            <span class="text-sm">${item.icon}</span>
            <span>${item.title}</span>
          </div>
          <span class="text-[10px] bg-amber-100 text-amber-900 border border-amber-200 font-semibold px-2 py-0.5 rounded-full">${item.badge}</span>
        </div>
        <div class="text-slate-700 leading-relaxed">
          <strong class="font-semibold text-slate-900">🔍 What is happening:</strong> ${item.summary}
        </div>
        <div class="text-rose-950 leading-relaxed bg-rose-50/80 p-2.5 rounded-lg border border-rose-200">
          <strong class="font-semibold text-rose-950">⚠️ Why it is harmful:</strong> ${item.danger}
        </div>
      </div>
    `
    )
    .join("");

  // Severity badge styles
  const severityStyles = {
    LOW: "bg-emerald-50 text-emerald-700 border border-emerald-200",
    MEDIUM: "bg-amber-50 text-amber-700 border border-amber-200",
    HIGH: "bg-rose-50 text-rose-700 border border-rose-200 font-semibold",
  };
  const badgeClass = severityStyles[severity] || severityStyles.LOW;

  // Status badge
  const statusStyles = {
    QUARANTINED: "bg-amber-50 text-amber-700 border border-amber-200",
    APPROVED_RAW: "bg-emerald-50 text-emerald-700 border border-emerald-200",
    APPROVED_SANITIZED: "bg-sky-50 text-sky-700 border border-sky-200",
    REJECTED: "bg-rose-50 text-rose-700 border border-rose-200",
  };
  const statusClass = statusStyles[status] || statusStyles.QUARANTINED;
  const statusLabel = status.replace(/_/g, " ");

  // Risk bar color
  let barColor = "bg-emerald-500";
  if (risk > 65) barColor = "bg-rose-500";
  else if (risk > 25) barColor = "bg-amber-500";

  // Excerpts
  const excerpts = inc.flagged_excerpts || [];
  const excerptHTML = excerpts
    .slice(0, 5)
    .map(
      (e) =>
        `<div class="bg-rose-50 border border-rose-100 rounded-lg px-3 py-2 text-xs text-rose-800 font-mono break-all">${escapeHtml(e.substring(0, 200))}</div>`
    )
    .join("");

  // Preview text
  const preview = inc.extracted_text_preview || "";

  // Action buttons (only for quarantined)
  const actionsHTML =
    status === "QUARANTINED"
      ? `
    <div class="mt-4 pt-4 border-t border-slate-100">
      <div class="flex items-center justify-between mb-3">
        <div>
          <span class="text-xs font-bold text-slate-900 uppercase tracking-wider">Take Action:</span>
          <span class="text-xs text-slate-500 ml-1.5">— Whichever you click immediately syncs with Claude Desktop:</span>
        </div>
        <span class="text-[11px] bg-emerald-100 text-emerald-800 font-semibold px-2 py-0.5 rounded-full border border-emerald-200 flex items-center gap-1">
          <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping"></span>
          Live Sync Active
        </span>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
        <!-- Allow Sanitized (Recommended) -->
        <div class="bg-amber-50/70 border border-amber-200/80 rounded-xl p-3 flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-xs font-bold text-amber-950 flex items-center gap-1">
                <span>🛡️</span> Allow Sanitized
              </span>
              <span class="text-[10px] bg-amber-200 text-amber-900 px-1.5 py-0.5 rounded font-bold uppercase tracking-wider">Recommended</span>
            </div>
            <p class="text-[11px] text-amber-900 leading-snug mb-3">
              Safely removes the malicious injection commands and tracking URLs, then releases the safe document text so Claude can analyze it.
            </p>
          </div>
          <button data-action="APPROVED_SANITIZED" data-id="${id}" class="w-full bg-amber-500 hover:bg-amber-600 text-white font-semibold text-xs py-2 px-3 rounded-lg shadow-sm transition-colors flex items-center justify-center gap-1.5 ring-2 ring-amber-300 ring-offset-1">
            <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Allow Sanitized
          </button>
        </div>

        <!-- Approve Raw -->
        <div class="bg-emerald-50/70 border border-emerald-200/80 rounded-xl p-3 flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-xs font-bold text-emerald-950 flex items-center gap-1">
                <span>🟢</span> Approve Raw
              </span>
              <span class="text-[10px] bg-rose-100 text-rose-800 px-1.5 py-0.5 rounded font-bold uppercase tracking-wider">Risky</span>
            </div>
            <p class="text-[11px] text-emerald-950 leading-snug mb-3">
              Releases the exact original file without changes. ⚠️ Dangerous: Claude will read the attack directives. Only for security testing.
            </p>
          </div>
          <button data-action="APPROVED_RAW" data-id="${id}" class="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-xs py-2 px-3 rounded-lg shadow-sm transition-colors flex items-center justify-center gap-1.5">
            <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            Approve Raw (Full Text)
          </button>
        </div>

        <!-- Reject & Drop -->
        <div class="bg-rose-50/70 border border-rose-200/80 rounded-xl p-3 flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-xs font-bold text-rose-950 flex items-center gap-1">
                <span>🔴</span> Reject &amp; Drop
              </span>
              <span class="text-[10px] bg-rose-200 text-rose-900 px-1.5 py-0.5 rounded font-bold uppercase tracking-wider">Block</span>
            </div>
            <p class="text-[11px] text-rose-900 leading-snug mb-3">
              Blocks the file completely and marks it as dropped. Claude will not read or process any part of this file.
            </p>
          </div>
          <button data-action="REJECTED" data-id="${id}" class="w-full bg-rose-600 hover:bg-rose-700 text-white font-semibold text-xs py-2 px-3 rounded-lg shadow-sm transition-colors flex items-center justify-center gap-1.5">
            <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            Reject &amp; Drop
          </button>
        </div>
      </div>
    </div>
  `
      : `
    <div class="mt-4 pt-3.5 border-t border-slate-100">
      <div class="flex items-center gap-2 text-xs text-slate-500">
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        Resolved ${inc.resolved_by ? "via " + inc.resolved_by : ""} ${inc.resolved_at ? "at " + new Date(inc.resolved_at).toLocaleString() : ""}
      </div>
    </div>
  `;

  return `
    <div class="bg-white border border-slate-200 shadow-sm rounded-xl p-5 hover:shadow-md transition-shadow">
      <!-- Header -->
      <div class="flex items-start justify-between gap-3 mb-3">
        <div class="flex items-center gap-2 min-w-0">
          <span class="inline-flex items-center justify-center w-8 h-8 rounded-lg ${status === "QUARANTINED" ? "bg-amber-100" : "bg-slate-100"}">
            ${status === "QUARANTINED" ? '<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-amber-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' : '<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-slate-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>'}
          </span>
          <div class="min-w-0">
            <p class="text-sm font-semibold text-slate-900 truncate">${escapeHtml(id)}</p>
            <p class="text-xs text-slate-500">${escapeHtml(source)} · ${createdAt}</p>
          </div>
        </div>
        <div class="flex items-center gap-2 flex-shrink-0">
          <span class="inline-flex items-center text-xs px-2 py-0.5 rounded-full ${badgeClass}">${severity}</span>
          <span class="inline-flex items-center text-xs px-2 py-0.5 rounded-full ${statusClass}">${statusLabel}</span>
        </div>
      </div>

      <!-- Risk Bar -->
      <div class="mb-3">
        <div class="flex items-center justify-between text-xs text-slate-500 mb-1">
          <span>Risk Score</span>
          <span class="font-medium text-slate-700">${risk}%</span>
        </div>
        <div class="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
          <div class="${barColor} h-full rounded-full transition-all duration-500" style="width: ${risk}%"></div>
        </div>
      </div>

      <!-- Threat Type Badge -->
      <div class="flex items-center gap-1.5 text-xs text-slate-600 mb-3">
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Threat Detected: <span class="font-semibold text-slate-800">${threat}</span>
      </div>

      <!-- Plain English Security Explanation Boxes (For Non-Technical Users) -->
      ${explanationCardsHTML}

      <!-- Collapsible Excerpts -->
      ${
        excerpts.length > 0
          ? `
        <button data-toggle="excerpts-${id}" class="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-700 transition-colors mb-2">
          <svg class="w-3 h-3 toggle-arrow transition-transform" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
          Flagged Excerpts (${excerpts.length})
        </button>
        <div id="excerpts-${id}" class="hidden space-y-1.5 mb-2">
          ${excerptHTML}
        </div>
      `
          : ""
      }

      <!-- Collapsible Payload Preview -->
      ${
        preview
          ? `
        <button data-toggle="preview-${id}" class="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-700 transition-colors mb-2">
          <svg class="w-3 h-3 toggle-arrow transition-transform" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
          Payload Preview
        </button>
        <div id="preview-${id}" class="hidden">
          <div class="bg-slate-100 border border-slate-200 font-mono text-xs text-slate-800 rounded-lg p-3 max-h-40 overflow-y-auto break-all">${escapeHtml(preview.substring(0, 1000))}</div>
        </div>
      `
          : ""
      }

      <!-- Actions -->
      ${actionsHTML}
    </div>
  `;
}

// ── Action Handler ──────────────────────────────────────────────────────────
async function handleAction(e) {
  const btn = e.currentTarget;
  const action = btn.getAttribute("data-action");
  const id = btn.getAttribute("data-id");

  if (!confirm(`Are you sure you want to ${action.replace(/_/g, " ")} incident ${id}?`)) {
    return;
  }

  btn.disabled = true;
  btn.innerHTML = `
    <svg class="animate-spin w-3.5 h-3.5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path>
    </svg>
    Processing…
  `;

  try {
    const incidentRef = ref(db, `incidents/${id}`);
    await update(incidentRef, {
      status: action,
      resolved_by: "WEB_DASHBOARD",
      resolved_at: serverTimestamp(),
    });
  } catch (err) {
    console.error("Update failed:", err);
    alert("Failed to update incident. Check console for details.");
    btn.disabled = false;
  }
}

// ── Utility ─────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  const div = document.createElement("div");
  div.appendChild(document.createTextNode(str || ""));
  return div.innerHTML;
}
