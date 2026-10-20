/**
 * GuardRail Security Analyst Workspace — Client Logic
 */

let selectedIncidentId = "INC-001";
let allIncidents = [];

document.addEventListener("DOMContentLoaded", () => {
  fetchHealth();
  fetchIncidents();
  setupEventListeners();
});

async function fetchHealth() {
  try {
    const res = await fetch("/health");
    if (!res.ok) return;
    const data = await res.json();
    const providerBadge = document.getElementById("providerBadge");
    if (providerBadge) {
      providerBadge.textContent = `${data.provider.toUpperCase()} (Offline)`;
    }
  } catch (err) {
    console.warn("Health check unreachable:", err);
  }
}

async function fetchIncidents() {
  const container = document.getElementById("incidentList");
  try {
    const res = await fetch("/api/incidents");
    if (!res.ok) throw new Error("Failed to load incidents");
    allIncidents = await res.json();

    document.getElementById("incidentCountBadge").textContent = `${allIncidents.length} loaded`;

    container.innerHTML = "";
    allIncidents.forEach((inc) => {
      const card = createIncidentCard(inc);
      container.appendChild(card);
    });

    // Select the first incident by default
    if (allIncidents.length > 0) {
      selectIncident(allIncidents[0].id);
    }
  } catch (err) {
    container.innerHTML = `<div class="p-3 bg-red-950/40 border border-red-800 rounded-lg text-xs text-red-300">Error loading incidents: ${err.message}</div>`;
  }
}

function createIncidentCard(inc) {
  const div = document.createElement("div");
  div.id = `card-${inc.id}`;
  div.className =
    "p-3 rounded-lg border border-slate-800 bg-slate-900/60 hover:border-slate-700 cursor-pointer transition flex flex-col space-y-1.5";

  const severityColors = {
    critical: "bg-red-950 text-red-400 border-red-800",
    high: "bg-orange-950 text-orange-400 border-orange-800",
    medium: "bg-amber-950 text-amber-400 border-amber-800",
    low: "bg-blue-950 text-blue-400 border-blue-800",
  };
  const badgeClass = severityColors[inc.severity] || "bg-slate-800 text-slate-300";

  div.innerHTML = `
    <div class="flex items-center justify-between">
      <span class="text-xs font-mono font-bold text-slate-200">${inc.id}</span>
      <span class="text-[10px] uppercase font-mono px-2 py-0.5 rounded border ${badgeClass}">${inc.severity}</span>
    </div>
    <h3 class="text-xs font-medium text-slate-300 line-clamp-1">${inc.title}</h3>
    <p class="text-[11px] text-slate-500 line-clamp-2">${inc.description}</p>
    <div class="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-800/60">
      <span>Tier: <span class="text-slate-400 font-mono">${inc.sensitivity_tier}</span></span>
      <span>${inc.created_at.split("T")[0]}</span>
    </div>
  `;

  div.addEventListener("click", () => selectIncident(inc.id));
  return div;
}

function selectIncident(id) {
  selectedIncidentId = id;

  // Highlight selected card
  allIncidents.forEach((inc) => {
    const el = document.getElementById(`card-${inc.id}`);
    if (el) {
      if (inc.id === id) {
        el.classList.add("border-emerald-500/80", "bg-emerald-950/20");
        el.classList.remove("border-slate-800", "bg-slate-900/60");
      } else {
        el.classList.remove("border-emerald-500/80", "bg-emerald-950/20");
        el.classList.add("border-slate-800", "bg-slate-900/60");
      }
    }
  });

  const tag = document.getElementById("selectedIncidentTag");
  if (tag) tag.textContent = `Target: ${id}`;
}

function setupEventListeners() {
  // Quick Prompt buttons
  document.querySelectorAll(".quick-prompt-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const prompt = btn.getAttribute("data-prompt");
      const textarea = document.getElementById("queryInput");
      if (textarea) textarea.value = prompt;
    });
  });

  // Toggle tool trace drawer
  const toggleBtn = document.getElementById("toggleTraceBtn");
  const traceContent = document.getElementById("traceContent");
  const caret = document.getElementById("traceCaret");

  if (toggleBtn && traceContent) {
    toggleBtn.addEventListener("click", () => {
      const isHidden = traceContent.classList.contains("hidden");
      if (isHidden) {
        traceContent.classList.remove("hidden");
        caret.classList.add("rotate-180");
      } else {
        traceContent.classList.add("hidden");
        caret.classList.remove("rotate-180");
      }
    });
  }

  // Investigation form submission
  const form = document.getElementById("investigateForm");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      await runInvestigation();
    });
  }
}

async function runInvestigation() {
  const query = document.getElementById("queryInput").value.trim();
  const analystRole = document.getElementById("analystRoleSelect").value;
  const executionMode = document.getElementById("executionModeSelect")
    ? document.getElementById("executionModeSelect").value
    : "hardened";
  const submitBtn = document.getElementById("submitBtn");
  const resultsCard = document.getElementById("resultsCard");
  const emptyStateCard = document.getElementById("emptyStateCard");

  if (!query) return;

  // Loading state
  const originalBtnHTML = submitBtn.innerHTML;
  submitBtn.disabled = true;
  submitBtn.innerHTML = `
    <i class="fa-solid fa-spinner fa-spin text-xs"></i>
    <span>Analyzing Evidence...</span>
  `;

  try {
    const response = await fetch("/api/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        incident_id: selectedIncidentId,
        query: query,
        analyst_role: analystRole,
        execution_mode: executionMode,
      }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Server error: ${response.status}`);
    }

    const data = await response.json();
    displayResults(data);
  } catch (err) {
    alert(`Investigation failed: ${err.message}`);
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = originalBtnHTML;
  }
}

function displayResults(data) {
  const resultsCard = document.getElementById("resultsCard");
  const emptyStateCard = document.getElementById("emptyStateCard");

  if (emptyStateCard) emptyStateCard.classList.add("hidden");
  if (resultsCard) resultsCard.classList.remove("hidden");

  // Summary
  document.getElementById("findingsSummary").textContent = data.summary;

  // Timeline list
  const timelineList = document.getElementById("timelineList");
  timelineList.innerHTML = "";
  if (data.timeline_findings && data.timeline_findings.length > 0) {
    data.timeline_findings.forEach((finding) => {
      const li = document.createElement("li");
      li.className = "flex items-start space-x-2";
      li.innerHTML = `
        <i class="fa-solid fa-angle-right text-emerald-400 text-xs mt-1"></i>
        <span>${finding}</span>
      `;
      timelineList.appendChild(li);
    });
  } else {
    timelineList.innerHTML = `<li class="text-slate-500 italic">No specific timeline points identified.</li>`;
  }

  // Root cause
  document.getElementById("rootCauseText").textContent = data.root_cause_analysis;

  // Uncertainty & Limitations
  const uncertaintyEl = document.getElementById("uncertaintyText");
  if (uncertaintyEl) {
    uncertaintyEl.textContent =
      data.uncertainty_and_limitations ||
      "Analysis bounded by synthetic logs and available documentation.";
  }

  // Confidence & Mode
  const confBadge = document.getElementById("confidenceBadge");
  confBadge.textContent = `${data.confidence} Confidence`;

  // Mode badge styling based on hardened vs baseline
  const modeBadge = document.getElementById("executionModeBadge");
  if (data.execution_mode === "hardened") {
    modeBadge.className = "text-xs font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 px-2 py-1 rounded";
    modeBadge.textContent = "Mode: HARDENED (SECURE)";
  } else {
    modeBadge.className = "text-xs font-mono bg-amber-950 text-amber-400 border border-amber-800 px-2 py-1 rounded";
    modeBadge.textContent = "Mode: BASELINE (VULNERABLE DEMO)";
  }

  // Security Alerts display
  const alertsContainer = document.getElementById("securityAlertsContainer");
  if (alertsContainer) {
    alertsContainer.innerHTML = "";
    if (data.security_alerts && data.security_alerts.length > 0) {
      alertsContainer.classList.remove("hidden");
      data.security_alerts.forEach((alertMsg) => {
        const alertDiv = document.createElement("div");
        alertDiv.className =
          "p-2.5 rounded-lg bg-red-950/40 border border-red-800/80 text-red-300 text-xs flex items-start space-x-2";
        alertDiv.innerHTML = `
          <i class="fa-solid fa-shield-virus text-red-400 text-xs mt-0.5"></i>
          <span class="font-mono">${alertMsg}</span>
        `;
        alertsContainer.appendChild(alertDiv);
      });
    } else {
      alertsContainer.classList.add("hidden");
    }
  }

  // Cited records
  const citedContainer = document.getElementById("citedRecordsContainer");
  citedContainer.innerHTML = "";
  if (data.cited_records && data.cited_records.length > 0) {
    data.cited_records.forEach((recId) => {
      const span = document.createElement("span");
      span.className =
        "px-2 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800 text-xs font-mono font-medium flex items-center space-x-1";
      span.innerHTML = `<i class="fa-solid fa-file-lines text-[10px]"></i><span>${recId}</span>`;
      citedContainer.appendChild(span);
    });
  } else {
    citedContainer.innerHTML = `<span class="text-xs text-slate-500 italic">No explicit records cited.</span>`;
  }

  // Tool executions trace
  const toolCountEl = document.getElementById("toolCount");
  const traceContent = document.getElementById("traceContent");
  toolCountEl.textContent = data.tool_executions ? data.tool_executions.length : 0;
  traceContent.innerHTML = "";

  if (data.tool_executions && data.tool_executions.length > 0) {
    data.tool_executions.forEach((tool, idx) => {
      const traceCard = document.createElement("div");
      traceCard.className = "p-3 rounded-lg bg-dark-950 border border-slate-800 text-xs space-y-2";
      traceCard.innerHTML = `
        <div class="flex items-center justify-between font-mono">
          <span class="text-emerald-400 font-semibold">#${idx + 1} ${tool.tool_name}</span>
          <span class="px-1.5 py-0.5 rounded text-[10px] uppercase ${
            tool.status === "success"
              ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
              : "bg-red-950 text-red-400 border border-red-800"
          }">${tool.status}</span>
        </div>
        <div class="text-slate-400">
          <span class="text-slate-500">Arguments:</span>
          <code class="text-slate-300 bg-slate-900 px-1.5 py-0.5 rounded ml-1">${JSON.stringify(
            tool.arguments
          )}</code>
        </div>
        <div class="text-slate-400">
          <span class="text-slate-500">Summary:</span>
          <span class="text-slate-300 ml-1">${tool.result_summary}</span>
        </div>
      `;
      traceContent.appendChild(traceCard);
    });
  } else {
    traceContent.innerHTML = `<div class="text-slate-500 italic p-2">No tools were invoked during this investigation.</div>`;
  }
}
