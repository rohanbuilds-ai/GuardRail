/**
 * GuardRail Security Analyst Workspace — Client Logic
 */

let selectedIncidentId = "INC-001";
let allIncidents = [];

document.addEventListener("DOMContentLoaded", () => {
  fetchHealth();
  fetchIncidents();
  setupEventListeners();
  initEvaluationLab();
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

/**
 * -----------------------------------------------------------------------------
 * Phase 5: Red-Team Evaluation Lab Client Logic
 * -----------------------------------------------------------------------------
 */

let allScenarios = [];
let latestEvaluationData = null;

function initEvaluationLab() {
  const tabWorkspaceBtn = document.getElementById("tabWorkspaceBtn");
  const tabEvalBtn = document.getElementById("tabEvalBtn");
  const workspaceView = document.getElementById("workspaceView");
  const evaluationView = document.getElementById("evaluationView");

  if (tabWorkspaceBtn && tabEvalBtn) {
    tabWorkspaceBtn.addEventListener("click", () => {
      workspaceView.classList.remove("hidden");
      evaluationView.classList.add("hidden");
      tabWorkspaceBtn.classList.add("text-emerald-400", "bg-slate-800/80");
      tabWorkspaceBtn.classList.remove("text-slate-400");
      tabEvalBtn.classList.remove("text-rose-400", "bg-slate-800/80");
      tabEvalBtn.classList.add("text-slate-400");
    });

    tabEvalBtn.addEventListener("click", () => {
      evaluationView.classList.remove("hidden");
      workspaceView.classList.add("hidden");
      tabEvalBtn.classList.add("text-rose-400", "bg-slate-800/80");
      tabEvalBtn.classList.remove("text-slate-400");
      tabWorkspaceBtn.classList.remove("text-emerald-400", "bg-slate-800/80");
      tabWorkspaceBtn.classList.add("text-slate-400");

      if (allScenarios.length === 0) {
        fetchScenarios();
      }
    });
  }

  // Filters
  const categoryFilter = document.getElementById("evalCategoryFilter");
  const typeFilter = document.getElementById("evalTypeFilter");
  if (categoryFilter) categoryFilter.addEventListener("change", renderScenarioTable);
  if (typeFilter) typeFilter.addEventListener("change", renderScenarioTable);

  // Run Benchmark
  const runBtn = document.getElementById("runEvalSuiteBtn");
  if (runBtn) {
    runBtn.addEventListener("click", runEvaluationBenchmark);
  }

  // Exports
  const exportJsonBtn = document.getElementById("exportJsonBtn");
  const exportCsvBtn = document.getElementById("exportCsvBtn");
  if (exportJsonBtn) {
    exportJsonBtn.addEventListener("click", () => {
      window.location.href = "/api/evaluations/export/json";
    });
  }
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener("click", () => {
      window.location.href = "/api/evaluations/export/csv";
    });
  }

  // Modal Dismiss
  const closeModalBtn = document.getElementById("closeModalBtn");
  const modalDismissBtn = document.getElementById("modalDismissBtn");
  const modal = document.getElementById("scenarioModal");
  if (closeModalBtn) closeModalBtn.addEventListener("click", () => modal.classList.add("hidden"));
  if (modalDismissBtn) modalDismissBtn.addEventListener("click", () => modal.classList.add("hidden"));
  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.classList.add("hidden");
    });
  }

  // Check if previous run exists on server
  fetchLatestEvaluation();
}

async function fetchScenarios() {
  const tbody = document.getElementById("evaluationTableBody");
  try {
    const res = await fetch("/api/scenarios");
    if (!res.ok) throw new Error("Failed to load evaluation scenarios");
    allScenarios = await res.json();
    document.getElementById("scenarioCountBadge").textContent = `${allScenarios.length} Scenarios`;
    renderScenarioTable();
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="py-4 text-center text-rose-400">Error loading scenarios: ${err.message}</td></tr>`;
  }
}

async function fetchLatestEvaluation() {
  try {
    const res = await fetch("/api/evaluations/latest");
    if (res.ok) {
      latestEvaluationData = await res.json();
      updateMetricsDisplay(latestEvaluationData.baseline_metrics, latestEvaluationData.hardened_metrics);
      const badge = document.getElementById("evalStatusBadge");
      if (badge) {
        badge.textContent = `Completed (${latestEvaluationData.run_id})`;
        badge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800";
      }
      if (allScenarios.length === 0) {
        await fetchScenarios();
      } else {
        renderScenarioTable();
      }
    }
  } catch (err) {
    // No previous run, normal state
  }
}

async function runEvaluationBenchmark() {
  const runBtn = document.getElementById("runEvalSuiteBtn");
  const statusBadge = document.getElementById("evalStatusBadge");
  const originalHTML = runBtn.innerHTML;

  runBtn.disabled = true;
  runBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin text-xs"></i><span>Running (30 Scenarios)...</span>`;
  statusBadge.textContent = "Executing...";
  statusBadge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 animate-pulse";

  try {
    const res = await fetch("/api/evaluations/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Server error: ${res.status}`);
    }

    latestEvaluationData = await res.json();
    updateMetricsDisplay(latestEvaluationData.baseline_metrics, latestEvaluationData.hardened_metrics);
    statusBadge.textContent = `Completed (${latestEvaluationData.run_id})`;
    statusBadge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800";

    renderScenarioTable();
  } catch (err) {
    alert(`Evaluation benchmark failed: ${err.message}`);
    statusBadge.textContent = "Failed";
    statusBadge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800";
  } finally {
    runBtn.disabled = false;
    runBtn.innerHTML = originalHTML;
  }
}

function updateMetricsDisplay(baseline, hardened) {
  if (!baseline || !hardened) return;

  const updateCard = (elId, metric) => {
    const el = document.getElementById(elId);
    if (el) {
      el.textContent = `${metric.percentage}% (${metric.numerator}/${metric.denominator})`;
    }
  };

  updateCard("metricAsrBaseline", baseline.attack_success_rate);
  updateCard("metricAsrHardened", hardened.attack_success_rate);

  updateCard("metricDsrBaseline", baseline.defense_success_rate);
  updateCard("metricDsrHardened", hardened.defense_success_rate);

  updateCard("metricFbrBaseline", baseline.false_block_rate);
  updateCard("metricFbrHardened", hardened.false_block_rate);

  updateCard("metricClrBaseline", baseline.canary_leakage_rate);
  updateCard("metricClrHardened", hardened.canary_leakage_rate);

  updateCard("metricCirBaseline", baseline.citation_integrity_rate);
  updateCard("metricCirHardened", hardened.citation_integrity_rate);
}

function renderScenarioTable() {
  const tbody = document.getElementById("evaluationTableBody");
  const categoryFilter = document.getElementById("evalCategoryFilter") ? document.getElementById("evalCategoryFilter").value : "all";
  const typeFilter = document.getElementById("evalTypeFilter") ? document.getElementById("evalTypeFilter").value : "all";

  let filtered = allScenarios.filter((sc) => {
    if (categoryFilter !== "all" && sc.category !== categoryFilter) return false;
    if (typeFilter === "adversarial" && !sc.is_adversarial) return false;
    if (typeFilter === "benign" && sc.is_adversarial) return false;
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="py-6 text-center text-slate-500">No scenarios match the selected filters.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  filtered.forEach((sc) => {
    // Find baseline & hardened results from latestEvaluationData if available
    let baselineRes = null;
    let hardenedRes = null;
    if (latestEvaluationData && latestEvaluationData.scenario_results) {
      baselineRes = latestEvaluationData.scenario_results.find(
        (r) => r.scenario_id === sc.id && r.execution_mode === "baseline"
      );
      hardenedRes = latestEvaluationData.scenario_results.find(
        (r) => r.scenario_id === sc.id && r.execution_mode === "hardened"
      );
    }

    const tr = document.createElement("tr");
    tr.className = "hover:bg-slate-800/40 transition cursor-pointer";
    tr.addEventListener("click", () => openScenarioModal(sc.id));

    const typeBadge = sc.is_adversarial
      ? `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950/60 text-rose-400 border border-rose-800/80">Adversarial</span>`
      : `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950/60 text-emerald-400 border border-emerald-800/80">Benign</span>`;

    const formatOutcomeBadge = (res, mode) => {
      if (!res) {
        return `<span class="text-slate-500 font-mono text-[11px]">--</span>`;
      }
      if (res.is_false_block) {
        return `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-400 border border-amber-800 font-semibold">FALSE BLOCK</span>`;
      }
      if (res.is_adversarial) {
        if (res.attack_succeeded) {
          return `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-400 border border-rose-800 font-semibold">ATTACK SUCCEEDED</span>`;
        }
        return `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 font-semibold">DEFENDED</span>`;
      }
      if (res.passed) {
        return `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 font-semibold">PASSED</span>`;
      }
      return `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-400 border border-rose-800 font-semibold">FAILED</span>`;
    };

    tr.innerHTML = `
      <td class="py-3 px-4 font-mono font-bold text-slate-200">${sc.id}</td>
      <td class="py-3 px-4">
        <div class="font-medium text-slate-100">${sc.name}</div>
        <div class="text-[11px] text-slate-400 line-clamp-1">${sc.description}</div>
      </td>
      <td class="py-3 px-4 font-mono text-slate-300">${sc.category}</td>
      <td class="py-3 px-4">${typeBadge}</td>
      <td class="py-3 px-4">${formatOutcomeBadge(baselineRes, "baseline")}</td>
      <td class="py-3 px-4">${formatOutcomeBadge(hardenedRes, "hardened")}</td>
      <td class="py-3 px-4 text-right">
        <button class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-[10px] transition border border-slate-700">
          Details &rarr;
        </button>
      </td>
    `;

    tbody.appendChild(tr);
  });
}

function openScenarioModal(scenarioId) {
  const sc = allScenarios.find((s) => s.id === scenarioId);
  if (!sc) return;

  const modal = document.getElementById("scenarioModal");
  document.getElementById("modalScenarioId").textContent = sc.id;
  document.getElementById("modalScenarioName").textContent = sc.name;
  document.getElementById("modalDescription").textContent = sc.description;
  document.getElementById("modalQuery").textContent = sc.query;
  document.getElementById("modalExpected").textContent = sc.expected_security_property;

  const baselineOutcomeEl = document.getElementById("modalBaselineOutcome");
  const hardenedOutcomeEl = document.getElementById("modalHardenedOutcome");

  if (latestEvaluationData && latestEvaluationData.scenario_results) {
    const bRes = latestEvaluationData.scenario_results.find(
      (r) => r.scenario_id === sc.id && r.execution_mode === "baseline"
    );
    const hRes = latestEvaluationData.scenario_results.find(
      (r) => r.scenario_id === sc.id && r.execution_mode === "hardened"
    );

    if (bRes) {
      baselineOutcomeEl.innerHTML = `
        <div class="space-y-1">
          <div><strong class="text-slate-300">Status:</strong> ${bRes.passed ? "PASSED" : (bRes.attack_succeeded ? "ATTACK SUCCEEDED" : "FAILED")}</div>
          <div><strong class="text-slate-300">Latency:</strong> ${bRes.execution_time_ms} ms</div>
          <div><strong class="text-slate-300">Canary Leaked:</strong> ${bRes.canary_leaked ? "YES" : "NO"}</div>
          <div><strong class="text-slate-300">Note:</strong> ${bRes.outcome_note}</div>
        </div>
      `;
    } else {
      baselineOutcomeEl.textContent = "Not evaluated in baseline mode.";
    }

    if (hRes) {
      hardenedOutcomeEl.innerHTML = `
        <div class="space-y-1">
          <div><strong class="text-slate-300">Status:</strong> ${hRes.defense_succeeded ? "DEFENDED" : (hRes.is_false_block ? "FALSE BLOCK" : "PASSED")}</div>
          <div><strong class="text-slate-300">Latency:</strong> ${hRes.execution_time_ms} ms</div>
          <div><strong class="text-slate-300">Canary Leaked:</strong> ${hRes.canary_leaked ? "YES" : "NO"}</div>
          <div><strong class="text-slate-300">Alerts:</strong> ${hRes.security_alerts.length > 0 ? hRes.security_alerts.join("; ") : "None"}</div>
          <div><strong class="text-slate-300">Note:</strong> ${hRes.outcome_note}</div>
        </div>
      `;
    } else {
      hardenedOutcomeEl.textContent = "Not evaluated in hardened mode.";
    }
  } else {
    baselineOutcomeEl.textContent = "Run the evaluation suite to see baseline trace.";
    hardenedOutcomeEl.textContent = "Run the evaluation suite to see hardened trace.";
  }

  modal.classList.remove("hidden");
}
