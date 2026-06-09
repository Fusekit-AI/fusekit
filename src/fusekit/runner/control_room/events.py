"""Control-room browser event script."""

from __future__ import annotations

import json

from fusekit.runner.gate_guidance import gate_guidance_payload

_GATE_GUIDANCE_JSON = (
    json.dumps(
        gate_guidance_payload(),
        ensure_ascii=True,
        separators=(",", ":"),
    )
    .replace("<", "\\u003c")
    .replace(">", "\\u003e")
    .replace("&", "\\u0026")
)

SCRIPT = r"""
const initialJob = JSON.parse(document.getElementById("job-data").textContent);
const gateGuidanceData = __GATE_GUIDANCE_JSON__;

const labels = {
  created: "Created",
  pending: "Pending",
  running: "Running",
  waiting: "Human gate",
  done: "Done",
  failed: "Needs repair",
  skipped: "Skipped",
  passed: "Passed",
  repairing: "Repairing",
  needs_human_gate: "Needs human gate",
  resume_requested: "Retrying gate",
};

function label(status) {
  return labels[status] || String(status || "unknown").replaceAll("_", " ");
}

function stepDetail(step) {
  return publicCopy(step?.detail || "Queued and ready for the worker.");
}

function publicCopy(value) {
  let text = String(value || "");
  const replacements = [
    [
      "paste it into FuseKit's " + "hidden prompt",
      "copy it inside the VM browser, then click the matching Capture from VM clipboard button",
    ],
    [
      "paste into FuseKit's " + "hidden prompt",
      "copy inside the VM browser, then click the matching Capture from VM clipboard button",
    ],
    ["hidden Cloud Shell prompts", "VM clipboard Capture buttons"],
    ["hidden prompts/env handoff", "VM clipboard Capture fallback"],
    ["hidden prompts", "VM clipboard Capture fallback"],
    ["hidden " + "prompt", "VM clipboard Capture"],
  ];
  for (const [oldText, newText] of replacements) {
    text = text.replaceAll(oldText, newText);
  }
  return text;
}

function publicTarget(value) {
  let text = publicCopy(value);
  const patterns = [
    /sk-[A-Za-z0-9_-]{12,}/g,
    /sk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}/g,
    /pk_(?:live|test|prod)_[A-Za-z0-9_-]{12,}/g,
    /gh[pousr]_[A-Za-z0-9_]{12,}/g,
    /github_pat_[A-Za-z0-9_]{12,}/g,
    /whsec_[A-Za-z0-9_]{12,}/g,
    /rk_[A-Za-z0-9_-]{12,}/g,
    /re_[A-Za-z0-9_-]{12,}/g,
    /plaid-[A-Za-z0-9_-]{12,}/g,
    /eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}/g,
    /\b[A-Za-z0-9_-]{36,}\b/g,
  ];
  for (const pattern of patterns) {
    text = text.replace(pattern, "[redacted]");
  }
  text = text.replace(
    /([?&](?:access_token|auth_token|token|api_key|key|secret|code|password|passphrase|signature)=)[^&#\s]+/gi,
    "$1[redacted]",
  );
  return text;
}

function statusCounts(steps) {
  const counts = { running: 0, waiting: 0, done: 0, failed: 0 };
  for (const step of steps || []) {
    if (step.status === "skipped") counts.done += 1;
    else if (counts[step.status] !== undefined) counts[step.status] += 1;
  }
  return counts;
}

function activeGate(job) {
  return (job.gates || []).find((gate) =>
    ["waiting", "resurfaced", "resume_requested"].includes(gate.status));
}

function gateStateErrorStep(job) {
  if (!job.gate_state_error) return null;
  return {
    id: "gate.state.error",
    label: "Gate state needs repair",
    status: "failed",
    detail: job.gate_state_error,
  };
}

function gateStep(gate) {
  if (!gate) return null;
  const retrying = gate.status === "resume_requested";
  return {
    id: gate.id || "provider.gate",
    label: retrying
      ? `${gate.provider || "Provider"} gate is being rechecked`
      : `${gate.provider || "Provider"} needs your approval`,
    status: retrying ? "running" : "waiting",
    detail: retrying
      ? gateRetryDetail(gate)
      : gate.reason || "A provider-created human gate is waiting.",
    provider: gate.provider || "",
    resume_url: gate.resume_url || "",
    classification: gate.classification || "",
    target: gate.target || "",
    follow_steps: gate.follow_steps || [],
    next_action: gate.next_action || "",
    resume_hint: gate.resume_hint || "",
    attempts: gate.attempts || 0,
    captured_targets: gate.captured_targets || [],
    updated_at: gate.updated_at,
  };
}

function gateRetryDetail(gate) {
  const nextAction = String(gate.next_action || "").trim();
  if (nextAction) return nextAction;
  const classification = String(gate.classification || "").toLowerCase();
  const provider = String(gate.provider || "").toLowerCase();
  if (classification === "dns-approval" || provider === "dns") {
    return "FuseKit is applying the approved DNS records now.";
  }
  if (classification === "setup-approval" || provider === "fusekit") {
    return "FuseKit is continuing with the approved setup plan now.";
  }
  return "You marked this step finished. FuseKit is retrying provider verification now.";
}

function progress(job) {
  const steps = job.steps || [];
  const total = Math.max(steps.length, 1);
  const done = steps.filter((step) => ["done", "skipped"].includes(step.status)).length;
  return { done, total: steps.length, percent: Math.round((done / total) * 100) };
}

function currentStep(job) {
  const gateError = gateStateErrorStep(job);
  if (gateError) return gateError;
  const gate = gateStep(activeGate(job));
  if (gate) return gate;
  for (const status of ["failed", "waiting", "running"]) {
    const active = (job.steps || []).find((step) => step.status === status);
    if (active) return active;
  }
  return (job.steps || []).find((step) => step.status === "pending") || (job.steps || []).at(-1);
}

function nextStep(job, current) {
  if (!current) return null;
  const steps = job.steps || [];
  const index = steps.findIndex((step) => step.id === current.id);
  return steps.slice(index + 1).find((step) => !["done", "skipped"].includes(step.status));
}

function focusKicker(step) {
  if (!step) return "Current focus";
  if (step.status === "waiting") return "Human gate";
  if (step.status === "failed") return "Repair needed";
  if (step.status === "running") return "Now running";
  return "Up next";
}

function mascotState(step, job) {
  if (step?.id === "detonate.workspace") return "detonate";
  if (job.status === "done") return "done";
  if (isPrivacyStep(step)) return "privacy";
  if (step?.status === "waiting") return "gate";
  if (step?.status === "failed") return "repair";
  if (step?.id?.includes("verify")) return "verify";
  if (["provision", "bootstrap", "upload", "setup"].some((part) => step?.id?.includes(part))) {
    return "working";
  }
  return "launch";
}

function mascotCaption(state) {
  return {
    launch: "packing the clean-room suitcase",
    working: "tightening the little launch bolts",
    gate: "waiting politely with a tiny access badge",
    privacy: "covering his eyes while secrets stay private",
    verify: "checking the live app with a frosty magnifier",
    repair: "patching the route with a tiny wrench",
    detonate: "melting away the worker state",
    done: "celebrating with a snow-safe high five",
  }[state] || "packing the clean-room suitcase";
}

const privacyStepSignals = [
  "api key",
  "api-key",
  "captcha",
  "credential",
  "hidden " + "prompt",
  "mfa",
  "passkey",
  "passphrase",
  "password",
  "payment",
  "private key",
  "secret",
  "token",
  "vault",
];

function isPrivacyStep(step) {
  if (!step || !["waiting", "running"].includes(step.status)) return false;
  const text = `${step.id || ""} ${step.label || ""} ${step.detail || ""}`.toLowerCase();
  return privacyStepSignals.some((signal) => text.includes(signal));
}

function inferGateProvider(text) {
  const lower = String(text || "").toLowerCase();
  for (const provider of Object.keys(gateGuidanceData.providers || {})) {
    if (lower.includes(provider)) return provider;
  }
  if (lower.includes("oracle") || lower.includes("cloud shell")) return "oci";
  return "generic";
}

function gateGuidance(provider) {
  return (gateGuidanceData.providers || {})[provider] || gateGuidanceData.generic;
}

function renderGateHelp(step) {
  if (!step) return "";
  const retrying = isRetryingGateStep(step);
  if (step.status !== "waiting" && !retrying) return "";
  const provider = String(step.provider || "").trim().toLowerCase() ||
    inferGateProvider(`${step.id} ${step.label} ${step.detail}`);
  const guidance = gateGuidance(provider);
  if (retrying) {
    const classification = step.classification
      ? [
          `<span class="gate-classification">`,
          `${escapeHtml(step.classification.replaceAll("_", " "))}</span>`,
        ].join("")
      : "";
    const nextAction = publicCopy(step.next_action || "").trim();
    const resumeHint = publicCopy(step.resume_hint || "").trim();
    const nextBlock = nextAction || resumeHint
      ? [
          `<div class="gate-next">`,
          `<strong>Next</strong><p>${escapeHtml(nextAction)}</p>`,
          `<em>${escapeHtml(resumeHint)}</em>`,
          `</div>`,
        ].join("")
      : "";
    return `
      <div class="gate-help gate-rechecking">
        <span>FuseKit is rechecking now</span>${classification}
        <strong>${escapeHtml(step.label || guidance.title)}</strong>
        <p>${escapeHtml(stepDetail(step))}</p>
        <em>${escapeHtml(publicCopy(guidance.reassurance))}</em>
        ${nextBlock}
      </div>
    `;
  }
  const followSteps = Array.isArray(step.follow_steps) && step.follow_steps.length
    ? step.follow_steps
    : guidance.actions;
  const resumeLink = step.resume_url && step.id
    ? [
        `<button class="gate-link" type="button" `,
        `data-gate-open="${escapeAttr(step.id)}">Open provider gate in VM</button>`,
      ].join("")
    : "";
  const attempts = step.attempts
    ? [
        `<span class="gate-attempts">Resurfaced ${escapeHtml(String(step.attempts))}`,
        ` time${step.attempts === 1 ? "" : "s"}</span>`,
      ].join("")
    : "";
  const meta = resumeLink || attempts
    ? `<div class="gate-meta">${resumeLink}${attempts}</div>`
    : "";
  const classification = step.classification
    ? [
        `<span class="gate-classification">`,
        `${escapeHtml(step.classification.replaceAll("_", " "))}</span>`,
      ].join("")
    : "";
  const target = step.target
    ? [
        `<p class="gate-target">Snowman highlighted: `,
        `<strong>${escapeHtml(publicTarget(step.target))}</strong></p>`,
      ].join("")
    : "";
  const hasCaptureTargets = captureTargets(step.target).length > 0;
  const resumeButton = step.id && !hasCaptureTargets
    ? [
        `<button class="gate-done" type="button" `,
        `data-gate-pass="${escapeAttr(step.id)}">${escapeHtml(gateDoneLabel(step))}</button>`,
      ].join("")
    : "";
  const captureButtons = renderCaptureButtons(step.id, step.target, step.captured_targets);
  const nextAction = publicCopy(step.next_action || "").trim();
  const resumeHint = publicCopy(step.resume_hint || "").trim();
  const nextBlock = nextAction || resumeHint
    ? [
        `<div class="gate-next">`,
        `<strong>Next</strong><p>${escapeHtml(nextAction)}</p>`,
        `<em>${escapeHtml(resumeHint)}</em>`,
        `</div>`,
      ].join("")
    : "";
  return `
    <div class="gate-help">
      <span>What you need to do</span>${classification}
      <strong>${escapeHtml(guidance.title)}</strong>
      <p>${escapeHtml(guidance.body)}</p>
      ${target}
      ${meta}
      <ol>${followSteps.map((action) => `<li>${escapeHtml(publicCopy(action))}</li>`).join("")}</ol>
      <em>${escapeHtml(guidance.reassurance)}</em>
      ${nextBlock}
      ${captureButtons}
      ${resumeButton}
    </div>
  `;
}

function isRetryingGateStep(step) {
  return step?.status === "running" &&
    Boolean(String(step.id || "")) &&
    Boolean(String(step.provider || "")) &&
    (Boolean(String(step.next_action || "")) || Boolean(String(step.resume_hint || "")));
}

function captureTargets(target) {
  return String(target || "")
    .split(",")
    .map((item) => item.trim().toUpperCase())
    .filter((item) => /^[A-Z][A-Z0-9_]{2,}$/.test(item) && item.includes("_"));
}

function gateDoneLabel(step) {
  const classification = String(step.classification || "").toLowerCase();
  const provider = String(step.provider || "").toLowerCase();
  if (classification === "dns-approval" || provider === "dns") return "Approve DNS apply";
  if (classification === "setup-approval" || provider === "fusekit") return "Approve setup plan";
  return "I finished this step";
}

function renderCaptureButtons(gateId, target, capturedTargets = []) {
  const targets = captureTargets(target);
  if (!gateId || !targets.length) return "";
  const captured = new Set((capturedTargets || []).map((item) => String(item).toUpperCase()));
  const capturedCount = targets.filter((item) => captured.has(item)).length;
  const progress = targets.length > 1
    ? `<span>${capturedCount}/${targets.length} captured</span>`
    : "";
  const plural = targets.length === 1 ? "value" : "values";
  return [
    `<div class="gate-capture-panel">`,
    `<div class="gate-capture-head">`,
    `<strong>Safe secret capture</strong>`,
    progress,
    `</div>`,
    `<p>Copy the provider ${plural} inside the VM browser, then click the matching ` +
      `Capture from VM clipboard button below. ` +
      `FuseKit reads only the VM clipboard and saves it directly into the encrypted vault.</p>`,
    `<div class="gate-capture-row">`,
    targets.map((item) => {
      const isCaptured = captured.has(item);
      const label = isCaptured ? `Captured ${item}` : `Capture ${item} from VM clipboard`;
      return [
        `<button class="gate-capture" type="button" `,
        `data-gate-capture="${escapeAttr(gateId)}" `,
        `data-gate-capture-target="${escapeAttr(item)}"`,
        isCaptured ? " disabled" : "",
        `>${escapeHtml(label)}</button>`,
      ].join("");
    }).join(""),
    `</div>`,
    `</div>`,
  ].join("");
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value || "";
  return div.innerHTML;
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll('"', "&quot;");
}

function classToken(value) {
  return String(value || "").replace(/[^a-zA-Z0-9_-]/g, "");
}

function controlRoomActionToken() {
  if (initialJob.control_room_action_token) return initialJob.control_room_action_token;
  try {
    return new URLSearchParams(window.location.search).get("token") || "";
  } catch {
    return "";
  }
}

function controlRoomHeaders(extra = {}) {
  const headers = { "x-fusekit-control-room": "resume", ...extra };
  const token = controlRoomActionToken();
  if (token) headers["x-fusekit-action-token"] = token;
  return headers;
}

function renderSteps(job) {
  const root = document.querySelector("[data-steps]");
  root.innerHTML = (job.steps || [])
    .map((step, index) => `
      <li class="step-card ${classToken(step.status)}" data-step-id="${escapeAttr(step.id)}">
        <span class="step-number">${String(index + 1).padStart(2, "0")}</span>
        <div class="step-copy">
          <strong>${escapeHtml(step.label)}</strong>
          <span>${escapeHtml(stepDetail(step))}</span>
        </div>
        <span class="badge ${classToken(step.status)}">${escapeHtml(label(step.status))}</span>
      </li>
    `)
    .join("");
}

function renderArtifacts(job) {
  const root = document.querySelector("[data-artifacts]");
  const entries = Object.entries(job.artifacts || {}).sort();
  if (!entries.length) {
    root.innerHTML =
      "<li class='empty'>Encrypted vault, receipts, and audit logs appear " +
      "here after retrieval.</li>";
    return;
  }
  root.innerHTML = entries
    .map(([name, path]) => `
      <li>
        <div>
          <strong>${escapeHtml(name)}</strong>
          <code>${escapeHtml(path)}</code>
        </div>
        <button type="button" data-copy="${escapeAttr(path)}" data-copy-label="path">
          Copy path
        </button>
      </li>
    `)
    .join("");
}

function renderVisual(job) {
  const root = document.querySelector("[data-visual-session]");
  if (!root) return;
  const visual = job.visual || {};
  if (!visual.novnc_url) {
    root.innerHTML = "";
    return;
  }
  const novncUrl = String(visual.novnc_url || "");
  const controlRoomUrl = String(visual.control_room_url || "");
  const status = String(visual.status || "ready");
  const password = String(visual.novnc_password || "");
  const iframeUrl = withQueryParam(novncUrl, "password", password);
  const existingFrame = root.querySelector("iframe.visual-frame");
  const sameVisualSession =
    root.dataset.novncUrl === novncUrl &&
    root.dataset.controlRoomUrl === controlRoomUrl &&
    existingFrame?.getAttribute("src") === iframeUrl;
  if (sameVisualSession && existingFrame) {
    const statusNode = root.querySelector("[data-visual-status]");
    if (statusNode) {
      statusNode.textContent = `Visual session: ${status}`;
    }
    return;
  }
  root.dataset.novncUrl = novncUrl;
  root.dataset.controlRoomUrl = controlRoomUrl;
  const passwordRow = password
    ? `
        <div class="visual-secret-row">
          <input value="${escapeAttr(password)}" readonly aria-label="noVNC password" />
          <button type="button" data-copy="${escapeAttr(password)}" data-copy-label="password">
            Copy
          </button>
        </div>
      `
    : "<span>Stored only on the active VM</span>";
  const controlLink = controlRoomUrl
    ? [
        `<a href="${escapeAttr(controlRoomUrl)}" target="_blank" rel="noreferrer">`,
        "Open live control room</a>",
      ].join("")
    : "";
  root.innerHTML = `
    <section class="visual-panel" aria-label="Live VM browser">
      <div class="section-head compact">
        <div>
          <span class="section-kicker">Live VM browser</span>
          <h2>Human gates happen here</h2>
        </div>
        <span class="live-pill" data-visual-status>Visual session: ${escapeHtml(status)}</span>
      </div>
      <div class="visual-grid">
        <iframe
          class="visual-frame"
          src="${escapeAttr(iframeUrl)}"
          title="FuseKit VM browser"
          tabindex="0"
          referrerpolicy="no-referrer"
          allow="clipboard-read; clipboard-write"
          sandbox="allow-scripts allow-same-origin allow-forms allow-pointer-lock allow-modals"
        ></iframe>
        <aside class="visual-help">
          <strong>Interactive remote browser</strong>
          <p>
            This is the disposable VM display. Use it to click, type, and pass
            provider gates while FuseKit keeps observing the same session.
          </p>
          <div class="visual-secret">
            <span>noVNC password</span>
            ${passwordRow}
          </div>
          <div class="visual-actions">
            <a href="${escapeAttr(iframeUrl)}" target="_blank" rel="noreferrer">
              Open browser surface
            </a>
            <button
              type="button"
              data-copy="${escapeAttr(novncUrl)}"
              data-copy-label="browser link"
            >
              Copy browser link
            </button>
            ${controlLink}
          </div>
        </aside>
      </div>
    </section>
  `;
}

function visibleCheckpoints(job) {
  const checkpoints = job.checkpoints || [];
  const active = checkpoints.filter((item) =>
    ["failed", "waiting", "running"].includes(item.status),
  );
  if (active.length) return active.slice(0, 4);
  const pending = checkpoints.filter((item) => item.status === "pending");
  if (pending.length) return pending.slice(0, 3);
  return checkpoints.slice(-3);
}

function renderCheckpoints(job) {
  const root = document.querySelector("[data-checkpoints]");
  if (!root) return;
  const checkpoints = visibleCheckpoints(job);
  if (!checkpoints.length) {
    root.innerHTML =
      "<article class='checkpoint-card pending'><div></div><div>" +
      "<span>Ready</span><strong>Waiting for first checkpoint</strong>" +
      "<p>FuseKit will populate this map as soon as the worker starts.</p>" +
      "<em>Nothing needed yet.</em><code>Keep this control room open.</code>" +
      "</div></article>";
    return;
  }
  root.innerHTML = checkpoints
    .map((checkpoint) => `
      <article class="checkpoint-card ${classToken(checkpoint.status)}"
        data-checkpoint-id="${escapeAttr(checkpoint.id)}">
        <div class="checkpoint-snow state-${classToken(checkpoint.mascot_state)}"
          aria-hidden="true">
          <span class="mini-snow-head"></span>
          <span class="mini-snow-body"></span>
        </div>
        <div>
          <span>${escapeHtml(label(checkpoint.status))}</span>
          <strong>${escapeHtml(checkpoint.label)}</strong>
          <p>${escapeHtml(publicCopy(checkpoint.detail))}</p>
          <em>${escapeHtml(publicCopy(checkpoint.next_action))}</em>
          <code>${escapeHtml(publicCopy(checkpoint.resume_hint))}</code>
        </div>
      </article>
    `)
    .join("");
}

function trustSnowState(status) {
  return {
    passed: "passed",
    pending: "checking",
    repairing: "repairing",
    failed: "failed",
    needs_human_gate: "checking",
    skipped: "checking",
  }[status] || "checking";
}

function renderTrust(job) {
  const root = document.querySelector("[data-trust-checks]");
  if (!root) return;
  const report = job.verification || {};
  const checks = report.checks || [];
  if (!checks.length) {
    root.innerHTML =
      "<article class='trust-card pending'>" +
      "<div class='trust-snow state-checking' aria-hidden='true'></div><div>" +
      "<span>Waiting</span><strong>Trust checks appear after verification</strong>" +
      "<p>Snowman will inspect provider setup, DNS, app health, " +
      "and encrypted survivor artifacts.</p>" +
      "<em>Nothing to do yet. Keep the control room open.</em>" +
      "</div></article>";
    return;
  }
  root.innerHTML = checks
    .slice(0, 8)
    .map((check) => {
      const status = classToken(check.status || "pending");
      const snow = trustSnowState(status);
      const title = `${check.provider || "provider"} · ${check.check || "check"}`.replaceAll(
        "_",
        " ",
      );
      const copy = trustCardCopy(check);
      return `
        <article class="trust-card ${status}">
          <div class="trust-snow state-${classToken(snow)}" aria-hidden="true"></div>
          <div>
            <span>${escapeHtml(label(status))}</span>
            <strong>${escapeHtml(title)}</strong>
            <p>${escapeHtml(copy.summary)}</p>
            <em>${escapeHtml(copy.repair)}</em>
          </div>
        </article>
      `;
    })
    .join("");
}

function acceptanceCards(report) {
  const blockers = acceptanceBlockers(report);
  const mode = String(report.mode || "").trim().toLowerCase();
  if (report.error) {
    return [
      {
        status: "failed",
        snow: "failed",
        label: "Needs repair",
        title: "Acceptance report could not load",
        body: String(report.error),
        foot: "Rerun acceptance so FuseKit can rebuild launch-readiness proof.",
      },
    ];
  }
  if (report.launch_ready && mode === "live") {
    return [
      {
        status: "passed",
        snow: "passed",
        label: "Passed",
        title: "Acceptance blockers are clear",
        body: "The live run has the required proof to be launch-ready.",
        foot: "Record the demo from this clean state.",
      },
    ];
  }
  if (report.launch_ready) {
    return [
      {
        status: "pending",
        snow: "checking",
        label: "Rehearsal passed",
        title: "Live acceptance is still required",
        body: "Local rehearsal proof is clear, but it is not live provider evidence.",
        foot: "Run live acceptance after the provider run before recording the demo.",
      },
    ];
  }
  if (blockers.length) {
    return blockers.slice(0, 8).map((blocker) => ({
      status: "failed",
      snow: "failed",
      label: blocker.category || "Launch blocker",
      title: blocker.item || "Acceptance item",
      body: blocker.next_action || "Run acceptance again after fixing this.",
      detail: blocker.detail || "",
      foot: "FuseKit will keep this visible until acceptance proof passes.",
    }));
  }
  return [
    {
      status: "pending",
      snow: "checking",
      label: "Waiting",
      title: "Launch blockers appear after acceptance",
      body: "FuseKit will list any remaining provider, DNS, vault, audit, or demo blockers here.",
      foot: "Keep the control room open while setup and verification run.",
    },
  ];
}

function acceptanceBlockers(report) {
  const blockers = Array.isArray(report.blockers) ? report.blockers : [];
  const normalized = blockers.filter((blocker) => blocker && typeof blocker === "object");
  if (normalized.length) return normalized;
  const missing = Array.isArray(report.missing) ? report.missing : [];
  return missing
    .map((item) => String(item).trim())
    .filter(Boolean)
    .map((item) => missingAcceptanceBlocker(item));
}

function missingAcceptanceBlocker(item) {
  const guidance = {
    "encrypted vault": [
      "Vault",
      "Run the launcher with vault capture enabled so FuseKit stores secrets " +
        "only in the encrypted vault.",
    ],
    "redacted setup receipt": [
      "Receipt",
      "Rerun setup so the worker writes a redacted setup receipt with no raw secrets.",
    ],
    "safe verification report": [
      "Verification",
      "Let FuseKit finish provider verification and resolve any visible provider " +
        "gate it surfaces in the VM browser.",
    ],
    "rollback metadata": [
      "Rollback",
      "Let FuseKit generate rollback actions from the redacted setup receipt.",
    ],
    "audited human gate interventions": [
      "Human gates",
      "Open, capture, or resume each control-room gate through the launcher so " +
        "redacted audit events are written.",
    ],
    "resolved human gates": [
      "Human gates",
      "Finish or repair every waiting, resurfaced, or retrying control-room gate before recording.",
    ],
    "guided human gates": [
      "Human gates",
      "Regenerate gate state so every control-room gate has follow-me steps, " +
        "next action, and resume hint.",
    ],
    "provider strategy decisions": [
      "Provider routes",
      "Run provider setup through the strategy recorder so API, vault, or " +
        "VM follow-me choices are proven.",
    ],
    "complete provider strategy evidence": [
      "Provider routes",
      "Record selected-route kind, status, deterministic flags, reason, and candidates.",
    ],
    "complete provider strategy coverage": [
      "Provider routes",
      "Record provider strategy evidence for every provider declared by the manifest.",
    ],
    "complete provider verification coverage": [
      "Verification",
      "Record verification checks for every provider declared by the manifest.",
    ],
    "complete rollback coverage": [
      "Rollback",
      "Record rollback metadata for every provider declared by the manifest.",
    ],
    "Resend-before-DNS provider setup order": [
      "Provider order",
      "Run Resend domain setup before Cloudflare/DNS so Resend DNS records are included.",
    ],
    "Resend DNS records in receipt DNS proposal": [
      "Provider order",
      "Let FuseKit create or reuse the Resend sending domain first, then approve " +
        "the DNS apply gate so Cloudflare receives the exact Resend records.",
    ],
    "Resend runtime env in Vercel receipt": [
      "Deployment env",
      "Capture or generate the required RESEND_* values in the launcher, then " +
        "let FuseKit push them into Vercel before verification.",
    ],
    "validated provider capability packs": [
      "Provider packs",
      "Regenerate provider capability packs for this app's providers before setup runs.",
    ],
    "verified live URL": [
      "Deployment",
      "Let FuseKit verify the deployed live URL and write it into the setup receipt.",
    ],
    "clean leak scan": [
      "Security",
      "Remove plaintext setup secrets from app files and rerun the launch leak scan.",
    ],
    "detonated worker state": [
      "Detonation",
      "Run detonation so plaintext worker, browser, visual, and auth scratch state " +
        "is destroyed after encrypted proof is preserved.",
    ],
  };
  const fallback = [
    "Launch evidence",
    "Repair this acceptance item, then rerun live acceptance.",
  ];
  const [category, nextAction] = guidance[item] || fallback;
  return { category, item, next_action: nextAction };
}

function renderAcceptance(job) {
  const root = document.querySelector("[data-acceptance-blockers]");
  if (!root) return;
  const report = job.acceptance && typeof job.acceptance === "object" ? job.acceptance : {};
  const blockers = acceptanceBlockers(report);
  const summary = report.error
    ? "acceptance report needs repair"
    : report.launch_ready && String(report.mode || "").trim().toLowerCase() === "live"
      ? "launch-ready proof is clear"
      : report.launch_ready
        ? "live acceptance still required"
      : blockers.length
        ? `${blockers.length} launch blocker${blockers.length === 1 ? "" : "s"}`
        : "acceptance proof is waiting";
  const summaryNode = document.querySelector("[data-acceptance-overall]");
  if (summaryNode) summaryNode.textContent = summary;
  root.innerHTML = acceptanceCards(report)
    .map((card) => {
      const detail = card.detail
        ? `<code>${escapeHtml(publicCopy(card.detail))}</code>`
        : "";
      return `
      <article class="trust-card ${classToken(card.status)}">
        <div class="trust-snow state-${classToken(card.snow)}" aria-hidden="true"></div>
        <div>
          <span>${escapeHtml(card.label)}</span>
          <strong>${escapeHtml(card.title)}</strong>
          <p>${escapeHtml(card.body)}</p>
          ${detail}
          <em>${escapeHtml(card.foot)}</em>
        </div>
      </article>
    `;
    })
    .join("");
}

function trustCardCopy(check) {
  const details = check && typeof check.details === "object" && check.details
    ? check.details
    : {};
  const reason = String(details.reason || "").toLowerCase();
  if (
    check?.status === "pending" &&
    Boolean(details.pending_safe) &&
    reason.includes("dns") &&
    reason.includes("approval")
  ) {
    return {
      summary: "DNS changes are waiting for approval or propagation.",
      repair:
        "Approve/apply the exact DNS records in the setup plan; FuseKit will keep verifying.",
    };
  }
  return {
    summary: check?.summary || "Verification is running.",
    repair: check?.repair || "Keep the control room open.",
  };
}

function renderProviderStrategies(job) {
  const root = document.querySelector("[data-provider-strategies]");
  if (!root) return;
  const payload = job.provider_strategies || {};
  const providers = Array.isArray(payload.providers) ? payload.providers : [];
  if (!providers.length) {
    root.innerHTML =
      "<article class='strategy-card pending'>" +
      "<span>Waiting</span><strong>Provider routes appear after setup starts</strong>" +
      "<p>FuseKit will show whether it chose API, CLI, browser guidance, or follow-me.</p>" +
      "</article>";
    return;
  }
  root.innerHTML =
    renderProviderStrategyPlan(providers) +
    providers.map(renderProviderStrategyCard).join("");
}

function renderProviderStrategyPlan(providers) {
  const items = providerStrategyPlanItems(providers);
  if (!items.length) return "";
  return `
    <article class="strategy-card strategy-plan">
      <span>Route plan</span>
      <strong>What happens in order</strong>
      <ol>
        ${items.map((item) => `<li>${escapeHtml(publicCopy(item))}</li>`).join("")}
      </ol>
    </article>
  `;
}

function providerStrategyPlanItems(providers) {
  const records = providerStrategyRecords(providers);
  if (!records.length) return [];
  const hasResendDomain = records.some((record) =>
    strategyProvider(record) === "resend" &&
    strategyRecipe(record) === "resend-domain" &&
    strategyRoute(record) === "api" &&
    strategyEvidence(record).downstream_order === "before_dns_apply"
  );
  const hasDns = records.some((record) =>
    ["cloudflare", "dns"].includes(strategyProvider(record)) ||
    strategyRecipe(record).includes("dns")
  );
  const hasVercelResendEnv = records.some((record) =>
    strategyProvider(record) === "vercel" &&
    strategyRoute(record) === "api" &&
    strategyRecipe(record).includes("env")
  );
  const tokenTargets = Array.from(new Set(records
    .filter((record) =>
      ["browser_guided", "human_follow_me"].includes(strategyRoute(record)) &&
      String(record.target || "").trim()
    )
    .map((record) => String(record.target || "").trim().toUpperCase())))
    .sort();
  const hasHumanGate = records.some((record) =>
    ["browser_guided", "human_follow_me"].includes(strategyRoute(record))
  );
  const hasApi = records.some((record) => strategyRoute(record) === "api");
  const items = [];
  if (hasResendDomain) {
    items.push(
      "First, FuseKit creates or reuses the Resend sending domain by API; " +
      "do not manually click Add domain in Resend unless FuseKit asks.",
    );
  }
  if (hasResendDomain && hasDns) {
    items.push(
      "Then FuseKit carries the Resend DNS records into the DNS approval gate " +
      "with the app records before Cloudflare/DNS apply runs.",
    );
  }
  if (hasVercelResendEnv) {
    items.push(
      "After Resend values exist, FuseKit writes the required RESEND_* runtime " +
      "variables into Vercel before deployment verification.",
    );
  }
  if (tokenTargets.length) {
    items.push(
      "If a provider token gate appears, open it in the VM browser and use " +
      `Capture from VM clipboard for ${tokenTargets.join(", ")}.`,
    );
  } else if (hasHumanGate) {
    items.push(
      "For provider-owned login, MFA, consent, or billing gates, use the VM " +
      "browser and click I finished this step only after the provider confirms.",
    );
  }
  if (!items.length && hasApi) {
    items.push(
      "FuseKit will run deterministic provider API setup after authorization " +
      "and read-only health checks pass.",
    );
  }
  return items;
}

function providerStrategyRecords(providers) {
  return providers.flatMap((providerRecord) => {
    const provider = String(providerRecord.provider || "").trim().toLowerCase();
    const strategies = Array.isArray(providerRecord.strategies)
      ? providerRecord.strategies
      : [];
    return strategies
      .filter((strategy) => strategy && typeof strategy === "object")
      .map((strategy) => ({ ...strategy, _provider: provider }));
  });
}

function strategyProvider(record) {
  return String(record._provider || record.provider || "").trim().toLowerCase();
}

function strategyRecipe(record) {
  return String(record.recipe || "").trim().toLowerCase();
}

function strategyRoute(record) {
  const decision = record.decision && typeof record.decision === "object"
    ? record.decision
    : {};
  const selected = decision.selected && typeof decision.selected === "object"
    ? decision.selected
    : {};
  return String(record.strategy || selected.kind || "").trim();
}

function strategyEvidence(record) {
  const decision = record.decision && typeof record.decision === "object"
    ? record.decision
    : {};
  const selected = decision.selected && typeof decision.selected === "object"
    ? decision.selected
    : {};
  return selected.evidence && typeof selected.evidence === "object"
    ? selected.evidence
    : {};
}

function renderProviderStrategyCard(providerRecord) {
  const provider = String(providerRecord.provider || "provider");
  const strategies = Array.isArray(providerRecord.strategies) ? providerRecord.strategies : [];
  if (!strategies.length) {
    return `
      <article class="strategy-card pending">
        <span>${escapeHtml(provider)}</span>
        <strong>No route decision recorded yet</strong>
        <p>FuseKit is still preparing provider setup.</p>
      </article>
    `;
  }
  return `
    <article class="strategy-card">
      <span>${escapeHtml(provider)}</span>
      <strong>${strategies.length} setup route${strategies.length === 1 ? "" : "s"}</strong>
      <div>
        ${strategies.map((strategy) => renderProviderStrategyRow(provider, strategy)).join("")}
      </div>
    </article>
  `;
}

function renderProviderStrategyRow(provider, strategy) {
  const decision = strategy.decision || {};
  const selected = decision.selected || {};
  const recipe = String(strategy.recipe || "setup");
  const route = String(strategy.strategy || "unknown").replaceAll("_", " ");
  const status = String(strategy.status || "pending");
  const reason = String(selected.reason || "");
  const routeSummary = providerStrategyRouteSummary(provider, strategy, selected);
  const nextAction = publicCopy(strategy.next_action || "").trim();
  const resumeHint = publicCopy(strategy.resume_hint || "").trim();
  const followSteps = Array.isArray(strategy.follow_steps) ? strategy.follow_steps : [];
  const guide = nextAction
    ? `<small><b>Next:</b> ${escapeHtml(nextAction)}</small>`
    : "";
  const hint = resumeHint ? `<small>${escapeHtml(resumeHint)}</small>` : "";
  const steps = followSteps.length
    ? [
        `<ol>`,
        followSteps
          .filter((step) => String(step || "").trim())
          .map((step) => `<li>${escapeHtml(publicCopy(step))}</li>`)
          .join(""),
        `</ol>`,
      ].join("")
    : "";
  return `
    <div class="strategy-row">
      <b>${escapeHtml(recipe)}</b>
      <em>${escapeHtml(route)} · ${escapeHtml(status)}</em>
      <small>${escapeHtml(routeSummary)}</small>
      <small>${escapeHtml(reason)}</small>
      ${guide}
      ${hint}
      ${steps}
    </div>
  `;
}

function providerStrategyRouteSummary(provider, strategy, selected) {
  const route = String(strategy.strategy || selected.kind || "unknown");
  const recipe = String(strategy.recipe || "");
  const evidence = selected.evidence && typeof selected.evidence === "object"
    ? selected.evidence
    : {};
  const deterministic = Boolean(selected.deterministic);
  const implemented = Boolean(selected.implemented);
  if (route === "api") {
    if (
      String(provider || "").toLowerCase() === "resend" &&
      recipe === "resend-domain" &&
      evidence.downstream_order === "before_dns_apply"
    ) {
      return (
        "API automation: FuseKit creates or reuses the Resend domain, " +
        "collects DNS records, then waits for DNS approval."
      );
    }
    if (
      String(provider || "").toLowerCase() === "resend" &&
      recipe === "resend-audience" &&
      evidence.conditional === "only_when_app_requires_audience"
    ) {
      return (
        "API automation: FuseKit creates or reuses a Resend audience only " +
        "when this app requires one."
      );
    }
    return "API automation: deterministic provider setup runs after authorization.";
  }
  if (route === "official_cli") {
    return "Official CLI route: deterministic when installed and enabled.";
  }
  if (route === "local_vault") {
    return "Vault capture: already-approved values move directly into the encrypted vault.";
  }
  if (["browser_guided", "human_follow_me"].includes(route)) {
    return (
      "VM follow-me: the user passes provider-owned gates, then FuseKit " +
      "continues with verified setup."
    );
  }
  if (deterministic || implemented) {
    return "Deterministic route selected for this setup step.";
  }
  return "FuseKit recorded the safest available route for this setup step.";
}

const runStateLabels = {
  app_repo_known: "App repo",
  runner_selected: "Runner",
  oci_ready: "OCI",
  browser_ready: "Browser",
  provider_sessions_known: "Provider gates",
  vault_created: "Vault",
  secrets_captured: "Secrets",
  provider_checks_passed_or_pending_safe: "Provider checks",
  receipt_written: "Receipt",
  detonation_safe: "Detonation",
};

const runStateDetails = {
  app_repo_known: [
    "Source found. FuseKit knows what to launch.",
    "Waiting for a repo URL or local app source that the clean room can fetch.",
  ],
  runner_selected: [
    "Execution lane selected.",
    "Choosing local, OCI Cloud Shell, or OCI VM based on available authorization.",
  ],
  oci_ready: [
    "Clean-room runner is ready or not required.",
    "Waiting for OCI Cloud Shell, OCI VM provisioning, or a local-runner decision.",
  ],
  browser_ready: [
    "Computer-use browser is ready.",
    "Waiting for the provider browser spine to open and report healthy state.",
  ],
  provider_sessions_known: [
    "Provider gates are tracked.",
    "Waiting for provider login, MFA, consent, billing, or token gates to surface.",
  ],
  vault_created: [
    "Encrypted vault exists.",
    "Creating the passphrase-protected vault before any secrets are captured.",
  ],
  secrets_captured: [
    "Secrets are stored only in the vault.",
    "Waiting for approved tokens, keys, webhook secrets, or generated credentials.",
  ],
  provider_checks_passed_or_pending_safe: [
    "Provider checks passed or are explicitly safe to wait on.",
    "Waiting for API, DNS, deploy, webhook, email, and live-app checks.",
  ],
  receipt_written: [
    "Redacted receipt exists.",
    "Writing the audit-friendly receipt without raw secrets.",
  ],
  detonation_safe: [
    "Preflight passed and detonation can run.",
    "Waiting for vault, audit, receipt, verification, rollback, and leak checks.",
  ],
};

function renderRunState(job) {
  const root = document.querySelector("[data-run-state-checks]");
  if (!root) return;
  const state = job.run_state || {};
  const missing = Array.isArray(state.missing_for_detonation)
    ? state.missing_for_detonation
    : [];
  const summary = state.ready_to_detonate
    ? "detonation preflight is ready"
    : missing.length
      ? `${missing.length} detonation preflight items pending`
      : "launch contract is still filling in";
  const summaryNode = document.querySelector("[data-run-state-overall]");
  if (summaryNode) summaryNode.textContent = summary;
  root.innerHTML = Object.entries(runStateLabels)
    .map(([field, title]) => {
      const passed = Boolean(state[field]);
      const status = passed ? "passed" : "pending";
      const snow = passed ? "passed" : "checking";
      const detail = runStateDetails[field] || ["Ready and recorded.", "Waiting for this phase."];
      return `
        <article class="trust-card ${status}" data-run-state-field="${escapeAttr(field)}">
          <div class="trust-snow state-${snow}" aria-hidden="true"></div>
          <div>
            <span>${escapeHtml(label(status))}</span>
            <strong>${escapeHtml(title)}</strong>
            <p>${escapeHtml(passed ? detail[0] : detail[1])}</p>
            <em>${escapeHtml(field.replaceAll("_", " "))}</em>
          </div>
        </article>
      `;
    })
    .join("");
}

function render(job) {
  const prog = progress(job);
  const counts = statusCounts(job.steps);
  const gate = activeGate(job);
  if (
    gate &&
    gate.status !== "resume_requested" &&
    !(job.steps || []).some((step) => step.status === "waiting")
  ) {
    counts.waiting += 1;
  }
  if (job.gate_state_error && !(job.steps || []).some((step) => step.status === "failed")) {
    counts.failed += 1;
  }
  const current = currentStep(job);
  const next = nextStep(job, current);
  const statusPill = document.querySelector("[data-job-status]");
  statusPill.textContent = label(job.status);
  statusPill.className = `pill status ${classToken(job.status)}`;
  document.querySelector("[data-updated-at]").textContent = "Updated just now";
  document.querySelector("[data-progress-label]").textContent = `${prog.done}/${prog.total} steps`;
  document.querySelector("[data-progress-bar]").style.width = `${prog.percent}%`;
  document.querySelector("[data-count-running]").textContent = counts.running;
  document.querySelector("[data-count-waiting]").textContent = counts.waiting;
  document.querySelector("[data-count-done]").textContent = counts.done;
  document.querySelector("[data-count-failed]").textContent = counts.failed;

  const focus = document.querySelector("[data-focus-panel]");
  focus.classList.toggle("gate", current?.status === "waiting");
  document.querySelector("[data-focus-kicker]").textContent = focusKicker(current);
  const state = mascotState(current, job);
  const scene = document.querySelector("[data-snow-scene]");
  scene.className = `snow-scene state-${state}`;
  document.querySelector("[data-snow-caption]").textContent = mascotCaption(state);
  const dot = document.querySelector("[data-focus-dot]");
  dot.className = `mini-dot ${classToken(current?.status || job.status)}`;
  document.querySelector("[data-current-title]").textContent = current?.label || "Launch complete";
  document.querySelector("[data-current-detail]").textContent =
    current ? stepDetail(current) : "FuseKit is preserving encrypted and redacted artifacts.";
  document.querySelector("[data-gate-help]").innerHTML = renderGateHelp(current);
  document.querySelector("[data-next-title]").textContent =
    next?.label || "Artifacts and audit review";
  renderCheckpoints(job);
  renderRunState(job);
  renderAcceptance(job);
  renderTrust(job);
  renderProviderStrategies(job);
  renderVisual(job);
  renderSteps(job);
  renderArtifacts(job);
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through to the selection-based copy path for public HTTP VM URLs.
    }
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.inset = "0 auto auto 0";
  textarea.style.width = "1px";
  textarea.style.height = "1px";
  textarea.style.opacity = "0";
  document.body.append(textarea);
  textarea.focus();
  textarea.select();
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    textarea.remove();
  }
}

function controlRoomFailureMessage(payload, fallback) {
  const parts = [];
  const reason = String(payload?.error || payload?.message || "").trim();
  if (reason) parts.push(reason);
  const missingTargets = Array.isArray(payload?.missing_targets)
    ? payload.missing_targets.map((item) => String(item).trim()).filter(Boolean)
    : [];
  if (missingTargets.length) {
    parts.push(`Missing: ${missingTargets.join(", ")}`);
  }
  const nextAction = String(payload?.next_action || "").trim();
  if (nextAction) parts.push(nextAction);
  return parts.join(" ") || fallback;
}

document.addEventListener("click", async (event) => {
  const gateOpenButton = event.target.closest("[data-gate-open]");
  if (gateOpenButton) {
    gateOpenButton.disabled = true;
    const originalText = gateOpenButton.textContent;
    gateOpenButton.textContent = "Opening in VM...";
    try {
      const response = await fetch(
        `/api/gates/${encodeURIComponent(gateOpenButton.dataset.gateOpen)}/open`,
        {
          method: "POST",
          headers: controlRoomHeaders(),
        },
      );
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.ok) {
        throw new Error(controlRoomFailureMessage(
          payload,
          "Could not open the provider gate inside the VM. Use the noVNC browser surface.",
        ));
      }
      setRefreshStatus(
        payload.message || "Provider gate opened inside the shared VM browser.",
      );
    } catch (error) {
      setRefreshStatus(
        error?.message ||
          "Could not open the provider gate inside the VM. Use the noVNC browser surface.",
        "stale",
      );
    } finally {
      gateOpenButton.disabled = false;
      gateOpenButton.textContent = originalText;
    }
    return;
  }
  const captureButton = event.target.closest("[data-gate-capture]");
  if (captureButton) {
    captureButton.disabled = true;
    const originalText = captureButton.textContent;
    const target = captureButton.dataset.gateCaptureTarget || "";
    captureButton.textContent = `Capturing ${target}...`;
    try {
      const response = await fetch(
        `/api/gates/${encodeURIComponent(captureButton.dataset.gateCapture)}/capture-clipboard`,
        {
          method: "POST",
          headers: controlRoomHeaders({ "content-type": "application/json" }),
          body: JSON.stringify({ target }),
        },
      );
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.ok) {
        throw new Error(controlRoomFailureMessage(
          payload,
          `Could not capture ${target} from the VM clipboard. Copy it in the VM and try again.`,
        ));
      }
      setRefreshStatus(payload.message || `${target} captured into the encrypted vault.`);
      await refreshJob({ preserveStatus: true });
    } catch (error) {
      setRefreshStatus(
        error?.message ||
          `Could not capture ${target} from the VM clipboard. Copy it in the VM and try again.`,
        "stale",
      );
    } finally {
      captureButton.disabled = false;
      captureButton.textContent = originalText;
    }
    return;
  }
  const gateButton = event.target.closest("[data-gate-pass]");
  if (gateButton) {
    gateButton.disabled = true;
    const originalText = gateButton.textContent;
    gateButton.textContent = "Checking again...";
    try {
      const response = await fetch(
        `/api/gates/${encodeURIComponent(gateButton.dataset.gatePass)}/pass`,
        {
          method: "POST",
          headers: controlRoomHeaders(),
        },
      );
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.ok) {
        throw new Error(controlRoomFailureMessage(
          payload,
          "Could not mark the gate done from this snapshot. FuseKit will keep waiting.",
        ));
      }
      setRefreshStatus(
        payload.message ||
          "Snowman is rechecking the provider now. The next step will appear here.",
      );
      await refreshJob({ preserveStatus: true });
    } catch (error) {
      gateButton.disabled = false;
      gateButton.textContent = originalText;
      setRefreshStatus(
        error?.message ||
          "Could not mark the gate done from this snapshot. FuseKit will keep waiting.",
        "stale",
      );
    }
    return;
  }
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const copyLabel = button.dataset.copyLabel || "value";
  const originalText = button.textContent;
  try {
    const copied = await copyText(button.dataset.copy || "");
    if (!copied) throw new Error("copy blocked");
    button.textContent = "Copied";
    setTimeout(() => {
      button.textContent = originalText;
    }, 1200);
  } catch {
    button.textContent = "Copy blocked";
    const nearbyInput = button.parentElement?.querySelector("input");
    if (nearbyInput) {
      nearbyInput.focus();
      nearbyInput.select();
    }
    setRefreshStatus(
      `Copy was blocked by the browser. FuseKit left the ${copyLabel} visible.`,
      "stale",
    );
  }
});

function withQueryParam(url, key, value) {
  if (!url || !value) return url;
  try {
    const parsed = new URL(url, window.location.href);
    parsed.searchParams.set(key, value);
    return parsed.toString();
  } catch {
    const separator = url.includes("?") ? "&" : "?";
    return `${url}${separator}${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
  }
}

function setRefreshStatus(text, tone = "ok") {
  const node = document.querySelector("[data-refresh-status]");
  if (!node) return;
  node.textContent = text;
  node.className = `pill ${tone === "stale" ? "refresh-stale" : "refresh-ok"}`;
}

async function refreshJob(options = {}) {
  const preserveStatus = Boolean(options.preserveStatus);
  try {
    const response = await fetch("/api/job", { cache: "no-store" });
    if (!response.ok) {
      setRefreshStatus(`Live refresh paused (${response.status})`, "stale");
      return;
    }
    render(await response.json());
    if (!preserveStatus) {
      setRefreshStatus("Live refresh connected");
    }
  } catch {
    setRefreshStatus(
      location.protocol.startsWith("http")
        ? "Live refresh paused. Reopen or restart the control-room server."
        : "Snapshot view. Serve the control room for live updates.",
      "stale",
    );
  }
}

render(initialJob);
if (location.protocol.startsWith("http")) {
  setInterval(refreshJob, 2000);
}
""".replace("__GATE_GUIDANCE_JSON__", _GATE_GUIDANCE_JSON)
