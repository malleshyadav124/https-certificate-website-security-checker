"use strict";

const form = document.querySelector("#scan-form");
const input = document.querySelector("#website-url");
const button = document.querySelector("#scan-button");
const loadingMessage = document.querySelector("#loading-message");
const apiError = document.querySelector("#api-error");
const results = document.querySelector("#results");

const validStatuses = new Set(["PASS", "WARNING", "FAIL", "NOT_CHECKED"]);
const statusLabels = {
  PASS: "PASS",
  WARNING: "WARNING",
  FAIL: "FAIL",
  NOT_CHECKED: "NOT CHECKED",
};

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!form.reportValidity()) {
    return;
  }

  setLoading(true);
  apiError.hidden = true;
  apiError.textContent = "";
  results.hidden = true;

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ url: input.value.trim() }),
    });
    const payload = await readJsonResponse(response);
    if (!response.ok) {
      throw new Error(
        typeof payload.error === "string"
          ? payload.error
          : "The scan request could not be completed.",
      );
    }

    validateReport(payload);
    renderReport(payload);
    results.hidden = false;
  } catch (error) {
    apiError.textContent =
      error instanceof Error
        ? error.message
        : "A network or server error prevented the scan.";
    apiError.hidden = false;
  } finally {
    setLoading(false);
  }
});

async function readJsonResponse(response) {
  try {
    return await response.json();
  } catch {
    throw new Error("The server returned a response that could not be read.");
  }
}

function setLoading(isLoading) {
  button.disabled = isLoading;
  button.classList.toggle("is-loading", isLoading);
  button.setAttribute("aria-busy", String(isLoading));
  button.querySelector(".button-label").textContent = isLoading
    ? "Scanning…"
    : "Scan website";
  loadingMessage.hidden = !isLoading;
}

function validateReport(report) {
  if (
    !report ||
    typeof report !== "object" ||
    typeof report.url !== "string" ||
    !report.overall ||
    typeof report.overall.summary !== "string" ||
    !report.certificate ||
    !report.certificate.checks ||
    !report.tls ||
    !report.tls.check ||
    !report.redirect ||
    !report.headers ||
    !Array.isArray(report.recommendations)
  ) {
    throw new Error("The server response did not contain a complete scan report.");
  }

  if (!validStatuses.has(report.overall.status)) {
    throw new Error("The server returned an invalid overall status.");
  }
  if (
    typeof report.overall.badge_label !== "string" ||
    typeof report.overall.connection_status !== "string" ||
    typeof report.overall.findings_status !== "string" ||
    typeof report.overall.scan_status !== "string"
  ) {
    throw new Error("The server returned an invalid overall assessment.");
  }
  readCheck(report.tls.check);
  readCheck(report.redirect);
  for (const check of Object.values(report.certificate.checks)) {
    readCheck(check);
  }
  for (const check of Object.values(report.headers)) {
    readCheck(check);
  }
  for (const recommendation of report.recommendations) {
    if (
      !recommendation ||
      typeof recommendation.finding !== "string" ||
      typeof recommendation.advice !== "string"
    ) {
      throw new Error("The server returned an invalid recommendation.");
    }
  }
}

function readCheck(check) {
  if (
    !check ||
    typeof check !== "object" ||
    !validStatuses.has(check.status) ||
    typeof check.message !== "string"
  ) {
    throw new Error("The server returned an invalid scan result.");
  }
  return check;
}

function renderReport(report) {
  document.querySelector("#scanned-url").textContent = report.url;
  document.querySelector("#overall-summary").textContent = report.overall.summary;
  renderBadge(
    document.querySelector("#overall-status"),
    report.overall.status,
    report.overall.badge_label,
  );
  renderCertificate(report.certificate);
  renderCheckContainer(document.querySelector("#tls-result"), [
    ["Negotiation", report.tls.check],
  ]);
  renderDetails(document.querySelector("#tls-details"), [
    ["TLS version", report.tls.version],
    ["Cipher suite", report.tls.cipher_suite],
    ["Cipher protocol", report.tls.cipher_protocol],
  ]);
  renderCheckContainer(document.querySelector("#redirect-result"), [
    ["HTTP to HTTPS redirect", report.redirect],
  ]);
  const finalUrl = document.querySelector("#redirect-final-url");
  finalUrl.hidden = typeof report.redirect.final_url !== "string";
  finalUrl.textContent =
    typeof report.redirect.final_url === "string"
      ? `Final destination: ${report.redirect.final_url}`
      : "";
  renderCheckContainer(
    document.querySelector("#header-results"),
    Object.entries(report.headers),
  );
  renderRecommendations(report.recommendations);
}

function renderCertificate(certificate) {
  const details = document.querySelector("#certificate-details");
  renderDetails(details, [
    ["Hostname", certificate.hostname],
    ["Port", certificate.port],
    ["Issuer", certificate.issuer],
    ["Valid from", formatDate(certificate.not_before)],
    ["Expires", formatDate(certificate.expires_at)],
  ]);

  renderCheckContainer(
    document.querySelector("#certificate-checks"),
    [
      ["Validity period", certificate.checks.validity],
      ["Hostname match", certificate.checks.hostname_match],
      ["Certificate-chain trust", certificate.checks.chain_trust],
    ],
  );
}

function renderDetails(container, fields) {
  container.replaceChildren();
  for (const [label, value] of fields) {
    if (value === null || value === undefined || value === "") {
      continue;
    }
    const term = document.createElement("dt");
    term.textContent = label;
    const description = document.createElement("dd");
    description.textContent = String(value);
    container.append(term, description);
  }
}

function formatDate(value) {
  if (typeof value !== "string") {
    return value;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function renderCheckContainer(container, entries) {
  container.replaceChildren();
  for (const [label, check] of entries) {
    const item = document.createElement("article");
    item.className = "check-item";

    const titleRow = document.createElement("div");
    titleRow.className = "check-title-row";
    const title = document.createElement("span");
    title.className = "check-title";
    title.textContent = label;
    titleRow.append(title, createBadge(check.status));

    const message = document.createElement("p");
    message.className = "check-message";
    message.textContent = check.message;
    item.append(titleRow, message);
    container.append(item);
  }
}

function renderBadge(container, status, label = statusLabels[status]) {
  container.replaceChildren(createBadge(status, label));
}

function createBadge(status, label = statusLabels[status]) {
  const badge = document.createElement("span");
  badge.className = `status-badge ${statusClass(status)}`;
  badge.textContent = label;
  return badge;
}

function statusClass(status) {
  return {
    PASS: "status-pass",
    WARNING: "status-warning",
    FAIL: "status-fail",
    NOT_CHECKED: "status-not-checked",
  }[status];
}

function renderRecommendations(recommendations) {
  const list = document.querySelector("#recommendations-list");
  list.replaceChildren();
  if (recommendations.length === 0) {
    const message = document.createElement("li");
    message.className = "empty-recommendations";
    message.textContent = "The scan did not return any remediation recommendations.";
    list.append(message);
    return;
  }

  for (const recommendation of recommendations) {
    if (
      !recommendation ||
      typeof recommendation.finding !== "string" ||
      typeof recommendation.advice !== "string"
    ) {
      continue;
    }
    const item = document.createElement("li");
    const finding = document.createElement("span");
    finding.className = "recommendation-finding";
    finding.textContent = recommendation.finding;
    item.append(finding, document.createTextNode(recommendation.advice));
    list.append(item);
  }
}
