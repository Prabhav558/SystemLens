// Every value shown here originates in log text, which anyone who can make a
// watched service log a line controls. Nothing from the API is ever parsed
// as HTML: all rendering goes through createElement + textContent.
"use strict";

const STORAGE_KEY = "systemlens_api_key";
const VERDICTS = {
  root_cause_identified: "root cause",
  probable_cause: "probable cause",
  insufficient_evidence: "insufficient evidence",
};

let pollHandle = null;

function apiKey() { return localStorage.getItem(STORAGE_KEY); }

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

async function api(path) {
  const res = await fetch(path, { headers: { "Authorization": "Bearer " + apiKey() } });
  if (res.status === 401) { logout(); throw new Error("unauthorized"); }
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function logout() {
  localStorage.removeItem(STORAGE_KEY);
  document.getElementById("app-view").style.display = "none";
  document.getElementById("login-view").style.display = "flex";
  if (pollHandle) clearInterval(pollHandle);
}

async function login(key) {
  localStorage.setItem(STORAGE_KEY, key);
  try {
    const me = await api("/agents/me");
    document.getElementById("who").textContent = "agent: " + me.name;
    document.getElementById("login-view").style.display = "none";
    document.getElementById("app-view").style.display = "block";
    refresh();
    pollHandle = setInterval(refresh, 10000);
  } catch (e) {
    localStorage.removeItem(STORAGE_KEY);
    document.getElementById("login-error").textContent = "Invalid API key.";
  }
}

function row(label, value) {
  const line = el("div", "finding-row");
  line.append(el("span", "label", label + ":"), document.createTextNode(value || "—"));
  return line;
}

function findingCard(f) {
  const known = Object.prototype.hasOwnProperty.call(VERDICTS, f.verdict);
  const card = el("div", "finding" + (known ? " verdict-" + f.verdict : ""));

  const top = el("div", "finding-top");
  const title = el("span", "finding-project", f.project + " ");
  title.append(el("span", "finding-fp", f.fingerprint));
  top.append(title, el("span", "finding-time", new Date(f.received_at * 1000).toLocaleString()));

  const body = el("div", "finding-body");
  const badgeRow = el("div", "finding-row");
  badgeRow.append(el("span", "verdict-badge", known ? VERDICTS[f.verdict] : f.verdict));
  body.append(
    badgeRow,
    row("component", f.affected_component),
    row("root cause", f.root_cause),
    row("fix", f.fix_suggestion),
    row("confidence", typeof f.confidence === "number" ? f.confidence.toFixed(2) : null),
  );

  let assumptions = [];
  try { assumptions = JSON.parse(f.analysis_json).unverified_assumptions || []; } catch (e) { /* older rows */ }
  for (const note of assumptions) body.append(el("div", "finding-notes", "note: " + note));

  card.append(top, body);
  return card;
}

function render(findings) {
  const container = document.getElementById("findings");
  const select = document.getElementById("project-filter");
  const current = select.value;

  const projects = [...new Set(findings.map(f => f.project))].sort();
  if (current && !projects.includes(current)) projects.push(current);
  const all = el("option", null, "All projects");
  all.value = "";
  select.replaceChildren(all, ...projects.map(p => {
    const option = el("option", null, p);
    option.value = p;
    return option;
  }));
  select.value = current;

  if (findings.length === 0) {
    container.replaceChildren(el("div", "empty", "No findings yet for this window."));
    return;
  }
  container.replaceChildren(...findings.map(findingCard));
}

async function refresh() {
  const params = new URLSearchParams();
  const project = document.getElementById("project-filter").value;
  const sinceHours = document.getElementById("since-filter").value;
  if (project) params.set("project", project);
  if (sinceHours) params.set("since_hours", sinceHours);
  try {
    render(await api("/findings?" + params.toString()));
  } catch (e) { /* 401 already handled by logout(); ignore transient errors */ }
}

document.getElementById("login-btn").addEventListener("click", () => {
  const key = document.getElementById("key-input").value.trim();
  if (key) login(key);
});
document.getElementById("key-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("login-btn").click();
});
document.getElementById("logout-btn").addEventListener("click", logout);
document.getElementById("project-filter").addEventListener("change", refresh);
document.getElementById("since-filter").addEventListener("change", refresh);

if (apiKey()) login(apiKey());
