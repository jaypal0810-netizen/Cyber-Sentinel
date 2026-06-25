const loginView = document.querySelector("#loginView");
const dashboardView = document.querySelector("#dashboardView");
const loginForm = document.querySelector("#loginForm");
const logoutBtn = document.querySelector("#logoutBtn");
const logsEl = document.querySelector("#activityLogs");
const eventCountEl = document.querySelector("#eventCount");
const encryptedCountEl = document.querySelector("#encryptedCount");
const openPortCountEl = document.querySelector("#openPortCount");
const riskScoreEl = document.querySelector("#riskScore");
const reportBox = document.querySelector("#reportBox");
const incidentCountEl = document.querySelector("#incidentCount");
const firewallCountEl = document.querySelector("#firewallCount");

const state = {
  encryptedFiles: 0,
  openPorts: 0,
  logs: JSON.parse(localStorage.getItem("cyberLogs") || "[]"),
  firewallRules: JSON.parse(localStorage.getItem("cyberFirewallRules") || "[]"),
  incidents: JSON.parse(localStorage.getItem("cyberIncidents") || "[]"),
  checklist: JSON.parse(localStorage.getItem("cyberChecklist") || "{}"),
  currentOtp: "",
  otpExpiresAt: 0,
};

function addLog(message) {
  const entry = `${new Date().toLocaleString()} - ${message}`;
  state.logs.unshift(entry);
  state.logs = state.logs.slice(0, 30);
  localStorage.setItem("cyberLogs", JSON.stringify(state.logs));
  renderLogs();
}

function renderLogs() {
  logsEl.innerHTML = state.logs.map((log) => `<li>${escapeHtml(log)}</li>`).join("");
  eventCountEl.textContent = state.logs.length;
  renderReport();
}

function renderReport() {
  const hardeningScore = getChecklistScore();
  const risk = Math.min(96, 26 + state.openPorts * 9 + state.incidents.length * 7 - Math.min(state.encryptedFiles * 2, 14) - Math.round(hardeningScore / 8));
  riskScoreEl.textContent = Math.max(8, risk);
  encryptedCountEl.textContent = state.encryptedFiles;
  openPortCountEl.textContent = state.openPorts;
  incidentCountEl.textContent = state.incidents.length;
  firewallCountEl.textContent = state.firewallRules.length;
  reportBox.innerHTML = `
    <strong>Current summary</strong><br>
    Risk score is ${riskScoreEl.textContent}/100. ${state.openPorts} open ports were found in the last scan.
    ${state.incidents.length} incident(s) are open and ${state.firewallRules.length} firewall rule(s) are active.
    Hardening checklist is ${hardeningScore}% complete. Logs are stored locally in this browser.
  `;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  })[char]);
}

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const username = document.querySelector("#username").value.trim();
  const password = document.querySelector("#password").value;
  if (username === "admin" && password === "admin123") {
    loginView.classList.add("hidden");
    dashboardView.classList.remove("hidden");
    addLog(`User ${username} logged in`);
    return;
  }
  addLog(`Failed login attempt for ${username || "unknown user"}`);
  alert("Invalid demo credentials. Use admin / admin123");
});

logoutBtn.addEventListener("click", () => {
  dashboardView.classList.add("hidden");
  loginView.classList.remove("hidden");
  addLog("User logged out");
});

const rules = [
  ["At least 10 characters", (v) => v.length >= 10],
  ["Uppercase and lowercase letters", (v) => /[a-z]/.test(v) && /[A-Z]/.test(v)],
  ["Contains a number", (v) => /\d/.test(v)],
  ["Contains a symbol", (v) => /[^A-Za-z0-9]/.test(v)],
  ["Avoids common words", (v) => !/(password|admin|qwerty|welcome|login)/i.test(v)],
];

document.querySelector("#passwordCheck").addEventListener("input", (event) => {
  const value = event.target.value;
  const passed = rules.filter(([, test]) => test(value)).length;
  const percent = Math.round((passed / rules.length) * 100);
  const label = document.querySelector("#strengthLabel");
  const bar = document.querySelector("#strengthBar");
  const labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Excellent"];
  label.textContent = value ? labels[passed] : "Waiting";
  bar.style.width = `${percent}%`;
  bar.style.background = percent < 40 ? "var(--red)" : percent < 80 ? "var(--amber)" : "var(--green)";
  document.querySelector("#passwordRules").innerHTML = rules
    .map(([text, test]) => `<li class="${test(value) ? "pass" : ""}">${test(value) ? "PASS" : "CHECK"} - ${text}</li>`)
    .join("");
});

const cryptoFile = document.querySelector("#cryptoFile");
cryptoFile.addEventListener("change", () => {
  document.querySelector("#fileName").textContent = cryptoFile.files[0]?.name || "Choose a file";
});

async function getCryptoMaterial(passphrase, salt) {
  const encoded = new TextEncoder().encode(passphrase);
  const material = await crypto.subtle.importKey("raw", encoded, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 120000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptFile() {
  const file = cryptoFile.files[0];
  const passphrase = document.querySelector("#cryptoKey").value;
  if (!file || !passphrase) return alert("Select a file and enter a passphrase.");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getCryptoMaterial(passphrase, salt);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, await file.arrayBuffer());
  downloadBlob(new Blob([salt, iv, new Uint8Array(encrypted)]), `${file.name}.encrypted`);
  state.encryptedFiles += 1;
  addLog(`Encrypted ${file.name}`);
  renderReport();
}

async function decryptFile() {
  const file = cryptoFile.files[0];
  const passphrase = document.querySelector("#cryptoKey").value;
  if (!file || !passphrase) return alert("Select an encrypted file and enter the passphrase.");
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const salt = bytes.slice(0, 16);
    const iv = bytes.slice(16, 28);
    const data = bytes.slice(28);
    const key = await getCryptoMaterial(passphrase, salt);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    downloadBlob(new Blob([decrypted]), file.name.replace(/\.encrypted$/i, "") || "decrypted-file");
    addLog(`Decrypted ${file.name}`);
  } catch {
    addLog(`Failed to decrypt ${file.name}`);
    alert("Decryption failed. Check the passphrase and file.");
  }
}

function downloadBlob(blob, fileName) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}

document.querySelector("#encryptBtn").addEventListener("click", encryptFile);
document.querySelector("#decryptBtn").addEventListener("click", decryptFile);

document.querySelector("#scanBtn").addEventListener("click", async () => {
  const host = document.querySelector("#scanHost").value.trim() || "localhost";
  const ports = document.querySelector("#scanPorts").value
    .split(",")
    .map((port) => Number(port.trim()))
    .filter((port) => Number.isInteger(port) && port > 0 && port <= 65535)
    .slice(0, 24);

  const results = await Promise.all(ports.map((port) => probePort(host, port)));
  state.openPorts = results.filter((result) => result.open).length;
  document.querySelector("#scanResults").innerHTML = results.map((result) => `
    <div class="port-chip ${result.open ? "open" : "closed"}">
      <strong>${result.port}</strong>
      <small>${result.open ? "Open / reachable" : "Closed / blocked"}</small>
    </div>
  `).join("");
  addLog(`Scanned ${host} on ${ports.length} port(s)`);
  renderReport();
});

function probePort(host, port) {
  return new Promise((resolve) => {
    const img = new Image();
    const timeout = setTimeout(() => resolve({ port, open: likelyWebService(port) }), 900);
    img.onload = img.onerror = () => {
      clearTimeout(timeout);
      resolve({ port, open: true });
    };
    img.src = `http://${host}:${port}/favicon.ico?scan=${Date.now()}`;
  });
}

function likelyWebService(port) {
  return [80, 443, 3000, 5000, 5173, 8000, 8080].includes(port);
}

document.querySelector("#generateOtp").addEventListener("click", () => {
  state.currentOtp = String(Math.floor(100000 + Math.random() * 900000));
  state.otpExpiresAt = Date.now() + 60000;
  document.querySelector("#otpCode").textContent = state.currentOtp;
  document.querySelector("#otpStatus").textContent = "60s Valid";
  addLog("Generated demo OTP");
});

document.querySelector("#verifyOtp").addEventListener("click", () => {
  const value = document.querySelector("#otpInput").value.trim();
  const status = document.querySelector("#otpStatus");
  if (!state.currentOtp || Date.now() > state.otpExpiresAt) {
    status.textContent = "Expired";
    addLog("OTP verification failed: expired");
    return alert("OTP expired. Generate a new one.");
  }
  if (value === state.currentOtp) {
    status.textContent = "Verified";
    addLog("OTP verification passed");
    return;
  }
  status.textContent = "Failed";
  addLog("OTP verification failed: wrong code");
});

function renderHealth() {
  const cpu = 28 + Math.floor(Math.random() * 48);
  const memory = 36 + Math.floor(Math.random() * 42);
  const network = 18 + Math.floor(Math.random() * 62);
  document.querySelector("#cpuLoad").textContent = `${cpu}%`;
  document.querySelector("#memoryLoad").textContent = `${memory}%`;
  document.querySelector("#networkLoad").textContent = `${network}%`;
  document.querySelector("#healthTag").textContent = Math.max(cpu, memory, network) > 76 ? "Watch" : "Stable";
}

document.querySelector("#refreshHealth").addEventListener("click", () => {
  renderHealth();
  addLog("Refreshed system health");
});

function renderFirewallRules() {
  const list = document.querySelector("#firewallRules");
  list.innerHTML = state.firewallRules.length
    ? state.firewallRules.map((rule) => `
      <li>
        <span>${escapeHtml(rule)}</span>
        <button class="secondary-button small" data-remove-rule="${escapeHtml(rule)}" type="button">Allow</button>
      </li>
    `).join("")
    : "<li><span>No blocked IPs or domains yet.</span></li>";
  localStorage.setItem("cyberFirewallRules", JSON.stringify(state.firewallRules));
  renderReport();
}

document.querySelector("#addFirewallRule").addEventListener("click", () => {
  const input = document.querySelector("#firewallInput");
  const value = input.value.trim();
  if (!value) return alert("Enter an IP or domain.");
  if (!state.firewallRules.includes(value)) state.firewallRules.unshift(value);
  input.value = "";
  addLog(`Blocked ${value} in firewall simulator`);
  renderFirewallRules();
});

document.querySelector("#firewallRules").addEventListener("click", (event) => {
  const rule = event.target.dataset.removeRule;
  if (!rule) return;
  state.firewallRules = state.firewallRules.filter((item) => item !== rule);
  addLog(`Removed firewall rule for ${rule}`);
  renderFirewallRules();
});

function renderIncidents() {
  const list = document.querySelector("#incidentList");
  document.querySelector("#incidentStatus").textContent = `${state.incidents.length} Open`;
  list.innerHTML = state.incidents.length
    ? state.incidents.map((incident) => `
      <li>
        <span>${escapeHtml(incident)}</span>
        <button class="secondary-button small" data-close-incident="${escapeHtml(incident)}" type="button">Close</button>
      </li>
    `).join("")
    : "<li><span>No active incidents.</span></li>";
  localStorage.setItem("cyberIncidents", JSON.stringify(state.incidents));
  renderReport();
}

document.querySelector("#addIncident").addEventListener("click", () => {
  const input = document.querySelector("#incidentInput");
  const value = input.value.trim();
  if (!value) return alert("Describe the incident.");
  state.incidents.unshift(value);
  input.value = "";
  addLog(`Added incident: ${value}`);
  renderIncidents();
});

document.querySelector("#incidentList").addEventListener("click", (event) => {
  const incident = event.target.dataset.closeIncident;
  if (!incident) return;
  state.incidents = state.incidents.filter((item) => item !== incident);
  addLog(`Closed incident: ${incident}`);
  renderIncidents();
});

const checklistItems = [
  "Enable multi-factor authentication",
  "Use strong password policy",
  "Encrypt sensitive files",
  "Review open ports",
  "Block suspicious IPs",
  "Download weekly security report",
  "Keep activity logs reviewed",
  "Patch operating system and apps",
];

function getChecklistScore() {
  const complete = checklistItems.filter((item) => state.checklist[item]).length;
  return Math.round((complete / checklistItems.length) * 100);
}

function renderChecklist() {
  document.querySelector("#securityChecklist").innerHTML = checklistItems.map((item) => `
    <label class="check-item">
      <input type="checkbox" data-check-item="${escapeHtml(item)}" ${state.checklist[item] ? "checked" : ""} />
      <span>${escapeHtml(item)}</span>
    </label>
  `).join("");
  document.querySelector("#checklistScore").textContent = `${getChecklistScore()}%`;
  localStorage.setItem("cyberChecklist", JSON.stringify(state.checklist));
  renderReport();
}

document.querySelector("#securityChecklist").addEventListener("change", (event) => {
  const item = event.target.dataset.checkItem;
  if (!item) return;
  state.checklist[item] = event.target.checked;
  addLog(`${event.target.checked ? "Completed" : "Reopened"} checklist item: ${item}`);
  renderChecklist();
});

document.querySelector("#downloadReport").addEventListener("click", () => {
  const report = [
    "Cyber Sentinel Security Report",
    `Generated: ${new Date().toLocaleString()}`,
    `Risk Score: ${riskScoreEl.textContent}/100`,
    `Encrypted Files: ${state.encryptedFiles}`,
    `Open Ports Found: ${state.openPorts}`,
    `Active Incidents: ${state.incidents.length}`,
    `Firewall Rules: ${state.firewallRules.length}`,
    `Checklist Score: ${getChecklistScore()}%`,
    "",
    "Firewall Rules:",
    ...(state.firewallRules.length ? state.firewallRules : ["No rules"]),
    "",
    "Open Incidents:",
    ...(state.incidents.length ? state.incidents : ["No incidents"]),
    "",
    "Recent Activity:",
    ...state.logs.slice(0, 10),
  ].join("\n");
  downloadBlob(new Blob([report], { type: "text/plain" }), "security-report.txt");
  addLog("Downloaded security report");
});

document.querySelector("#clearLogs").addEventListener("click", () => {
  state.logs = [];
  localStorage.removeItem("cyberLogs");
  renderLogs();
});

renderLogs();
renderHealth();
renderFirewallRules();
renderIncidents();
renderChecklist();
document.querySelector("#passwordCheck").dispatchEvent(new Event("input"));
document.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !dashboardView.classList.contains("hidden")) {
        return;
    }

    if (e.key === "Enter") {
        e.preventDefault();
        loginForm.requestSubmit();
    }
});