function getSelectedDate() {
    const input = document.getElementById("date-input");
    return input.value;
}

async function fetchJSON(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return res.json();
}

function asList(x) {
    if (Array.isArray(x)) return x;
    if (x == null) return [];
    return [x];
}

function renderSessionsList(data) {
    const container = document.getElementById("sessions-list");
    container.innerHTML = "";

    const all = data.sessions || [];
    const f = document.getElementById("sensor-filter").value;

    const sessions = all.filter(s => f === "all" || s.sensor === f);

    if (sessions.length === 0) {
        container.innerHTML = "<p>No sessions for this date.</p>";
        return;
    }

    sessions.forEach((s) => {
        const item = document.createElement("div");
        item.className = "session-item";
        item.dataset.sessionId = s.session_id;

        item.innerHTML = `
            <div class="session-item-header">
                <span class="sensor">${(s.sensor || "?").toUpperCase()}</span>
                <span class="session-id">${s.session_id}</span>
            </div>
            <div class="session-item-meta">
                <span class="intent">${s.attack_intent || "unknown"}</span>
                <span class="risk">Risk: ${s.risk_score ?? "?"}</span>
            </div>
            <div class="session-item-summary">${s.short_summary || ""}</div>
        `;

        item.addEventListener("click", () => {
            loadSessionDetail(getSelectedDate(), s.session_id);

            document.querySelectorAll(".session-item.selected")
                .forEach(el => el.classList.remove("selected"));
            item.classList.add("selected");
        });

        container.appendChild(item);
    });
}

function renderKeyIndicators(key) {
    if (!key) return "<p>No key indicators.</p>";

    const srcPorts = asList(key.src_ports).join(", ");
    const destPorts = asList(key.dest_ports).join(", ");
    const protocols = asList(key.protocols).join(", ");

    const commands = asList(key.commands)
        .map(c => `<li><code>${c}</code></li>`).join("");

    const urls = asList(key.urls)
        .map(u => `<li><a href="${u}" target="_blank">${u}</a></li>`).join("");

    const files = asList(key.files)
        .map(f => `<li><code>${f}</code></li>`).join("");

    const sigs = asList(key.signatures)
        .map(s => `<li>${s}</li>`).join("");

    return `
        <div class="block">
            <h3>Key indicators</h3>
            <p><strong>Source IP:</strong> ${key.src_ip}</p>
            <p><strong>Destination IP:</strong> ${key.dest_ip}</p>
            <p><strong>Source ports:</strong> ${srcPorts || "-"}</p>
            <p><strong>Destination ports:</strong> ${destPorts || "-"}</p>
            <p><strong>Protocols:</strong> ${protocols || "-"}</p>

            <h4>Commands</h4>
            <ul>${commands || "<li>None</li>"}</ul>

            <h4>URLs</h4>
            <ul>${urls || "<li>None</li>"}</ul>

            <h4>Files</h4>
            <ul>${files || "<li>None</li>"}</ul>

            <h4>Signatures</h4>
            <ul>${sigs || "<li>None</li>"}</ul>
        </div>
    `;
}

function renderMitreCandidates(list) {
    list = asList(list);
    if (list.length === 0) return "<p>No MITRE candidates.</p>";

    return `
        <div class="block">
            <h3>MITRE candidates</h3>
            <ul class="list">
                ${list.map(m => `
                    <li>
                        <span class="badge">${m.tid}</span>
                        <span>${m.name}</span>
                        <span class="score">dist: ${m.distance?.toFixed(3)}</span>
                        <a href="${m.mitre_url}" target="_blank">open</a>
                    </li>
                `).join("")}
            </ul>
        </div>
    `;
}

function renderSigmaCandidates(list) {
    list = asList(list);
    if (list.length === 0) return "<p>No Sigma candidates.</p>";

    return `
        <div class="block">
            <h3>Sigma candidates</h3>
            <ul class="list">
                ${list.map(s => `
                    <li>
                        <div class="sigma-row">
                            <div>
                                <span class="badge">${s.sid}</span>
                                <span class="sigma-title">${s.title}</span>
                            </div>
                            <div class="sigma-meta">
                                <span>${s.logsource_product} ${s.logsource_service}</span>
                                <span>level: ${s.level}</span>
                                <span>dist: ${s.distance?.toFixed(3)}</span>
                            </div>
                            <button class="sigma-view-btn" data-sid="${s.sid}">
                                View Sigma rule
                            </button>
                        </div>
                    </li>
                `).join("")}
            </ul>
        </div>
    `;
}

function renderSuricataAlerts(list) {
    list = asList(list);
    if (list.length === 0) return "<p>No Suricata alerts.</p>";

    return `
        <div class="block">
            <h3>Suricata alerts</h3>
            <ul class="list">
                ${list.map(a => `
                    <li>
                        <span class="badge">${a.sid}</span>
                        <span>${a.message}</span>
                        <span>${a.category}</span>
                        <span>prio: ${a.priority}</span>
                    </li>
                `).join("")}
            </ul>
        </div>
    `;
}

function renderSessionDetail(data) {
    const container = document.getElementById("session-detail");

    const key = data.key_indicators;
    const mitre = asList(data.mitre_candidates);
    const sigma = asList(data.sigma_candidates);
    const alerts = asList(data.suricata_alerts);

    const ts = data.timestamp_range || {};
    const start = ts.start || "";
    const end = ts.end || "";

    container.innerHTML = `
        <div class="block">
            <h3>Overview</h3>
            <p><strong>Session ID:</strong> ${data.session_id}</p>
            <p><strong>Sensor:</strong> ${data.sensor}</p>
            <p><strong>Intent:</strong> ${data.attack_intent}</p>
            <p><strong>Risk score:</strong> ${data.risk_score}</p>
            <p><strong>Confidence:</strong> ${data.confidence}</p>
            <p><strong>Time range:</strong> ${start} → ${end}</p>
        </div>

        <div class="block">
            <h3>Summary</h3>
            <p>${data.summary}</p>
        </div>

        ${renderKeyIndicators(key)}
        ${renderMitreCandidates(mitre)}
        ${renderSigmaCandidates(sigma)}
        ${renderSuricataAlerts(alerts)}

        <div class="block">
            <h3>Raw JSON</h3>
            <button id="show-raw-json">Show raw JSON</button>
            <pre id="raw-json" class="hidden"></pre>
        </div>
    `;

    document.getElementById("show-raw-json").addEventListener("click", () => {
        const pre = document.getElementById("raw-json");
        if (pre.classList.contains("hidden")) {
            pre.textContent = JSON.stringify(data, null, 2);
            pre.classList.remove("hidden");
            event.target.textContent = "Hide raw JSON";
        } else {
            pre.classList.add("hidden");
            event.target.textContent = "Show raw JSON";
        }
    });

    document.querySelectorAll(".sigma-view-btn").forEach(btn => {
        btn.addEventListener("click", () => openSigmaModal(btn.dataset.sid));
    });
}

async function loadSessions(date) {
    try {
        const data = await fetchJSON(`/api/sessions?date=${date}`);
        renderSessionsList(data);

        if (data.sessions?.length)
            loadSessionDetail(date, data.sessions[0].session_id);
    } catch (err) {
        document.getElementById("sessions-list").innerHTML =
            `<p>Error loading sessions: ${err.message}</p>`;
    }
}

async function loadSessionDetail(date, sessionId) {
    try {
        const data = await fetchJSON(
            `/api/session/${sessionId}?date=${date}`
        );
        renderSessionDetail(data);
    } catch (err) {
        document.getElementById("session-detail").innerHTML =
            `<p>Error loading session detail: ${err.message}</p>`;
    }
}

function setupSigmaModal() {
    const modal = document.getElementById("sigma-modal");
    const backdrop = document.getElementById("sigma-modal-backdrop");
    const close = document.getElementById("sigma-modal-close");

    function hide() {
        modal.classList.add("hidden");
        document.getElementById("sigma-modal-body").textContent = "";
    }

    close.addEventListener("click", hide);
    backdrop.addEventListener("click", hide);

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") hide();
    });

    document.getElementById("sigma-copy-btn").addEventListener("click", () => {
        const text = document.getElementById("sigma-modal-body").textContent;
        navigator.clipboard.writeText(text);
    });
}

async function openSigmaModal(sid) {
    const modal   = document.getElementById("sigma-modal");
    const title   = document.getElementById("sigma-modal-title");
    const body    = document.getElementById("sigma-modal-body");
    const copyBtn = document.getElementById("sigma-copy-btn");

    title.textContent = `Sigma rule: ${sid}`;
    body.textContent  = "Loading...";
    modal.classList.remove("hidden");

    try {
        const data = await fetchJSON(`/api/sigma/${encodeURIComponent(sid)}`);
        const meta = data.metadata || {};

        // Be robust: try all possible fields where YAML might live
        const yaml =
            data.yaml ||          // if backend returns { "yaml": "..." }
            meta.yaml_raw ||      // if stored in metadata
            data.document ||      // if YAML is the Chroma document
            "No YAML content available";

        // Save plain text for copy-to-clipboard
        const plainYaml = yaml;

        if (window.hljs) {
            // Let highlight.js parse and color the YAML
            const result = hljs.highlight(yaml, { language: "yaml" });
            body.innerHTML = result.value;
            body.classList.add("hljs", "language-yaml");
        } else {
            // Fallback if highlight.js not loaded
            body.textContent = yaml;
        }

        // Copy button
        if (copyBtn) {
            copyBtn.onclick = () => {
                navigator.clipboard.writeText(plainYaml)
                    .then(() => {
                        copyBtn.textContent = "Copied!";
                        setTimeout(() => { copyBtn.textContent = "Copy to clipboard"; }, 1500);
                    })
                    .catch(() => {
                        copyBtn.textContent = "Copy failed";
                        setTimeout(() => { copyBtn.textContent = "Copy to clipboard"; }, 1500);
                    });
            };
        }
    } catch (err) {
        body.textContent = `Error loading Sigma rule: ${err.message}`;
    }
}



document.addEventListener("DOMContentLoaded", () => {
    setupSigmaModal();

    document.getElementById("reload-btn").addEventListener("click", () => {
        loadSessions(getSelectedDate());
    });

    document.getElementById("sensor-filter").addEventListener("change", () => {
        loadSessions(getSelectedDate());
    });

    loadSessions(getSelectedDate());
});
