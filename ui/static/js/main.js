function getSelectedDate() {
    const input = document.getElementById("date-input");
    return input.value;
}

async function fetchJSON(url) {
    const res = await fetch(url);
    if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    return res.json();
}

// Always return a list to avoid ".map is not a function"
function asList(x) {
    if (Array.isArray(x)) return x;
    if (x == null) return [];
    return [x];
}

function renderSessionsList(data) {
    const container = document.getElementById("sessions-list");
    container.innerHTML = "";

    const allSessions = data.sessions || [];
    const filterEl = document.getElementById("sensor-filter");
    const currentFilter = filterEl ? filterEl.value : "all";

    const sessions = allSessions.filter(
        (s) => currentFilter === "all" || s.sensor === currentFilter
    );

    if (sessions.length === 0) {
        container.innerHTML = "<p>No sessions for this date.</p>";
        return;
    }

    sessions.forEach((s) => {
        const item = document.createElement("div");
        item.className = "session-item";
        item.dataset.sessionId = s.session_id;

        const header = document.createElement("div");
        header.className = "session-item-header";
        header.innerHTML = `
            <span class="sensor">${(s.sensor || "?").toUpperCase()}</span>
            <span class="session-id">${s.session_id || ""}</span>
        `;

        const meta = document.createElement("div");
        meta.className = "session-item-meta";
        meta.innerHTML = `
            <span class="intent">${s.attack_intent || "unknown"}</span>
            <span class="risk">Risk: ${
                s.risk_score != null ? s.risk_score : "?"
            }</span>
        `;

        const summary = document.createElement("div");
        summary.className = "session-item-summary";
        summary.textContent = s.short_summary || "";

        item.appendChild(header);
        item.appendChild(meta);
        item.appendChild(summary);

        item.addEventListener("click", () => {
            const date = getSelectedDate();
            loadSessionDetail(date, s.session_id);

            document
                .querySelectorAll(".session-item.selected")
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

    const signatures = asList(key.signatures)
        .map(s => `<li>${s}</li>`).join("");

    return `
        <div class="block">
            <h3>Key indicators</h3>
            <p><strong>Source IP:</strong> ${key.src_ip || "?"}</p>
            <p><strong>Destination IP:</strong> ${key.dest_ip || "?"}</p>
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
            <ul>${signatures || "<li>None</li>"}</ul>
        </div>
    `;
}

function renderMitreCandidates(list) {
    list = asList(list);
    if (list.length === 0) return "<p>No MITRE candidates.</p>";

    const items = list.map(m => `
        <li>
            <span class="badge">${m.tid}</span>
            <span>${m.name}</span>
            <span class="score">dist: ${m.distance?.toFixed(3)}</span>
            <a href="${m.mitre_url}" target="_blank">open</a>
        </li>
    `).join("");

    return `
        <div class="block">
            <h3>MITRE candidates</h3>
            <ul class="list">${items}</ul>
        </div>
    `;
}

function renderSigmaCandidates(list) {
    list = asList(list);
    if (list.length === 0) return "<p>No Sigma candidates.</p>";

    const items = list.map(s => `
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
                <button class="sigma-view-btn" data-sid="${s.sid}">View Sigma rule</button>
            </div>
        </li>
    `).join("");

    return `
        <div class="block">
            <h3>Sigma candidates</h3>
            <ul class="list">${items}</ul>
        </div>
    `;
}

function renderSuricataAlerts(list) {
    list = asList(list);
    if (list.length === 0) return "<p>No Suricata alerts.</p>";

    const items = list.map(a => `
        <li>
            <span class="badge">${a.sid}</span>
            <span>${a.message}</span>
            <span class="sigma-meta">${a.category}</span>
            <span class="sigma-meta">prio: ${a.priority}</span>
        </li>
    `).join("");

    return `
        <div class="block">
            <h3>Suricata alerts</h3>
            <ul class="list">${items}</ul>
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
    const startTs = ts.start || "";
    const endTs = ts.end || "";

    container.innerHTML = `
        <div class="block">
            <h3>Overview</h3>
            <p><strong>Session ID:</strong> ${data.session_id}</p>
            <p><strong>Sensor:</strong> ${data.sensor}</p>
            <p><strong>Intent:</strong> ${data.attack_intent}</p>
            <p><strong>Risk score:</strong> ${data.risk_score}</p>
            <p><strong>Confidence:</strong> ${data.confidence}</p>
            <p><strong>Time range:</strong> ${startTs} → ${endTs}</p>
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

    // Raw JSON toggle
    const rawBtn = document.getElementById("show-raw-json");
    const rawPre = document.getElementById("raw-json");

    rawBtn.addEventListener("click", () => {
        if (rawPre.classList.contains("hidden")) {
            rawPre.textContent = JSON.stringify(data, null, 2);
            rawPre.classList.remove("hidden");
            rawBtn.textContent = "Hide raw JSON";
        } else {
            rawPre.classList.add("hidden");
            rawBtn.textContent = "Show raw JSON";
        }
    });

    // Sigma modal buttons
    document.querySelectorAll(".sigma-view-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            openSigmaModal(btn.dataset.sid);
        });
    });
}

// Load sessions for the selected date
async function loadSessions(date) {
    try {
        const data = await fetchJSON(`/api/sessions?date=${encodeURIComponent(date)}`);
        renderSessionsList(data);

        if (data.sessions && data.sessions.length > 0) {
            const first = data.sessions[0];
            loadSessionDetail(date, first.session_id);
        }
    } catch (err) {
        document.getElementById("sessions-list").innerHTML =
            `<p>Error loading sessions: ${err.message}</p>`;
    }
}

async function loadSessionDetail(date, sessionId) {
    try {
        const data = await fetchJSON(
            `/api/session/${encodeURIComponent(sessionId)}?date=${encodeURIComponent(date)}`
        );
        renderSessionDetail(data);
    } catch (err) {
        document.getElementById("session-detail").innerHTML =
            `<p>Error loading session detail: ${err.message}</p>`;
    }
}

// Modal setup
function setupSigmaModal() {
    const modal = document.getElementById("sigma-modal");
    const backdrop = document.getElementById("sigma-modal-backdrop");
    const closeBtn = document.getElementById("sigma-modal-close");

    function close() {
        modal.classList.add("hidden");
        document.getElementById("sigma-modal-body").textContent = "";
    }

    backdrop.addEventListener("click", close);
    closeBtn.addEventListener("click", close);

    document.addEventListener("keydown", (ev) => {
        if (ev.key === "Escape" && !modal.classList.contains("hidden")) {
            close();
        }
    });
}

async function openSigmaModal(sid) {
    const modal = document.getElementById("sigma-modal");
    const title = document.getElementById("sigma-modal-title");
    const body = document.getElementById("sigma-modal-body");

    title.textContent = `Sigma rule: ${sid}`;
    body.textContent = "Loading...";
    modal.classList.remove("hidden");

    try {
        const data = await fetchJSON(`/api/sigma/${encodeURIComponent(sid)}`);
        const meta = data.metadata || {};
        const doc = data.document || "";

        const header = [];
        if (meta.title) header.push(`# ${meta.title}`);
        if (meta.sid) header.push(`# SID: ${meta.sid}`);
        if (meta.level) header.push(`# Level: ${meta.level}`);
        if (meta.mitre_techniques) header.push(`# MITRE: ${meta.mitre_techniques}`);

        body.textContent = header.join("\n") + "\n\n" + doc;
    } catch (err) {
        body.textContent = `Error loading Sigma rule: ${err.message}`;
    }
}

// DOM ready
document.addEventListener("DOMContentLoaded", () => {
    setupSigmaModal();

    document.getElementById("reload-btn").addEventListener("click", () => {
        loadSessions(getSelectedDate());
    });

    // Sensor filter
    document.getElementById("sensor-filter").addEventListener("change", () => {
        loadSessions(getSelectedDate());
    });

    loadSessions(getSelectedDate());
});
