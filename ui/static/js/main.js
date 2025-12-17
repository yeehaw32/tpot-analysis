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

function fmtTime(ts) {
    if (!ts) return "-";
    if (typeof ts === "string" && ts.includes("T")) {
        const timePart = ts.split("T")[1] || "";
        return timePart.replace("Z", "").split(".")[0] || ts;
    }
    return ts;
}

function distanceHelpText() {
    return `Distance is a similarity score from the RAG matching. Lower = closer match, higher = weaker match.`;
}

function renderSessionsList(data) {
    const container = document.getElementById("sessions-list");
    container.innerHTML = "";

    const all = data.sessions || [];
    const f = document.getElementById("sensor-filter").value;

    const sessions = all.filter(s => f === "all" || s.sensor === f);

    if (sessions.length === 0) {
        container.innerHTML = "<p style='color:var(--muted); margin:8px 4px;'>No sessions for this date.</p>";
        return;
    }

    sessions.forEach((s) => {
        const item = document.createElement("div");
        item.className = "session-item";
        item.dataset.sessionId = s.session_id;

        // Summary moved to tooltip to keep list compact
        if (s.short_summary) item.title = s.short_summary;

        const srcIp = s.src_ip || "-";
        const dstIp = s.dest_ip || "-";
        const start = fmtTime(s.start_time);

        item.innerHTML = `
            <div class="session-item-top">
                <span class="sensor-chip">${(s.sensor || "?").toUpperCase()}</span>
                <span class="risk-badge">Risk ${s.risk_score ?? "?"}</span>
            </div>

            <div class="session-item-main">
                <div class="session-intent">${s.attack_intent || "unknown"}</div>
                <div class="session-id">${s.session_id}</div>
            </div>

            <div class="session-item-sub">
                <span class="session-ips">${srcIp} → ${dstIp}</span>
                <span class="session-time">${start}</span>
            </div>
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
    if (!key) return "<div class='block'><p style='margin:0; color:var(--muted);'>No key indicators.</p></div>";

    const srcPorts = asList(key.src_ports).join(", ");
    const destPorts = asList(key.dest_ports).join(", ");
    const protocols = asList(key.protocols).join(", ");

    const commands = asList(key.commands)
        .map(c => `<li><code>${c}</code></li>`).join("");

    const urls = asList(key.urls)
        .map(u => `<li><a href="${u}" target="_blank" rel="noreferrer">${u}</a></li>`).join("");

    const files = asList(key.files)
        .map(f => `<li><code>${f}</code></li>`).join("");

    const sigs = asList(key.signatures)
        .map(s => `<li>${s}</li>`).join("");

    return `
        <div class="block">
            <div class="block-header">
                <h3>Session Observables</h3>    
                <span class="chip">Extracted from events</span>
            </div>

            <dl class="kv">
                <dt>Source IP</dt><dd>${key.src_ip || "-"}</dd>
                <dt>Destination IP</dt><dd>${key.dest_ip || "-"}</dd>
                <dt>Source ports</dt><dd>${srcPorts || "-"}</dd>
                <dt>Destination ports</dt><dd>${destPorts || "-"}</dd>
                <dt>Protocols</dt><dd>${protocols || "-"}</dd>
            </dl>

            <h4>Commands</h4>
            <ul class="list" style="gap:4px;">${commands || "<li style='color:var(--muted);'>None</li>"}</ul>

            <h4>URLs</h4>
            <ul class="list" style="gap:4px;">${urls || "<li style='color:var(--muted);'>None</li>"}</ul>

            <h4>Files</h4>
            <ul class="list" style="gap:4px;">${files || "<li style='color:var(--muted);'>None</li>"}</ul>

            <h4>Signatures</h4>
            <ul class="list" style="gap:4px;">${sigs || "<li style='color:var(--muted);'>None</li>"}</ul>
        </div>
    `;
}

function renderMitreCandidates(list) {
    const full = asList(list);
    const total = full.length;
    const top = full.slice(0, 3);

    return `
        <details class="block" open>
            <summary class="block-header">
                <h3 style="margin:0;">MITRE candidates</h3>
                <span class="chip">AI Layer 2 (RAG enrichment)</span>
            </summary>

            <p class="section-help">${distanceHelpText()}</p>
            ${total > 3 ? `<p class="section-subtle">Showing top 3 of ${total} results.</p>` : ""}

            ${top.length === 0 ? "<p style='margin:0; color:var(--muted);'>No MITRE candidates.</p>" : `
            <ul class="list">
                ${top.map(m => `
                    <li class="mitre-card">
                        <div class="mitre-left">
                            <div class="mitre-title">
                                <span class="badge">${m.tid}</span>
                                <span>${m.name}</span>
                            </div>
                            <div class="mitre-meta">
                                <span class="pill">dist ${m.distance?.toFixed(3)}</span>
                            </div>
                        </div>
                        <div class="mitre-right">
                            <a href="${m.mitre_url}" target="_blank" rel="noreferrer">open</a>
                        </div>
                    </li>
                `).join("")}
            </ul>`}
        </details>
    `;
}

function renderSigmaCandidates(list) {
    const full = asList(list);
    const total = full.length;
    const top = full.slice(0, 3);

    return `
        <details class="block" open>
            <summary class="block-header">
                <h3 style="margin:0;">Sigma candidates</h3>
                <span class="chip">AI Layer 2 (RAG enrichment)</span>
            </summary>

            <p class="section-help">${distanceHelpText()}</p>
            ${total > 3 ? `<p class="section-subtle">Showing top 3 of ${total} results.</p>` : ""}

            ${top.length === 0 ? "<p style='margin:0; color:var(--muted);'>No Sigma candidates.</p>" : `
            <ul class="list">
                ${top.map(s => `
                    <li class="sigma-card">
                        <div class="sigma-title">${s.title}</div>

                        <div class="sigma-meta">
                            <span>${(s.logsource_product || "").toLowerCase()}${s.logsource_service ? ` · ${s.logsource_service}` : ""}</span>
                            <span>level: ${s.level || "-"}</span>
                            <span class="pill">dist ${s.distance?.toFixed(3)}</span>
                        </div>

                        <button class="sigma-view-btn" data-sid="${s.sid}" data-title="${(s.title || "").replace(/"/g, "&quot;")}">
                            View Sigma rule
                        </button>
                    </li>
                `).join("")}
            </ul>`}
        </details>
    `;
}

function renderSessionDetail(data) {
    const container = document.getElementById("session-detail");

    const key = data.key_indicators;
    const mitre = asList(data.mitre_candidates);
    const sigma = asList(data.sigma_candidates);

    const ts = data.timestamp_range || {};
    const start = ts.start || "";
    const end = ts.end || "";

    container.innerHTML = `
        <div class="detail-grid">

            <div class="detail-col">
                <div class="block">
                    <div class="block-header">
                        <h3>Overview</h3>
                        <span class="chip">AI Layer 1</span>
                    </div>

                    <dl class="kv">
                        <dt>Session ID</dt><dd>${data.session_id || "-"}</dd>
                        <dt>Sensor</dt><dd class="normal">${data.sensor || "-"}</dd>
                        <dt>Intent</dt><dd class="normal">${data.attack_intent || "-"}</dd>
                        <dt>Risk score</dt><dd>${data.risk_score ?? "-"}</dd>
                        <dt>Confidence</dt><dd>${data.confidence ?? "-"}</dd>
                        <dt>Time range</dt><dd class="normal">${start} → ${end}</dd>
                    </dl>
                </div>

                <div class="block">
                    <div class="block-header">
                        <h3>Summary</h3>
                        <span class="chip">AI Layer 1</span>
                    </div>
                    <p style="margin:0; line-height:1.45;">${data.summary || "-"}</p>
                </div>

                ${renderKeyIndicators(key)}

                <details class="block">
                    <summary class="block-header">
                        <h3 style="margin:0;">Raw JSON</h3>
                        <span class="chip">Audit</span>
                    </summary>
                    <pre id="raw-json"></pre>
                </details>
            </div>

            <div class="detail-col">
                ${renderMitreCandidates(mitre)}
                ${renderSigmaCandidates(sigma)}
            </div>

        </div>
    `;

    const rawPre = document.getElementById("raw-json");
    if (rawPre) rawPre.textContent = JSON.stringify(data, null, 2);

    document.querySelectorAll(".sigma-view-btn").forEach(btn => {
        btn.addEventListener("click", () => openSigmaModal(btn.dataset.sid, btn.dataset.title));
    });
}

function selectSessionInList(sessionId) {
    const el = document.querySelector(`.session-item[data-session-id="${sessionId}"]`);
    if (!el) return;

    document.querySelectorAll(".session-item.selected")
        .forEach(x => x.classList.remove("selected"));
    el.classList.add("selected");
    el.scrollIntoView({ block: "nearest" });
}

async function loadSessions(date) {
    try {
        const data = await fetchJSON(`/api/sessions?date=${date}`);
        renderSessionsList(data);

        if (data.sessions?.length) {
            const firstId = data.sessions[0].session_id;
            await loadSessionDetail(date, firstId);
            selectSessionInList(firstId);
        } else {
            document.getElementById("session-detail").innerHTML =
                `<p style="color:var(--muted); margin:0;">Select a session to view details.</p>`;
        }
    } catch (err) {
        document.getElementById("sessions-list").innerHTML =
            `<p style="color:var(--muted); margin:8px 4px;">Error loading sessions: ${err.message}</p>`;
    }
}

async function loadSessionDetail(date, sessionId) {
    try {
        const data = await fetchJSON(`/api/session/${sessionId}?date=${date}`);
        renderSessionDetail(data);
    } catch (err) {
        document.getElementById("session-detail").innerHTML =
            `<p style="color:var(--muted); margin:0;">Error loading session detail: ${err.message}</p>`;
    }
}

function setupSigmaModal() {
    const modal = document.getElementById("sigma-modal");
    const backdrop = document.getElementById("sigma-modal-backdrop");
    const close = document.getElementById("sigma-modal-close");

    function hide() {
        modal.classList.add("hidden");
        const body = document.getElementById("sigma-modal-body");
        body.textContent = "";
        body.classList.remove("hljs", "language-yaml");
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

async function openSigmaModal(sid, titleText) {
    const modal   = document.getElementById("sigma-modal");
    const title   = document.getElementById("sigma-modal-title");
    const body    = document.getElementById("sigma-modal-body");
    const copyBtn = document.getElementById("sigma-copy-btn");

    title.textContent = titleText ? `Sigma rule: ${titleText}` : `Sigma rule`;
    body.textContent  = "Loading...";
    modal.classList.remove("hidden");

    try {
        const data = await fetchJSON(`/api/sigma/${encodeURIComponent(sid)}`);
        const meta = data.metadata || {};

        const yaml =
            data.yaml ||
            meta.yaml_raw ||
            data.document ||
            "No YAML content available";

        const plainYaml = yaml;

        if (window.hljs) {
            const result = hljs.highlight(yaml, { language: "yaml" });
            body.innerHTML = result.value;
            body.classList.add("hljs", "language-yaml");
            hljs.highlightElement(body);
        } else {
            body.textContent = yaml;
        }

        copyBtn.onclick = () => {
            navigator.clipboard.writeText(plainYaml)
                .then(() => {
                    copyBtn.textContent = "Copied!";
                    setTimeout(() => copyBtn.textContent = "Copy to clipboard", 1200);
                })
                .catch(() => {
                    copyBtn.textContent = "Copy failed";
                    setTimeout(() => copyBtn.textContent = "Copy to clipboard", 1200);
                });
        };

    } catch (err) {
        body.textContent = `Error loading Sigma rule: ${err.message}`;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    setupSigmaModal();

    const themeBtn = document.getElementById("theme-toggle");
    if (themeBtn) {
        const saved = localStorage.getItem("ui_theme");
        if (saved) {
            document.body.classList.toggle("theme-light", saved === "light");
            themeBtn.textContent = (saved === "light") ? "Dark mode" : "Light mode";
        }

        themeBtn.addEventListener("click", () => {
            const isLight = document.body.classList.toggle("theme-light");
            localStorage.setItem("ui_theme", isLight ? "light" : "dark");
            themeBtn.textContent = isLight ? "Dark mode" : "Light mode";
        });
    }

    document.getElementById("reload-btn").addEventListener("click", () => {
        loadSessions(getSelectedDate());
    });

    document.getElementById("sensor-filter").addEventListener("change", () => {
        loadSessions(getSelectedDate());
    });

    loadSessions(getSelectedDate());
});
