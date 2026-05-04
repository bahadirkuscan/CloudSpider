/* ── CloudSpider GUI — Application Logic ─────────────────────────── */

// ── State ────────────────────────────────────────────────────────────
let graphData = { nodes: [], links: [] };
let simulation = null;
let svg, gLinks, gNodes, gLabels, gLinkLabels;
let currentMode = "scratch";
let currentModal = null;
let logCount = 0;

// Tracks which nodes are compromised (ARN set)
let compromisedNodes = new Set();
// Tracks edge action status: key = "source|target|type", value = "taken"|"possible"|"blocked"
let edgeStatus = {};

function edgeKey(d) {
    const s = typeof d.source === "object" ? d.source.id : d.source;
    const t = typeof d.target === "object" ? d.target.id : d.target;
    return `${s}|${t}|${d.type}`;
}

// ── Node color map ───────────────────────────────────────────────────
const NODE_COLORS = {
    USER: "#58a6ff", ROLE: "#bc8cff", COMPUTE: "#f0883e",
    STORAGE: "#3fb950", GROUP: "#e3b341", UNKNOWN: "#8b949e"
};

// Edge status styles: taken = green solid, possible = amber dashed, blocked = gray dotted
const EDGE_STATUS_STYLES = {
    taken:    { color: "#3fb950", dash: "",    width: 2.5 },
    possible: { color: "#f0883e", dash: "8,4", width: 2   },
    blocked:  { color: "#484f58", dash: "3,5", width: 1.5 }
};

// ── Init ─────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    initGraph();
    initSocketIO();
    refreshCredentials();
    refreshSnapshots();
});

// ── SocketIO ─────────────────────────────────────────────────────────
function initSocketIO() {
    const socket = io();
    socket.on("log", (data) => {
        addLogLine(data.level, data.message);
    });
    socket.on("pipeline_status", (data) => {
        setPipelineStage(data.stage, data.message);
    });
}

// ── Sidebar Toggle ───────────────────────────────────────────────────
function toggleSection(id) {
    document.getElementById(id).classList.toggle("open");
}

function toggleLog() {
    document.getElementById("log-panel").classList.toggle("collapsed");
}

// ── Toast Notifications ──────────────────────────────────────────────
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = "0"; setTimeout(() => toast.remove(), 300); }, 4000);
}

// ── Log Console ──────────────────────────────────────────────────────
function addLogLine(level, message) {
    const body = document.getElementById("log-body");
    const line = document.createElement("div");
    line.className = "log-line";
    line.setAttribute("data-level", level);
    line.textContent = message;
    body.appendChild(line);
    body.scrollTop = body.scrollHeight;
    logCount++;
    document.getElementById("log-count").textContent = logCount;
}

// ── Pipeline Stage ───────────────────────────────────────────────────
function setPipelineStage(stage, message) {
    const el = document.getElementById("pipeline-stage");
    el.setAttribute("data-stage", stage);
    el.textContent = stage.replace("_", " ").toUpperCase();
    if (message) showToast(message, stage === "error" ? "error" : "success");
}

// ── Loading state helper ─────────────────────────────────────────────
function setLoading(btnId, loading) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    if (loading) { btn.classList.add("loading"); btn.disabled = true; }
    else { btn.classList.remove("loading"); btn.disabled = false; }
}

// ── API Helper ───────────────────────────────────────────────────────
async function api(url, method = "GET", body = null) {
    const opts = { method, headers: { "Content-Type": "application/json" } };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(url, opts);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    return data;
}

// ══════════════════════════════════════════════════════════════════════
// ── Credential Manager ───────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════

async function addCredential() {
    const name = document.getElementById("cred-name").value.trim();
    const key = document.getElementById("cred-key").value.trim();
    const secret = document.getElementById("cred-secret").value.trim();
    const token = document.getElementById("cred-token").value.trim();
    const region = document.getElementById("cred-region").value.trim() || "us-east-1";
    if (!name || !key || !secret) return showToast("Name, Access Key, and Secret are required.", "error");
    setLoading("btn-add-cred", true);
    try {
        await api("/api/credentials", "POST", { name, access_key_id: key, secret_access_key: secret, session_token: token, region });
        showToast(`Profile "${name}" added.`, "success");
        document.getElementById("cred-name").value = "";
        document.getElementById("cred-key").value = "";
        document.getElementById("cred-secret").value = "";
        document.getElementById("cred-token").value = "";
        refreshCredentials();
    } catch (e) { showToast(e.message, "error"); }
    setLoading("btn-add-cred", false);
}

async function refreshCredentials() {
    try {
        const creds = await api("/api/credentials");
        const list = document.getElementById("cred-list");
        list.innerHTML = "";
        creds.forEach(c => {
            const div = document.createElement("div");
            div.className = `cred-item ${c.is_active ? "active" : ""}`;
            div.innerHTML = `
                <div class="cred-item-info">
                    <div class="cred-item-name">${c.name}</div>
                    <div class="cred-item-region">${c.region}</div>
                </div>
                <div class="cred-item-actions">
                    ${c.is_active ? '<span style="color:var(--accent-green);font-size:12px">● Active</span>' :
                      `<button class="btn btn-sm btn-ghost" onclick="activateProfile('${c.name}')">Activate</button>`}
                    <button class="btn btn-sm btn-ghost" onclick="deleteProfile('${c.name}')" style="color:var(--accent-red)">✕</button>
                </div>`;
            list.appendChild(div);
        });
        const active = creds.find(c => c.is_active);
        const badge = document.getElementById("profile-badge");
        const text = document.getElementById("profile-badge-text");
        if (active) { badge.classList.add("active"); text.textContent = active.name; }
        else { badge.classList.remove("active"); text.textContent = "No Profile"; }
    } catch (e) { /* silent */ }
}

async function activateProfile(name) {
    try {
        const res = await api(`/api/credentials/${name}/activate`, "POST");
        showToast(`Profile "${name}" activated. Identity: ${res.identity.arn}`, "success");
        // Mark the user's ARN as compromised
        compromisedNodes.add(res.identity.arn);
        if (graphData.nodes.length) { computeEdgeStatuses(); renderGraph(); }
        refreshCredentials();
    } catch (e) { showToast(e.message, "error"); }
}

async function deleteProfile(name) {
    try {
        await api(`/api/credentials/${name}`, "DELETE");
        showToast(`Profile "${name}" removed.`, "info");
        refreshCredentials();
    } catch (e) { showToast(e.message, "error"); }
}

// ══════════════════════════════════════════════════════════════════════
// ── Pipeline Controls ────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════

function setMode(mode) {
    currentMode = mode;
    document.querySelectorAll(".mode-toggle-btn").forEach(b => {
        b.classList.toggle("active", b.dataset.mode === mode);
    });
}

async function runDiscover() {
    setLoading("btn-discover", true);
    setPipelineStage("discovering");
    try {
        const res = await api("/api/pipeline/discover", "POST");
        setPipelineStage("discovered", `Discovered ${res.identities} identities, ${res.resources} resources.`);
    } catch (e) { setPipelineStage("error", e.message); }
    setLoading("btn-discover", false);
}

async function runBuild() {
    setLoading("btn-build", true);
    setPipelineStage("building");
    try {
        const res = await api("/api/pipeline/build", "POST", { mode: currentMode });
        setPipelineStage("graph_built", `Graph: ${res.nodes} nodes, ${res.edges} edges.`);
        await loadGraphData();
    } catch (e) { setPipelineStage("error", e.message); }
    setLoading("btn-build", false);
}

async function runAll() {
    setLoading("btn-run-all", true);
    setPipelineStage("discovering");
    try {
        const res = await api("/api/pipeline/run-all", "POST", { mode: currentMode });
        setPipelineStage("graph_built", `Pipeline complete. ${res.build.nodes} nodes, ${res.build.edges} edges.`);
        await loadGraphData();
    } catch (e) { setPipelineStage("error", e.message); }
    setLoading("btn-run-all", false);
}

// ══════════════════════════════════════════════════════════════════════
// ── D3 Graph Renderer ────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════

function initGraph() {
    svg = d3.select("#graph-svg");
    const defs = svg.append("defs");

    // Arrow markers for each edge status
    Object.entries(EDGE_STATUS_STYLES).forEach(([status, style]) => {
        defs.append("marker")
            .attr("id", `arrow-${status}`)
            .attr("viewBox", "0 -5 10 10").attr("refX", 22).attr("refY", 0)
            .attr("markerWidth", 8).attr("markerHeight", 8).attr("orient", "auto")
            .append("path").attr("d", "M0,-5L10,0L0,5")
            .attr("fill", style.color);
    });
    // Default marker
    defs.append("marker").attr("id", "arrow-default")
        .attr("viewBox", "0 -5 10 10").attr("refX", 22).attr("refY", 0)
        .attr("markerWidth", 8).attr("markerHeight", 8).attr("orient", "auto")
        .append("path").attr("d", "M0,-5L10,0L0,5").attr("fill", "#484f58");

    const g = svg.append("g").attr("id", "graph-root");
    gLinks = g.append("g").attr("class", "links");
    gLinkLabels = g.append("g").attr("class", "link-labels");
    gNodes = g.append("g").attr("class", "nodes");
    gLabels = g.append("g").attr("class", "labels");

    // Zoom
    const zoom = d3.zoom().scaleExtent([0.1, 5]).on("zoom", (e) => g.attr("transform", e.transform));
    svg.call(zoom);
}

async function loadGraphData() {
    try {
        graphData = await api("/api/graph");
        computeEdgeStatuses();
        renderGraph();
        populatePathfinderDropdowns();
    } catch (e) { showToast("Failed to load graph: " + e.message, "error"); }
}

function computeEdgeStatuses() {
    edgeStatus = {};
    graphData.links.forEach(l => {
        const src = typeof l.source === "object" ? l.source.id : l.source;
        const key = edgeKey(l);
        if (compromisedNodes.has(src)) {
            edgeStatus[key] = "possible";
        } else {
            edgeStatus[key] = "blocked";
        }
    });
}

function getEdgeStyle(d) {
    const status = edgeStatus[edgeKey(d)] || "blocked";
    return EDGE_STATUS_STYLES[status] || EDGE_STATUS_STYLES.blocked;
}

function renderGraph() {
    const canvas = document.getElementById("canvas");
    const W = canvas.clientWidth;
    const H = canvas.clientHeight;

    const emptyMsg = document.getElementById("graph-empty");
    const legend = document.getElementById("graph-legend");
    if (!graphData.nodes.length) { emptyMsg.classList.remove("hidden"); legend.classList.add("hidden"); return; }
    emptyMsg.classList.add("hidden");
    legend.classList.remove("hidden");

    // Compute degree for sizing
    const degreeMap = {};
    graphData.nodes.forEach(n => degreeMap[n.id] = 0);
    graphData.links.forEach(l => { degreeMap[l.source] = (degreeMap[l.source] || 0) + 1; degreeMap[l.target] = (degreeMap[l.target] || 0) + 1; });

    // Build parallel-edge index for curving
    const pairCount = {};
    const pairIndex = {};
    graphData.links.forEach(l => {
        const s = typeof l.source === "object" ? l.source.id : l.source;
        const t = typeof l.target === "object" ? l.target.id : l.target;
        const pairKey = s < t ? `${s}||${t}` : `${t}||${s}`;
        pairCount[pairKey] = (pairCount[pairKey] || 0) + 1;
        pairIndex[edgeKey(l)] = pairCount[pairKey] - 1;
    });

    // Clear previous
    gLinks.selectAll("*").remove();
    gLinkLabels.selectAll("*").remove();
    gNodes.selectAll("*").remove();
    gLabels.selectAll("*").remove();

    // Invisible wide hitbox paths for easier clicking
    const linkHitbox = gLinks.selectAll("path.link-hitbox").data(graphData.links).enter().append("path")
        .attr("class", "link-hitbox")
        .attr("fill", "none")
        .attr("stroke", "transparent")
        .attr("stroke-width", 16)
        .style("cursor", "pointer")
        .attr("data-source", d => d.source)
        .attr("data-target", d => d.target)
        .attr("data-type", d => d.type)
        .on("click", (e, d) => openActionModal(d));

    // Visible edge paths
    const link = gLinks.selectAll("path.link-line").data(graphData.links).enter().append("path")
        .attr("class", d => `link-line status-${edgeStatus[edgeKey(d)] || "blocked"}`)
        .attr("fill", "none")
        .attr("stroke", d => getEdgeStyle(d).color)
        .attr("stroke-width", d => getEdgeStyle(d).width)
        .attr("stroke-dasharray", d => getEdgeStyle(d).dash)
        .attr("marker-end", d => { const st = edgeStatus[edgeKey(d)] || "blocked"; return `url(#arrow-${st})`; })
        .attr("data-source", d => d.source)
        .attr("data-target", d => d.target)
        .attr("data-type", d => d.type)
        .style("pointer-events", "none");

    // Link labels — only visible on hover via CSS
    const linkLabel = gLinkLabels.selectAll("g").data(graphData.links).enter().append("g")
        .attr("class", "link-label-group");
    linkLabel.append("rect").attr("class", "link-label-bg");
    linkLabel.append("text")
        .attr("class", "link-label")
        .text(d => d.type);

    // Nodes
    const nodeG = gNodes.selectAll("g").data(graphData.nodes).enter().append("g")
        .attr("class", "node-group")
        .attr("data-id", d => d.id)
        .on("mouseover", (e, d) => showTooltip(e, d))
        .on("mouseout", hideTooltip)
        .on("click", (e, d) => highlightConnected(d))
        .call(d3.drag().on("start", dragStart).on("drag", dragging).on("end", dragEnd));

    // Main circle
    nodeG.append("circle")
        .attr("class", "node-circle")
        .attr("r", d => Math.max(8, Math.min(20, 8 + (degreeMap[d.id] || 0) * 2)))
        .attr("fill", d => NODE_COLORS[d.type] || NODE_COLORS.UNKNOWN)
        .attr("stroke", d => NODE_COLORS[d.type] || NODE_COLORS.UNKNOWN)
        .attr("stroke-width", 2)
        .attr("stroke-opacity", 0.3)
        .attr("data-id", d => d.id);

    // Compromised glow ring
    nodeG.filter(d => compromisedNodes.has(d.id)).append("circle")
        .attr("class", "node-compromised-ring")
        .attr("r", d => Math.max(8, Math.min(20, 8 + (degreeMap[d.id] || 0) * 2)) + 5)
        .attr("fill", "none")
        .attr("stroke", "#f85149")
        .attr("stroke-width", 2)
        .attr("stroke-dasharray", "4,3");

    // Compromised icon
    nodeG.filter(d => compromisedNodes.has(d.id)).append("text")
        .attr("class", "node-compromised-icon")
        .attr("dy", d => -(Math.max(8, Math.min(20, 8 + (degreeMap[d.id] || 0) * 2)) + 10))
        .attr("text-anchor", "middle")
        .attr("font-size", "12px")
        .text("⚠");

    // Node labels
    const label = gLabels.selectAll("text").data(graphData.nodes).enter().append("text")
        .attr("class", d => `node-label${compromisedNodes.has(d.id) ? " compromised" : ""}`)
        .text(d => d.name.length > 18 ? d.name.slice(0, 16) + "…" : d.name)
        .attr("dy", d => Math.max(8, Math.min(20, 8 + (degreeMap[d.id] || 0) * 2)) + 14);

    // Simulation
    if (simulation) simulation.stop();
    simulation = d3.forceSimulation(graphData.nodes)
        .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(300))
        .force("charge", d3.forceManyBody().strength(-800))
        .force("center", d3.forceCenter(W / 2, H / 2))
        .force("collision", d3.forceCollide().radius(80))
        .on("tick", () => {
            // Shared path builder for curved edges
            const buildPath = d => {
                const s = typeof d.source === "object" ? d.source : { x: 0, y: 0 };
                const t = typeof d.target === "object" ? d.target : { x: 0, y: 0 };
                const sId = typeof d.source === "object" ? d.source.id : d.source;
                const tId = typeof d.target === "object" ? d.target.id : d.target;
                const pk = sId < tId ? `${sId}||${tId}` : `${tId}||${sId}`;
                const count = pairCount[pk] || 1;
                const idx = pairIndex[edgeKey(d)] || 0;
                if (count <= 1) {
                    return `M${s.x},${s.y}L${t.x},${t.y}`;
                }
                const dx = t.x - s.x, dy = t.y - s.y;
                const offset = (idx - (count - 1) / 2) * 30;
                const mx = (s.x + t.x) / 2 - dy * offset / Math.max(Math.sqrt(dx*dx+dy*dy), 1) * 0.5;
                const my = (s.y + t.y) / 2 + dx * offset / Math.max(Math.sqrt(dx*dx+dy*dy), 1) * 0.5;
                return `M${s.x},${s.y}Q${mx},${my} ${t.x},${t.y}`;
            };
            link.attr("d", buildPath);
            linkHitbox.attr("d", buildPath);
            // Label positions at midpoint of curve
            linkLabel.each(function(d) {
                const s = typeof d.source === "object" ? d.source : { x: 0, y: 0 };
                const t = typeof d.target === "object" ? d.target : { x: 0, y: 0 };
                const sId = typeof d.source === "object" ? d.source.id : d.source;
                const tId = typeof d.target === "object" ? d.target.id : d.target;
                const pk = sId < tId ? `${sId}||${tId}` : `${tId}||${sId}`;
                const count = pairCount[pk] || 1;
                const idx = pairIndex[edgeKey(d)] || 0;
                const dx = t.x - s.x, dy = t.y - s.y;
                const len = Math.max(Math.sqrt(dx*dx+dy*dy), 1);
                let mx, my;
                if (count <= 1) { mx = (s.x+t.x)/2; my = (s.y+t.y)/2; }
                else {
                    const offset = (idx - (count - 1) / 2) * 30;
                    mx = (s.x+t.x)/2 - dy * offset / len * 0.5;
                    my = (s.y+t.y)/2 + dx * offset / len * 0.5;
                }
                const g = d3.select(this);
                const txt = g.select("text");
                txt.attr("x", mx).attr("y", my);
                const bbox = txt.node().getBBox();
                g.select("rect")
                    .attr("x", bbox.x - 3).attr("y", bbox.y - 1)
                    .attr("width", bbox.width + 6).attr("height", bbox.height + 2)
                    .attr("rx", 3);
            });
            nodeG.attr("transform", d => `translate(${d.x},${d.y})`);
            label.attr("x", d => d.x).attr("y", d => d.y);
        });
}

function dragStart(e, d) { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }
function dragging(e, d) { d.fx = e.x; d.fy = e.y; }
function dragEnd(e, d) { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }

// ── Tooltip ──────────────────────────────────────────────────────────
function showTooltip(event, d) {
    const tt = document.getElementById("node-tooltip");
    document.getElementById("tt-name").textContent = d.name;
    document.getElementById("tt-type").textContent = d.type;
    document.getElementById("tt-arn").textContent = d.id;
    tt.style.left = (event.pageX + 16) + "px";
    tt.style.top = (event.pageY - 10) + "px";
    tt.classList.add("visible");
}
function hideTooltip() { document.getElementById("node-tooltip").classList.remove("visible"); }

// ── Highlight connected edges ────────────────────────────────────────
function highlightConnected(d) {
    clearHighlights();
    gLinks.selectAll("path").each(function() {
        const el = d3.select(this);
        if (el.attr("data-source") === d.id || el.attr("data-target") === d.id) {
            el.classed("highlighted", true);
        }
    });
}

function clearHighlights() {
    gLinks.selectAll("path").classed("highlighted", false);
    gNodes.selectAll(".node-circle").classed("highlighted", false);
    document.querySelectorAll(".path-card").forEach(c => c.classList.remove("highlighted"));
}

// ══════════════════════════════════════════════════════════════════════
// ── Pathfinder ───────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════

function populatePathfinderDropdowns() {
    const startSel = document.getElementById("path-start");
    const targetSel = document.getElementById("path-target");
    startSel.innerHTML = '<option value="">— Select a node —</option>';
    targetSel.innerHTML = '<option value="">— Any target —</option>';
    graphData.nodes.forEach(n => {
        const opt1 = document.createElement("option"); opt1.value = n.id; opt1.textContent = `${n.name} (${n.type})`;
        const opt2 = opt1.cloneNode(true);
        startSel.appendChild(opt1);
        targetSel.appendChild(opt2);
    });
}

async function findPaths() {
    const startArn = document.getElementById("path-start").value;
    if (!startArn) return showToast("Select a start node.", "error");
    const targetArn = document.getElementById("path-target").value || undefined;
    setLoading("btn-find-paths", true);
    try {
        const res = await api("/api/pathfinder/query", "POST", { start_arn: startArn, target_arn: targetArn });
        renderPathResults(res.paths);
        showToast(`Found ${res.count} path(s).`, "info");
    } catch (e) { showToast(e.message, "error"); }
    setLoading("btn-find-paths", false);
}

function renderPathResults(paths) {
    const container = document.getElementById("path-results");
    container.innerHTML = "";
    if (!paths.length) { container.innerHTML = '<p class="text-muted" style="font-size:12px;padding:8px 0">No paths found.</p>'; return; }
    paths.forEach((path, idx) => {
        const card = document.createElement("div");
        card.className = "path-card";
        card.onclick = () => highlightPath(path, card);
        let html = `<div style="font-weight:600;margin-bottom:6px;color:var(--accent-cyan)">Path ${idx + 1} (${path.length} hop${path.length > 1 ? "s" : ""})</div>`;
        path.forEach(step => {
            html += `<div class="path-step">
                <span>${step.from_name}</span>
                <span class="arrow">→</span>
                <span class="rel">${step.relationship}</span>
                <span class="arrow">→</span>
                <span>${step.to_name}</span>
            </div>`;
        });
        card.innerHTML = html;
        container.appendChild(card);
    });
}

function highlightPath(path, cardEl) {
    clearHighlights();
    if (cardEl) cardEl.classList.add("highlighted");
    const pathArns = new Set();
    path.forEach(step => {
        pathArns.add(step.from_arn);
        pathArns.add(step.to_arn);
        gLinks.selectAll("path").each(function() {
            const el = d3.select(this);
            if (el.attr("data-source") === step.from_arn && el.attr("data-target") === step.to_arn) {
                el.classed("highlighted", true);
            }
        });
    });
    gNodes.selectAll(".node-circle").each(function() {
        const el = d3.select(this);
        if (pathArns.has(el.attr("data-id"))) el.classed("highlighted", true);
    });
}

// ══════════════════════════════════════════════════════════════════════
// ── Action Modal ─────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════

function openActionModal(edgeData) {
    currentModal = edgeData;
    const srcId = typeof edgeData.source === "object" ? edgeData.source.id : edgeData.source;
    const tgtId = typeof edgeData.target === "object" ? edgeData.target.id : edgeData.target;
    document.getElementById("modal-source").textContent = srcId;
    document.getElementById("modal-target").textContent = tgtId;
    document.getElementById("modal-edge-type").textContent = edgeData.type;
    document.getElementById("modal-title-text").textContent = `Execute: ${edgeData.type}`;
    document.getElementById("modal-result-area").innerHTML = "";
    document.getElementById("btn-execute-action").disabled = false;
    document.getElementById("btn-execute-action").classList.remove("loading");
    document.getElementById("action-modal").classList.add("visible");
}

function closeModal() {
    document.getElementById("action-modal").classList.remove("visible");
    currentModal = null;
}

async function executeAction() {
    if (!currentModal) return;
    const srcId = typeof currentModal.source === "object" ? currentModal.source.id : currentModal.source;
    const tgtId = typeof currentModal.target === "object" ? currentModal.target.id : currentModal.target;
    setLoading("btn-execute-action", true);
    try {
        const res = await api("/api/action/execute", "POST", {
            edge_type: currentModal.type, source_arn: srcId, target_arn: tgtId
        });
        const area = document.getElementById("modal-result-area");
        if (res.success) {
            area.innerHTML = `<div class="modal-result success">${JSON.stringify(res.result, null, 2)}</div>`;
            showToast("Action executed successfully.", "success");
            // Mark this edge as taken and target as compromised
            const key = `${srcId}|${tgtId}|${currentModal.type}`;
            edgeStatus[key] = "taken";
            compromisedNodes.add(tgtId);
            // If we got new credentials, auto-register them
            if (res.result.access_key_id) {
                const credName = `${currentModal.type}-${tgtId.split('/').pop() || tgtId.split(':').pop()}`;
                try {
                    await api("/api/credentials", "POST", {
                        name: credName,
                        access_key_id: res.result.access_key_id,
                        secret_access_key: res.result.secret_access_key,
                        session_token: res.result.session_token || "",
                    });
                    showToast(`Credentials auto-saved as "${credName}".`, "info");
                    refreshCredentials();
                } catch(_) {}
            }
            computeEdgeStatuses();
            renderGraph();
        } else {
            area.innerHTML = `<div class="modal-result error">${res.error}</div>`;
            showToast("Action failed.", "error");
        }
    } catch (e) {
        document.getElementById("modal-result-area").innerHTML = `<div class="modal-result error">${e.message}</div>`;
    }
    setLoading("btn-execute-action", false);
}

// ══════════════════════════════════════════════════════════════════════
// ── Snapshots ────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════

async function saveSnapshot() {
    const name = document.getElementById("snap-name").value.trim();
    if (!name) return showToast("Enter a snapshot name.", "error");
    setLoading("btn-save-snap", true);
    try {
        const res = await api("/api/snapshots/save", "POST", { name });
        showToast(`Snapshot "${name}" saved (${res.nodes} nodes, ${res.links} links).`, "success");
        document.getElementById("snap-name").value = "";
        refreshSnapshots();
    } catch (e) { showToast(e.message, "error"); }
    setLoading("btn-save-snap", false);
}

async function refreshSnapshots() {
    try {
        const snaps = await api("/api/snapshots");
        const list = document.getElementById("snapshot-list");
        list.innerHTML = "";
        if (!snaps.length) { list.innerHTML = '<p class="text-muted" style="font-size:12px">No snapshots saved yet.</p>'; return; }
        snaps.forEach(s => {
            const div = document.createElement("div");
            div.className = "snapshot-item";
            div.innerHTML = `
                <div class="snapshot-info">
                    <div class="snapshot-name">${s.name}</div>
                    <div class="snapshot-meta">${s.nodes || 0} nodes · ${s.links || 0} edges · ${s.timestamp || ""}</div>
                </div>
                <div class="cred-item-actions">
                    <button class="btn btn-sm btn-ghost" onclick="loadSnapshot('${s.name}')">Load</button>
                    <button class="btn btn-sm btn-ghost" onclick="deleteSnapshot('${s.name}')" style="color:var(--accent-red)">✕</button>
                </div>`;
            list.appendChild(div);
        });
    } catch (e) { /* silent */ }
}

async function loadSnapshot(name) {
    try {
        await api("/api/snapshots/load", "POST", { name, mode: currentMode });
        showToast(`Snapshot "${name}" loaded.`, "success");
        await loadGraphData();
    } catch (e) { showToast(e.message, "error"); }
}

async function deleteSnapshot(name) {
    try {
        await api(`/api/snapshots/${name}`, "DELETE");
        showToast(`Snapshot "${name}" deleted.`, "info");
        refreshSnapshots();
    } catch (e) { showToast(e.message, "error"); }
}
