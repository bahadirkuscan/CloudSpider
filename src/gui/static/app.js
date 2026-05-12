/* ── CloudSpider GUI — Application Logic ─────────────────────────── */

// ── State ────────────────────────────────────────────────────────────
let graphData = { nodes: [], links: [] };
let simulation = null;
let svg, gLinks, gNodes, gLabels, gLinkLabels;
let currentMode = "build";
let currentModal = null;
let logCount = 0;

// Tracks which nodes are compromised (ARN set)
let compromisedNodes = new Set();
// Tracks edge action status: key = "source|target|type", value = "taken"|"possible"|"blocked"
let edgeStatus = {};
// Tracks manual edge offsets from label dragging: key = edgeKey, value = offset number
let edgeManualOffset = {};

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

// Edge status styles: taken = green solid, possible = amber dashed, blocked = gray dotted, false_positive = dashed red
const EDGE_STATUS_STYLES = {
    taken: { color: "#3fb950", dash: "", width: 2.5 },
    possible: { color: "#f0883e", dash: "8,4", width: 2 },
    blocked: { color: "#484f58", dash: "3,5", width: 1.5 },
    false_positive: { color: "#f85149", dash: "6,4", width: 1.5 }
};

// Filter visibility state
let visibleNodeIds = new Set();
let visibleEdgeTypes = new Set();
let filterInitialized = false;

// Tracks the initial compromised ARN from active profile activation
let initialCompromisedArn = null;

// ── Init ─────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
    initGraph();
    initSocketIO();
    refreshCredentials();
    refreshSnapshots();
    // Restore session state and graph on page refresh
    const hadState = await restoreSessionState();
    if (hadState) {
        try {
            const gd = await api("/api/graph");
            if (gd.nodes && gd.nodes.length) {
                graphData = gd;
                if (initialCompromisedArn) compromisedNodes.add(initialCompromisedArn);
                computeEdgeStatuses();
                populateFilterCheckboxes();
                renderGraph();
                populatePathfinderDropdowns();
            }
        } catch (_) { /* no graph yet */ }
    }
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
    const opts = { method, headers: { "Content-Type": "application/json" }, credentials: "same-origin" };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(url, opts);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    return data;
}

// ── Session State Persistence ────────────────────────────────────────
async function persistSessionState() {
    try {
        await api("/api/session/state", "POST", {
            compromisedNodes: [...compromisedNodes],
            edgeStatus: { ...edgeStatus },
            edgeManualOffset: { ...edgeManualOffset },
            initialCompromisedArn,
        });
    } catch (_) { /* best-effort */ }
}

async function restoreSessionState() {
    try {
        const res = await api("/api/session/state");
        if (res.has_state) {
            compromisedNodes = new Set(res.compromisedNodes || []);
            edgeStatus = res.edgeStatus || {};
            edgeManualOffset = res.edgeManualOffset || {};
            initialCompromisedArn = res.initialCompromisedArn || null;
            return true;
        }
    } catch (_) { /* no state */ }
    return false;
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
            let identityHtml = "";
            if (c.identity) {
                identityHtml = `<div class="cred-identity">
                    <div title="${c.identity.arn}">ARN: ${c.identity.arn.split(':').pop()}</div>
                    <div>Account: ${c.identity.account}</div>
                </div>`;
            }
            div.innerHTML = `
                <div class="cred-item-info">
                    <div class="cred-item-name">${c.name}</div>
                    <div class="cred-item-region">${c.region}</div>
                    ${identityHtml}
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
        // Mark the user's ARN as compromised and persist it
        initialCompromisedArn = res.identity.arn;
        compromisedNodes.add(res.identity.arn);
        if (graphData.nodes.length) { computeEdgeStatuses(); renderGraph(); }
        refreshCredentials();
        persistSessionState();
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
        // Re-apply initial compromised node from active profile
        if (initialCompromisedArn) compromisedNodes.add(initialCompromisedArn);
        computeEdgeStatuses();
        populateFilterCheckboxes();
        renderGraph();
        populatePathfinderDropdowns();
        persistSessionState();
    } catch (e) { showToast("Failed to load graph: " + e.message, "error"); }
}

function computeEdgeStatuses() {
    graphData.links.forEach(l => {
        const src = typeof l.source === "object" ? l.source.id : l.source;
        const key = edgeKey(l);
        // Preserve taken and false_positive statuses across re-renders
        if (edgeStatus[key] === "taken" || edgeStatus[key] === "false_positive") return;
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

    // Apply filters — only show visible nodes (by ID) and edge types
    const filteredNodes = graphData.nodes.filter(n => visibleNodeIds.has(n.id));
    const filteredNodeIdSet = new Set(filteredNodes.map(n => n.id));
    const filteredLinks = graphData.links.filter(l => {
        const sId = typeof l.source === "object" ? l.source.id : l.source;
        const tId = typeof l.target === "object" ? l.target.id : l.target;
        return visibleEdgeTypes.has(l.type) && filteredNodeIdSet.has(sId) && filteredNodeIdSet.has(tId);
    });

    // Compute degree for sizing
    const degreeMap = {};
    filteredNodes.forEach(n => degreeMap[n.id] = 0);
    filteredLinks.forEach(l => {
        const sId = typeof l.source === "object" ? l.source.id : l.source;
        const tId = typeof l.target === "object" ? l.target.id : l.target;
        degreeMap[sId] = (degreeMap[sId] || 0) + 1;
        degreeMap[tId] = (degreeMap[tId] || 0) + 1;
    });

    // Build direction-aware parallel-edge index for curving
    // Each directed edge between A→B and B→A gets separate offsets
    const pairCount = {};
    const pairIndex = {};
    filteredLinks.forEach(l => {
        const s = typeof l.source === "object" ? l.source.id : l.source;
        const t = typeof l.target === "object" ? l.target.id : l.target;
        // Use ordered pair key for same-direction grouping
        const pairKey = `${s}||${t}`;
        pairCount[pairKey] = (pairCount[pairKey] || 0) + 1;
        pairIndex[edgeKey(l)] = pairCount[pairKey] - 1;
    });
    // Compute total edges between any two nodes (both directions)
    const biCount = {};
    filteredLinks.forEach(l => {
        const s = typeof l.source === "object" ? l.source.id : l.source;
        const t = typeof l.target === "object" ? l.target.id : l.target;
        const bk = s < t ? `${s}||${t}` : `${t}||${s}`;
        biCount[bk] = (biCount[bk] || 0) + 1;
    });

    // Clear previous
    gLinks.selectAll("*").remove();
    gLinkLabels.selectAll("*").remove();
    gNodes.selectAll("*").remove();
    gLabels.selectAll("*").remove();

    // Invisible wide hitbox paths for easier clicking — blocked edges are NOT clickable
    const linkHitbox = gLinks.selectAll("path.link-hitbox").data(filteredLinks).enter().append("path")
        .attr("class", "link-hitbox")
        .attr("fill", "none")
        .attr("stroke", "transparent")
        .attr("stroke-width", 18)
        .style("cursor", d => {
            const st = edgeStatus[edgeKey(d)] || "blocked";
            return st === "blocked" ? "default" : "pointer";
        })
        .attr("data-source", d => typeof d.source === "object" ? d.source.id : d.source)
        .attr("data-target", d => typeof d.target === "object" ? d.target.id : d.target)
        .attr("data-type", d => d.type)
        .on("click", (e, d) => {
            const st = edgeStatus[edgeKey(d)] || "blocked";
            if (st !== "blocked") openActionModal(d);
        });

    // Visible edge paths
    const link = gLinks.selectAll("path.link-line").data(filteredLinks).enter().append("path")
        .attr("class", d => `link-line status-${edgeStatus[edgeKey(d)] || "blocked"}`)
        .attr("fill", "none")
        .attr("stroke", d => getEdgeStyle(d).color)
        .attr("stroke-width", d => getEdgeStyle(d).width)
        .attr("stroke-dasharray", d => getEdgeStyle(d).dash)
        .attr("marker-end", d => { const st = edgeStatus[edgeKey(d)] || "blocked"; return `url(#arrow-${st})`; })
        .attr("data-source", d => typeof d.source === "object" ? d.source.id : d.source)
        .attr("data-target", d => typeof d.target === "object" ? d.target.id : d.target)
        .attr("data-type", d => d.type)
        .style("pointer-events", "none");

    // Shared path builder for direction-aware curved edges (hoisted for drag + tick access)
    const buildPath = d => {
        const s = typeof d.source === "object" ? d.source : { x: 0, y: 0 };
        const t = typeof d.target === "object" ? d.target : { x: 0, y: 0 };
        const sId = typeof d.source === "object" ? d.source.id : d.source;
        const tId = typeof d.target === "object" ? d.target.id : d.target;
        const dpk = `${sId}||${tId}`;
        const dirCount = pairCount[dpk] || 1;
        const dirIdx = pairIndex[edgeKey(d)] || 0;
        const rpk = `${tId}||${sId}`;
        const hasReverse = (pairCount[rpk] || 0) > 0;
        const bk = sId < tId ? `${sId}||${tId}` : `${tId}||${sId}`;
        const totalEdges = biCount[bk] || 1;
        const manual = edgeManualOffset[edgeKey(d)] || 0;

        const canonFirst = sId < tId;
        const cdx = canonFirst ? (t.x - s.x) : (s.x - t.x);
        const cdy = canonFirst ? (t.y - s.y) : (s.y - t.y);
        const clen = Math.max(Math.sqrt(cdx * cdx + cdy * cdy), 1);

        if (totalEdges <= 1 && dirCount <= 1 && manual === 0) {
            return `M${s.x},${s.y}L${t.x},${t.y}`;
        }
        let baseOffset = hasReverse ? (canonFirst ? 1 : -1) * 50 : 0;
        const spreadOffset = (dirIdx - (dirCount - 1) / 2) * 80;
        const totalOffset = baseOffset + spreadOffset + manual;
        const mx = (s.x + t.x) / 2 - cdy * totalOffset / clen * 0.5;
        const my = (s.y + t.y) / 2 + cdx * totalOffset / clen * 0.5;
        return `M${s.x},${s.y}Q${mx},${my} ${t.x},${t.y}`;
    };

    // Link labels — always visible, draggable to reposition edges
    const linkLabel = gLinkLabels.selectAll("g").data(filteredLinks).enter().append("g")
        .attr("class", "link-label-group")
        .style("cursor", "grab")
        .call(d3.drag()
            .on("start", function () { d3.select(this).style("cursor", "grabbing"); })
            .on("drag", function (event, d) {
                const s = typeof d.source === "object" ? d.source : { x: 0, y: 0 };
                const t = typeof d.target === "object" ? d.target : { x: 0, y: 0 };
                const sId = typeof d.source === "object" ? d.source.id : d.source;
                const tId = typeof d.target === "object" ? d.target.id : d.target;
                const canonFirst = sId < tId;
                const cdx = canonFirst ? (t.x - s.x) : (s.x - t.x);
                const cdy = canonFirst ? (t.y - s.y) : (s.y - t.y);
                const clen = Math.max(Math.sqrt(cdx * cdx + cdy * cdy), 1);
                const perpX = -cdy / clen;
                const perpY = cdx / clen;
                const delta = event.dx * perpX + event.dy * perpY;
                const key = edgeKey(d);
                edgeManualOffset[key] = (edgeManualOffset[key] || 0) + delta;
                // Rebuild paths and reposition labels immediately
                link.attr("d", buildPath);
                linkHitbox.attr("d", buildPath);
                updateLabelPositions();
            })
            .on("end", function () { d3.select(this).style("cursor", "grab"); })
        );
    linkLabel.append("rect").attr("class", "link-label-bg");
    linkLabel.append("text")
        .attr("class", "link-label")
        .text(d => d.type);

    // Nodes
    const nodeG = gNodes.selectAll("g").data(filteredNodes).enter().append("g")
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
    const label = gLabels.selectAll("text").data(filteredNodes).enter().append("text")
        .attr("class", d => `node-label${compromisedNodes.has(d.id) ? " compromised" : ""}`)
        .text(d => d.name.length > 18 ? d.name.slice(0, 16) + "…" : d.name)
        .attr("dy", d => Math.max(8, Math.min(20, 8 + (degreeMap[d.id] || 0) * 2)) + 14);

    // Helper to update label positions (used by both tick and drag)
    function updateLabelPositions() {
        linkLabel.each(function (d) {
            const s = typeof d.source === "object" ? d.source : { x: 0, y: 0 };
            const t = typeof d.target === "object" ? d.target : { x: 0, y: 0 };
            const sId = typeof d.source === "object" ? d.source.id : d.source;
            const tId = typeof d.target === "object" ? d.target.id : d.target;
            const dpk = `${sId}||${tId}`;
            const dirCount = pairCount[dpk] || 1;
            const dirIdx = pairIndex[edgeKey(d)] || 0;
            const rpk = `${tId}||${sId}`;
            const hasReverse = (pairCount[rpk] || 0) > 0;
            const bk = sId < tId ? `${sId}||${tId}` : `${tId}||${sId}`;
            const totalEdges = biCount[bk] || 1;
            const manual = edgeManualOffset[edgeKey(d)] || 0;
            const canonFirst = sId < tId;
            const cdx = canonFirst ? (t.x - s.x) : (s.x - t.x);
            const cdy = canonFirst ? (t.y - s.y) : (s.y - t.y);
            const clen = Math.max(Math.sqrt(cdx * cdx + cdy * cdy), 1);
            let mx, my;
            if (totalEdges <= 1 && dirCount <= 1 && manual === 0) {
                mx = (s.x + t.x) / 2; my = (s.y + t.y) / 2;
            } else {
                let baseOffset = hasReverse ? (canonFirst ? 1 : -1) * 50 : 0;
                const spreadOffset = (dirIdx - (dirCount - 1) / 2) * 80;
                const totalOffset = baseOffset + spreadOffset + manual;
                // Control point of the quadratic Bezier
                const cx = (s.x + t.x) / 2 - cdy * totalOffset / clen * 0.5;
                const cy = (s.y + t.y) / 2 + cdx * totalOffset / clen * 0.5;
                // Actual curve midpoint at t=0.5: (start + 2*control + end) / 4
                mx = (s.x + 2 * cx + t.x) / 4;
                my = (s.y + 2 * cy + t.y) / 4;
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
    }

    // Simulation — increased spacing to reduce overlaps
    if (simulation) simulation.stop();
    simulation = d3.forceSimulation(filteredNodes)
        .force("link", d3.forceLink(filteredLinks).id(d => d.id).distance(400))
        .force("charge", d3.forceManyBody().strength(-1200))
        .force("center", d3.forceCenter(W / 2, H / 2))
        .force("collision", d3.forceCollide().radius(100))
        .on("tick", () => {
            link.attr("d", buildPath);
            linkHitbox.attr("d", buildPath);
            updateLabelPositions();
            nodeG.attr("transform", d => `translate(${d.x},${d.y})`);
            label.attr("x", d => d.x).attr("y", d => d.y);
        });
}

// Drag handlers — nodes stay pinned where dragged for free positioning
function dragStart(e, d) { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }
function dragging(e, d) { d.fx = e.x; d.fy = e.y; }
function dragEnd(e, d) { if (!e.active) simulation.alphaTarget(0); /* keep d.fx/d.fy so node stays pinned */ }

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
    gLinks.selectAll("path").each(function () {
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

// Tracks the currently displayed path for step-by-step execution
let activePath = null;
let activePathIndex = 0; // which step to execute next

function populatePathfinderDropdowns() {
    const startSel = document.getElementById("path-start");
    const targetSel = document.getElementById("path-target");
    startSel.innerHTML = '<option value="">— Select source —</option>';
    targetSel.innerHTML = '<option value="">— Select target —</option>';
    // Sort nodes alphabetically by name
    const sorted = [...graphData.nodes].sort((a, b) => a.name.localeCompare(b.name));
    sorted.forEach(n => {
        const isCompromised = compromisedNodes.has(n.id);
        const opt1 = document.createElement("option");
        opt1.value = n.id;
        opt1.textContent = `${n.name} (${n.type})`;
        if (isCompromised) { opt1.style.color = "#f0883e"; opt1.className = "compromised-option"; }
        const opt2 = opt1.cloneNode(true);
        startSel.appendChild(opt1);
        targetSel.appendChild(opt2);
    });
}

async function findPaths() {
    const startArn = document.getElementById("path-start").value;
    const targetArn = document.getElementById("path-target").value;
    if (!startArn) return showToast("Select a source node.", "error");
    if (!targetArn) return showToast("Select a target node.", "error");
    if (startArn === targetArn) return showToast("Source and target must be different.", "error");
    setLoading("btn-find-paths", true);
    try {
        const res = await api("/api/pathfinder/query", "POST", { start_arn: startArn, target_arn: targetArn });
        renderPathResults(res.paths);
        if (res.count > 0) {
            showToast(`Found ${res.count} path(s) — ${res.paths[0].length} edge(s) in shortest path.`, "info");
        } else {
            showToast("No path found between these nodes.", "info");
        }
    } catch (e) { showToast(e.message, "error"); }
    setLoading("btn-find-paths", false);
}

function renderPathResults(paths) {
    const container = document.getElementById("path-results");
    container.innerHTML = "";
    activePath = null;
    activePathIndex = 0;

    if (!paths.length) {
        container.innerHTML = '<p class="text-muted" style="font-size:12px;padding:8px 0">No paths found.</p>';
        return;
    }

    paths.forEach((path, idx) => {
        const card = document.createElement("div");
        card.className = "path-card";
        card.id = `path-card-${idx}`;

        let html = `<div class="path-card-header">
            <span style="font-weight:600;color:var(--accent-cyan)">Path ${idx + 1}</span>
            <span class="text-muted" style="font-size:11px">${path.length} edge${path.length > 1 ? "s" : ""}</span>
        </div>`;

        // Render each edge/step
        html += '<div class="path-steps">';
        path.forEach((step, stepIdx) => {
            const stepId = `path-${idx}-step-${stepIdx}`;
            html += `<div class="path-step-row" id="${stepId}" data-path="${idx}" data-step="${stepIdx}">
                <div class="path-step-number">${stepIdx + 1}</div>
                <div class="path-step-detail">
                    <div class="path-step-nodes">
                        <span class="node-name">${step.from_name}</span>
                        <span class="path-step-arrow">→</span>
                        <span class="edge-type">${step.relationship}</span>
                        <span class="path-step-arrow">→</span>
                        <span class="node-name">${step.to_name}</span>
                    </div>
                </div>
                <button class="btn btn-sm btn-execute-step" id="${stepId}-btn"
                    onclick="executePathStep(${idx}, ${stepIdx})"
                    title="Execute this step">▶</button>
            </div>`;
        });
        html += '</div>';

        // Action buttons
        html += `<div class="path-action-bar">
            <button class="btn btn-sm btn-primary flex-1" onclick="highlightAndSelectPath(${idx})">
                🔍 Highlight
            </button>
            <button class="btn btn-sm btn-danger flex-1" id="btn-exec-all-${idx}" onclick="executeAllSteps(${idx})">
                ⚡ Execute All
            </button>
        </div>`;

        card.innerHTML = html;
        container.appendChild(card);
    });

    // Store paths globally for execution
    window._pathfinderPaths = paths;

    // Auto-highlight the first path
    if (paths.length > 0) {
        highlightAndSelectPath(0);
    }
}

function highlightAndSelectPath(pathIdx) {
    const path = window._pathfinderPaths[pathIdx];
    if (!path) return;

    clearHighlights();
    activePath = path;
    activePathIndex = 0;

    // Highlight the card
    document.querySelectorAll(".path-card").forEach(c => c.classList.remove("highlighted"));
    const card = document.getElementById(`path-card-${pathIdx}`);
    if (card) card.classList.add("highlighted");

    // Highlight path on graph
    highlightPath(path);
}

function highlightPath(path, cardEl) {
    clearHighlights();
    if (cardEl) cardEl.classList.add("highlighted");
    const pathArns = new Set();
    path.forEach(step => {
        pathArns.add(step.from_arn);
        pathArns.add(step.to_arn);
        gLinks.selectAll("path.link-line").each(function () {
            const el = d3.select(this);
            if (el.attr("data-source") === step.from_arn &&
                el.attr("data-target") === step.to_arn &&
                el.attr("data-type") === step.relationship) {
                el.classed("highlighted", true);
            }
        });
        // Also highlight hitbox for visual consistency
        gLinks.selectAll("path.link-hitbox").each(function () {
            const el = d3.select(this);
            if (el.attr("data-source") === step.from_arn &&
                el.attr("data-target") === step.to_arn &&
                el.attr("data-type") === step.relationship) {
                el.classed("highlighted", true);
            }
        });
    });
    gNodes.selectAll(".node-circle").each(function () {
        const el = d3.select(this);
        if (pathArns.has(el.attr("data-id"))) el.classed("highlighted", true);
    });
}

async function executePathStep(pathIdx, stepIdx) {
    const path = window._pathfinderPaths[pathIdx];
    if (!path || !path[stepIdx]) return;

    const step = path[stepIdx];
    const btnId = `path-${pathIdx}-step-${stepIdx}-btn`;
    const rowEl = document.getElementById(`path-${pathIdx}-step-${stepIdx}`);
    const btn = document.getElementById(btnId);

    if (btn) { btn.disabled = true; btn.textContent = "⏳"; }

    try {
        const res = await api("/api/action/execute", "POST", {
            edge_type: step.relationship,
            source_arn: step.from_arn,
            target_arn: step.to_arn,
        });

        if (res.success) {
            // Mark step as done
            if (rowEl) rowEl.classList.add("step-done");
            if (btn) { btn.textContent = "✓"; btn.classList.add("step-success"); }
            showToast(`Step ${stepIdx + 1} executed: ${step.relationship}`, "success");

            // Update edge and node status
            const key = `${step.from_arn}|${step.to_arn}|${step.relationship}`;
            edgeStatus[key] = "taken";
            compromisedNodes.add(step.to_arn);

            // Auto-register credentials if returned
            if (res.result.access_key_id) {
                const credName = `${step.relationship}-${step.to_name}`;
                try {
                    await api("/api/credentials", "POST", {
                        name: credName,
                        access_key_id: res.result.access_key_id,
                        secret_access_key: res.result.secret_access_key,
                        session_token: res.result.session_token || "",
                    });
                    // Auto-activate so subsequent chain steps use this identity
                    await api(`/api/credentials/${credName}/activate`, "POST");
                    showToast(`Credentials saved and activated as "${credName}".`, "info");
                    refreshCredentials();
                } catch (_) { }

                // For CanUpdateFunction, also mark the Lambda's execution role as compromised
                // since we now hold its credentials
                if (res.result.execution_role_arn) {
                    compromisedNodes.add(res.result.execution_role_arn);
                }
            }

            computeEdgeStatuses();
            renderGraph();
            populatePathfinderDropdowns();
        } else {
            if (rowEl) rowEl.classList.add("step-failed");
            if (btn) { btn.textContent = "✕"; btn.classList.add("step-error"); }
            showToast(`Step ${stepIdx + 1} failed: ${res.error}`, "error");
        }
    } catch (e) {
        if (rowEl) rowEl.classList.add("step-failed");
        if (btn) { btn.textContent = "✕"; btn.classList.add("step-error"); }
        showToast(`Step ${stepIdx + 1} error: ${e.message}`, "error");
    }
}

async function executeAllSteps(pathIdx) {
    const path = window._pathfinderPaths[pathIdx];
    if (!path) return;

    const allBtn = document.getElementById(`btn-exec-all-${pathIdx}`);
    if (allBtn) { allBtn.disabled = true; allBtn.textContent = "⏳ Executing..."; }

    for (let i = 0; i < path.length; i++) {
        await executePathStep(pathIdx, i);
        // Small delay between steps for readability
        if (i < path.length - 1) await new Promise(r => setTimeout(r, 500));
    }

    if (allBtn) { allBtn.textContent = "✓ Done"; allBtn.classList.remove("btn-danger"); allBtn.classList.add("btn-success"); }
    showToast("All path steps executed.", "success");
}

function clearPathfinder() {
    clearHighlights();
    activePath = null;
    activePathIndex = 0;
    window._pathfinderPaths = [];
    document.getElementById("path-results").innerHTML = "";
    document.getElementById("path-start").value = "";
    document.getElementById("path-target").value = "";
}

// ══════════════════════════════════════════════════════════════════════
// ── Action Modal ─────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════

function openActionModal(edgeData) {
    currentModal = edgeData;
    const srcId = typeof edgeData.source === "object" ? edgeData.source.id : edgeData.source;
    const tgtId = typeof edgeData.target === "object" ? edgeData.target.id : edgeData.target;
    const key = `${srcId}|${tgtId}|${edgeData.type}`;
    const status = edgeStatus[key] || "blocked";
    document.getElementById("modal-source").textContent = srcId;
    document.getElementById("modal-target").textContent = tgtId;
    document.getElementById("modal-edge-type").textContent = edgeData.type;
    document.getElementById("modal-title-text").textContent = `Execute: ${edgeData.type}`;
    document.getElementById("modal-result-area").innerHTML = "";
    document.getElementById("btn-execute-action").disabled = false;
    document.getElementById("btn-execute-action").classList.remove("loading");
    // Show/hide false positive button based on status
    const fpBtn = document.getElementById("btn-false-positive");
    if (status === "false_positive") {
        fpBtn.textContent = "\u21a9\ufe0f Unmark False Positive";
        fpBtn.style.display = "";
    } else if (status === "blocked") {
        fpBtn.style.display = "none";
    } else {
        fpBtn.textContent = "\ud83d\udeab Mark as False Positive";
        fpBtn.style.display = "";
    }
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
            // If we got new credentials, auto-register and activate them
            if (res.result.access_key_id) {
                const credName = `${currentModal.type}-${tgtId.split('/').pop() || tgtId.split(':').pop()}`;
                try {
                    await api("/api/credentials", "POST", {
                        name: credName,
                        access_key_id: res.result.access_key_id,
                        secret_access_key: res.result.secret_access_key,
                        session_token: res.result.session_token || "",
                    });
                    await api(`/api/credentials/${credName}/activate`, "POST");
                    showToast(`Credentials auto-saved and activated as "${credName}".`, "info");
                    refreshCredentials();
                } catch (_) { }

                if (res.result.execution_role_arn) {
                    compromisedNodes.add(res.result.execution_role_arn);
                }
            }
            computeEdgeStatuses();
            renderGraph();
            populatePathfinderDropdowns();
            persistSessionState();
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
    const password = prompt("Enter a password to encrypt this snapshot:");
    if (!password) return showToast("Password is required to save a snapshot.", "error");
    setLoading("btn-save-snap", true);
    try {
        const clientState = {
            compromisedNodes: [...compromisedNodes],
            edgeStatus: { ...edgeStatus },
            edgeManualOffset: { ...edgeManualOffset },
            initialCompromisedArn,
        };
        const res = await api("/api/snapshots/save", "POST", { name, password, state: clientState });
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
    const password = prompt(`Enter the password for snapshot "${name}":`);
    if (!password) return showToast("Password is required to load a snapshot.", "error");
    try {
        const res = await api("/api/snapshots/load", "POST", { name, password, mode: currentMode });
        // Restore frontend state from snapshot
        if (res.state) {
            compromisedNodes = new Set(res.state.compromisedNodes || []);
            edgeStatus = res.state.edgeStatus || {};
            edgeManualOffset = res.state.edgeManualOffset || {};
            initialCompromisedArn = res.state.initialCompromisedArn || null;
        }
        showToast(`Snapshot "${name}" loaded.`, "success");
        await loadGraphData();
        refreshCredentials();
    } catch (e) { showToast(e.message, "error"); }
}

async function deleteSnapshot(name) {
    const password = prompt(`Enter the password for snapshot "${name}" to delete it:`);
    if (!password) return showToast("Password is required to delete a snapshot.", "error");
    try {
        await api(`/api/snapshots/${name}`, "DELETE", { password });
        showToast(`Snapshot "${name}" deleted.`, "info");
        refreshSnapshots();
    } catch (e) { showToast(e.message, "error"); }
}

// ══════════════════════════════════════════════════════════════════════
// ── Mark False Positive ──────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════

function markFalsePositive() {
    if (!currentModal) return;
    const srcId = typeof currentModal.source === "object" ? currentModal.source.id : currentModal.source;
    const tgtId = typeof currentModal.target === "object" ? currentModal.target.id : currentModal.target;
    const key = `${srcId}|${tgtId}|${currentModal.type}`;
    if (edgeStatus[key] === "false_positive") {
        // Unmark: revert to computed status
        delete edgeStatus[key];
        computeEdgeStatuses();
        showToast(`Edge "${currentModal.type}" unmarked from false positive.`, "info");
    } else {
        edgeStatus[key] = "false_positive";
        showToast(`Edge "${currentModal.type}" marked as false positive.`, "info");
    }
    renderGraph();
    persistSessionState();
    closeModal();
}

// ══════════════════════════════════════════════════════════════════════
// ── Clear Graph ──────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════

async function clearGraph() {
    graphData = { nodes: [], links: [] };
    edgeStatus = {};
    edgeManualOffset = {};
    filterInitialized = false;
    visibleNodeIds.clear();
    visibleEdgeTypes.clear();
    if (simulation) simulation.stop();
    gLinks.selectAll("*").remove();
    gLinkLabels.selectAll("*").remove();
    gNodes.selectAll("*").remove();
    gLabels.selectAll("*").remove();
    document.getElementById("graph-empty").classList.remove("hidden");
    document.getElementById("graph-legend").classList.add("hidden");
    document.getElementById("filter-nodes-list").innerHTML = "";
    document.getElementById("filter-edges-list").innerHTML = "";
    clearPathfinder();
    showToast("Graph cleared. Click 'Build Graph' to rebuild.", "info");
}

// ══════════════════════════════════════════════════════════════════════
// ── Filter Panel ─────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════

function toggleFilterPanel() {
    const panel = document.getElementById("filter-panel");
    const isHidden = panel.classList.contains("hidden");
    panel.classList.toggle("hidden");
    // Close panel when clicking outside
    if (isHidden) {
        setTimeout(() => {
            function closeOnOutside(e) {
                const wrapper = document.querySelector(".filter-wrapper");
                if (!wrapper.contains(e.target)) {
                    panel.classList.add("hidden");
                    document.removeEventListener("click", closeOnOutside, true);
                }
            }
            document.addEventListener("click", closeOnOutside, true);
        }, 0);
    }
}

function toggleFilterSection(listId) {
    const section = document.getElementById(listId).parentElement;
    section.classList.toggle("open");
}

function populateFilterCheckboxes() {
    // Collect all unique edge types
    const edgeTypes = new Set();
    graphData.links.forEach(l => edgeTypes.add(l.type));

    // Initialize visibility sets on first load (all visible)
    if (!filterInitialized) {
        visibleNodeIds = new Set(graphData.nodes.map(n => n.id));
        visibleEdgeTypes = new Set(edgeTypes);
        filterInitialized = true;
    } else {
        // Add any new nodes/types that appeared
        graphData.nodes.forEach(n => visibleNodeIds.add(n.id));
        edgeTypes.forEach(t => visibleEdgeTypes.add(t));
    }

    // Build node checkboxes — per individual node, sorted alphabetically
    const nodeList = document.getElementById("filter-nodes-list");
    nodeList.innerHTML = "";
    const sortedNodes = [...graphData.nodes].sort((a, b) => a.name.localeCompare(b.name));

    // Select All checkbox for nodes
    const nodeSelectAllLbl = document.createElement("label");
    nodeSelectAllLbl.style.cssText = "font-weight:600;border-bottom:1px solid var(--glass-border);padding-bottom:6px;margin-bottom:2px";
    const nodeSelectAllCb = document.createElement("input");
    nodeSelectAllCb.type = "checkbox";
    nodeSelectAllCb.checked = sortedNodes.every(n => visibleNodeIds.has(n.id));
    nodeSelectAllLbl.appendChild(nodeSelectAllCb);
    nodeSelectAllLbl.appendChild(document.createTextNode(" Select All"));
    nodeList.appendChild(nodeSelectAllLbl);

    const nodeCbs = [];
    sortedNodes.forEach(n => {
        const lbl = document.createElement("label");
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = visibleNodeIds.has(n.id);
        cb.addEventListener("change", () => {
            if (cb.checked) visibleNodeIds.add(n.id);
            else visibleNodeIds.delete(n.id);
            nodeSelectAllCb.checked = sortedNodes.every(nd => visibleNodeIds.has(nd.id));
            renderGraph();
        });
        nodeCbs.push({ cb, node: n });
        const dot = document.createElement("span");
        dot.style.cssText = `display:inline-block;width:8px;height:8px;border-radius:50%;background:${NODE_COLORS[n.type] || NODE_COLORS.UNKNOWN};flex-shrink:0`;
        const txt = document.createElement("span");
        txt.style.cssText = "overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
        txt.textContent = n.name;
        txt.title = n.id;
        lbl.appendChild(cb);
        lbl.appendChild(dot);
        lbl.appendChild(txt);
        nodeList.appendChild(lbl);
    });

    nodeSelectAllCb.addEventListener("change", () => {
        nodeCbs.forEach(({ cb, node }) => {
            cb.checked = nodeSelectAllCb.checked;
            if (nodeSelectAllCb.checked) visibleNodeIds.add(node.id);
            else visibleNodeIds.delete(node.id);
        });
        renderGraph();
    });

    // Build edge checkboxes
    const edgeList = document.getElementById("filter-edges-list");
    edgeList.innerHTML = "";
    const sortedEdgeTypes = [...edgeTypes].sort();

    // Select All checkbox for edges
    const edgeSelectAllLbl = document.createElement("label");
    edgeSelectAllLbl.style.cssText = "font-weight:600;border-bottom:1px solid var(--glass-border);padding-bottom:6px;margin-bottom:2px";
    const edgeSelectAllCb = document.createElement("input");
    edgeSelectAllCb.type = "checkbox";
    edgeSelectAllCb.checked = sortedEdgeTypes.every(t => visibleEdgeTypes.has(t));
    edgeSelectAllLbl.appendChild(edgeSelectAllCb);
    edgeSelectAllLbl.appendChild(document.createTextNode(" Select All"));
    edgeList.appendChild(edgeSelectAllLbl);

    const edgeCbs = [];
    sortedEdgeTypes.forEach(t => {
        const lbl = document.createElement("label");
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = visibleEdgeTypes.has(t);
        cb.addEventListener("change", () => {
            if (cb.checked) visibleEdgeTypes.add(t);
            else visibleEdgeTypes.delete(t);
            edgeSelectAllCb.checked = sortedEdgeTypes.every(et => visibleEdgeTypes.has(et));
            renderGraph();
        });
        edgeCbs.push({ cb, type: t });
        lbl.appendChild(cb);
        lbl.appendChild(document.createTextNode(" " + t));
        edgeList.appendChild(lbl);
    });

    edgeSelectAllCb.addEventListener("change", () => {
        edgeCbs.forEach(({ cb, type }) => {
            cb.checked = edgeSelectAllCb.checked;
            if (edgeSelectAllCb.checked) visibleEdgeTypes.add(type);
            else visibleEdgeTypes.delete(type);
        });
        renderGraph();
    });
}
