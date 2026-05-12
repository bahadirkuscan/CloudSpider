import os
import uuid
import logging
from flask import Flask, request, jsonify, send_from_directory, session
from flask_socketio import SocketIO
from src.gui.orchestrator import Orchestrator

# ── Logging Setup ──────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# ── Flask App ──────────────────────────────────────────────────────────

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

# ── SocketIO Log Handler ──────────────────────────────────────────────

class SocketIOLogHandler(logging.Handler):
    """Intercepts log messages from CloudSpider modules and emits them to connected browser clients."""
    def emit(self, record):
        try:
            msg = self.format(record)
            socketio.emit("log", {
                "level": record.levelname,
                "message": msg,
                "logger": record.name,
                "timestamp": record.created,
            })
        except Exception:
            pass

socket_handler = SocketIOLogHandler()
socket_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
# Attach to root src logger so all submodules get captured
logging.getLogger("src").addHandler(socket_handler)

# ── Session-scoped Orchestrator Instances ─────────────────────────────

_orchestrators = {}  # session_id -> Orchestrator

def get_orchestrator() -> Orchestrator:
    """Return the Orchestrator for the current session, creating one if needed."""
    sid = session.get("sid")
    if not sid:
        sid = str(uuid.uuid4())
        session["sid"] = sid
        session.permanent = True
    if sid not in _orchestrators:
        _orchestrators[sid] = Orchestrator()
        logger.info(f"New session orchestrator created: {sid[:8]}…")
    return _orchestrators[sid]

# ── Static Files ──────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

# ── Credential API ────────────────────────────────────────────────────

@app.route("/api/credentials", methods=["GET"])
def list_credentials():
    return jsonify(get_orchestrator().list_credentials())

@app.route("/api/credentials", methods=["POST"])
def add_credential():
    data = request.json
    if not data or not data.get("name") or not data.get("access_key_id") or not data.get("secret_access_key"):
        return jsonify({"error": "name, access_key_id, and secret_access_key are required."}), 400
    get_orchestrator().add_credential(
        name=data["name"],
        access_key_id=data["access_key_id"],
        secret_access_key=data["secret_access_key"],
        session_token=data.get("session_token", ""),
        region=data.get("region", "us-east-1"),
    )
    return jsonify({"status": "ok", "name": data["name"]})

@app.route("/api/credentials/<name>", methods=["DELETE"])
def delete_credential(name):
    get_orchestrator().remove_credential(name)
    return jsonify({"status": "ok"})

@app.route("/api/credentials/<name>/activate", methods=["POST"])
def activate_credential(name):
    try:
        identity = get_orchestrator().activate_credential(name)
        return jsonify({"status": "ok", "identity": identity})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/credentials/active", methods=["GET"])
def get_active_credential():
    profile = get_orchestrator().get_active_profile()
    if not profile:
        return jsonify({"active": False})
    return jsonify({"active": True, **profile})

# ── Pipeline API ──────────────────────────────────────────────────────

@app.route("/api/pipeline/discover", methods=["POST"])
def run_discovery():
    try:
        result = get_orchestrator().run_discovery()
        socketio.emit("pipeline_status", {"stage": "discovered", "message": "Discovery complete."})
        return jsonify({"status": "ok", **result})
    except Exception as e:
        socketio.emit("pipeline_status", {"stage": "error", "message": str(e)})
        return jsonify({"error": str(e)}), 500

@app.route("/api/pipeline/build", methods=["POST"])
def build_graph():
    data = request.json or {}
    mode = data.get("mode", "build")
    try:
        result = get_orchestrator().build_graph(mode)
        socketio.emit("pipeline_status", {"stage": "graph_built", "message": "Graph build complete."})
        return jsonify({"status": "ok", **result})
    except Exception as e:
        socketio.emit("pipeline_status", {"stage": "error", "message": str(e)})
        return jsonify({"error": str(e)}), 500

@app.route("/api/pipeline/run-all", methods=["POST"])
def run_full_pipeline():
    data = request.json or {}
    mode = data.get("mode", "build")
    try:
        result = get_orchestrator().run_full_pipeline(mode)
        socketio.emit("pipeline_status", {"stage": "graph_built", "message": "Full pipeline complete."})
        return jsonify({"status": "ok", **result})
    except Exception as e:
        socketio.emit("pipeline_status", {"stage": "error", "message": str(e)})
        return jsonify({"error": str(e)}), 500

# ── Graph API ─────────────────────────────────────────────────────────

@app.route("/api/graph", methods=["GET"])
def get_graph():
    try:
        data = get_orchestrator().get_graph_data()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/graph", methods=["DELETE"])
def clear_graph():
    try:
        orch = get_orchestrator()
        orch._ensure_builder()
        orch._builder.clear_graph()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Pathfinder API ────────────────────────────────────────────────────

@app.route("/api/pathfinder/query", methods=["POST"])
def query_paths():
    data = request.json or {}
    start_arn = data.get("start_arn")
    target_arn = data.get("target_arn")
    if not start_arn or not target_arn:
        return jsonify({"error": "Both start_arn and target_arn are required."}), 400
    try:
        paths = get_orchestrator().find_paths(start_arn, target_arn)
        return jsonify({"status": "ok", "paths": paths, "count": len(paths)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Action Execution API ──────────────────────────────────────────────

@app.route("/api/action/execute", methods=["POST"])
def execute_action():
    data = request.json or {}
    edge_type = data.get("edge_type")
    source_arn = data.get("source_arn")
    target_arn = data.get("target_arn")
    if not all([edge_type, source_arn, target_arn]):
        return jsonify({"error": "edge_type, source_arn, and target_arn are required."}), 400
    try:
        result = get_orchestrator().execute_action(edge_type, source_arn, target_arn)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Snapshot API (encrypted, password-protected) ──────────────────────

@app.route("/api/snapshots", methods=["GET"])
def list_snapshots():
    return jsonify(get_orchestrator().list_snapshots())

@app.route("/api/snapshots/save", methods=["POST"])
def save_snapshot():
    data = request.json or {}
    name = data.get("name")
    password = data.get("password")
    client_state = data.get("state")
    if not name:
        return jsonify({"error": "name is required."}), 400
    if not password:
        return jsonify({"error": "password is required."}), 400
    try:
        result = get_orchestrator().save_graph(name, password, client_state)
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/snapshots/load", methods=["POST"])
def load_snapshot():
    data = request.json or {}
    name = data.get("name")
    password = data.get("password")
    mode = data.get("mode", "build")
    if not name:
        return jsonify({"error": "name is required."}), 400
    if not password:
        return jsonify({"error": "password is required."}), 400
    try:
        result = get_orchestrator().load_graph(name, password, mode)
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/snapshots/<name>", methods=["DELETE"])
def delete_snapshot(name):
    data = request.json or {}
    password = data.get("password")
    if not password:
        return jsonify({"error": "password is required."}), 400
    try:
        # Verify password by attempting to decrypt
        orch = get_orchestrator()
        filepath = os.path.join(orch.snapshot_dir, f"{name}.json")
        if not os.path.exists(filepath):
            return jsonify({"error": f"Snapshot '{name}' not found."}), 404
        import json as _json, base64 as _b64
        from cryptography.fernet import Fernet, InvalidToken
        with open(filepath, "r") as f:
            envelope = _json.load(f)
        salt = _b64.b64decode(envelope["salt"])
        key = Orchestrator._derive_key(password, salt)
        fernet = Fernet(key)
        try:
            fernet.decrypt(envelope["encrypted"].encode())
        except InvalidToken:
            return jsonify({"error": "Incorrect password."}), 403
        orch.delete_snapshot(name)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Session State API (persist client state across page refreshes) ────

_session_states = {}  # session_id -> dict of client-side state

@app.route("/api/session/state", methods=["GET"])
def get_session_state():
    sid = session.get("sid", "")
    state = _session_states.get(sid)
    if not state:
        return jsonify({"has_state": False})
    return jsonify({"has_state": True, **state})

@app.route("/api/session/state", methods=["POST"])
def save_session_state():
    sid = session.get("sid")
    if not sid:
        sid = str(uuid.uuid4())
        session["sid"] = sid
        session.permanent = True
    data = request.json or {}
    _session_states[sid] = data
    return jsonify({"status": "ok"})

@app.route("/api/session/state", methods=["DELETE"])
def clear_session_state():
    sid = session.get("sid")
    if sid in _session_states:
        del _session_states[sid]
    return jsonify({"status": "ok"})

# ── Pipeline Status ───────────────────────────────────────────────────

@app.route("/api/pipeline/status", methods=["GET"])
def pipeline_status():
    return jsonify({"stage": get_orchestrator().stage.value})
