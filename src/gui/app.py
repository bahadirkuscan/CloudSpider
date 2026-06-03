import os
import uuid
import logging
import functools
from flask import Flask, request, jsonify, send_from_directory, session, redirect
from flask_socketio import SocketIO
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user,
)
from src.gui.orchestrator import Orchestrator
from src.gui import db as userdb

# ── Logging Setup ──────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# ── Flask App ──────────────────────────────────────────────────────────

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

# ── Flask-Login Setup ─────────────────────────────────────────────────

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_page"


class User(UserMixin):
    """Flask-Login user wrapper around a DB user dict."""

    def __init__(self, user_dict):
        self._data = user_dict

    def get_id(self):
        return self._data["username"]

    @property
    def username(self):
        return self._data["username"]

    @property
    def role(self):
        return self._data["role"]

    @property
    def is_admin(self):
        return self._data["role"] == "admin"

    @property
    def is_readonly(self):
        return self._data["role"] == "readonly"

    @property
    def can_write(self):
        return self._data["role"] in ("admin", "full")


@login_manager.user_loader
def load_user(username):
    u = userdb.get_user(username)
    if u:
        return User(u)
    return None


@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith("/api/"):
        return jsonify({"error": "Authentication required."}), 401
    return redirect("/login")


# ── Role-checking decorator ───────────────────────────────────────────

def role_required(*allowed_roles):
    """Decorator that checks the current user has one of the allowed roles."""
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.role not in allowed_roles:
                return jsonify({"error": "Insufficient permissions."}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


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

# ── User-scoped Orchestrator Instances ────────────────────────────────

_orchestrators = {}  # username -> Orchestrator

def get_orchestrator() -> Orchestrator:
    """Return the Orchestrator for the current user, creating one if needed."""
    username = current_user.username
    if username not in _orchestrators:
        _orchestrators[username] = Orchestrator(owner=username)
        logger.info(f"New orchestrator created for user: {username}")
    return _orchestrators[username]

# ── Database Initialization ──────────────────────────────────────────

admin_password = userdb.init_db()
if admin_password:
    print("\n" + "=" * 60)
    print("  CloudSpider — First Run Setup")
    print("=" * 60)
    print(f"  Default admin credentials:")
    print(f"    Username : admin")
    print(f"    Password : {admin_password}")
    print()
    print("  ⚠  This password will NOT be shown again.")
    print("  Change it from the Admin Panel after login.")
    print("=" * 60 + "\n")
    logger.info("Default admin account created. Credentials printed to stdout.")

# ── Static Files & Login Page ─────────────────────────────────────────

@app.route("/login")
def login_page():
    if current_user.is_authenticated:
        return redirect("/")
    return send_from_directory(app.static_folder, "login.html")

@app.route("/")
@login_required
def index():
    return send_from_directory(app.static_folder, "index.html")

# ── Auth API ──────────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400
    user_dict = userdb.authenticate_user(username, password)
    if not user_dict:
        return jsonify({"error": "Invalid username or password."}), 401
    user = User(user_dict)
    login_user(user, remember=True)
    session.permanent = True
    logger.info(f"User '{username}' logged in.")
    return jsonify({"status": "ok", "username": user.username, "role": user.role})

@app.route("/api/auth/logout", methods=["POST"])
@login_required
def api_logout():
    username = current_user.username
    logout_user()
    logger.info(f"User '{username}' logged out.")
    return jsonify({"status": "ok"})

@app.route("/api/auth/me", methods=["GET"])
@login_required
def api_me():
    return jsonify({"username": current_user.username, "role": current_user.role})

# ── Admin API ─────────────────────────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
@role_required("admin")
def admin_list_users():
    return jsonify(userdb.list_users())

@app.route("/api/admin/users", methods=["POST"])
@role_required("admin")
def admin_create_user():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "full")
    try:
        user = userdb.create_user(username, password, role, created_by=current_user.username)
        logger.info(f"Admin created user '{username}' with role '{role}'.")
        return jsonify(user)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/admin/users/<username>", methods=["DELETE"])
@role_required("admin")
def admin_delete_user(username):
    try:
        # Clean up user's snapshots
        snapshots = userdb.list_snapshots_for_user(username)
        orch = Orchestrator(owner=username)  # scoped orchestrator for cleanup
        for snap in snapshots.get("own", []):
            try:
                orch.delete_snapshot_file(snap["filename"])
                userdb.delete_snapshot_meta(snap["filename"])
            except Exception:
                pass
        # Clear the user's Neo4j graph data
        try:
            orch._ensure_builder()
            orch._builder.clear_graph()
        except Exception:
            pass
        userdb.delete_user(username)
        # Remove orchestrator if exists
        if username in _orchestrators:
            del _orchestrators[username]
        logger.info(f"Admin deleted user '{username}'.")
        return jsonify({"status": "ok"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/admin/users/<username>/role", methods=["PUT"])
@role_required("admin")
def admin_change_role(username):
    data = request.json or {}
    new_role = data.get("role", "")
    try:
        userdb.update_role(username, new_role)
        logger.info(f"Admin changed role of '{username}' to '{new_role}'.")
        return jsonify({"status": "ok"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/admin/password", methods=["PUT"])
@role_required("admin")
def admin_change_password():
    data = request.json or {}
    current_pw = data.get("current_password", "")
    new_pw = data.get("new_password", "")
    if not current_pw or not new_pw:
        return jsonify({"error": "Both current and new password are required."}), 400
    if not userdb.authenticate_user(current_user.username, current_pw):
        return jsonify({"error": "Current password is incorrect."}), 403
    try:
        userdb.update_password(current_user.username, new_pw)
        logger.info(f"Admin '{current_user.username}' changed password.")
        return jsonify({"status": "ok"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/admin/users/<username>/password", methods=["PUT"])
@role_required("admin")
def admin_reset_user_password(username):
    data = request.json or {}
    new_pw = data.get("new_password", "")
    if not new_pw:
        return jsonify({"error": "New password is required."}), 400
    user = userdb.get_user(username)
    if not user:
        return jsonify({"error": f"User '{username}' not found."}), 404
    if user["role"] == "admin":
        return jsonify({"error": "Use the admin password change form to change your own password."}), 400
    try:
        userdb.update_password(username, new_pw)
        logger.info(f"Admin '{current_user.username}' reset password for user '{username}'.")
        return jsonify({"status": "ok"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/auth/password", methods=["PUT"])
@login_required
def change_own_password():
    data = request.json or {}
    current_pw = data.get("current_password", "")
    new_pw = data.get("new_password", "")
    if not current_pw or not new_pw:
        return jsonify({"error": "Both current and new password are required."}), 400
    if not userdb.authenticate_user(current_user.username, current_pw):
        return jsonify({"error": "Current password is incorrect."}), 403
    try:
        userdb.update_password(current_user.username, new_pw)
        logger.info(f"User '{current_user.username}' changed their own password.")
        return jsonify({"status": "ok"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

# ── Credential API ────────────────────────────────────────────────────

@app.route("/api/credentials", methods=["GET"])
@login_required
def list_credentials():
    return jsonify(get_orchestrator().list_credentials())

@app.route("/api/credentials", methods=["POST"])
@role_required("admin", "full")
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
@role_required("admin", "full")
def delete_credential(name):
    get_orchestrator().remove_credential(name)
    return jsonify({"status": "ok"})

@app.route("/api/credentials/<name>/activate", methods=["POST"])
@role_required("admin", "full")
def activate_credential(name):
    try:
        identity = get_orchestrator().activate_credential(name)
        return jsonify({"status": "ok", "identity": identity})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/credentials/active", methods=["GET"])
@login_required
def get_active_credential():
    profile = get_orchestrator().get_active_profile()
    if not profile:
        return jsonify({"active": False})
    return jsonify({"active": True, **profile})

# ── Pipeline API ──────────────────────────────────────────────────────

@app.route("/api/pipeline/discover", methods=["POST"])
@role_required("admin", "full")
def run_discovery():
    try:
        result = get_orchestrator().run_discovery()
        socketio.emit("pipeline_status", {"stage": "discovered", "message": "Discovery complete."})
        return jsonify({"status": "ok", **result})
    except Exception as e:
        socketio.emit("pipeline_status", {"stage": "error", "message": str(e)})
        return jsonify({"error": str(e)}), 500

@app.route("/api/pipeline/build", methods=["POST"])
@role_required("admin", "full")
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
@role_required("admin", "full")
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
@login_required
def get_graph():
    try:
        data = get_orchestrator().get_graph_data()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/graph", methods=["DELETE"])
@role_required("admin", "full")
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
@login_required
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
@role_required("admin", "full")
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

# ── Snapshot API (user-owned, with visibility control) ────────────────

@app.route("/api/snapshots", methods=["GET"])
@login_required
def list_snapshots():
    data = userdb.list_snapshots_for_user(current_user.username)
    return jsonify(data)

@app.route("/api/snapshots/save", methods=["POST"])
@role_required("admin", "full")
def save_snapshot():
    data = request.json or {}
    name = data.get("name")
    client_state = data.get("state")
    if not name:
        return jsonify({"error": "name is required."}), 400
    try:
        result = get_orchestrator().save_graph(name, current_user.username, client_state)
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/snapshots/load", methods=["POST"])
@login_required
def load_snapshot():
    data = request.json or {}
    name = data.get("name")
    password = data.get("password")
    mode = data.get("mode", "build")
    if not name:
        return jsonify({"error": "name is required."}), 400

    # Find snapshot metadata
    meta = userdb.get_snapshot_meta_by_name(name)
    if not meta:
        return jsonify({"error": f"Snapshot '{name}' not found."}), 404

    # Check access
    is_owner = meta["created_by"] == current_user.username
    is_admin = current_user.is_admin

    if not is_owner and not is_admin:
        # Must be a public snapshot with correct password
        if meta["visibility"] != "public":
            return jsonify({"error": "Snapshot is private."}), 403
        if current_user.is_readonly and meta["visibility"] != "public":
            return jsonify({"error": "Read-only users can only load public snapshots."}), 403
        if not password:
            return jsonify({"error": "Password is required to load another user's snapshot."}), 400
        if not userdb.verify_snapshot_password(meta["filename"], password):
            return jsonify({"error": "Incorrect password."}), 403

    try:
        result = get_orchestrator().load_graph_from_file(meta["filename"], mode)
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/snapshots/<name>", methods=["DELETE"])
@login_required
def delete_snapshot(name):
    meta = userdb.get_snapshot_meta_by_name(name)
    if not meta:
        return jsonify({"error": f"Snapshot '{name}' not found."}), 404

    is_owner = meta["created_by"] == current_user.username
    is_admin = current_user.is_admin

    if not is_owner and not is_admin:
        return jsonify({"error": "You can only delete your own snapshots."}), 403

    try:
        get_orchestrator().delete_snapshot_file(meta["filename"])
        userdb.delete_snapshot_meta(meta["filename"])
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/snapshots/<name>/visibility", methods=["POST"])
@role_required("admin", "full")
def toggle_snapshot_visibility(name):
    meta = userdb.get_snapshot_meta_by_name(name)
    if not meta:
        return jsonify({"error": f"Snapshot '{name}' not found."}), 404

    if meta["created_by"] != current_user.username and not current_user.is_admin:
        return jsonify({"error": "You can only change visibility of your own snapshots."}), 403

    data = request.json or {}
    visibility = data.get("visibility")
    password = data.get("password")

    try:
        userdb.update_snapshot_visibility(meta["filename"], visibility, password)
        logger.info(f"Snapshot '{name}' visibility changed to '{visibility}' by '{current_user.username}'.")
        return jsonify({"status": "ok"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

# ── Session State API (persist client state across page refreshes) ────

_session_states = {}  # username -> dict of client-side state

@app.route("/api/session/state", methods=["GET"])
@login_required
def get_session_state():
    username = current_user.username
    state = _session_states.get(username)
    if not state:
        return jsonify({"has_state": False})
    return jsonify({"has_state": True, **state})

@app.route("/api/session/state", methods=["POST"])
@login_required
def save_session_state():
    username = current_user.username
    data = request.json or {}
    _session_states[username] = data
    return jsonify({"status": "ok"})

@app.route("/api/session/state", methods=["DELETE"])
@login_required
def clear_session_state():
    username = current_user.username
    if username in _session_states:
        del _session_states[username]
    return jsonify({"status": "ok"})

# ── Pipeline Status ───────────────────────────────────────────────────

@app.route("/api/pipeline/status", methods=["GET"])
@login_required
def pipeline_status():
    return jsonify({"stage": get_orchestrator().stage.value})
