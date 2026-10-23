import os, secrets, sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, abort

APP_SECRET = os.environ.get("APP_SECRET", "change-this-secret-before-deploying")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change-this-password-before-deploying")
DB_PATH = os.environ.get("DB_PATH", "keys.db")

app = Flask(__name__)
app.secret_key = APP_SECRET

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                duration TEXT NOT NULL,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                max_activations INTEGER NOT NULL DEFAULT 1,
                activations INTEGER NOT NULL DEFAULT 0
            )
        """)

def now():
    return datetime.now(timezone.utc)

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def create_license(duration, max_activations=1):
    created = now()
    durations = {"1h": timedelta(hours=1), "1d": timedelta(days=1), "7d": timedelta(days=7), "lifetime": None}
    if duration not in durations:
        raise ValueError("duration must be 1h, 1d, 7d, or lifetime")
    expiry = created + durations[duration] if durations[duration] else None
    key = "CF-" + secrets.token_urlsafe(18).replace("-", "").replace("_", "")[:24].upper()
    with db() as con:
        con.execute(
            "INSERT INTO licenses (license_key,duration,expires_at,created_at,max_activations) VALUES (?,?,?,?,?)",
            (key, duration, expiry.isoformat() if expiry else None, created.isoformat(), max(1, min(int(max_activations), 100)))
        )
    return key

@app.route("/")
def home():
    if not session.get("admin"):
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("dashboard"))
        error = "Senha incorreta."
    return render_template_string(LOGIN_HTML, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard", methods=["GET", "POST"])
@admin_required
def dashboard():
    message = ""
    if request.method == "POST":
        duration = request.form.get("duration", "")
        max_activations = request.form.get("max_activations", "1")
        try:
            key = create_license(duration, max_activations)
            message = "Key criada: " + key
        except Exception as e:
            message = "Erro: " + str(e)
    with db() as con:
        licenses = con.execute("SELECT * FROM licenses ORDER BY id DESC LIMIT 200").fetchall()
    return render_template_string(DASHBOARD_HTML, licenses=licenses, message=message)

@app.post("/admin/revoke/<int:license_id>")
@admin_required
def revoke(license_id):
    with db() as con:
        con.execute("UPDATE licenses SET revoked=1 WHERE id=?", (license_id,))
    return redirect(url_for("dashboard"))

@app.post("/api/validate")
def validate():
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    if not key:
        return jsonify(valid=False, reason="missing_key"), 400
    with db() as con:
        lic = con.execute("SELECT * FROM licenses WHERE license_key=?", (key,)).fetchone()
    if not lic:
        return jsonify(valid=False, reason="invalid_key"), 404
    if lic["revoked"]:
        return jsonify(valid=False, reason="revoked"), 403
    expiry = datetime.fromisoformat(lic["expires_at"]) if lic["expires_at"] else None
    if expiry and now() >= expiry:
        return jsonify(valid=False, reason="expired"), 403
    return jsonify(valid=True, duration=lic["duration"], expires_at=lic["expires_at"])

@app.post("/api/activate")
def activate():
    """Basic activation counter. Production apps should send a stable, privacy-reviewed device identifier."""
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    device_id = str(data.get("device_id", "")).strip()
    if not key or not device_id:
        return jsonify(ok=False, reason="key_and_device_id_required"), 400
    with db() as con:
        lic = con.execute("SELECT * FROM licenses WHERE license_key=?", (key,)).fetchone()
        if not lic:
            return jsonify(ok=False, reason="invalid_key"), 404
        if lic["revoked"]:
            return jsonify(ok=False, reason="revoked"), 403
        expiry = datetime.fromisoformat(lic["expires_at"]) if lic["expires_at"] else None
        if expiry and now() >= expiry:
            return jsonify(ok=False, reason="expired"), 403
        # Starter limitation: counts activation requests; it does not yet persist unique device IDs.
        if lic["activations"] >= lic["max_activations"]:
            return jsonify(ok=False, reason="activation_limit"), 403
        con.execute("UPDATE licenses SET activations=activations+1 WHERE id=?", (lic["id"],))
    return jsonify(ok=True, message="activated")

LOGIN_HTML = """
<!doctype html><html lang="pt-br"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Key Server — Login</title><style>
body{font-family:system-ui;background:#10131a;color:#f4f6fb;max-width:480px;margin:12vh auto;padding:20px}
.card{background:#1b202b;padding:24px;border-radius:16px}input,button{box-sizing:border-box;width:100%;padding:12px;margin-top:10px;border-radius:8px;border:1px solid #444;background:#111722;color:white}button{background:#5865f2;border:0;font-weight:700}.err{color:#ff8888}
</style><div class="card"><h1>Key Server</h1><p>Painel administrativo</p><form method="post"><input type="password" name="password" placeholder="Senha de administrador" required><button>Entrar</button></form><p class="err">{{error}}</p></div></html>
"""

DASHBOARD_HTML = """
<!doctype html><html lang="pt-br"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Key Server — Painel</title><style>
body{font-family:system-ui;background:#10131a;color:#f4f6fb;margin:0;padding:18px}
main{max-width:1000px;margin:auto}.card{background:#1b202b;padding:18px;border-radius:14px;margin:14px 0}
input,select,button{padding:10px;border-radius:8px;border:1px solid #444;background:#111722;color:white}
button{background:#5865f2;border:0;font-weight:700;cursor:pointer}.msg{background:#243d2e;padding:12px;border-radius:8px;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:9px;border-bottom:1px solid #343a46;overflow-wrap:anywhere}
.revoked{color:#ff8888}.active{color:#8ce6a2}.muted{color:#aab2c0}.tablewrap{overflow-x:auto}
</style><main><h1>Key Server</h1><p class="muted">Gerenciamento de licenças</p>
<div class="card"><h2>Criar key</h2><form method="post">
<label>Validade <select name="duration"><option value="1h">1 hora</option><option value="1d">1 dia</option><option value="7d">7 dias</option><option value="lifetime">Lifetime</option></select></label>
<label> Máximo de ativações <input type="number" name="max_activations" value="1" min="1" max="100"></label>
<button type="submit">Gerar key</button></form>
{% if message %}<p class="msg">{{message}}</p>{% endif %}</div>
<div class="card"><h2>Keys recentes</h2><div class="tablewrap"><table><tr><th>Key</th><th>Validade</th><th>Expira</th><th>Ativações</th><th>Status</th><th>Ação</th></tr>
{% for l in licenses %}
<tr><td>{{l['license_key']}}</td><td>{{l['duration']}}</td><td>{{l['expires_at'] or 'Nunca'}}</td><td>{{l['activations']}} / {{l['max_activations']}}</td><td>{% if l['revoked'] %}<span class="revoked">Revogada</span>{% else %}<span class="active">Ativa*</span>{% endif %}</td><td>{% if not l['revoked'] %}<form method="post" action="/admin/revoke/{{l['id']}}"><button>Revogar</button></form>{% endif %}</td></tr>
{% endfor %}</table></div><p class="muted">*O status de expiração é validado pela API quando a key é usada.</p></div><p><a style="color:#aab2c0" href="/logout">Sair</a></p></main></html>
"""

if __name__ == "__main__":
    init_db()
    # Local-only development server. Use a production WSGI server and HTTPS for deployment.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
