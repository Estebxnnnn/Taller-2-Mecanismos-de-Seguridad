"""
GeoConsent - Backend REST para localización CON CONSENTIMIENTO
Guía-Taller No. 2, Parte II · Universidad Distrital FJDC

Principios (coherentes con la nota ética de la guía):
  - Ningún dispositivo se rastrea sin inscribirse y verificar su número (consentimiento informado).
  - El dispositivo controla su estado de compartición y puede pausar o revocar en cualquier momento.
  - Minimización de datos, acceso autenticado (JWT) y registro de auditoría de consentimiento.

No contiene técnica alguna para localizar un número de WhatsApp/Telegram o un celular sin la
participación activa de su propietario: eso no es posible de forma legítima y la guía lo prohíbe.
"""
import os, sqlite3, secrets, time, math, datetime as dt, hmac, hashlib, json, functools
from flask import Flask, request, jsonify, g
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("GEO_DB", os.path.join(BASE, "data", "geoloc.db"))
JWT_SECRET = os.environ.get("GEO_JWT_SECRET", "lab-demo-secret-fijo-de-laboratorio-32bytes-min")
JWT_ALG = "HS256"
TOKEN_TTL_OWNER = 3600          # 1 h para el panel del propietario
TOKEN_TTL_DEVICE = 30 * 86400   # 30 días para el dispositivo inscrito
TZ = dt.timezone(dt.timedelta(hours=-5))  # America/Bogota

app = Flask(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS owners(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, phone TEXT NOT NULL, display_name TEXT,
  device_label TEXT, consent_state TEXT NOT NULL DEFAULT 'pending',  -- pending|active|paused|revoked
  verify_code TEXT, verify_expires REAL, interval_s INTEGER DEFAULT 600,
  enrolled_at TEXT, consented_at TEXT, revoked_at TEXT,
  UNIQUE(owner_id, phone));
CREATE TABLE IF NOT EXISTS locations(
  id INTEGER PRIMARY KEY, device_id TEXT NOT NULL, ts TEXT NOT NULL, epoch REAL NOT NULL,
  lat REAL NOT NULL, lon REAL NOT NULL, accuracy_m REAL, speed_kmh REAL, battery INTEGER,
  FOREIGN KEY(device_id) REFERENCES devices(id));
CREATE TABLE IF NOT EXISTS geofences(
  id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, name TEXT NOT NULL,
  lat REAL NOT NULL, lon REAL NOT NULL, radius_m REAL NOT NULL,
  notify_on TEXT NOT NULL DEFAULT 'both');  -- enter|exit|both
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, device_id TEXT NOT NULL,
  geofence_id INTEGER, kind TEXT NOT NULL, ts TEXT NOT NULL, epoch REAL NOT NULL,
  detail TEXT, acknowledged INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS consent_log(
  id INTEGER PRIMARY KEY, device_id TEXT NOT NULL, ts TEXT NOT NULL, event TEXT NOT NULL,
  actor TEXT, note TEXT);
CREATE INDEX IF NOT EXISTS ix_loc_dev ON locations(device_id, epoch);
CREATE INDEX IF NOT EXISTS ix_geo_state ON devices(consent_state);
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH); con.executescript(SCHEMA); con.commit(); con.close()

def now():
    return dt.datetime.now(TZ)

def iso(d=None):
    return (d or now()).isoformat(timespec="seconds")

def haversine_m(a_lat, a_lon, b_lat, b_lon):
    R = 6371000.0
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dphi = math.radians(b_lat - a_lat); dl = math.radians(b_lon - a_lon)
    h = math.sin(dphi/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2*R*math.asin(min(1, math.sqrt(h)))

# ----------------------------------------------------------------- auth helpers
def make_token(sub, kind, ttl):
    payload = {"sub": str(sub), "kind": kind, "iat": int(time.time()), "exp": int(time.time())+ttl}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def read_token(kind):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, ("falta cabecera Authorization Bearer", 401)
    try:
        p = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        return None, ("token expirado", 401)
    except jwt.InvalidTokenError:
        return None, ("token inválido", 401)
    if p.get("kind") != kind:
        return None, ("tipo de token incorrecto", 403)
    return p, None

def require(kind):
    def deco(fn):
        @functools.wraps(fn)
        def wrap(*a, **k):
            p, err = read_token(kind)
            if err: return jsonify(error=err[0]), err[1]
            g.claims = p
            return fn(*a, **k)
        return wrap
    return deco

def log_consent(con, device_id, event, actor, note=""):
    con.execute("INSERT INTO consent_log(device_id,ts,event,actor,note) VALUES(?,?,?,?,?)",
                (device_id, iso(), event, actor, note))

# ----------------------------------------------------------------- cuentas
@app.post("/api/v1/owners")
def create_owner():
    d = request.get_json(force=True)
    u, pw = d.get("username", "").strip(), d.get("password", "")
    if len(u) < 3 or len(pw) < 8:
        return jsonify(error="usuario >= 3 y contraseña >= 8 caracteres"), 400
    con = db()
    try:
        con.execute("INSERT INTO owners(username,pw_hash,created_at) VALUES(?,?,?)",
                    (u, generate_password_hash(pw), iso())); con.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="el usuario ya existe"), 409
    return jsonify(status="creado", username=u), 201

@app.post("/api/v1/login")
def login():
    d = request.get_json(force=True)
    row = db().execute("SELECT * FROM owners WHERE username=?", (d.get("username"),)).fetchone()
    if not row or not check_password_hash(row["pw_hash"], d.get("password", "")):
        return jsonify(error="credenciales inválidas"), 401
    return jsonify(access_token=make_token(row["id"], "owner", TOKEN_TTL_OWNER),
                   token_type="Bearer", expires_in=TOKEN_TTL_OWNER)

# ----------------------------------------------------------------- inscripción con consentimiento
@app.post("/api/v1/devices/enroll")
@require("owner")
def enroll():
    """El propietario invita a un número. El dispositivo NO se activa hasta que verifica el código
    que recibe por SMS: así se registra el consentimiento informado del titular del teléfono."""
    owner_id = int(g.claims["sub"])
    d = request.get_json(force=True)
    phone = d.get("phone", "").strip()
    if not phone.startswith("+") or not phone[1:].replace(" ", "").isdigit():
        return jsonify(error="teléfono en formato E.164, p.ej. +573001112233"), 400
    did = "dev_" + secrets.token_hex(6)
    code = f"{secrets.randbelow(1000000):06d}"
    con = db()
    try:
        con.execute("""INSERT INTO devices(id,owner_id,phone,display_name,device_label,consent_state,
                       verify_code,verify_expires,interval_s,enrolled_at)
                       VALUES(?,?,?,?,?, 'pending', ?,?,?,?)""",
                    (did, owner_id, phone, d.get("display_name"), d.get("device_label"),
                     code, time.time()+600, int(d.get("interval_s", 600)), iso()))
        log_consent(con, did, "enroll_invited", f"owner:{owner_id}", f"phone={phone}")
        con.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="ese número ya está inscrito para este propietario"), 409
    # En producción el código viaja por SMS; aquí se devuelve para la demo de laboratorio.
    return jsonify(device_id=did, consent_state="pending",
                   sms_simulado=f"GeoConsent: {d.get('display_name') or phone} te invita a compartir "
                                f"tu ubicación. Código: {code} (vence en 10 min). Si no autorizas, ignora.",
                   verify_code_demo=code), 201

@app.post("/api/v1/devices/verify")
def verify():
    """El titular introduce el código: aquí nace el consentimiento y el dispositivo recibe su token."""
    d = request.get_json(force=True)
    did, code = d.get("device_id"), d.get("code")
    con = db()
    row = con.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()
    if not row: return jsonify(error="dispositivo no encontrado"), 404
    if row["consent_state"] == "revoked":
        return jsonify(error="inscripción revocada"), 403
    if not row["verify_code"] or time.time() > (row["verify_expires"] or 0):
        return jsonify(error="código vencido, solicita una nueva invitación"), 400
    if not hmac.compare_digest(row["verify_code"], str(code)):
        return jsonify(error="código incorrecto"), 400
    con.execute("UPDATE devices SET consent_state='active', consented_at=?, verify_code=NULL WHERE id=?",
                (iso(), did))
    log_consent(con, did, "consent_granted", f"device:{did}", "código verificado por el titular")
    con.commit()
    return jsonify(status="consentimiento registrado", consent_state="active",
                   device_token=make_token(did, "device", TOKEN_TTL_DEVICE),
                   token_type="Bearer",
                   aviso="Estás compartiendo tu ubicación. Puedes pausar o revocar cuando quieras "
                         "desde la app (POST /devices/sharing o DELETE /devices/me).")

# ----------------------------------------------------------------- control del titular
@app.post("/api/v1/devices/sharing")
@require("device")
def sharing():
    """El propio dispositivo pausa o reanuda su compartición (control del titular)."""
    did = g.claims["sub"]
    state = request.get_json(force=True).get("state")
    if state not in ("active", "paused"):
        return jsonify(error="state debe ser 'active' o 'paused'"), 400
    con = db()
    con.execute("UPDATE devices SET consent_state=? WHERE id=? AND consent_state IN('active','paused')",
                (state, did))
    log_consent(con, did, f"sharing_{state}", f"device:{did}")
    con.commit()
    return jsonify(consent_state=state)

@app.delete("/api/v1/devices/me")
@require("device")
def unenroll():
    """Derecho de revocación y borrado: el titular se da de baja y se eliminan sus ubicaciones."""
    did = g.claims["sub"]
    con = db()
    n = con.execute("SELECT COUNT(*) c FROM locations WHERE device_id=?", (did,)).fetchone()["c"]
    con.execute("DELETE FROM locations WHERE device_id=?", (did,))
    con.execute("UPDATE devices SET consent_state='revoked', revoked_at=?, verify_code=NULL WHERE id=?",
                (iso(), did))
    log_consent(con, did, "consent_revoked", f"device:{did}", f"{n} ubicaciones borradas")
    con.commit()
    return jsonify(status="revocado", ubicaciones_borradas=n)

# ----------------------------------------------------------------- ingesta de ubicación
def eval_geofences(con, dev, lat, lon, epoch, ts):
    """Detecta entradas/salidas comparando el estado previo (dentro/fuera) con el actual."""
    owner_id = dev["owner_id"]
    fences = con.execute("SELECT * FROM geofences WHERE owner_id=?", (owner_id,)).fetchall()
    prev = con.execute("""SELECT lat,lon FROM locations WHERE device_id=? ORDER BY epoch DESC LIMIT 1""",
                       (dev["id"],)).fetchone()
    events = []
    if prev is None:
        return events   # sin estado previo no se puede inferir entrada/salida (evita falsos "enter" en el 1.er fix)
    for f in fences:
        inside_now = haversine_m(lat, lon, f["lat"], f["lon"]) <= f["radius_m"]
        inside_prev = (haversine_m(prev["lat"], prev["lon"], f["lat"], f["lon"]) <= f["radius_m"]) if prev else False
        kind = None
        if inside_now and not inside_prev: kind = "enter"
        elif inside_prev and not inside_now: kind = "exit"
        if kind and f["notify_on"] in (kind, "both"):
            con.execute("""INSERT INTO alerts(owner_id,device_id,geofence_id,kind,ts,epoch,detail)
                           VALUES(?,?,?,?,?,?,?)""",
                        (owner_id, dev["id"], f["id"], f"geofence_{kind}", ts, epoch,
                         json.dumps({"geofence": f["name"], "radius_m": f["radius_m"]})))
            events.append({"geofence": f["name"], "event": kind})
    return events

@app.post("/api/v1/locations")
@require("device")
def ingest():
    did = g.claims["sub"]
    con = db()
    dev = con.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()
    if not dev: return jsonify(error="dispositivo no encontrado"), 404
    if dev["consent_state"] != "active":
        # Si el titular pausó o revocó, el servidor rechaza la ingesta: sin consentimiento activo no hay datos.
        return jsonify(error=f"compartición no activa (estado={dev['consent_state']})",
                       consent_state=dev["consent_state"]), 403
    d = request.get_json(force=True)
    try:
        lat, lon = float(d["lat"]), float(d["lon"])
    except (KeyError, TypeError, ValueError):
        return jsonify(error="lat y lon obligatorios"), 400
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return jsonify(error="coordenadas fuera de rango"), 400
    ts = d.get("ts") or iso()
    try:
        epoch = dt.datetime.fromisoformat(ts).timestamp()
    except ValueError:
        epoch = time.time(); ts = iso()
    events = eval_geofences(con, dev, lat, lon, epoch, ts)
    con.execute("""INSERT INTO locations(device_id,ts,epoch,lat,lon,accuracy_m,speed_kmh,battery)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (did, ts, epoch, lat, lon, d.get("accuracy_m"), d.get("speed_kmh"), d.get("battery")))
    con.commit()
    return jsonify(status="ok", consent_state="active", geofence_events=events,
                   aviso_compartiendo=True), 201

# ----------------------------------------------------------------- consulta (propietario)
@app.get("/api/v1/devices")
@require("owner")
def list_devices():
    owner_id = int(g.claims["sub"])
    rows = db().execute("SELECT * FROM devices WHERE owner_id=? AND consent_state!='revoked'",
                        (owner_id,)).fetchall()
    out = []
    for r in rows:
        last = db().execute("SELECT * FROM locations WHERE device_id=? ORDER BY epoch DESC LIMIT 1",
                            (r["id"],)).fetchone()
        out.append({"device_id": r["id"], "display_name": r["display_name"],
                    "phone": r["phone"][:-4] + "****", "consent_state": r["consent_state"],
                    "interval_s": r["interval_s"], "consented_at": r["consented_at"],
                    "last": dict(lat=last["lat"], lon=last["lon"], ts=last["ts"],
                                 battery=last["battery"], speed_kmh=last["speed_kmh"]) if last else None})
    return jsonify(devices=out)

@app.get("/api/v1/devices/<did>/history")
@require("owner")
def history(did):
    owner_id = int(g.claims["sub"])
    dev = db().execute("SELECT * FROM devices WHERE id=? AND owner_id=?", (did, owner_id)).fetchone()
    if not dev: return jsonify(error="no encontrado"), 404
    q = "SELECT ts,lat,lon,accuracy_m,speed_kmh,battery FROM locations WHERE device_id=?"
    args = [did]
    if request.args.get("from"):
        q += " AND epoch>=?"; args.append(dt.datetime.fromisoformat(request.args["from"]).timestamp())
    if request.args.get("to"):
        q += " AND epoch<=?"; args.append(dt.datetime.fromisoformat(request.args["to"]).timestamp())
    q += " ORDER BY epoch ASC"
    rows = db().execute(q, args).fetchall()
    return jsonify(device_id=did, points=[dict(r) for r in rows], count=len(rows))

@app.get("/api/v1/devices/<did>/stats")
@require("owner")
def stats(did):
    owner_id = int(g.claims["sub"])
    dev = db().execute("SELECT * FROM devices WHERE id=? AND owner_id=?", (did, owner_id)).fetchone()
    if not dev: return jsonify(error="no encontrado"), 404
    pts = db().execute("SELECT epoch,lat,lon,speed_kmh,battery FROM locations WHERE device_id=? ORDER BY epoch",
                       (did,)).fetchall()
    if len(pts) < 2:
        return jsonify(device_id=did, points=len(pts), note="datos insuficientes")
    dist = sum(haversine_m(pts[i-1]["lat"], pts[i-1]["lon"], pts[i]["lat"], pts[i]["lon"])
               for i in range(1, len(pts)))
    speeds = [p["speed_kmh"] for p in pts if p["speed_kmh"] is not None]
    dur = pts[-1]["epoch"] - pts[0]["epoch"]
    # tiempo dentro de cada geocerca
    fences = db().execute("SELECT * FROM geofences WHERE owner_id=?", (owner_id,)).fetchall()
    tin = {}
    for f in fences:
        secs = 0.0
        for i in range(1, len(pts)):
            if haversine_m(pts[i]["lat"], pts[i]["lon"], f["lat"], f["lon"]) <= f["radius_m"]:
                secs += pts[i]["epoch"] - pts[i-1]["epoch"]
        tin[f["name"]] = round(secs/60, 1)
    return jsonify(device_id=did, points=len(pts),
                   distance_km=round(dist/1000, 3),
                   duration_min=round(dur/60, 1),
                   avg_speed_kmh=round(sum(speeds)/len(speeds), 1) if speeds else None,
                   max_speed_kmh=round(max(speeds), 1) if speeds else None,
                   battery_start=pts[0]["battery"], battery_end=pts[-1]["battery"],
                   minutes_in_geofence=tin)

# ----------------------------------------------------------------- geocercas y alertas
@app.post("/api/v1/geofences")
@require("owner")
def create_geofence():
    owner_id = int(g.claims["sub"])
    d = request.get_json(force=True)
    for k in ("name", "lat", "lon", "radius_m"):
        if k not in d: return jsonify(error=f"falta {k}"), 400
    notify = d.get("notify_on", "both")
    if notify not in ("enter", "exit", "both"): return jsonify(error="notify_on inválido"), 400
    con = db()
    cur = con.execute("INSERT INTO geofences(owner_id,name,lat,lon,radius_m,notify_on) VALUES(?,?,?,?,?,?)",
                      (owner_id, d["name"], float(d["lat"]), float(d["lon"]), float(d["radius_m"]), notify))
    con.commit()
    return jsonify(geofence_id=cur.lastrowid, name=d["name"]), 201

@app.get("/api/v1/geofences")
@require("owner")
def list_geofences():
    owner_id = int(g.claims["sub"])
    rows = db().execute("SELECT * FROM geofences WHERE owner_id=?", (owner_id,)).fetchall()
    return jsonify(geofences=[dict(r) for r in rows])

@app.get("/api/v1/alerts")
@require("owner")
def list_alerts():
    owner_id = int(g.claims["sub"])
    rows = db().execute("""SELECT a.*, g.name gname FROM alerts a LEFT JOIN geofences g ON a.geofence_id=g.id
                           WHERE a.owner_id=? ORDER BY a.epoch DESC LIMIT 200""", (owner_id,)).fetchall()
    return jsonify(alerts=[{**dict(r), "detail": json.loads(r["detail"]) if r["detail"] else None} for r in rows])

@app.get("/api/v1/devices/<did>/consent-log")
@require("owner")
def consent_log(did):
    owner_id = int(g.claims["sub"])
    dev = db().execute("SELECT 1 FROM devices WHERE id=? AND owner_id=?", (did, owner_id)).fetchone()
    if not dev: return jsonify(error="no encontrado"), 404
    rows = db().execute("SELECT ts,event,actor,note FROM consent_log WHERE device_id=? ORDER BY id", (did,)).fetchall()
    return jsonify(device_id=did, consent_log=[dict(r) for r in rows])

@app.get("/api/v1/health")
def health():
    return jsonify(status="ok", service="GeoConsent", ts=iso())

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5055)), threaded=True)
