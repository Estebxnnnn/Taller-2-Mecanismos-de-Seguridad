"""Demostración extremo a extremo SOBRE HTTP REAL contra el backend GeoConsent.
Arranca el servidor, crea un propietario, inscribe dos dispositivos CON consentimiento verificado,
define geocercas, inyecta los recorridos y consulta mapa/historial/estadísticas/alertas.
Guarda las salidas JSON y un transcripto de la API para las figuras del informe."""
import os, sys, json, time, threading, datetime as dt
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "backend"))
sys.path.insert(0, os.path.join(BASE, "simulator"))

DEMO_DB = os.path.join(BASE, "data", "demo.db")
if os.path.exists(DEMO_DB): os.remove(DEMO_DB)
os.environ["GEO_DB"] = DEMO_DB
os.environ["GEO_JWT_SECRET"] = "lab-demo-secret-fijo-de-laboratorio-32bytes-min"

import app as backend
import requests
from track import build_track, GEOFENCES

OUT = os.path.join(BASE, "data", "demo_outputs")
os.makedirs(OUT, exist_ok=True)
BASEURL = "http://127.0.0.1:5055"
TRANSCRIPT = []

def start_server():
    backend.init_db()
    threading.Thread(target=lambda: backend.app.run(host="127.0.0.1", port=5055, threaded=True,
                                                     use_reloader=False), daemon=True).start()
    for _ in range(50):
        try:
            if requests.get(BASEURL+"/api/v1/health", timeout=1).ok: return
        except Exception: time.sleep(0.1)
    raise RuntimeError("el servidor no respondió")

def call(method, path, token=None, show_body=True, **kw):
    h = kw.pop("headers", {})
    if token: h["Authorization"] = "Bearer " + token
    r = requests.request(method, BASEURL+path, headers=h, timeout=10, **kw)
    body = None
    try: body = r.json()
    except Exception: body = r.text
    TRANSCRIPT.append({"method": method, "path": path, "status": r.status_code,
                       "req": kw.get("json"), "resp": body if show_body else "<omitido>"})
    return r.status_code, body

def main():
    start_server()
    # 1) cuenta del propietario y login
    call("POST", "/api/v1/owners", json={"username": "coordinador", "password": "ClaveSegura#2026"})
    _, tok = call("POST", "/api/v1/login", json={"username": "coordinador", "password": "ClaveSegura#2026"})
    owner = tok["access_token"]

    # 2) geocercas
    for g in GEOFENCES:
        call("POST", "/api/v1/geofences", token=owner, json=g)

    # 3) inscripción + CONSENTIMIENTO de dos dispositivos
    devices = {}
    for name, phone, label, seed in [("Repartidor 1", "+573001112233", "Android 13", 42),
                                     ("Familiar", "+573004445566", "iPhone 14", 7)]:
        _, enr = call("POST", "/api/v1/devices/enroll", token=owner,
                      json={"phone": phone, "display_name": name, "device_label": label, "interval_s": 20})
        did = enr["device_id"]
        # el titular introduce el código recibido por SMS (consentimiento)
        _, ver = call("POST", "/api/v1/devices/verify", json={"device_id": did, "code": enr["verify_code_demo"]})
        devices[did] = {"name": name, "token": ver["device_token"], "seed": seed,
                        "kind": "repartidor" if "Repartidor" in name else "familiar"}

    # 4) ingesta de los recorridos (HTTP real, en orden temporal)
    all_events = {}
    for did, info in devices.items():
        track = build_track(info["kind"], seed=info["seed"])
        json.dump(track, open(os.path.join(OUT, f"track_{did}.json"), "w"))
        ev = []
        for p in track:
            st, body = call("POST", "/api/v1/locations", token=info["token"], show_body=bool(0), json=p)
            if isinstance(body, dict) and body.get("geofence_events"):
                TRANSCRIPT[-1]["resp"] = body
            if isinstance(body, dict) and body.get("geofence_events"):
                for e in body["geofence_events"]:
                    ev.append({**e, "ts": p["ts"]})
        all_events[did] = ev

    # 5) prueba de control del titular: pausar e intentar enviar (debe ser rechazado)
    any_token = next(iter(devices.values()))["token"]
    call("POST", "/api/v1/devices/sharing", token=any_token, json={"state": "paused"})
    call("POST", "/api/v1/locations", token=any_token,
         json={"lat": 4.6, "lon": -74.08, "battery": 50})   # 403 esperado
    call("POST", "/api/v1/devices/sharing", token=any_token, json={"state": "active"})

    # 6) consultas del propietario
    _, devs = call("POST" if False else "GET", "/api/v1/devices", token=owner)
    json.dump(devs, open(os.path.join(OUT, "devices.json"), "w"), indent=1)
    _, alerts = call("GET", "/api/v1/alerts", token=owner)
    json.dump(alerts, open(os.path.join(OUT, "alerts.json"), "w"), indent=1)
    for did, info in devices.items():
        _, hist = call("GET", f"/api/v1/devices/{did}/history", token=owner, show_body=False)
        json.dump(hist, open(os.path.join(OUT, f"history_{did}.json"), "w"))
        _, stx = call("GET", f"/api/v1/devices/{did}/stats", token=owner)
        json.dump(stx, open(os.path.join(OUT, f"stats_{did}.json"), "w"), indent=1)
        _, clog = call("GET", f"/api/v1/devices/{did}/consent-log", token=owner)
        json.dump(clog, open(os.path.join(OUT, f"consent_{did}.json"), "w"), indent=1)

    # 7) intento de acceso sin token (debe fallar 401) y con token de dispositivo en endpoint de owner (403)
    call("GET", "/api/v1/devices")  # 401
    call("GET", "/api/v1/devices", token=any_token)  # 403

    json.dump({"devices": {k: v["name"] for k, v in devices.items()}, "geofence_events": all_events,
               "transcript_len": len(TRANSCRIPT)},
              open(os.path.join(OUT, "summary.json"), "w"), indent=1, ensure_ascii=False)
    json.dump(TRANSCRIPT, open(os.path.join(OUT, "transcript.json"), "w"), indent=1, ensure_ascii=False)
    print("OK:", len(TRANSCRIPT), "llamadas;", sum(len(v) for v in all_events.values()), "eventos de geocerca")
    for did, info in devices.items():
        s = json.load(open(os.path.join(OUT, f"stats_{did}.json")))
        print(info["name"], "->", {k: s[k] for k in ("points", "distance_km", "duration_min", "avg_speed_kmh", "max_speed_kmh")})

if __name__ == "__main__":
    main()
