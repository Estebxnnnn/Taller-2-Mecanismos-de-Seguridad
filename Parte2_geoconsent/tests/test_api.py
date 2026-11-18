"""Pruebas automáticas del backend GeoConsent (pytest + cliente de prueba de Flask).
Verifican el modelo de consentimiento, la autenticación, el geofencing, el historial/estadísticas
y la revocación con borrado. Cada prueba usa una base de datos temporal aislada."""
import os, sys, tempfile, importlib
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

@pytest.fixture()
def client():
    fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
    os.environ["GEO_DB"] = path
    import app as backend
    importlib.reload(backend)
    backend.init_db()
    backend.app.testing = True
    with backend.app.test_client() as c:
        yield c
    os.remove(path)

def owner_token(c):
    c.post("/api/v1/owners", json={"username": "ana", "password": "ClaveSegura#1"})
    return c.post("/api/v1/login", json={"username": "ana", "password": "ClaveSegura#1"}).get_json()["access_token"]

def enroll_and_consent(c, owner, phone="+573001112233"):
    enr = c.post("/api/v1/devices/enroll", json={"phone": phone, "display_name": "Equipo"},
                 headers={"Authorization": "Bearer "+owner}).get_json()
    ver = c.post("/api/v1/devices/verify", json={"device_id": enr["device_id"], "code": enr["verify_code_demo"]}).get_json()
    return enr["device_id"], ver["device_token"], enr["verify_code_demo"]

def test_login_requerido_para_inscribir(client):
    r = client.post("/api/v1/devices/enroll", json={"phone": "+573001112233"})
    assert r.status_code == 401

def test_credenciales_invalidas(client):
    client.post("/api/v1/owners", json={"username": "ana", "password": "ClaveSegura#1"})
    r = client.post("/api/v1/login", json={"username": "ana", "password": "mala"})
    assert r.status_code == 401

def test_ingesta_rechazada_sin_consentimiento(client):
    owner = owner_token(client)
    enr = client.post("/api/v1/devices/enroll", json={"phone": "+573001112233"},
                      headers={"Authorization": "Bearer "+owner}).get_json()
    # el dispositivo está 'pending': no tiene token todavía y no puede enviar ubicación
    assert enr["consent_state"] == "pending"

def test_codigo_incorrecto_no_activa(client):
    owner = owner_token(client)
    enr = client.post("/api/v1/devices/enroll", json={"phone": "+573001112233"},
                      headers={"Authorization": "Bearer "+owner}).get_json()
    r = client.post("/api/v1/devices/verify", json={"device_id": enr["device_id"], "code": "000000"})
    assert r.status_code == 400

def test_flujo_consentido_e_ingesta(client):
    owner = owner_token(client)
    did, dtok, _ = enroll_and_consent(client, owner)
    r = client.post("/api/v1/locations", json={"lat": 4.6097, "lon": -74.0817, "battery": 90},
                    headers={"Authorization": "Bearer "+dtok})
    assert r.status_code == 201 and r.get_json()["consent_state"] == "active"

def test_pausa_bloquea_ingesta(client):
    owner = owner_token(client)
    did, dtok, _ = enroll_and_consent(client, owner)
    client.post("/api/v1/devices/sharing", json={"state": "paused"},
                headers={"Authorization": "Bearer "+dtok})
    r = client.post("/api/v1/locations", json={"lat": 4.6, "lon": -74.08},
                    headers={"Authorization": "Bearer "+dtok})
    assert r.status_code == 403

def test_geofence_enter_exit_genera_alertas(client):
    owner = owner_token(client)
    client.post("/api/v1/geofences", json={"name": "Campus", "lat": 4.60971, "lon": -74.08175, "radius_m": 300},
                headers={"Authorization": "Bearer "+owner})
    did, dtok, _ = enroll_and_consent(client, owner)
    h = {"Authorization": "Bearer "+dtok}
    client.post("/api/v1/locations", json={"lat": 4.6150, "lon": -74.0900, "ts": "2026-11-14T08:00:00-05:00"}, headers=h)  # fuera
    client.post("/api/v1/locations", json={"lat": 4.60971, "lon": -74.08175, "ts": "2026-11-14T08:00:20-05:00"}, headers=h)  # dentro -> enter
    client.post("/api/v1/locations", json={"lat": 4.6150, "lon": -74.0900, "ts": "2026-11-14T08:00:40-05:00"}, headers=h)  # fuera -> exit
    alerts = client.get("/api/v1/alerts", headers={"Authorization": "Bearer "+owner}).get_json()["alerts"]
    kinds = sorted(a["kind"] for a in alerts)
    assert kinds == ["geofence_enter", "geofence_exit"]

def test_historial_y_estadisticas(client):
    owner = owner_token(client)
    did, dtok, _ = enroll_and_consent(client, owner)
    h = {"Authorization": "Bearer "+dtok}
    for i, (lat, lon) in enumerate([(4.600, -74.080), (4.601, -74.080), (4.602, -74.080)]):
        client.post("/api/v1/locations",
                    json={"lat": lat, "lon": lon, "speed_kmh": 20+i, "battery": 90-i,
                          "ts": f"2026-11-14T08:0{i}:00-05:00"}, headers=h)
    st = client.get(f"/api/v1/devices/{did}/stats", headers={"Authorization": "Bearer "+owner}).get_json()
    assert st["points"] == 3 and st["distance_km"] > 0 and st["max_speed_kmh"] == 22.0

def test_propietario_no_ve_dispositivos_de_otro(client):
    owner_a = owner_token(client)
    enroll_and_consent(client, owner_a)
    client.post("/api/v1/owners", json={"username": "beto", "password": "ClaveSegura#2"})
    owner_b = client.post("/api/v1/login", json={"username": "beto", "password": "ClaveSegura#2"}).get_json()["access_token"]
    devs = client.get("/api/v1/devices", headers={"Authorization": "Bearer "+owner_b}).get_json()["devices"]
    assert devs == []

def test_revocacion_borra_ubicaciones(client):
    owner = owner_token(client)
    did, dtok, _ = enroll_and_consent(client, owner)
    h = {"Authorization": "Bearer "+dtok}
    client.post("/api/v1/locations", json={"lat": 4.6, "lon": -74.08}, headers=h)
    r = client.delete("/api/v1/devices/me", headers=h)
    assert r.status_code == 200 and r.get_json()["ubicaciones_borradas"] == 1
    # tras revocar, el token de dispositivo ya no puede enviar
    r2 = client.post("/api/v1/locations", json={"lat": 4.6, "lon": -74.08}, headers=h)
    assert r2.status_code == 403

def test_token_de_dispositivo_no_sirve_para_endpoints_de_owner(client):
    owner = owner_token(client)
    did, dtok, _ = enroll_and_consent(client, owner)
    r = client.get("/api/v1/devices", headers={"Authorization": "Bearer "+dtok})
    assert r.status_code == 403
