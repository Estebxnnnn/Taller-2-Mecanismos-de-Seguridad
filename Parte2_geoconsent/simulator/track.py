"""Generador de recorridos sintéticos (dispositivos que YA dieron consentimiento) para la demo.
Coordenadas plausibles en Bogotá (UTC-5). Determinista con semilla fija."""
import math, random, datetime as dt

TZ = dt.timezone(dt.timedelta(hours=-5))

# Geocercas de referencia (las crea el propietario en la demo)
GEOFENCES = [
    {"name": "Campus UD", "lat": 4.60971, "lon": -74.08175, "radius_m": 300, "notify_on": "both"},
    {"name": "Casa",      "lat": 4.62640, "lon": -74.06380, "radius_m": 200, "notify_on": "enter"},
]

def _haversine(a, b):
    R = 6371000.0
    p1, p2 = math.radians(a[0]), math.radians(b[0])
    dphi = math.radians(b[0]-a[0]); dl = math.radians(b[1]-a[1])
    h = math.sin(dphi/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2*R*math.asin(min(1, math.sqrt(h)))

def _interp(waypoints, step_m):
    """Interpola los waypoints a puntos separados ~step_m metros."""
    pts = [waypoints[0]]
    for a, b in zip(waypoints, waypoints[1:]):
        d = _haversine(a, b)
        n = max(1, int(d/step_m))
        for i in range(1, n+1):
            t = i/n
            pts.append((a[0]+(b[0]-a[0])*t, a[1]+(b[1]-a[1])*t))
    return pts

def build_track(device="repartidor", seed=42, start=None):
    rng = random.Random(seed)
    start = start or dt.datetime(2026, 11, 14, 8, 0, 0, tzinfo=TZ)
    if device == "repartidor":
        # Sale fuera del campus, entra al campus (enter), recorre, sale (exit) y va hacia la casa (enter).
        wps = [(4.60350, -74.08900), (4.60700, -74.08400), (4.60971, -74.08175),  # entra Campus UD
               (4.61150, -74.07950), (4.61000, -74.07600), (4.60850, -74.08050),  # da vueltas dentro/alrededor
               (4.60600, -74.07900), (4.61400, -74.07200), (4.62100, -74.06800),  # sale del campus
               (4.62640, -74.06380)]                                               # entra a Casa
        step, interval, v_base = 55, 20, 22
    else:  # familiar: trayecto de casa al campus (commute en transporte)
        wps = [(4.62640, -74.06380), (4.62000, -74.07000), (4.61300, -74.07600),
               (4.60971, -74.08175)]
        step, interval, v_base = 70, 20, 28
    path = _interp(wps, step)
    pts = []
    battery = 96 if device == "repartidor" else 88
    t = start
    prev = None
    for i, (lat, lon) in enumerate(path):
        jlat = lat + rng.gauss(0, 0.00004)   # ruido GPS ~4-6 m
        jlon = lon + rng.gauss(0, 0.00004)
        acc = round(rng.uniform(5, 18), 1)
        if prev is not None:
            d = _haversine((prev[0], prev[1]), (jlat, jlon))
            speed = round((d/interval)*3.6 * rng.uniform(0.85, 1.15), 1)   # km/h
        else:
            speed = 0.0
        # batería: baja ~1% cada ~25 puntos, más rápido si hay GPS activo
        if i % 22 == 21:
            battery -= 1
        pts.append({"lat": round(jlat, 6), "lon": round(jlon, 6), "ts": t.isoformat(timespec="seconds"),
                    "accuracy_m": acc, "speed_kmh": speed, "battery": battery})
        prev = (jlat, jlon)
        t += dt.timedelta(seconds=interval)
    return pts
