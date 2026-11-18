# GeoConsent — Localización con consentimiento (Guía-Taller No. 2, Parte II)

Sistema para **compartir la ubicación de un dispositivo con el consentimiento explícito de su
titular**, que implementa los requisitos funcionales (4.1), técnicos (4.3) y avanzados (4.4) del
taller. Ningún componente localiza a una persona por su número ni sin su participación activa: eso
no es viable de forma legítima y la nota ética de la guía lo prohíbe.

## Componentes

| Carpeta | Contenido |
|---|---|
| `backend/` | API REST (Flask + SQLite), JWT, geofencing, alertas, auditoría de consentimiento |
| `simulator/` | Generador de recorridos y demostración extremo a extremo sobre HTTP real |
| `tests/` | 11 pruebas automáticas (pytest) |
| `webapp/` | `dashboard.html` (panel del propietario, Leaflet+OSM) y `device.html` (PWA del dispositivo, GPS real) |
| `bot/` | Bot de Telegram basado en el botón nativo de compartir ubicación |
| `data/` | Base de datos de la demo y salidas JSON reales |

## Puesta en marcha

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 1) Backend
python3 backend/app.py            # queda escuchando en http://127.0.0.1:5055

# 2) Demostración completa (otra terminal): crea cuenta, inscribe dispositivos CON
#    consentimiento, define geocercas, inyecta recorridos y consulta mapa/historial/estadísticas.
python3 simulator/run_demo.py

# 3) Pruebas
python3 -m pytest tests/ -v

# 4) Interfaces web (abrir los .html en el navegador; la PWA pide permiso de GPS)
#    device.html  -> pega tu device_token (o modo demo) y comparte ubicación real
#    dashboard.html -> visualiza dispositivos, recorridos, geocercas, alertas y estadísticas
```

## Principios de privacidad aplicados
- **Consentimiento verificado** por código antes de registrar cualquier dato.
- **Minimización**: solo se guardan lat/lon, precisión, velocidad y batería.
- **Control del titular**: pausar (`POST /devices/sharing`) o revocar con borrado (`DELETE /devices/me`).
- **Transparencia**: indicador de compartición siempre visible y registro de consentimiento auditable.
- **Acceso autenticado**: JWT para el propietario (1 h) y para el dispositivo (30 d), con separación de roles.
