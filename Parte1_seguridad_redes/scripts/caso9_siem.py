"""Caso 9 – Priorización y correlación de alertas con IA y SIEM.
Normaliza los eventos producidos en los casos 1–8 (Suricata, Zeek, Windows, firewall, resolver DNS, detector ML)
a un esquema común (inspirado en ECS), deduplica sin perder trazabilidad, correlaciona por entidad y calcula una
puntuación de riesgo EXPLICABLE. Todo con datos sintéticos anonimizados.
"""
import json, csv, hashlib, collections, random
import pandas as pd
from lib import *
import matplotlib.patches as mpatches
random.seed(9)
style()
D = "2026-11-05"
raw = []
def ev(hhmmss, provider, rule_id, rule, src, dst, sev, n=1, spread_s=0, ref=""):
    base = pd.Timestamp(f"{D} {hhmmss}", tz="America/Bogota")
    for i in range(n):
        t = (base + pd.Timedelta(seconds=(spread_s * i / max(1, n-1)) if n > 1 else 0)).floor("s")
        raw.append({"@timestamp": t.isoformat(), "event.provider": provider, "rule.id": rule_id, "rule.name": rule, "source.ip": src,
                    "destination.ip": dst, "event.severity": sev, "evidence.ref": ref})
# C1 – prueba de carga SYN (autorizada) → objetivo .20
ev("09:02:00", "suricata", "1000101", "LAB TCP SYN > 50/s sostenido hacia servidor web", "198.18.0.0/15", "192.168.50.20", 3, n=18, spread_s=170, ref="C1_synflood_lab.pcap")
ev("09:02:30", "windows", "perfmon", "TCPv4 Connections Failed/s > 100 (SRV-WEB-LAB)", "192.168.50.20", "192.168.50.20", 2, n=6, spread_s=150, ref="C1_conteo_por_segundo.csv")
# C2 – DNS
ev("10:05:00", "zeek", "dns.long_qname", "Consulta DNS > 52 car. y entropía > 3,8", "192.168.50.44", "192.168.50.53", 3, n=40, spread_s=470, ref="C2_dns_tunel_entrenamiento.pcap")
ev("10:05:00", "bind9", "query-log", "Volumen TXT inusual hacia *.exfil-lab.test", "192.168.50.44", "192.168.50.53", 2, n=8, spread_s=470, ref="C2_consultas_dns.csv")
ev("10:01:00", "firewall", "dns-egress", "DNS hacia resolver no autorizado 192.168.50.99", "192.168.50.66", "192.168.50.99", 2, n=25, spread_s=850, ref="C2_consultas_dns.csv")
ev("10:00:03", "zeek", "dns.long_qname", "Consulta DNS > 30 car. con etiqueta hexadecimal", "192.168.50.115", "192.168.50.53", 1, n=15, spread_s=840, ref="C2_consultas_dns.csv")
# C3 – autenticación
ev("11:10:00", "windows", "4625", "Fallos de inicio de sesión RDP > 10/min", "192.168.50.66", "192.168.50.20", 3, n=11, spread_s=600, ref="C3_eventos_autenticacion.csv")
ev("11:10:24", "filezilla", "530", "Fallos de autenticación FTP repetidos", "192.168.50.66", "192.168.50.20", 2, n=9, spread_s=580, ref="C3_eventos_autenticacion.csv")
ev("11:21:40", "filezilla", "230", "Inicio de sesión FTP anónimo aceptado", "192.168.50.112", "192.168.50.20", 2, ref="C3_ftp_texto_claro.pcap")
# C4 – detector ML (eventos del prototipo, aplicados al día de laboratorio)
ev("10:06:00", "ml-iforest", "anomaly", "Score de anomalía > p99,5 (DNS qname largo)", "192.168.50.44", "-", 2, n=4, spread_s=300, ref="C4_metricas.json")
ev("16:10:00", "ml-iforest", "anomaly", "Score de anomalía > p99,5 (puertos únicos)", "192.168.50.66", "-", 2, n=1, ref="C4_metricas.json")
# C5 – RST
ev("13:20:02", "suricata", "1000501", "LAB TCP RST con TTL distinto al de la sesión", "192.168.50.20", "192.168.50.121", 3, n=7, spread_s=215, ref="C5_tcp_resets_lab.pcap")
ev("13:20:02", "zeek", "weird.data_after_reset", "Datos tras RST en la misma conexión", "192.168.50.121", "192.168.50.20", 2, n=7, spread_s=215, ref="C5_tcp_resets_lab.pcap")
ev("13:20:02", "switch", "port-security", "MAC 00:50:56:a1:00:66 vista con IP origen 192.168.50.20 (puerto Gi0/12 = host .66)", "192.168.50.66", "192.168.50.121", 3, n=1, ref="C5_tabla_rst.csv")
ev("13:12:00", "windows", "7036", "Servicio Tomcat9 detenido / iniciado (cambio planificado CHG-118)", "192.168.50.20", "192.168.50.20", 1, n=2, spread_s=4, ref="C5_tabla_rst.csv")
# C6 – reflexión
ev("14:04:00", "gateway", "udp-asym", "Respuestas UDP no solicitadas (ratio > 5) DNS/NTP/SSDP", "198.51.100.0/24,203.0.113.0/24", "192.168.50.20", 3, n=3, spread_s=170, ref="C6_contadores_udp_gateway.csv")
# C7 – ICMP
ev("15:05:00", "suricata", "1000701", "Barrido ICMP > 50 destinos/10 s", "192.168.50.66", "192.168.50.0/24", 2, n=1, ref="C7_icmp_lab.pcap")
ev("15:10:00", "suricata", "1000702", "ICMP echo con payload > 512 B persistente", "192.168.50.77", "192.168.50.250", 3, n=9, spread_s=480, ref="C7_icmp_lab.pcap")
ev("15:10:00", "zeek", "icmp.payload_mismatch", "Echo reply con payload distinto al request", "192.168.50.77", "192.168.50.250", 3, n=9, spread_s=480, ref="C7_icmp_lab.pcap")
# C8 – escaneo
ev("16:10:01", "suricata", "1000801", "Escaneo SYN > 25 puertos/60 s", "192.168.50.66", "192.168.50.20", 3, n=12, spread_s=8, ref="C8_escaneo_autorizado.pcap")
ev("16:10:01", "firewall", "pfirewall.DROP", "Bloqueo de 135/139 desde LAN de clientes", "192.168.50.66", "192.168.50.20", 1, n=2, ref="C8_pfirewall.log")
ev("16:10:13", "zeek", "banner-grab", "Conexiones cortas con lectura de banner (FTP/HTTP/MySQL)", "192.168.50.66", "192.168.50.20", 2, n=4, spread_s=3, ref="C8_escaneo_autorizado.pcap")
ev("16:40:00", "suricata", "1000801", "Escaneo SYN > 25 puertos/60 s", "192.168.50.15", "192.168.50.20", 3, n=8, spread_s=460, ref="C8_escaneo_autorizado.pcap")
ev("16:00:59", "zeek", "conn.rej", "Conexiones rechazadas dispersas (1 cada 15–35 s)", "192.168.50.88", "192.168.50.20", 1, n=5, spread_s=3300, ref="C8_escaneo_autorizado.pcap")
for i, r in enumerate(raw):
    r["event.id"] = hashlib.sha1(json.dumps(r, sort_keys=True).encode()).hexdigest()[:12]
raw_df = pd.DataFrame(raw)
raw_df.to_csv(f"{EVID}/C9_eventos_normalizados.csv", index=False)

# ---- deduplicación: misma (regla, origen, destino) en ventana de 15 min → 1 alerta con conteo y lista de event.id
raw_df["ts"] = pd.to_datetime(raw_df["@timestamp"], format="ISO8601")
raw_df["bucket"] = raw_df["ts"].dt.floor("15min")
dedup = raw_df.groupby(["rule.id", "rule.name", "event.provider", "source.ip", "destination.ip", "bucket"]).agg(
    primera=("ts", "min"), ultima=("ts", "max"), conteo=("event.id", "count"), severidad=("event.severity", "max"),
    ids=("event.id", lambda s: ",".join(s)), evidencia=("evidence.ref", "first")).reset_index()
print("eventos crudos", len(raw_df), "alertas tras deduplicar", len(dedup))

# ---- correlación por entidad (IP interna implicada como ORIGEN de la actividad)
ALLOW = {"192.168.50.15": "Escáner autorizado – ticket MNT-2211, ventana 16:40–16:50",
         "198.18.0.0/15": "Prueba de carga autorizada – acta LAB-02 (rango RFC 2544)"}
CRIT = {"192.168.50.20": 1.3, "192.168.50.53": 1.2}
FAMILIA = {"suricata": "IDS red", "zeek": "IDS red", "windows": "Host/SO", "filezilla": "Aplicación", "bind9": "DNS", "firewall": "Firewall",
           "gateway": "Firewall", "switch": "Infraestructura L2", "ml-iforest": "Detector ML"}
def entidad(r):
    if r["rule.id"] == "1000501": return "192.168.50.66 (por MAC)" if False else "192.168.50.20→121 (RST forjado)"
    return r["source.ip"]
dedup["entidad"] = dedup["source.ip"]
dedup.loc[dedup["rule.id"].isin(["1000501", "weird.data_after_reset"]), "entidad"] = "192.168.50.66"   # atribución vía switch (MAC)
dedup.loc[dedup["rule.id"] == "7036", "entidad"] = "192.168.50.20"
W_SEV = {1: 2, 2: 5, 3: 10, 4: 15}
prior = []
for ent, g in dedup.groupby("entidad"):
    tecnicas = g["rule.name"].nunique()
    familias = sorted(set(FAMILIA[p] for p in g["event.provider"]))
    base = sum(W_SEV[s] for s in g.groupby("rule.id")["severidad"].max())
    conv = 8 * (len(familias) - 1)
    dests = set(g["destination.ip"]); crit = max([CRIT.get(d, 1.0) for d in dests] + [1.0])
    raw_score = (base + conv) * crit
    sup = ALLOW.get(ent)
    score = min(100, round(raw_score * (0.2 if sup else 1.0)))
    prio = "P1 – Crítica" if score >= 70 else "P2 – Alta" if score >= 40 else "P3 – Media" if score >= 20 else "P4 – Baja"
    prior.append(dict(entidad=ent, alertas=len(g), eventos=int(g["conteo"].sum()), tecnicas=tecnicas, fuentes=" + ".join(familias),
                      puntos_severidad=base, bonus_convergencia=conv, factor_criticidad=crit, score_bruto=round(raw_score, 1), supresion=sup or "-", score=score, prioridad=prio,
                      primera=g["primera"].min().strftime("%H:%M"), ultima=g["ultima"].max().strftime("%H:%M")))
prior.sort(key=lambda r: -r["score"])
json.dump(prior, open(f"{WORK}/C9_priorizacion.json", "w"), indent=1, ensure_ascii=False)
for p in prior: print(p["entidad"], p["score"], p["prioridad"], p["tecnicas"], p["fuentes"])

# ---- alerta enriquecida (ejemplo) para .66
g66 = dedup[dedup.entidad == "192.168.50.66"].sort_values("primera")
alert = {"alert.id": "LAB-2026-11-05-0007", "entidad": "192.168.50.66", "activo": "ws-lab-66 (VM de estudiante, VLAN 50, switch Gi0/12)",
         "score": next(p["score"] for p in prior if p["entidad"] == "192.168.50.66"), "prioridad": "P1 – Crítica",
         "explicacion_score": {"severidad_por_tecnica": int(next(p["puntos_severidad"] for p in prior if p["entidad"] == "192.168.50.66")),
                               "convergencia_fuentes": int(next(p["bonus_convergencia"] for p in prior if p["entidad"] == "192.168.50.66")),
                               "criticidad_destino(192.168.50.20)": 1.3},
         "cronologia": [f"{r.primera.strftime('%H:%M:%S')} {r['rule.name']} (x{r.conteo}, {r['event.provider']})" for _, r in g66.iterrows()],
         "evidencia": sorted(set(g66["evidencia"])), "event_ids": sum((r.split(",") for r in g66["ids"]), [])[:6] + ["…"],
         "mitre_attack": ["T1046 Network Service Discovery", "T1018 Remote System Discovery", "T1110 Brute Force", "T1557 Adversary-in-the-Middle (hipótesis)"],
         "accion_sugerida": "Aislar ws-lab-66 en VLAN de cuarentena TRAS validación humana; preservar memoria/disco; revisar ARP/CAM del switch",
         "estado": "Pendiente de validación humana"}
json.dump(alert, open(f"{WORK}/C9_alerta_enriquecida.json", "w"), indent=1, ensure_ascii=False)

# ---- figura: línea de tiempo correlacionada por entidad
fig, ax = plt.subplots(figsize=(12.5, 5.6))
ents = [p["entidad"] for p in prior]
pc = {"IDS red": "#2471a3", "Host/SO": "#27ae60", "Aplicación": "#7d3c98", "DNS": "#d68910", "Firewall": "#5d6d7e", "Infraestructura L2": "#c0392b", "Detector ML": "#e91e63"}
for _, r in dedup.iterrows():
    fam = FAMILIA[r["event.provider"]]
    y = ents.index(r["entidad"]) + (list(pc).index(fam) - 3) * 0.1
    x0 = r["primera"].hour + r["primera"].minute/60 + r["primera"].second/3600; x1 = r["ultima"].hour + r["ultima"].minute/60 + r["ultima"].second/3600
    ax.plot([x0, max(x1, x0+0.02)], [y, y], lw=4, solid_capstyle="butt", color=pc[fam], alpha=.9)
    ax.scatter([x0], [y], s=14, color=pc[fam], zorder=3)
ax.set_yticks(range(len(ents))); ax.set_yticklabels([f"{p['entidad']}  [{p['score']} · {p['prioridad'][:2]}]" for p in prior], fontsize=8.5)
ax.invert_yaxis(); ax.set_xlim(8.8, 17.2); ax.set_xticks(range(9, 18)); ax.set_xticklabels([f"{h}:00" for h in range(9, 18)])
ax.legend(handles=[mpatches.Patch(color=c, label=k) for k, c in pc.items()], fontsize=7.5, ncol=7, loc="upper center", bbox_to_anchor=(0.5, -0.1))
ax.set_title("Caso 9 · Alertas deduplicadas correlacionadas por entidad (05-nov-2026) · [score · prioridad]")
save_fig(fig, "c9_fig2_correlacion_entidades.png")

# ---- diagrama del pipeline
fig, ax = plt.subplots(figsize=(13, 5.2)); ax.axis("off"); ax.set_xlim(0, 13); ax.set_ylim(0, 5.2)
def box(x, y, w, h, t, c):
    ax.add_patch(mpatches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.05,rounding_size=0.12", fc=c, ec="#34495e", lw=1))
    ax.text(x+w/2, y+h/2, t, ha="center", va="center", fontsize=8.2, wrap=True)
def arr(x0, y0, x1, y1): ax.annotate("", xy=(x1, y1), xytext=(x0, y0), arrowprops=dict(arrowstyle="-|>", color="#34495e", lw=1.2))
srcs = ["Suricata eve.json", "Zeek conn/dns/weird", "Windows Event Log\n(4624/4625/7036)", "Firewall (pfirewall.log)\n+ gateway", "BIND9 / FileZilla\n(logs de aplicación)", "Switch (CAM/ARP)"]
for i, s in enumerate(srcs): box(0.1, 4.45 - i*0.82, 2.0, 0.62, s, "#ebf5fb"); arr(2.15, 4.76 - i*0.82, 2.75, 2.6)
box(2.8, 2.05, 1.9, 1.1, "Agente Wazuh /\nFilebeat\n(TLS, NTP sincronizado)", "#fdebd0")
box(5.0, 2.05, 1.9, 1.1, "Normalización\nesquema común (ECS)\n+ hash SHA-1 event.id", "#fef9e7")
box(7.2, 2.05, 1.9, 1.1, "Deduplicación\n(regla, origen, destino,\nventana 15 min)\nconserva event.ids", "#fef9e7")
box(9.4, 3.3, 1.7, 1.1, "Detector ML\n(IsolationForest,\nagregados/min)", "#fadbd8")
box(9.4, 2.05, 1.7, 1.1, "Correlación por\nentidad + score\nexplicable", "#fef9e7")
box(9.4, 0.6, 1.7, 1.1, "LLM (solo resumen\nde alertas\nanonimizadas)", "#e8daef")
box(11.35, 2.05, 1.55, 1.1, "Analista humano\nvalida · decide ·\nregistra", "#d5f5e3")
box(11.35, 0.4, 1.55, 1.1, "Acción reversible\n(cuarentena VLAN,\nbloqueo temporal)", "#d6eaf8")
arr(4.7, 2.6, 5.0, 2.6); arr(6.9, 2.6, 7.2, 2.6); arr(9.1, 2.6, 9.4, 2.6); arr(10.25, 3.3, 10.25, 3.15); arr(10.25, 2.05, 10.25, 1.7)
arr(11.1, 2.6, 11.35, 2.6); arr(11.1, 1.15, 11.35, 2.3); arr(12.12, 2.05, 12.12, 1.5)
ax.text(6.95, 4.75, "Control de acceso a logs (RBAC) · registro de decisiones · evaluación periódica de sesgo/deriva · reversión documentada",
        ha="center", fontsize=8.5, style="italic", color="#7b241c")
ax.set_title("Caso 9 · Pipeline de priorización y correlación (laboratorio)", weight="bold")
save_fig(fig, "c9_fig1_pipeline.png", note="Diagrama de arquitectura propuesto · Uso académico")

# ---- alerta enriquecida + resumen LLM (pantallazo)
L = ["analista@siem-lab:~$ jq . alerta_LAB-2026-11-05-0007.json  (extracto)"]
for line in json.dumps({k: alert[k] for k in ["alert.id", "entidad", "score", "prioridad", "explicacion_score", "cronologia", "mitre_attack", "estado"]}, indent=1, ensure_ascii=False).splitlines():
    L.append(line[:150])
console_shot(f"{FIG}/c9_fig3_alerta_enriquecida.png", "Wazuh/SIEM de laboratorio — alerta enriquecida (JSON)", L, kind="bash", width=1450)
print(json.dumps(alert, indent=1, ensure_ascii=False))
