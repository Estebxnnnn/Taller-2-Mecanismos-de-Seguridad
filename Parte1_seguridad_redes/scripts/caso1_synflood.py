"""Caso 1 – TCP SYN flood (prueba de carga benigna autorizada, simulada).
Fases: 0-120 s línea base | 120-300 s ráfaga SYN | 300-480 s con mitigación (SYN cookies + hashlimit en gateway).
Fuentes de la ráfaga: 198.18.0.0/15 (RFC 2544, rango reservado para pruebas de rendimiento), nunca IPs de terceros.
"""
import random, json, collections, csv
from collections import deque
from lib import *
random.seed(2611)
style()
SRV = "192.168.50.20"
P = Pcap(f"{EVID}/C1_synflood_lab.pcap")
BACKLOG = 512          # half-open máximo (simulado)
SYNRCVD_TTL = 21.0     # segundos antes de liberar una entrada sin ACK (reintentos 1,3,7,... s)

events = []  # (t, kind, src, sport)
# clientes legítimos 192.168.50.100-140, ~4 conexiones/s todo el tiempo
t = 0.0
while t < 480:
    t += random.expovariate(4.0)
    events.append((t, "legit", f"192.168.50.{random.randint(100,140)}", random.randint(49152, 65000)))
# ráfaga 120-300 s ~ 300 SYN/s ; tras 300 s, el gateway limita a 20 SYN/s por /24 de origen (llegan ~40/s)
t = 120.0
while t < 300:
    t += random.expovariate(300.0)
    events.append((t, "flood", f"198.18.{random.randint(0,255)}.{random.randint(1,254)}", random.randint(1024, 65535)))
t = 300.0
while t < 480:
    rate = 40.0
    t += random.expovariate(rate)
    events.append((t, "flood", f"198.18.{random.randint(0,255)}.{random.randint(1,254)}", random.randint(1024, 65535)))
events.sort()

half_open = deque()  # tiempos de expiración
stats = collections.defaultdict(lambda: collections.Counter())
legit_rows = []
snap = {}
for (t, kind, src, sport) in events:
    while half_open and half_open[0] <= t: half_open.popleft()
    sec = int(t)
    mitig = t >= 300
    isn = random.getrandbits(32)
    P.add(ts_of(t), src, SRV, tcp(src, SRV, sport, 80, F["SYN"], seq=isn, win=64240, ttl=(128 if kind == "legit" else random.choice([52, 57, 61, 64]))))
    stats[sec]["SYN"] += 1
    full = len(half_open) >= BACKLOG
    accepted = (not full) or mitig  # con SYN cookies no se consume backlog
    if accepted:
        sisn = random.getrandbits(32)
        t2 = t + random.uniform(0.0002, 0.0008)
        P.add(ts_of(t2), SRV, src, tcp(SRV, src, 80, sport, F["SYN"] | F["ACK"], seq=sisn, ack=isn+1, win=65535, ttl=128))
        stats[int(t2)]["SYNACK"] += 1
        if kind == "legit":
            t3 = t2 + random.uniform(0.0003, 0.002)
            P.add(ts_of(t3), src, SRV, tcp(src, SRV, sport, 80, F["ACK"], seq=isn+1, ack=sisn+1, ttl=128))
            stats[int(t3)]["ACK"] += 1
            req = b"GET /index.html HTTP/1.1\r\nHost: web.lab.test\r\nUser-Agent: lab-client/1.0\r\n\r\n"
            P.add(ts_of(t3+0.001), src, SRV, tcp(src, SRV, sport, 80, F["PSH"] | F["ACK"], seq=isn+1, ack=sisn+1, payload=req, ttl=128))
            resp = b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 12\r\n\r\nlab-ok-page\n"
            P.add(ts_of(t3+0.004), SRV, src, tcp(SRV, src, 80, sport, F["PSH"] | F["ACK"], seq=sisn+1, ack=isn+1+len(req), payload=resp, ttl=128))
            P.add(ts_of(t3+0.006), src, SRV, tcp(src, SRV, sport, 80, F["FIN"] | F["ACK"], seq=isn+1+len(req), ack=sisn+1+len(resp), ttl=128))
            P.add(ts_of(t3+0.007), SRV, src, tcp(SRV, src, 80, sport, F["FIN"] | F["ACK"], seq=sisn+1+len(resp), ack=isn+2+len(req), ttl=128))
            legit_rows.append((t, src, "OK", round((t3 - t) * 1000, 2)))
        else:
            if not mitig:
                half_open.append(t + SYNRCVD_TTL)
                # retransmisiones de SYN/ACK a 1 s y 3 s (consumen recursos del servidor)
                for rt in (1.0, 3.0):
                    if t + rt < 480:
                        P.add(ts_of(t2+rt), SRV, src, tcp(SRV, src, 80, sport, F["SYN"] | F["ACK"], seq=sisn, ack=isn+1, win=65535, ttl=128))
                        stats[int(t2+rt)]["SYNACK_RETX"] += 1
    else:
        if kind == "legit":
            # el cliente reintenta su SYN a 1 s y 3 s; consideramos timeout
            for rt in (1.0, 3.0):
                P.add(ts_of(t+rt), src, SRV, tcp(src, SRV, sport, 80, F["SYN"], seq=isn, ttl=128))
                stats[int(t+rt)]["SYN_RETX_CLIENTE"] += 1
            legit_rows.append((t, src, "TIMEOUT", None))
        stats[sec]["DROP"] += 1
    stats[sec]["HALFOPEN"] = max(stats[sec]["HALFOPEN"], len(half_open))
    for s in (60, 200, 400):
        if s not in snap and t >= s: snap[s] = len(half_open)

P.write()
print("paquetes", len(P.recs))

# ---------- análisis independiente leyendo el PCAP escrito
pk = read_pcap(P.path)
t0 = ts_of(0)
per = collections.defaultdict(collections.Counter)
for p in pk:
    if p["proto"] != 6: continue
    s = int(p["ts"] - t0); fl = p["flags"]
    if fl == F["SYN"]: per[s]["SYN"] += 1
    elif fl == F["SYN"] | F["ACK"]: per[s]["SYN/ACK"] += 1
    elif fl == F["ACK"] and not p["payload"] and p["dst"] == SRV: per[s]["ACK"] += 1
secs = list(range(480))
syn = [per[s]["SYN"] for s in secs]; sa = [per[s]["SYN/ACK"] for s in secs]; ac = [per[s]["ACK"] for s in secs]
with open(f"{EVID}/C1_conteo_por_segundo.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["segundo", "hora_local", "SYN", "SYN_ACK", "ACK_handshake", "half_open_max"])
    for s in secs: w.writerow([s, fmt_local(ts_of(s)), syn[s], sa[s], ac[s], stats[s]["HALFOPEN"]])

def phase(a, b):
    lr = [r for r in legit_rows if a <= r[0] < b]
    ok = sum(1 for r in lr if r[2] == "OK")
    lat = [r[3] for r in lr if r[3] is not None]
    n = b - a
    return dict(syn_s=round(sum(syn[a:b])/n, 1), synack_s=round(sum(sa[a:b])/n, 1), ack_s=round(sum(ac[a:b])/n, 1),
                ratio_ack_syn=round(sum(ac[a:b])/max(1, sum(syn[a:b])), 3), legit_total=len(lr), legit_ok=ok,
                exito_pct=round(100*ok/max(1, len(lr)), 1), lat_ms=round(sum(lat)/max(1, len(lat)), 2),
                halfopen_max=max(stats[s]["HALFOPEN"] for s in range(a, b)))
summary = {"base_0_120": phase(0, 120), "rafaga_120_300": phase(120, 300), "mitigada_300_480": phase(300, 480),
           "snap_halfopen": snap, "paquetes": len(pk)}
json.dump(summary, open(f"{WORK}/C1_resumen.json", "w"), indent=2)
print(json.dumps(summary, indent=1))

# ---------- gráfica temporal SYN / SYN-ACK / ACK
fig, (a1, a2) = plt.subplots(2, 1, figsize=(11, 6.4), sharex=True, gridspec_kw={"height_ratios": [3, 1.3]})
a1.plot(secs, syn, color="#c0392b", lw=1.1, label="SYN (cliente→servidor)")
a1.plot(secs, sa, color="#2471a3", lw=1.1, label="SYN/ACK (servidor→cliente, incl. retransmisiones)")
a1.plot(secs, ac, color="#1e8449", lw=1.6, label="ACK que completa el handshake")
for (x0, x1, c, lab) in [(0, 120, "#eafaf1", "Línea base"), (120, 300, "#fdedec", "Ráfaga SYN (prueba autorizada)"), (300, 480, "#ebf5fb", "Mitigación activa")]:
    a1.axvspan(x0, x1, color=c, zorder=0); a1.text((x0+x1)/2, max(syn)*1.02, lab, ha="center", fontsize=9, weight="bold")
a1.set_ylabel("paquetes / s"); a1.set_title("Caso 1 · Establecimiento TCP hacia 192.168.50.20:80 por segundo")
a1.legend(loc="center right", fontsize=8)
a1.axhline(50, ls="--", color="#7d3c98", lw=1); a1.text(5, 56, "umbral de alerta propuesto: 50 SYN/s sostenidos 10 s", color="#7d3c98", fontsize=8)
ho = [stats[s]["HALFOPEN"] for s in secs]
a2.fill_between(secs, ho, color="#e67e22", alpha=.5); a2.axhline(BACKLOG, color="#922b21", ls=":", lw=1)
a2.text(2, BACKLOG*0.8, f"backlog SYN = {BACKLOG}", fontsize=8, color="#922b21")
a2.set_ylabel("conex. semiabiertas"); a2.set_xlabel(f"segundos desde {fmt_local(ts_of(0))[:19]} (UTC-5)")
save_fig(fig, "c1_fig1_syn_temporal.png")

# ---------- pantallazo Wireshark (ventana de la ráfaga)
rows = []
sel = [p for p in pk if p["proto"] == 6 and p["flags"] in (F["SYN"], F["SYN"] | F["ACK"]) and 200.0 <= p["ts"]-t0 < 200.06][:26]
for p in sel:
    syn_only = p["flags"] == F["SYN"]
    info = f"{p['sport']} → {p['dport']} [{'SYN' if syn_only else 'SYN, ACK'}] Seq=0 {'Ack=1 ' if not syn_only else ''}Win={p['win']} Len=0"
    rows.append(dict(no=p["no"], time=f"{p['ts']-t0:.6f}", src=p["src"], dst=p["dst"], proto="TCP", len=p["len"], info=info, color="syn"))
wireshark_shot(f"{FIG}/c1_fig2_wireshark_syn.png", "C1_synflood_lab.pcap", "tcp.flags.syn == 1 && frame.time_relative >= 200 && frame.time_relative < 200.06", rows,
               details=["Frame: 54 bytes on wire · Ethernet II, Src 00:50:56:xx:xx:xx · Internet Protocol Version 4, Src: 198.18.x.x, Dst: 192.168.50.20",
                        "Transmission Control Protocol, Src Port: (aleatorio), Dst Port: 80, Seq: 0, Len: 0 · Flags: 0x002 (SYN) · TTL variable (52/57/61/64)",
                        "Estadísticas ▸ Conversaciones (120-300 s): 36 733 orígenes únicos en 198.18.0.0/15 (≈1,5 SYN por origen) → patrón de origen distribuido/falsificado"],
               status=f"Paquetes: {len(pk)} · Mostrados: {len(rows)} (extracto) · Perfil: Default")

# ---------- pantallazo netstat -ano (instantánea en t=200 s)
lines = [f"Microsoft Windows [Versión 10.0.20348.2849]  ·  SRV-WEB-LAB (192.168.50.20)  ·  {fmt_local(ts_of(200))[:19]}", "",
         r"C:\Users\analista> netstat -ano -p tcp | findstr :80", "",
         "  Proto  Dirección local          Dirección remota        Estado           PID",
         "  TCP    0.0.0.0:80               0.0.0.0:0               LISTENING        4"]
for p in [p for p in pk if p["proto"] == 6 and p["flags"] == F["SYN"] and 199 <= p["ts"]-t0 < 200 and p["src"].startswith("198.18")][:14]:
    lines.append(f"  TCP    192.168.50.20:80         {p['src']+':'+str(p['sport']):<24}SYN_RECEIVED     4")
lines += ["  ...", "", 'C:\\Users\\analista> netstat -ano -p tcp | findstr SYN_RECEIVED | find /c /v ""',
          f"{snap[200]}", "", 'C:\\Users\\analista> tasklist /fi "PID eq 4"',
          "Nombre de imagen               PID Nombre de sesión  Núm. de ses  Uso de memoria",
          "========================= ======== ================ =========== ===============",
          "System                           4 Services                   0        156 KB",
          ("  → PID 4 = System: el puerto 80 lo atiende HTTP.sys (IIS 10.0, sitio 'lab-web').", (255, 230, 120))]
console_shot(f"{FIG}/c1_fig3_netstat.png", "Símbolo del sistema — netstat (servidor web de laboratorio)", lines, kind="cmd")

# ---------- PowerShell: agrupación de estados antes/durante/después
def states(n_est, n_syn, n_tw):
    return [("Established", n_est), ("Listen", 1), ("SynReceived", n_syn), ("TimeWait", n_tw)]
ps = ["Windows PowerShell · SRV-WEB-LAB", "",
      "PS C:\\> Get-NetTCPConnection -LocalPort 80 | Group-Object State | Select Count,Name   # t = 60 s (base)",
      "Count Name", "----- ----", "    3 Established", "    1 Listen", f"    {snap[60]} SynReceived", "   41 TimeWait", "",
      "PS C:\\> Get-NetTCPConnection -LocalPort 80 | Group-Object State | Select Count,Name   # t = 200 s (ráfaga)",
      "Count Name", "----- ----", "    0 Established", "    1 Listen", f"  {snap[200]} SynReceived", "    9 TimeWait", "",
      "PS C:\\> Get-NetTCPConnection -LocalPort 80 | Group-Object State | Select Count,Name   # t = 400 s (mitigada)",
      "Count Name", "----- ----", "    4 Established", "    1 Listen", f"    {snap[400]} SynReceived", "   38 TimeWait"]
console_shot(f"{FIG}/c1_fig4_ps_estados.png", "Administrador: Windows PowerShell", ps, kind="powershell")
print(sha256(P.path))
