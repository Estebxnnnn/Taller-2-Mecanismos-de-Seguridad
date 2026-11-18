"""Caso 8 – Escaneo de puertos y fingerprinting (PCAP autorizado sintético + registro de firewall, 60 min).
- .66: escaneo SYN rápido de 1–1024 + puertos altos inventariados contra .20, luego captura de banners.
- .15: escáner de vulnerabilidades AUTORIZADO (ventana de mantenimiento 16:40–16:50) → falso positivo esperado.
- .88: escaneo lento (1 puerto cada ~25 s) → difícil de detectar con umbrales por ventana corta.
"""
import random, collections, json, csv
from lib import *
random.seed(88)
style()
SRV = "192.168.50.20"
BASE_T = LAB_DAY.replace(hour=16)
P = Pcap(f"{EVID}/C8_escaneo_autorizado.pcap")
OPEN = {21, 80, 135, 139, 443, 445, 3306, 3389, 5985, 8080}
FW_BLOCK = {135, 139}  # Windows Defender Firewall bloquea RPC/NetBIOS desde la LAN de clientes
fw = []
def probe(t, src, port, ttl=64, grab=False):
    sp = random.randint(40000, 65000); s = random.getrandbits(32)
    P.add(ts_of(t, BASE_T), src, SRV, tcp(src, SRV, sp, port, F["SYN"], seq=s, win=1024, ttl=ttl))
    if port in FW_BLOCK:
        fw.append((t, "DROP", "TCP", src, SRV, sp, port, 44, "S", "RECEIVE")); return
    if port in OPEN:
        ss = random.getrandbits(32)
        P.add(ts_of(t+.0003, BASE_T), SRV, src, tcp(SRV, src, port, sp, F["SYN"] | F["ACK"], seq=ss, ack=s+1, ttl=128))
        fw.append((t, "ALLOW", "TCP", src, SRV, sp, port, 44, "S", "RECEIVE"))
        if grab:
            P.add(ts_of(t+.0006, BASE_T), src, SRV, tcp(src, SRV, sp, port, F["ACK"], seq=s+1, ack=ss+1, ttl=ttl))
            if port == 21: b = b"220-FileZilla Server 0.9.60 beta\r\n"; P.add(ts_of(t+.01, BASE_T), SRV, src, tcp(SRV, src, port, sp, F["PSH"] | F["ACK"], seq=ss+1, ack=s+1, payload=b, ttl=128))
            elif port in (80, 8080):
                q = b"HEAD / HTTP/1.0\r\n\r\n"; P.add(ts_of(t+.002, BASE_T), src, SRV, tcp(src, SRV, sp, port, F["PSH"] | F["ACK"], seq=s+1, ack=ss+1, payload=q, ttl=ttl))
                b = b"HTTP/1.1 200 OK\r\nServer: " + (b"Microsoft-IIS/10.0" if port == 80 else b"Apache-Coyote/1.1") + b"\r\n\r\n"
                P.add(ts_of(t+.01, BASE_T), SRV, src, tcp(SRV, src, port, sp, F["PSH"] | F["ACK"], seq=ss+1, ack=s+1+len(q), payload=b, ttl=128))
            elif port == 3306:
                b = b"J\x00\x00\x00\n5.7.44\x00"; P.add(ts_of(t+.01, BASE_T), SRV, src, tcp(SRV, src, port, sp, F["PSH"] | F["ACK"], seq=ss+1, ack=s+1, payload=b, ttl=128))
            P.add(ts_of(t+.02, BASE_T), src, SRV, tcp(src, SRV, sp, port, F["RST"] | F["ACK"], seq=s+1, ack=ss+1, ttl=ttl))
        else:
            P.add(ts_of(t+.0006, BASE_T), src, SRV, tcp(src, SRV, sp, port, F["RST"], seq=s+1, ttl=ttl))
    else:
        P.add(ts_of(t+.0003, BASE_T), SRV, src, tcp(SRV, src, port, sp, F["RST"] | F["ACK"], seq=0, ack=s+1, ttl=128))
        fw.append((t, "ALLOW", "TCP", src, SRV, sp, port, 44, "S", "RECEIVE"))
# tráfico normal de clientes
for k in range(900):
    t = random.uniform(0, 3600); probe(t, f"192.168.50.{random.randint(100,140)}", random.choice([443, 443, 443, 80]), ttl=128)
# escaneo rápido .66 (16:10)
ports = list(range(1, 1025)) + [3306, 3389, 5985, 8080, 8443, 9090]
random.shuffle(ports)
t = 600.0
for p in ports: t += random.uniform(0.004, 0.012); probe(t, "192.168.50.66", p)
for i, p in enumerate([21, 80, 3306, 8080]): probe(t + 5 + i, "192.168.50.66", p, grab=True)
# escáner autorizado .15 (16:40-16:50, ventana de mantenimiento)
t = 2400.0
for p in range(1, 2049): t += random.uniform(0.15, 0.3); probe(t, "192.168.50.15", p, ttl=128)
# escaneo lento .88 (todo el periodo)
t = 30.0
for p in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 11211, 27017] * 5:
    t += random.uniform(15, 35)
    if t > 3590: break
    probe(t, "192.168.50.88", p)
P.write()
with open(f"{EVID}/C8_pfirewall.log", "w") as f:
    f.write("#Version: 1.5\n#Software: Microsoft Windows Firewall\n#Time Format: Local\n#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid\n\n")
    for e in sorted(fw):
        d = fmt_local(ts_of(e[0], BASE_T))
        f.write(f"{d[:10]} {d[11:19]} {e[1]} {e[2]} {e[3]} {e[4]} {e[5]} {e[6]} {e[7]} {e[8]} - - - - - - {e[9]} 4\n")

pk = read_pcap(P.path); t0 = ts_of(0, BASE_T)
syns = [p for p in pk if p["proto"] == 6 and p["flags"] == F["SYN"]]
# ventana de 60 s: puertos únicos por origen
W = 60
win = collections.defaultdict(lambda: collections.defaultdict(set))
for p in syns: win[p["src"]][int((p["ts"]-t0)//W)].add(p["dport"])
summary = []
for src in sorted(set(p["src"] for p in syns), key=lambda s: -len(set(p["dport"] for p in syns if p["src"] == s))):
    ps = [p for p in syns if p["src"] == src]
    if len(set(p["dport"] for p in ps)) < 3: continue
    sa = sum(1 for p in pk if p["proto"] == 6 and p["dst"] == src and p["flags"] == F["SYN"] | F["ACK"])
    ra = sum(1 for p in pk if p["proto"] == 6 and p["dst"] == src and p["flags"] == F["RST"] | F["ACK"])
    summary.append(dict(origen=src, syn=len(ps), puertos_unicos=len(set(p["dport"] for p in ps)), max_puertos_60s=max(len(v) for v in win[src].values()),
                        abiertos_respondidos=sa, cerrados_rst=ra, inicio=fmt_local(min(p["ts"] for p in ps))[11:19], fin=fmt_local(max(p["ts"] for p in ps))[11:19],
                        banners=sum(1 for p in pk if p["proto"] == 6 and p["dst"] == src and p["payload"])))
clients = [s for s in set(p["src"] for p in syns) if s.startswith("192.168.50.1") and len(s.split(".")[-1]) == 3]
summary.append(dict(origen="clientes .100–.140 (41 hosts)", syn=sum(1 for p in syns if p["src"] in clients), puertos_unicos=2,
                    max_puertos_60s=2, abiertos_respondidos=None, cerrados_rst=0, inicio="16:00", fin="17:00", banners=0))
json.dump(summary, open(f"{WORK}/C8_resumen.json", "w"), indent=1, ensure_ascii=False)
for s in summary: print(s)

fig, ax = plt.subplots(1, 2, figsize=(13, 4.4), gridspec_kw={"width_ratios": [1.1, 1]})
cc = {"192.168.50.66": "#c0392b", "192.168.50.15": "#2471a3", "192.168.50.88": "#d68910"}
for s, c in cc.items():
    pts = [p for p in syns if p["src"] == s]
    ax[0].scatter([(p["ts"]-t0)/60 for p in pts], [p["dport"] for p in pts], s=2 if s != "192.168.50.88" else 10, color=c, label=s)
ax[0].set_yscale("symlog"); ax[0].set_xlabel("minuto desde 16:00 (UTC-5)"); ax[0].set_ylabel("puerto destino (escala log)")
ax[0].set_title("Puertos sondeados en 192.168.50.20 por origen"); ax[0].legend(fontsize=8, markerscale=2)
ax[0].axvspan(40, 50, color="#ebf5fb", zorder=0); ax[0].text(45, 2500, "ventana de\nmantenimiento\n(autorizado)", ha="center", fontsize=7.5)
for s, c in cc.items():
    xs = range(60); ax[1].step(list(xs), [len(win[s].get(i, ())) for i in xs], where="post", color=c, label=s)
ax[1].axhline(25, ls="--", color="#7d3c98"); ax[1].text(0.5, 28, "regla: >25 puertos únicos en 60 s", fontsize=8, color="#7d3c98")
ax[1].set_yscale("symlog"); ax[1].set_ylim(0, 3000); ax[1].set_xlabel("minuto desde 16:00"); ax[1].set_ylabel("puertos destino únicos / 60 s")
ax[1].set_title("Puertos únicos por origen y minuto"); ax[1].legend(fontsize=8)
save_fig(fig, "c8_fig1_puertos_tiempo.png")

# wireshark: banner grabbing
sel = [p for p in pk if p["proto"] == 6 and "192.168.50.66" in (p["src"], p["dst"]) and p["ts"]-t0 > 600][:12]
sel += [p for p in pk if p["proto"] == 6 and "192.168.50.66" in (p["src"], p["dst"]) and p["payload"]]
sel = sorted({p["no"]: p for p in sel}.values(), key=lambda p: p["ts"])
wr = []
for p in sel:
    fl = ", ".join(n for n, v in F.items() if p["flags"] & v)
    info = f"{p['sport']} → {p['dport']} [{fl}] Win={p['win']} Len={len(p['payload'])}"
    if p["payload"]: info += "  " + p["payload"][:44].decode(errors="replace").replace("\r\n", " ").replace("\x00", ".")
    col = "rst" if p["flags"] & F["RST"] else ("http" if p["payload"] else ("syn" if p["flags"] & F["SYN"] else "tcp"))
    wr.append(dict(no=p["no"], time=f"{p['ts']-t0:.6f}", src=p["src"], dst=p["dst"], proto="TCP" if not p["payload"] else {21: "FTP", 80: "HTTP", 8080: "HTTP", 3306: "MySQL"}.get(min(p["sport"], p["dport"]), "TCP"), len=p["len"], info=info, color=col))
wireshark_shot(f"{FIG}/c8_fig2_wireshark_escaneo.png", "C8_escaneo_autorizado.pcap", "ip.addr == 192.168.50.66 && (tcp.flags.syn == 1 || tcp.len > 0)", wr,
               details=["SYN con Win=1024, TTL=64, sin opciones TCP y RST inmediato tras SYN/ACK → firma de escaneo 'half-open' (no completa el handshake)",
                        "Estadísticas ▸ Endpoints: 192.168.50.66 contactó 1 030 puertos de .20 en ~8,5 s; luego 4 conexiones completas para obtener banners/versión"],
               status=f"Paquetes: {len(pk)} · Mostrados: {len(wr)} (extracto)")

lines = ["PS C:\\> Get-Content C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log -Tail 4000 |", ">>   Select-String '192.168.50.66' | Select -First 10 | % Line"]
for e in [e for e in sorted(fw) if e[3] == "192.168.50.66"][:10]:
    d = fmt_local(ts_of(e[0], BASE_T)); lines.append(f"{d[:10]} {d[11:19]} {e[1]:<5} TCP {e[3]} {e[4]} {e[5]} {e[6]:<5} 44 S - - - - - - RECEIVE 4")
lines += ["", "PS C:\\> Import-Csv pfirewall.csv | ? src-ip -eq '192.168.50.66' | Group dst-port | Measure | Select Count",
          "Count", "-----", str(len(set(e[6] for e in fw if e[3] == "192.168.50.66"))), "",
          "PS C:\\> Import-Csv pfirewall.csv | ? action -eq 'DROP' | Group src-ip,dst-port | Select Count,Name",
          "Count Name", "----- ----"] + [f"{c:>5} {k}" for k, c in collections.Counter(f"{e[3]}, {e[6]}" for e in fw if e[1] == "DROP").most_common(6)]
console_shot(f"{FIG}/c8_fig3_pfirewall.png", "Administrador: Windows PowerShell — registro de Windows Defender Firewall (SRV-WEB-LAB)", lines, kind="powershell", width=1300)
print(len(pk), sha256(P.path))
