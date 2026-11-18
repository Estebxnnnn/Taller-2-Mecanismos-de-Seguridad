"""Caso 7 – ICMP: escaneo, payloads atípicos y posible túnel (PCAP sintético/didáctico, 20 min).
- Línea base: ping de diagnóstico del analista (.10 → .20), 4 echo cada 5 min, payload Windows de 32 bytes.
- Barrido: .66 envía echo request a .1–.254 en ~6 s.
- Túnel didáctico: .77 ↔ .250 (VM de entrenamiento) echo de 1 000–1 400 B, cada ~1 s, payload de alta entropía y
  respuesta con payload DISTINTO a la solicitud (en un echo legítimo la respuesta replica el payload).
- ICMP legítimo de red: tipo 3 código 4 (PMTUD) y tipo 11 (traceroute del analista).
"""
import random, collections, json, csv, statistics
from lib import *
random.seed(77)
style()
BASE_T = LAB_DAY.replace(hour=15)
P = Pcap(f"{EVID}/C7_icmp_lab.pcap")
WIN = b"abcdefghijklmnopqrstuvwabcdefghi"
LIVE = {"192.168.50.1", "192.168.50.10", "192.168.50.20", "192.168.50.30", "192.168.50.53", "192.168.50.250", "192.168.50.77"}
def echo(t, a, b, ident, sq, pl, reply_pl=None, ttl_a=128, ttl_b=128):
    P.add(ts_of(t, BASE_T), a, b, icmp(a, b, 8, 0, ident, sq, pl, ttl=ttl_a))
    if b in LIVE:
        P.add(ts_of(t + random.uniform(0.0002, 0.0009), BASE_T), b, a, icmp(b, a, 0, 0, ident, sq, reply_pl if reply_pl is not None else pl, ttl=ttl_b))
# línea base
for k in range(0, 1200, 300):
    for i in range(4): echo(k + 10 + i, "192.168.50.10", "192.168.50.20", 1, k//300*4+i+1, WIN)
# traceroute del analista hacia el gateway (TTL excedido) y PMTUD
for i in range(3): P.add(ts_of(400 + i*0.01, BASE_T), "192.168.50.1", "192.168.50.10", icmp("192.168.50.1", "192.168.50.10", 11, 0, 0, 0, b"\x45" + b"\0"*27))
for i in range(2): P.add(ts_of(650 + i, BASE_T), "192.168.50.1", "192.168.50.20", icmp("192.168.50.1", "192.168.50.20", 3, 4, 0, 1400, b"\x45" + b"\0"*27))
# barrido
t = 300.0
for h in range(1, 255):
    t += random.uniform(0.015, 0.035)
    echo(t, "192.168.50.66", f"192.168.50.{h}", 0x1d2a, h, b"\0"*0, ttl_a=64, ttl_b=128 if h != 1 else 64)
# túnel didáctico
t = 600.0; sq = 0
while t < 1140:
    sq += 1
    n = random.randint(1000, 1400)
    req = bytes(random.getrandbits(8) for _ in range(n))
    rep = bytes(random.getrandbits(8) for _ in range(random.randint(900, 1400)))
    echo(t, "192.168.50.77", "192.168.50.250", 0x7777, sq, req, reply_pl=rep, ttl_a=64, ttl_b=64)
    t += random.uniform(0.9, 1.1)
P.write()

pk = read_pcap(P.path); t0 = ts_of(0, BASE_T)
ic = [p for p in pk if p["proto"] == 1]
# emparejar request/reply para detectar payload distinto
req = {(p["src"], p["dst"], p["iid"], p["iseq"]): p for p in ic if p["itype"] == 8}
mism = collections.Counter(); match = collections.Counter()
for p in ic:
    if p["itype"] == 0:
        q = req.get((p["dst"], p["src"], p["iid"], p["iseq"]))
        if q: (match if q["payload"] == p["payload"] else mism)[p["dst"]] += 1
agg = []
by = collections.defaultdict(list)
for p in ic: by[(p["src"])].append(p)
for src, ps in sorted(by.items(), key=lambda x: -len(x[1])):
    types = collections.Counter(f"{p['itype']}/{p['icode']}" for p in ps)
    lens = [len(p["payload"]) for p in ps]
    ts_ = sorted(p["ts"] for p in ps); ia = [b - a for a, b in zip(ts_, ts_[1:])]
    agg.append(dict(origen=src, paquetes=len(ps), destinos_unicos=len(set(p["dst"] for p in ps)), tipos=dict(types),
                    payload_min=min(lens), payload_med=int(statistics.median(lens)), payload_max=max(lens),
                    entropia_media=round(statistics.mean(shannon(p["payload"]) for p in ps), 2) if max(lens) else 0,
                    interarribo_med_s=round(statistics.median(ia), 3) if ia else None,
                    duracion_s=round(ts_[-1] - ts_[0], 1), respuestas_payload_distinto=mism.get(src, 0), respuestas_payload_igual=match.get(src, 0)))
json.dump(agg, open(f"{WORK}/C7_tabla_icmp.json", "w"), indent=1, ensure_ascii=False)
with open(f"{EVID}/C7_resumen_por_ip.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(agg[0].keys())); w.writeheader(); [w.writerow({**a, "tipos": json.dumps(a["tipos"])}) for a in agg]
for a in agg: print(a)

# ---------- dashboard por IP (4 paneles)
fig, ax = plt.subplots(2, 2, figsize=(13, 7.6))
top = [a for a in agg if a["paquetes"] > 3][:7]
names = [a["origen"] for a in top]
ax[0, 0].barh(names[::-1], [a["paquetes"] for a in top][::-1], color="#5d6d7e")
for i, a in enumerate(top[::-1]): ax[0, 0].text(a["paquetes"]+5, i, f"{a['destinos_unicos']} dst", va="center", fontsize=8)
ax[0, 0].set_title("Paquetes ICMP por IP origen (y destinos únicos)"); ax[0, 0].set_xlabel("paquetes")
srcs = ["192.168.50.10", "192.168.50.66", "192.168.50.77", "192.168.50.250"]
cc = {"192.168.50.10": "#27ae60", "192.168.50.66": "#d68910", "192.168.50.77": "#c0392b", "192.168.50.250": "#884ea0"}
for s in srcs:
    ax[0, 1].hist([len(p["payload"]) + 8 for p in by[s]], bins=40, range=(0, 1500), alpha=.65, color=cc[s], label=s)
ax[0, 1].set_yscale("log"); ax[0, 1].set_title("Distribución de longitud ICMP (cabecera+payload)"); ax[0, 1].set_xlabel("bytes"); ax[0, 1].legend(fontsize=8)
bins = range(0, 1201, 20)
for s in srcs:
    ax[1, 0].plot([b/60 for b in bins[:-1]], [sum(1 for p in by[s] if b <= p["ts"]-t0 < b+20) for b in bins[:-1]], color=cc[s], label=s, lw=1.2)
ax[1, 0].set_title("Paquetes ICMP por ventana de 20 s"); ax[1, 0].set_xlabel("minuto desde 15:00 (UTC-5)"); ax[1, 0].legend(fontsize=8)
lab = [f"{a['origen']}" for a in agg if a["respuestas_payload_igual"] + a["respuestas_payload_distinto"] > 0]
ig = [a["respuestas_payload_igual"] for a in agg if a["respuestas_payload_igual"] + a["respuestas_payload_distinto"] > 0]
di = [a["respuestas_payload_distinto"] for a in agg if a["respuestas_payload_igual"] + a["respuestas_payload_distinto"] > 0]
ax[1, 1].barh(lab, ig, color="#27ae60", label="eco con payload idéntico (normal)")
ax[1, 1].barh(lab, di, left=ig, color="#c0392b", label="eco con payload DISTINTO (anómalo)")
ax[1, 1].set_title("Coherencia request/reply por solicitante"); ax[1, 1].legend(fontsize=8); ax[1, 1].set_xlabel("respuestas recibidas")
fig.suptitle("Caso 7 · Dashboard ICMP por IP (C7_icmp_lab.pcap)", weight="bold")
fig.tight_layout()
save_fig(fig, "c7_fig1_dashboard.png")

# ---------- Wireshark: túnel
sel = [p for p in ic if "192.168.50.77" in (p["src"], p["dst"])][20:34] + [p for p in ic if p["src"] == "192.168.50.66"][40:48]
sel.sort(key=lambda p: p["ts"])
wr = []
for p in sel:
    nm = {8: "Echo (ping) request", 0: "Echo (ping) reply"}[p["itype"]]
    extra = ""
    if p["itype"] == 0 and p["dst"] == "192.168.50.77": extra = "  [payload ≠ request]"
    if p["itype"] == 8 and p["src"] == "192.168.50.66": extra = "  [no response found!]" if p["dst"] not in LIVE else ""
    wr.append(dict(no=p["no"], time=f"{p['ts']-t0:.6f}", src=p["src"], dst=p["dst"], proto="ICMP", len=p["len"],
                   info=f"{nm}  id=0x{p['iid']:04x}, seq={p['iseq']}, ttl={p['ttl']}{extra}", color="bad" if extra else "icmp"))
wireshark_shot(f"{FIG}/c7_fig2_wireshark_icmp.png", "C7_icmp_lab.pcap", "icmp && (ip.addr == 192.168.50.77 || ip.src == 192.168.50.66)", wr,
               details=["Paquete de .77: Data (1 000–1 400 bytes) · entropía ≈ 7,8 bits/byte (aleatoria/cifrada) · intervalo ≈ 1,0 s constante durante 9 min",
                        "La respuesta de .250 NO replica el payload de la solicitud (RFC 792 exige eco idéntico) → canal de datos encubierto",
                        "Barrido de .66: id=0x1d2a fijo, seq = último octeto del destino, 254 destinos en ~6 s, payload 0 B (firma de herramienta de descubrimiento)"],
               status=f"Paquetes ICMP: {len(ic)} · Mostrados: {len(wr)}")
print(len(pk), sha256(P.path))
