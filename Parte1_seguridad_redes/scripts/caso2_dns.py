"""Caso 2 – DNS tunneling (PCAP de entrenamiento sintético, solo dominios de prueba .test – RFC 6761).
Host .44 ejecuta una herramienta de túnel DIDÁCTICA que codifica un archivo ficticio (texto de relleno) en base32.
Host .115 es un agente de telemetría legítimo (nombres hexadecimales: explicación benigna a descartar).
Host .66 consulta un resolver NO autorizado de laboratorio (192.168.50.99).
"""
import random, base64, collections, csv, json, statistics
from lib import *
random.seed(53)
style()
RES = "192.168.50.53"; ROGUE = "192.168.50.99"
BASE_T = LAB_DAY.replace(hour=10)
P = Pcap(f"{EVID}/C2_dns_tunel_entrenamiento.pcap")
DUR = 900
normal_names = ["web.lab.test", "xmpp.lab.test", "dns.lab.test", "intranet.lab.test", "files.lab.test", "wpad.lab.test",
                "time.lab.test", "repo.lab.test", "printer01.lab.test", "mail.lab.test"]
log = []  # (t, src, dst, qname, qtype, qlen, resp_len)
def q(t, src, dst, name, qtype=1, txt=None):
    qid = random.randint(0, 65535); sp = random.randint(49152, 65535)
    pq = dns_query(qid, name, qtype)
    P.add(ts_of(t, BASE_T), src, dst, udp(src, dst, sp, 53, pq, ttl=128))
    pr = dns_response(qid, name, qtype, answer_ip="192.168.50.20", txt=txt)
    P.add(ts_of(t + random.uniform(0.0005, 0.003), BASE_T), dst, src, udp(dst, src, 53, sp, pr))
    log.append((t, src, dst, name, {1: "A", 16: "TXT", 28: "AAAA"}[qtype], len(pq) + 42, len(pr) + 42))

# 1) estaciones normales .101-.112
for h in range(101, 113):
    t = random.uniform(0, 10)
    while t < DUR:
        n = random.choice(normal_names)
        q(t, f"192.168.50.{h}", RES, n, random.choice([1, 1, 1, 28]))
        t += random.expovariate(1/12)
# 2) agente de telemetría legítimo .115 (cada 60 s, etiqueta hex de 12 caracteres + versión)
t = 3.0
while t < DUR:
    lab = "%012x" % random.getrandbits(48)
    q(t, "192.168.50.115", RES, f"{lab}.v2.telemetria.lab.test")
    q(t + 0.2, "192.168.50.115", RES, f"cdn{random.randint(1,4)}.edge.lab.test")
    t += 60 + random.uniform(-1, 1)
# 3) túnel didáctico .44 → *.t.exfil-lab.test, consultas TXT ~2/s entre 300 y 780 s
# "archivo" ficticio: 60 000 bytes pseudoaleatorios (equivale a un archivo comprimido; no contiene datos reales)
secret = b"ARCHIVO-DIDACTICO-SIN-DATOS-REALES" + bytes(random.getrandbits(8) for _ in range(60000))
chunks = base64.b32encode(secret).decode().rstrip("=").lower()
i = 0; seq = 0; t = 300.0
while t < 780 and i < len(chunks):
    c = chunks[i:i+100]; i += 100
    labels = [c[:60], c[60:]] if len(c) > 60 else [c]
    name = ".".join(labels + [f"{seq:05d}", "t", "exfil-lab.test"])
    txt = base64.b32encode(bytes(random.getrandbits(8) for _ in range(40))).decode().lower()
    q(t, "192.168.50.44", RES, name, 16, txt=txt)
    seq += 1; t += random.uniform(0.35, 0.65)
# 4) resolver no autorizado
for k in range(25):
    q(random.uniform(0, DUR), "192.168.50.66", ROGUE, random.choice(normal_names))
P.write()

# ----------------- análisis (desde el registro de consultas reconstruido del PCAP)
pk = read_pcap(P.path)
rows = []
for p in pk:
    if p["proto"] != 17 or p["dport"] != 53: continue
    pl = p["payload"]; o = 12; labs = []
    while pl[o]:
        L = pl[o]; labs.append(pl[o+1:o+1+L].decode()); o += 1 + L
    qtype = struct.unpack("!H", pl[o+1:o+3])[0]
    name = ".".join(labs)
    reg = ".".join(labs[-2:])
    sub = ".".join(labs[:-2]) if len(labs) > 2 else ""
    # para dominios lab.test el "registrable" es lab.test; el subdominio es el resto
    rows.append(dict(t=p["ts"] - ts_of(0, BASE_T), src=p["src"], dst=p["dst"], qname=name, qtype={1: "A", 16: "TXT", 28: "AAAA"}.get(qtype, qtype),
                     qlen=len(name), maxlab=max(len(l) for l in labs), ent=round(shannon(sub.replace(".", "")), 3), len=p["len"], sub_parent=".".join(labs[-3:])))
resp_len = collections.defaultdict(list)
for p in pk:
    if p["proto"] == 17 and p["sport"] == 53: resp_len[p["dst"]].append(p["len"])
with open(f"{EVID}/C2_consultas_dns.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

by = collections.defaultdict(list)
for r in rows: by[r["src"]].append(r)
def grp(src):
    rs = by[src]
    if src.endswith((".101", ".102", ".103", ".104", ".105", ".106", ".107", ".108", ".109", ".110", ".111", ".112")): return "estaciones .101–.112"
    return src
agg = collections.OrderedDict()
for src, rs in sorted(by.items()):
    g = grp(src); agg.setdefault(g, []).extend(rs)
table = []
for g, rs in agg.items():
    dom = collections.Counter(r["sub_parent"] if "exfil" in r["qname"] or "telemetria" in r["qname"] else ".".join(r["qname"].split(".")[-3:]) for r in rs)
    srcs = set(r["src"] for r in rs)
    rl = [l for s in srcs for l in resp_len[s]]
    table.append(dict(origen=g, consultas=len(rs), por_min=round(len(rs) / (DUR/60), 1), unicos=len(set(r["qname"] for r in rs)),
                      long_media=round(statistics.mean(r["qlen"] for r in rs), 1), etiqueta_max=max(r["maxlab"] for r in rs),
                      entropia_media=round(statistics.mean(r["ent"] for r in rs), 2), pct_txt=round(100*sum(r["qtype"] == "TXT" for r in rs)/len(rs), 1),
                      resp_media=round(statistics.mean(rl), 1), resolver=",".join(sorted(set(r["dst"] for r in rs))),
                      dominio_top=dom.most_common(1)[0][0]))
json.dump(table, open(f"{WORK}/C2_tabla_host.json", "w"), indent=1, ensure_ascii=False)
for r in table: print(r)

# ----------------- figura: longitud vs entropía
fig, ax = plt.subplots(1, 2, figsize=(12, 4.6), gridspec_kw={"width_ratios": [1.25, 1]})
cmap = {"estaciones .101–.112": "#7f8c8d", "192.168.50.115": "#2e86c1", "192.168.50.44": "#c0392b", "192.168.50.66": "#d68910"}
for g, rs in agg.items():
    ax[0].scatter([r["qlen"] for r in rs], [r["ent"] for r in rs], s=14 if g != "192.168.50.44" else 18, alpha=.6, color=cmap[g], label=f"{g} (n={len(rs)})")
ax[0].axvline(52, ls="--", color="#555"); ax[0].axhline(3.8, ls="--", color="#555")
ax[0].text(53, 1.55, "longitud > 52", fontsize=8); ax[0].text(2, 3.9, "entropía > 3,8 bits/car.", fontsize=8)
ax[0].set_xlabel("longitud del QNAME (caracteres)"); ax[0].set_ylabel("entropía de Shannon del subdominio (bits/carácter)")
ax[0].set_title("Longitud vs. entropía por consulta"); ax[0].legend(fontsize=8, loc="lower right")
bins = list(range(0, DUR+1, 60))
for g, rs in agg.items():
    cnt = [sum(1 for r in rs if b <= r["t"] < b+60) for b in bins[:-1]]
    ax[1].plot([b/60 for b in bins[:-1]], cnt, marker="o", ms=3, color=cmap[g], label=g)
ax[1].set_xlabel("minuto desde 10:00 (UTC-5)"); ax[1].set_ylabel("consultas / minuto"); ax[1].set_title("Frecuencia de consultas por origen")
ax[1].axvspan(5, 13, color="#fdedec", zorder=0)
save_fig(fig, "c2_fig1_longitud_entropia.png")

# ----------------- pantallazo Wireshark
sel = [p for p in pk if p["proto"] == 17 and "192.168.50.44" in (p["src"], p["dst"])]
sel = sel[40:62]
wrows = []
for p in sel:
    pl = p["payload"]; o = 12; labs = []
    while pl[o]:
        L = pl[o]; labs.append(pl[o+1:o+1+L].decode()); o += 1 + L
    name = ".".join(labs); qid = struct.unpack("!H", pl[:2])[0]
    info = (f"Standard query 0x{qid:04x} TXT {name}" if p["dport"] == 53 else f"Standard query response 0x{qid:04x} TXT {name} TXT")
    wrows.append(dict(no=p["no"], time=f"{p['ts']-ts_of(0, BASE_T):.6f}", src=p["src"], dst=p["dst"], proto="DNS", len=p["len"], info=info, color="dns"))
wireshark_shot(f"{FIG}/c2_fig2_wireshark_dns.png", "C2_dns_tunel_entrenamiento.pcap", "dns && ip.addr == 192.168.50.44   (previo: udp.port == 53)", wrows,
               details=["Domain Name System (query) · Queries: <etiqueta de 60 car. base32>.<40 car.>.<secuencia>.t.exfil-lab.test: type TXT, class IN",
                        "Name Length: 115–118 · Label Count: 6 · etiqueta máx. 60 car. (límite RFC 1035 = 63) · secuencia incremental 00000→00xxx",
                        "Estadísticas ▸ DNS: 192.168.50.44 = 100 % TXT, 1 consulta única por nombre, ~2 consultas/s durante 8 min"],
               status=f"Paquetes: {len(pk)} · Mostrados: {len(wrows)} (extracto) · udp.port == 53 → {sum(1 for p in pk if p['proto']==17)} paquetes")

# ----------------- registro del resolver (BIND9 query log)
lines = ["analista@dns-lab:~$ sudo tail -n 14 /var/log/named/queries.log", ""]
for r in [r for r in rows if r["src"] in ("192.168.50.44", "192.168.50.115", "192.168.50.103")][::23][:14]:
    tt = fmt_local(ts_of(r["t"], BASE_T))
    lines.append(f"05-Nov-2026 {tt[11:]} client @0x7f3a {r['src']}#{random.randint(49152,65535)} ({r['qname'][:46]}{'…' if len(r['qname'])>46 else ''}): query: … IN {r['qtype']} +E(0)")
lines += ["", "analista@dns-lab:~$ grep -c 'exfil-lab.test' /var/log/named/queries.log",
          str(sum(1 for r in rows if 'exfil-lab' in r['qname'])),
          "analista@dns-lab:~$ grep 'exfil-lab.test' /var/log/named/queries.log | awk '{print $4}' | cut -d'#' -f1 | sort | uniq -c",
          f"    {sum(1 for r in rows if 'exfil-lab' in r['qname'])} 192.168.50.44",
          "analista@dns-lab:~$ grep -c '192.168.50.66' /var/log/named/queries.log",
          ("0     ← .66 no usa el resolver autorizado: sus 25 consultas van a 192.168.50.99", (255, 220, 120))]
console_shot(f"{FIG}/c2_fig3_log_resolver.png", "analista@dns-lab — registro de consultas BIND 9 (servidor DNS de laboratorio 192.168.50.53)", lines, kind="bash", width=1400)
print("pk", len(pk), sha256(P.path))
