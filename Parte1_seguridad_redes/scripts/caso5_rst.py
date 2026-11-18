"""Caso 5 – TCP: resets inesperados (PCAP de laboratorio sintético, 30 min).
Causas incluidas: (A) reinicio de servicio Tomcat 8080, (B) puerto cerrado, (C) aborto del cliente,
(D) RST con indicios de INYECCIÓN (TTL y MAC incoherentes, el servidor real sigue enviando datos).
"""
import random, collections, json, csv
from lib import *
random.seed(55)
style()
SRV = "192.168.50.20"; ATT_MAC = "00:50:56:a1:00:66"
BASE_T = LAB_DAY.replace(hour=13)
P = Pcap(f"{EVID}/C5_tcp_resets_lab.pcap")
truth = []  # (t, cliente, sport, dport, categoria)

def session(t, cli, dport, n_data=6, end="fin", inject_at=None, restart_at=None):
    sp = random.randint(49152, 65000); cs = random.getrandbits(32); ss = random.getrandbits(32)
    ttl_c = 128; ttl_s = 128
    def add(tt, src, dst, a, b, fl, s, k, pl=b"", ttl=128, mac=None):
        P.add(ts_of(tt, BASE_T), src, dst, tcp(src, dst, a, b, fl, seq=s, ack=k, payload=pl, ttl=ttl), src_mac=mac)
    add(t, cli, SRV, sp, dport, F["SYN"], cs, 0); t += .0004
    if end == "cerrado":
        add(t, SRV, cli, dport, sp, F["RST"] | F["ACK"], 0, cs+1); truth.append((t, cli, sp, dport, "B · puerto cerrado")); return
    add(t, SRV, cli, dport, sp, F["SYN"] | F["ACK"], ss, cs+1); t += .0004
    cs += 1; ss += 1
    add(t, cli, SRV, sp, dport, F["ACK"], cs, ss)
    for i in range(n_data):
        t += random.uniform(0.05, 0.6)
        req = b"\x17\x03\x03\x00\x40" + bytes(random.getrandbits(8) for _ in range(64)) if dport == 443 else b"GET /app/estado HTTP/1.1\r\nHost: app.lab.test\r\n\r\n"
        add(t, cli, SRV, sp, dport, F["PSH"] | F["ACK"], cs, ss, req); cs += len(req)
        if restart_at is not None and t >= restart_at:
            add(restart_at + random.uniform(0, 0.01), SRV, cli, dport, sp, F["RST"] | F["ACK"], ss, cs)
            truth.append((restart_at, cli, sp, dport, "A · reinicio de servicio")); return
        t += random.uniform(0.002, 0.02)
        resp = b"\x17\x03\x03\x01\x00" + bytes(random.getrandbits(8) for _ in range(256)) if dport == 443 else b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        if inject_at is not None and i == inject_at:
            # RST forjado: misma IP/puerto del servidor, seq exacto, pero TTL 64 y MAC del host .66; llega 0,3 ms ANTES de la respuesta real
            add(t - 0.0003, SRV, cli, dport, sp, F["RST"], ss, 0, ttl=64, mac=ATT_MAC)
            truth.append((t - 0.0003, cli, sp, dport, "D · posible inyección"))
            add(t, SRV, cli, dport, sp, F["PSH"] | F["ACK"], ss, cs, resp); ss += len(resp)
            # el cliente ya destruyó el socket → responde RST al dato legítimo del servidor
            add(t + 0.0002, cli, SRV, sp, dport, F["RST"], cs, 0)
            truth.append((t + 0.0002, cli, sp, dport, "D' · RST del cliente tras desincronización"))
            return
        add(t, SRV, cli, dport, sp, F["PSH"] | F["ACK"], ss, cs, resp); ss += len(resp)
    t += 0.01
    if end == "fin":
        add(t, cli, SRV, sp, dport, F["FIN"] | F["ACK"], cs, ss); add(t+.0004, SRV, cli, dport, sp, F["FIN"] | F["ACK"], ss, cs+1); add(t+.0008, cli, SRV, sp, dport, F["ACK"], cs+1, ss+1)
    elif end == "aborto":
        add(t, cli, SRV, sp, dport, F["RST"] | F["ACK"], cs, ss); truth.append((t, cli, sp, dport, "C · aborto del cliente"))

RESTART = 720.0  # 13:12:00 reciclaje de Tomcat (evento 7036 en el Visor)
t = 0
while t < 1800:
    t += random.expovariate(0.5)
    cli = f"192.168.50.{random.randint(100,130)}"
    r = random.random()
    if r < 0.08: session(t, cli, 8443, end="cerrado")
    elif r < 0.14: session(t, cli, 443, end="aborto")
    elif RESTART - 4 < t < RESTART and r < 0.6: session(t, cli, 8080, n_data=12, restart_at=RESTART)
    else: session(t, cli, random.choice([443, 443, 8080]))
# sesiones largas a Tomcat activas durante el reciclaje
for k in range(14):
    session(RESTART - random.uniform(1, 6), f"192.168.50.{random.randint(100,130)}", 8080, n_data=40, restart_at=RESTART)
# inyección: 7 sesiones del cliente .121 hacia 443 entre 13:20 y 13:24
for k in range(7):
    session(1200 + k*35 + random.uniform(0, 5), "192.168.50.121", 443, n_data=8, inject_at=random.randint(2, 6))
P.write()

# ------------- análisis del PCAP: clasificar cada RST con evidencia observable
pk = read_pcap(P.path)
t0 = ts_of(0, BASE_T)
tcp_pk = [p for p in pk if p["proto"] == 6]
flows = collections.defaultdict(list)
for p in tcp_pk:
    key = tuple(sorted([(p["src"], p["sport"]), (p["dst"], p["dport"])]))
    flows[key].append(p)
srv_mac = mac_of(SRV)
rst_rows = []
for key, ps in flows.items():
    ps.sort(key=lambda x: x["ts"])
    for i, p in enumerate(ps):
        if not p["flags"] & F["RST"]: continue
        after = [q for q in ps[i+1:] if q["src"] == p["src"] and q["payload"]]
        from_srv = p["src"] == SRV
        ttl_bad = from_srv and p["ttl"] != 128
        mac_bad = from_srv and p["smac"] != srv_mac
        syn_only = any(q["flags"] == F["SYN"] for q in ps) and not any(q["flags"] == F["SYN"] | F["ACK"] for q in ps)
        dport = p["dport"] if not from_srv else p["sport"]
        if ttl_bad or mac_bad: cat = "D · RST con TTL/MAC incoherentes (posible inyección)"
        elif from_srv and len([q for q in ps if q["flags"] & F["SYN"]]) == 1 and i == 1: cat = "B · puerto cerrado (RST/ACK al SYN)"
        elif from_srv and abs(p["ts"] - t0 - RESTART) < 1: cat = "A · coincide con reinicio de servicio (7036)"
        elif not from_srv and any(q["flags"] & F["RST"] and q["ttl"] != 128 for q in ps[:i]): cat = "D' · RST del cliente tras desincronización"
        elif not from_srv: cat = "C · cierre abortivo del cliente"
        else: cat = "sin clasificar"
        rst_rows.append(dict(no=p["no"], t=round(p["ts"]-t0, 6), hora=fmt_local(p["ts"])[11:23], src=f"{p['src']}:{p['sport']}", dst=f"{p['dst']}:{p['dport']}",
                             flags="RST,ACK" if p["flags"] & F["ACK"] else "RST", ttl=p["ttl"], mac_src=p["smac"], ipid=p["ipid"],
                             datos_posteriores_mismo_emisor=len(after), categoria=cat, puerto_servicio=dport))
rst_rows.sort(key=lambda r: r["t"])
with open(f"{EVID}/C5_tabla_rst.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rst_rows[0].keys())); w.writeheader(); w.writerows(rst_rows)
cnt = collections.Counter(r["categoria"] for r in rst_rows)
print(len(pk), len(rst_rows), cnt)
json.dump({"paquetes": len(pk), "flujos": len(flows), "rst_total": len(rst_rows), "por_categoria": cnt}, open(f"{WORK}/C5_resumen.json", "w"), indent=1, ensure_ascii=False)

# ------------- figura temporal de RST por categoría
fig, ax = plt.subplots(figsize=(11.5, 3.9))
cats = sorted(cnt)
colors = {"A": "#f39c12", "B": "#95a5a6", "C": "#3498db", "D": "#c0392b", "D'": "#7b241c"}
for i, c in enumerate(cats):
    xs = [r["t"]/60 for r in rst_rows if r["categoria"] == c]
    ax.scatter(xs, [i]*len(xs), s=26, color=colors[c.split(" ")[0]], label=f"{c} (n={cnt[c]})")
ax.set_yticks(range(len(cats))); ax.set_yticklabels([c.split(" · ")[0] for c in cats])
ax.axvline(RESTART/60, ls="--", color="#f39c12"); ax.text(RESTART/60+0.3, 0.25, "13:12 Evento 7036: Tomcat9 detenido/iniciado", fontsize=8, color="#b9770e")
ax.set_xlabel("minuto desde 13:00 (UTC-5)"); ax.set_title("Caso 5 · RST observados por causa probable (tcp.flags.reset == 1)")
ax.legend(fontsize=7.5, loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=3); ax.set_xlim(0, 31)
save_fig(fig, "c5_fig1_rst_temporal.png")

# ------------- pantallazo Wireshark: sesión inyectada
sel = []
key_d = None
for r in rst_rows:
    if r["categoria"].startswith("D ·"): key_d = r; break
cli_port = int(key_d["dst"].split(":")[1])
sess = sorted([p for p in tcp_pk if cli_port in (p["sport"], p["dport"]) and "192.168.50.121" in (p["src"], p["dst"])], key=lambda x: x["ts"])
wr = []
for p in sess:
    fl = [n for n, v in F.items() if p["flags"] & v]
    info = f"{p['sport']} → {p['dport']} [{', '.join(fl)}] Seq={p['seq']%100000} Len={len(p['payload'])}  TTL={p['ttl']}"
    col = "rst" if p["flags"] & F["RST"] else ("tls" if p["payload"] else "tcp")
    if p["flags"] & F["RST"] and p["ttl"] != 128: col = "bad"
    if p["payload"] and any(q["flags"] & F["RST"] and q["ts"] < p["ts"] and q["dst"] == "192.168.50.121" for q in sess): col = "bad"; info += "  [TCP ACKed unseen segment] [Previous RST]"
    wr.append(dict(no=p["no"], time=f"{p['ts']-t0:.6f}", src=p["src"], dst=p["dst"], proto="TLSv1.3" if p["payload"] else "TCP", len=p["len"], info=info, color=col))
wireshark_shot(f"{FIG}/c5_fig2_wireshark_inyeccion.png", "C5_tcp_resets_lab.pcap", f"tcp.stream eq (sesión 192.168.50.121:{cli_port} ↔ 192.168.50.20:443)   ·   previo: tcp.flags.reset == 1", wr,
               details=[f"RST n.º {key_d['no']}: Src 192.168.50.20 pero Ethernet Src {ATT_MAC} (la MAC real de .20 es {srv_mac}) · TTL=64 (el servidor Windows usa 128) · IP ID={key_d['ipid']}",
                        "0,3 ms después llega el segmento legítimo del servidor (TTL 128, MAC correcta) con el mismo número de secuencia → carrera entre paquete forjado y real",
                        "El cliente, que ya cerró el socket, responde RST al dato legítimo → patrón clásico de inyección de RST en la misma L2 (requiere confirmar con ARP/switch)"],
               status=f"Paquetes: {len(pk)} · tcp.flags.reset == 1 → {len(rst_rows)} · Mostrados: {len(wr)}")

# ------------- Zeek conn.log / weird.log + Suricata eve.json (extractos reconstruidos a partir del PCAP)
lines = ["analista@sensor-lab:~$ zeek -C -r C5_tcp_resets_lab.pcap local", "analista@sensor-lab:~$ zeek-cut ts id.orig_h id.orig_p id.resp_h id.resp_p service conn_state history < conn.log \\", "                        | awk '$7 ~ /RST|REJ/' | head -12", ""]
shown = 0
for r in rst_rows:
    if shown > 11: break
    if r["categoria"][0] in "ABCD" and (shown < 3 or r["categoria"][0] == "D" or random.random() < .1):
        st = {"A": "RSTR", "B": "REJ", "C": "RSTO", "D": "RSTR"}[r["categoria"][0]]
        hist = {"A": "ShADadr", "B": "Sr", "C": "ShADadR", "D": "ShADadrR"}[r["categoria"][0]]
        o = r["dst"] if r["src"].startswith(SRV) else r["src"]; d_ = r["src"] if r["src"].startswith(SRV) else r["dst"]
        lines.append(f"{ts_of(r['t'], BASE_T):.6f}  {o.split(':')[0]:<15} {o.split(':')[1]:<6} {d_.split(':')[0]:<14} {d_.split(':')[1]:<5} {('-' if r['categoria'][0]=='B' else 'ssl' if d_.endswith('443') else ('http' if d_.endswith('8080') else '-')):<5} {st:<5} {hist}"); shown += 1
lines += ["", "analista@sensor-lab:~$ zeek-cut ts id.orig_h name < weird.log | sort -k3 | uniq -c -f2",
          f"      7 {ts_of(1200, BASE_T):.6f} 192.168.50.121  data_after_reset", f"      7 {ts_of(1200, BASE_T):.6f} 192.168.50.121  lab_rst_ttl_change*", "",
          "analista@sensor-lab:~$ jq -c 'select(.event_type==\"alert\") | [.timestamp,.src_ip,.dest_ip,.alert.signature_id,.alert.signature]' eve.json | head -3",
          *[f'["{fmt_local(ts_of(r["t"], BASE_T)).replace(" ", "T")}-0500","192.168.50.20","192.168.50.121",1000501,"LAB TCP RST con TTL distinto al de la sesión (posible inyección)"]' for r in rst_rows if r["categoria"].startswith("D ·")][:3],
          ("* weird personalizado del laboratorio (script local rst_ttl.zeek, ver Anexo).", (255, 220, 120))]
console_shot(f"{FIG}/c5_fig3_zeek_suricata.png", "analista@sensor-lab — Zeek 7.0 / Suricata 7.0 (sensor pasivo, puerto espejo)", lines, kind="bash", width=1500)
print(sha256(P.path))
