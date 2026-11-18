"""Librería común del laboratorio (Guía-Taller No. 2, Parte I).

- Escritor de PCAP (libpcap, LINKTYPE_ETHERNET) sin dependencias externas.
- Constructores de tramas Ethernet/IPv4/TCP/UDP/ICMP con checksums válidos.
- Renderizadores de "pantallazos" simulados (Wireshark, consola Windows, terminal).
Todo el tráfico es SINTÉTICO y se genera en direcciones privadas / reservadas de prueba.
"""
import struct, random, hashlib, os, math, datetime as dt
from zoneinfo import ZoneInfo
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from PIL import Image, ImageDraw, ImageFont

TZ = ZoneInfo("America/Bogota")
BASE = "/home/claude/taller"
EVID = f"{BASE}/evidencias/original"
WORK = f"{BASE}/evidencias/trabajo"
FIG = f"{BASE}/figuras"
for d in (EVID, WORK, FIG):
    os.makedirs(d, exist_ok=True)

# Fecha de la práctica (hora local Bogotá, UTC-5)
LAB_DAY = dt.datetime(2026, 11, 5, 9, 0, 0, tzinfo=TZ)

MAC = {
    "192.168.50.1": "00:50:56:a1:00:01", "192.168.50.10": "00:50:56:a1:00:10",
    "192.168.50.20": "00:50:56:a1:00:20", "192.168.50.30": "00:50:56:a1:00:30",
    "192.168.50.53": "00:50:56:a1:00:53",
}
def mac_of(ip):
    if ip in MAC: return MAC[ip]
    h = hashlib.md5(ip.encode()).hexdigest()
    return "00:50:56:" + ":".join(h[i:i+2] for i in (0, 2, 4))

def _mac(m): return bytes(int(x, 16) for x in m.split(":"))
def _ip(a): return bytes(int(x) for x in a.split("."))

def csum(data):
    if len(data) % 2: data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload, ttl=64, ident=None):
    ident = random.randint(0, 65535) if ident is None else ident
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(payload), ident, 0x4000, ttl, proto, 0, _ip(src), _ip(dst))
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload

def tcp(src, dst, sport, dport, flags, seq=0, ack=0, payload=b"", win=64240, ttl=64):
    off = 5 << 4
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xffffffff, ack & 0xffffffff, off, flags, win, 0, 0) + payload
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 6, len(seg))
    c = csum(pseudo + seg)
    seg = seg[:16] + struct.pack("!H", c) + seg[18:]
    return ipv4(src, dst, 6, seg, ttl=ttl)

def udp(src, dst, sport, dport, payload, ttl=64):
    seg = struct.pack("!HHHH", sport, dport, 8+len(payload), 0) + payload
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 17, len(seg))
    c = csum(pseudo + seg) or 0xffff
    seg = seg[:6] + struct.pack("!H", c) + seg[8:]
    return ipv4(src, dst, 17, seg, ttl=ttl)

def icmp(src, dst, typ, code, ident, seqn, payload, ttl=64):
    m = struct.pack("!BBHHH", typ, code, 0, ident, seqn) + payload
    m = m[:2] + struct.pack("!H", csum(m)) + m[4:]
    return ipv4(src, dst, 1, m, ttl=ttl)

def eth(src_ip, dst_ip, ippkt, src_mac=None):
    return _mac(mac_of(dst_ip)) + _mac(src_mac or mac_of(src_ip)) + b"\x08\x00" + ippkt

F = dict(FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10)

def dns_query(qid, name, qtype=1):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)

def dns_response(qid, name, qtype=1, answer_ip="192.168.50.20", txt=None):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    hdr = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    body = q + struct.pack("!HH", qtype, 1)
    if qtype == 16 and txt is not None:
        t = txt.encode()[:255]
        rdata = bytes([len(t)]) + t
    else:
        rdata = _ip(answer_ip)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
    return hdr + body + ans

class Pcap:
    """Escritor de PCAP clásico (magic a1b2c3d4, microsegundos)."""
    def __init__(self, path):
        self.path = path
        self.recs = []  # (ts, frame, meta)
    def add(self, ts, src, dst, ippkt, meta=None, src_mac=None):
        self.recs.append((ts, eth(src, dst, ippkt, src_mac), meta or {}))
    def write(self):
        self.recs.sort(key=lambda r: r[0])
        with open(self.path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for ts, fr, _ in self.recs:
                sec = int(ts); usec = int(round((ts - sec) * 1e6))
                if usec >= 1000000: sec += 1; usec -= 1000000
                f.write(struct.pack("<IIII", sec, usec, len(fr), len(fr)) + fr)
        return self.path

def read_pcap(path):
    """Lector mínimo: devuelve lista de dicts por paquete (para análisis independiente)."""
    out = []
    with open(path, "rb") as f:
        gh = f.read(24)
        assert struct.unpack("<I", gh[:4])[0] == 0xa1b2c3d4
        n = 0
        while True:
            h = f.read(16)
            if len(h) < 16: break
            sec, usec, incl, orig = struct.unpack("<IIII", h)
            fr = f.read(incl); n += 1
            ip = fr[14:]
            ihl = (ip[0] & 0xf) * 4
            proto = ip[9]; ttl = ip[8]
            src = ".".join(map(str, ip[12:16])); dst = ".".join(map(str, ip[16:20]))
            smac = ":".join("%02x" % b for b in fr[6:12])
            ipid = struct.unpack("!H", ip[4:6])[0]
            d = dict(no=n, ts=sec+usec/1e6, len=incl, src=src, dst=dst, proto=proto, ttl=ttl, smac=smac, ipid=ipid)
            l4 = ip[ihl:]
            if proto == 6:
                sp, dp, seq, ack, off, fl, win = struct.unpack("!HHIIBBH", l4[:16])
                d.update(sport=sp, dport=dp, seq=seq, ack=ack, flags=fl, win=win, payload=l4[(off >> 4)*4:])
            elif proto == 17:
                sp, dp, ln = struct.unpack("!HHH", l4[:6])
                d.update(sport=sp, dport=dp, payload=l4[8:])
            elif proto == 1:
                t, c, _, idf, sq = struct.unpack("!BBHHH", l4[:8])
                d.update(itype=t, icode=c, iid=idf, iseq=sq, payload=l4[8:])
            out.append(d)
    return out

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(65536), b""): h.update(b)
    return h.hexdigest()

def ts_of(offset_s, base=None):
    base = base or LAB_DAY
    return base.timestamp() + offset_s

def fmt_local(ts):
    return dt.datetime.fromtimestamp(ts, TZ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

# ---------------------------------------------------------------- renderizado
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONOB = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
SANSB = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

def _font(p, s):
    try: return ImageFont.truetype(p, s)
    except Exception: return ImageFont.load_default()

def _watermark(img, text="EVIDENCIA SIMULADA · PCAP/TELEMETRÍA SINTÉTICA · USO ACADÉMICO"):
    W, H = img.size
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    f = _font(SANSB, 13)
    tw = int(d.textlength(text, font=f)) + 16
    d.rectangle([W-tw-6, H-26, W-6, H-6], fill=(180, 30, 30, 200))
    d.text((W-tw+2, H-23), text, font=f, fill=(255, 255, 255, 255))
    return Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB")

WS_COLORS = {  # reglas de coloreado por defecto de Wireshark (aprox.)
    "rst": ((164, 0, 0), (255, 252, 156)),
    "syn": ((18, 39, 46), (160, 160, 160)),
    "tcp": ((18, 39, 46), (231, 230, 255)),
    "udp": ((18, 39, 46), (218, 238, 255)),
    "dns": ((18, 39, 46), (218, 238, 255)),
    "icmp": ((18, 39, 46), (252, 224, 255)),
    "icmperr": ((183, 247, 116), (18, 39, 46)),
    "http": ((18, 39, 46), (228, 255, 199)),
    "bad": ((247, 120, 120), (18, 39, 46)),
    "tls": ((18, 39, 46), (231, 230, 255)),
}

def wireshark_shot(path, title, dfilter, rows, details=None, status=None, width=1500):
    """rows: lista de dicts no,time,src,dst,proto,len,info,color(key) ; details: lista de líneas."""
    rh = 22
    n = len(rows)
    det_h = (len(details) * 20 + 16) if details else 0
    H = 30 + 30 + 34 + 26 + n * rh + 10 + det_h + 30
    img = Image.new("RGB", (width, H), (255, 255, 255))
    d = ImageDraw.Draw(img)
    fs, fb, fm = _font(SANS, 14), _font(SANSB, 14), _font(MONO, 13)
    # barra de título
    d.rectangle([0, 0, width, 30], fill=(54, 61, 70))
    d.text((12, 6), f"{title} — Wireshark (vista reconstruida a partir del PCAP sintético)", font=fb, fill=(240, 240, 240))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([width-80+i*22, 8, width-66+i*22, 22], fill=c)
    # menú
    d.rectangle([0, 30, width, 60], fill=(236, 236, 236))
    d.text((12, 37), "Archivo   Editar   Visualización   Ir   Captura   Analizar   Estadísticas   Telefonía   Inalámbrico   Herramientas   Ayuda", font=fs, fill=(30, 30, 30))
    # barra de filtro (verde = filtro válido)
    d.rectangle([6, 64, width-6, 92], fill=(175, 255, 175), outline=(90, 160, 90))
    d.text((14, 70), dfilter, font=fm, fill=(0, 0, 0))
    # cabecera de columnas
    y = 98
    cols = [("No.", 10, 70), ("Time", 80, 150), ("Source", 230, 160), ("Destination", 390, 160), ("Protocol", 550, 80), ("Length", 630, 70), ("Info", 700, width-710)]
    d.rectangle([0, y, width, y+24], fill=(225, 225, 225))
    for name, x, w in cols:
        d.text((x+2, y+4), name, font=fb, fill=(20, 20, 20))
        d.line([x-4, y, x-4, y+24], fill=(190, 190, 190))
    y += 26
    for r in rows:
        fg, bg = WS_COLORS.get(r.get("color", "tcp"), WS_COLORS["tcp"])
        d.rectangle([0, y, width, y+rh-1], fill=bg)
        vals = [str(r["no"]), r["time"], r["src"], r["dst"], r["proto"], str(r["len"]), r["info"]]
        for (name, x, w), v in zip(cols, vals):
            maxc = max(4, int(w / 8))
            d.text((x+2, y+3), v[:maxc], font=fm, fill=fg)
        y += rh
    y += 6
    if details:
        d.rectangle([0, y, width, y+det_h], fill=(248, 248, 248), outline=(200, 200, 200))
        yy = y + 8
        for line in details:
            d.text((12, yy), line, font=fm, fill=(20, 20, 20)); yy += 20
        y += det_h
    d.rectangle([0, H-30, width, H], fill=(236, 236, 236))
    d.text((12, H-24), status or f"Paquetes mostrados: {n}", font=fs, fill=(40, 40, 40))
    img = _watermark(img)
    img.save(path, optimize=True)
    return path

def console_shot(path, title, lines, kind="powershell", width=1300, wm="SALIDA SIMULADA · ENTORNO DE LABORATORIO · USO ACADÉMICO"):
    fm = _font(MONO, 15)
    lh = 21
    H = 34 + len(lines) * lh + 46
    bg = {"powershell": (1, 36, 86), "cmd": (12, 12, 12), "bash": (30, 30, 30)}[kind]
    fg = {"powershell": (238, 237, 240), "cmd": (204, 204, 204), "bash": (220, 220, 220)}[kind]
    img = Image.new("RGB", (width, H), bg)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, 32], fill=(240, 240, 240))
    d.text((12, 8), title, font=_font(SANS, 14), fill=(20, 20, 20))
    d.text((width-90, 6), "—   ☐   ✕", font=_font(SANS, 15), fill=(40, 40, 40))
    y = 42
    for ln in lines:
        col = fg
        if isinstance(ln, tuple): ln, col = ln
        d.text((12, y), ln, font=fm, fill=col); y += lh
    img = _watermark(img, wm)
    img.save(path, optimize=True)
    return path

def table_shot(path, title, header, rows, colw=None, width=None, highlight=None):
    """Tabla tipo panel (para dashboards/logs)."""
    fm, fb = _font(MONO, 14), _font(MONOB, 14)
    colw = colw or [max(len(str(h)), *(len(str(r[i])) for r in rows)) * 9 + 20 for i, h in enumerate(header)]
    W = width or sum(colw) + 20
    H = 40 + 28 + 24 * len(rows) + 40
    img = Image.new("RGB", (W, H), (250, 250, 250))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 34], fill=(37, 53, 80))
    d.text((12, 8), title, font=_font(SANSB, 15), fill=(255, 255, 255))
    y = 42; x = 10
    d.rectangle([0, y-2, W, y+24], fill=(220, 226, 236))
    for h, w in zip(header, colw):
        d.text((x+4, y+3), str(h), font=fb, fill=(20, 20, 20)); x += w
    y += 28
    for i, r in enumerate(rows):
        bg = (255, 255, 255) if i % 2 == 0 else (242, 244, 248)
        if highlight and highlight(r): bg = (255, 228, 225)
        d.rectangle([0, y-2, W, y+22], fill=bg)
        x = 10
        for v, w in zip(r, colw):
            d.text((x+4, y+2), str(v)[: max(3, w // 9)], font=fm, fill=(25, 25, 25)); x += w
        y += 24
    img = _watermark(img, "DATOS SIMULADOS · USO ACADÉMICO")
    img.save(path, optimize=True)
    return path

def style():
    plt.rcParams.update({
        "figure.dpi": 130, "savefig.dpi": 130, "font.size": 10, "axes.titlesize": 12,
        "axes.titleweight": "bold", "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "grid.alpha": 0.25, "legend.frameon": False,
    })

def save_fig(fig, name, note="Datos sintéticos generados en laboratorio aislado (192.168.50.0/24) · Uso académico"):
    fig.text(0.99, -0.03, note, ha="right", va="top", fontsize=7, color="#a33")
    p = f"{FIG}/{name}"
    fig.savefig(p, bbox_inches="tight")
    plt.close(fig)
    return p

def shannon(s):
    if not s: return 0.0
    from collections import Counter
    c = Counter(s); n = len(s)
    return -sum(v/n * math.log2(v/n) for v in c.values())
