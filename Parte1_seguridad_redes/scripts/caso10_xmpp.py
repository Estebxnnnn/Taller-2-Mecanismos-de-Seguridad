"""Caso 10 – Mensajería XMPP: interceptación y errores de TLS.
Parte REAL: se crea una CA de laboratorio y certificados (válido, vencido, nombre incorrecto) y se ejecutan pruebas
TLS reales con OpenSSL en la interfaz de loopback 127.0.0.1 (representa a xmpp.lab.test / 192.168.50.30).
Parte SINTÉTICA: PCAP de una sesión XMPP con STARTTLS + extractos de configuración/log de ejabberd del laboratorio.
"""
import subprocess, time, datetime as dt, os, random, json, ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from lib import *
random.seed(10)
PKI = f"{BASE}/evidencias/pki"; os.makedirs(PKI, exist_ok=True)
U = dt.timezone.utc
def key():
    return ec.generate_private_key(ec.SECP256R1())
def save(k, c, name):
    open(f"{PKI}/{name}.key", "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(f"{PKI}/{name}.crt", "wb").write(c.public_bytes(serialization.Encoding.PEM))
ca_k = key()
ca_name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "CO"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UD Lab Redes (academico)"), x509.NameAttribute(NameOID.COMMON_NAME, "LAB-CA Raiz 2026")])
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_k.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=U)).not_valid_after(dt.datetime(2031, 1, 1, tzinfo=U))
      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
      .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True).sign(ca_k, hashes.SHA256()))
save(ca_k, ca, "lab-ca")
def leaf(name, cn, sans, nb, na):
    k = key()
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UD Lab Redes (academico)"), x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(ca_name).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.SubjectAlternativeName(sans), critical=False)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
    c = b.sign(ca_k, hashes.SHA256()); save(k, c, name); return c
leaf("xmpp-valido", "xmpp.lab.test", [x509.DNSName("xmpp.lab.test"), x509.DNSName("lab.test"), x509.IPAddress(ipaddress.ip_address("192.168.50.30"))],
     dt.datetime(2026, 10, 1, tzinfo=U), dt.datetime(2027, 1, 1, tzinfo=U))
leaf("conference-vencido", "conference.lab.test", [x509.DNSName("conference.lab.test")], dt.datetime(2025, 10, 1, tzinfo=U), dt.datetime(2026, 9, 30, 23, 59, tzinfo=U))
leaf("admin-nombre-incorrecto", "localhost", [x509.DNSName("localhost")], dt.datetime(2026, 10, 1, tzinfo=U), dt.datetime(2027, 10, 1, tzinfo=U))

def run(cmd, inp=b""):
    r = subprocess.run(cmd, input=inp, capture_output=True, timeout=20)
    return (r.stdout + r.stderr).decode(errors="replace")
def server(cert, port, extra=()):
    return subprocess.Popen(["openssl", "s_server", "-quiet", "-accept", f"127.0.0.1:{port}", "-cert", f"{PKI}/{cert}.crt", "-key", f"{PKI}/{cert}.key",
                             "-min_protocol", "TLSv1.2", *extra], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.PIPE)
results = {}
s1 = server("xmpp-valido", 15223); time.sleep(0.6)
results["valido"] = run(["openssl", "s_client", "-connect", "127.0.0.1:15223", "-servername", "xmpp.lab.test", "-CAfile", f"{PKI}/lab-ca.crt",
                         "-verify_hostname", "xmpp.lab.test", "-verify_return_error", "-brief"], b"Q\n")
results["tls11"] = run(["openssl", "s_client", "-connect", "127.0.0.1:15223", "-tls1_1", "-cipher", "DEFAULT@SECLEVEL=0", "-brief"], b"Q\n")
results["tls12"] = run(["openssl", "s_client", "-connect", "127.0.0.1:15223", "-tls1_2", "-servername", "xmpp.lab.test", "-CAfile", f"{PKI}/lab-ca.crt", "-verify_return_error", "-brief"], b"Q\n")
s1.kill()
s2 = server("conference-vencido", 15224); time.sleep(0.6)
results["vencido"] = run(["openssl", "s_client", "-connect", "127.0.0.1:15224", "-servername", "conference.lab.test", "-CAfile", f"{PKI}/lab-ca.crt",
                          "-verify_hostname", "conference.lab.test", "-verify_return_error", "-brief"], b"Q\n")
s2.kill()
s3 = server("admin-nombre-incorrecto", 15280); time.sleep(0.6)
results["nombre"] = run(["openssl", "s_client", "-connect", "127.0.0.1:15280", "-servername", "xmpp.lab.test", "-CAfile", f"{PKI}/lab-ca.crt",
                         "-verify_hostname", "xmpp.lab.test", "-verify_return_error", "-brief"], b"Q\n")
s3.kill()
results["x509_valido"] = run(["openssl", "x509", "-in", f"{PKI}/xmpp-valido.crt", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName", "-fingerprint", "-sha256"])
results["x509_vencido"] = run(["openssl", "x509", "-in", f"{PKI}/conference-vencido.crt", "-noout", "-subject", "-enddate", "-checkend", "0"])
results["verify_cadena"] = run(["openssl", "verify", "-CAfile", f"{PKI}/lab-ca.crt", f"{PKI}/xmpp-valido.crt", f"{PKI}/conference-vencido.crt", f"{PKI}/admin-nombre-incorrecto.crt"])
results["fecha_ejecucion"] = dt.datetime.now(TZ).isoformat(timespec="seconds")
results["openssl"] = run(["openssl", "version"]).strip()
json.dump(results, open(f"{EVID}/C10_pruebas_tls_reales.json", "w"), indent=1, ensure_ascii=False)
for k, v in results.items(): print("=====", k, "\n", v)

def clean(txt, n=14):
    return [l.replace(PKI, "pki") for l in txt.strip().splitlines() if l.strip()][:n]
L = [f"analista@ws-analista:~$ # Pruebas REALES {results['fecha_ejecucion']} · {results['openssl'][:15]} · loopback 127.0.0.1 ≙ 192.168.50.30",
     "analista@ws-analista:~$ openssl s_client -connect 127.0.0.1:15223 -servername xmpp.lab.test -CAfile pki/lab-ca.crt \\",
     "                          -verify_hostname xmpp.lab.test -verify_return_error -brief"] + \
    [("  " + l, (150, 230, 150)) for l in clean(results["valido"], 9)] + \
    ["", "analista@ws-analista:~$ openssl s_client -connect 127.0.0.1:15223 -tls1_2 -servername xmpp.lab.test -CAfile pki/lab-ca.crt -brief"] + \
    [("  " + l[:150], (150, 230, 150)) for l in clean(results["tls12"], 3)] + \
    ["", "analista@ws-analista:~$ openssl s_client -connect 127.0.0.1:15223 -tls1_1 -cipher 'DEFAULT@SECLEVEL=0' -brief   # ¿el servidor acepta TLS 1.1?"] + \
    [("  " + l[:150], (255, 150, 150)) for l in clean(results["tls11"], 3)] + \
    ["", "analista@ws-analista:~$ openssl s_client -connect 127.0.0.1:15224 -servername conference.lab.test -CAfile pki/lab-ca.crt -verify_return_error -brief"] + \
    [("  " + l[:150], (255, 150, 150)) for l in clean(results["vencido"], 3)] + \
    ["", "analista@ws-analista:~$ openssl s_client -connect 127.0.0.1:15280 -servername xmpp.lab.test -CAfile pki/lab-ca.crt \\", "                          -verify_hostname xmpp.lab.test -verify_return_error -brief"] + \
    [("  " + l[:150], (255, 150, 150)) for l in clean(results["nombre"], 3)]
console_shot(f"{FIG}/c10_fig1_openssl_real.png", "analista@ws-analista — verificación TLS con OpenSSL (salida real, entorno loopback)", L, kind="bash", width=1500, wm="SALIDA REAL OPENSSL · LOOPBACK DE LABORATORIO · USO ACADÉMICO")
L2 = ["analista@ws-analista:~$ openssl x509 -in pki/xmpp-valido.crt -noout -subject -issuer -dates -ext subjectAltName -fingerprint -sha256"] + \
     ["  " + l for l in clean(results["x509_valido"], 12)] + \
     ["", "analista@ws-analista:~$ openssl x509 -in pki/conference-vencido.crt -noout -subject -enddate -checkend 0"] + ["  " + l for l in clean(results["x509_vencido"], 4)] + \
     ["", "analista@ws-analista:~$ openssl verify -CAfile pki/lab-ca.crt pki/xmpp-valido.crt pki/conference-vencido.crt pki/admin-nombre-incorrecto.crt"] + \
     ["  " + l for l in clean(results["verify_cadena"], 6)]
console_shot(f"{FIG}/c10_fig2_certificados_real.png", "analista@ws-analista — inspección de certificados y cadena de confianza (salida real)", L2, kind="bash", width=1500, wm="SALIDA REAL OPENSSL · CERTIFICADOS DE LABORATORIO · USO ACADÉMICO")

# ---------------- PCAP sintético: XMPP c2s con STARTTLS y un cliente heredado sin TLS
BASE_T = LAB_DAY.replace(hour=17)
SRV = "192.168.50.30"
P = Pcap(f"{EVID}/C10_xmpp_starttls_lab.pcap")
def conv(t, cli, msgs):
    sp = random.randint(49152, 65000); cs = random.getrandbits(32); ss = random.getrandbits(32)
    P.add(ts_of(t, BASE_T), cli, SRV, tcp(cli, SRV, sp, 5222, F["SYN"], cs)); P.add(ts_of(t+.0003, BASE_T), SRV, cli, tcp(SRV, cli, 5222, sp, F["SYN"] | F["ACK"], ss, cs+1))
    cs += 1; ss += 1; P.add(ts_of(t+.0006, BASE_T), cli, SRV, tcp(cli, SRV, sp, 5222, F["ACK"], cs, ss)); t += .001
    for who, pl in msgs:
        t += random.uniform(0.002, 0.05)
        if who == "c": P.add(ts_of(t, BASE_T), cli, SRV, tcp(cli, SRV, sp, 5222, F["PSH"] | F["ACK"], cs, ss, pl)); cs += len(pl)
        else: P.add(ts_of(t, BASE_T), SRV, cli, tcp(SRV, cli, 5222, sp, F["PSH"] | F["ACK"], ss, cs, pl)); ss += len(pl)
    P.add(ts_of(t+.01, BASE_T), cli, SRV, tcp(cli, SRV, sp, 5222, F["FIN"] | F["ACK"], cs, ss)); P.add(ts_of(t+.011, BASE_T), SRV, cli, tcp(SRV, cli, 5222, sp, F["FIN"] | F["ACK"], ss, cs+1))
def rec(ct, n): return bytes([ct, 3, 3]) + n.to_bytes(2, "big") + bytes(random.getrandbits(8) for _ in range(n))
hdr_c = b"<?xml version='1.0'?><stream:stream to='lab.test' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
hdr_s = b"<?xml version='1.0'?><stream:stream id='a91f' from='lab.test' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
feat = b"<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"
ok = [("c", hdr_c), ("s", hdr_s + feat), ("c", b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"), ("s", b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"),
      ("c", b"\x16\x03\x01\x01\x20" + bytes(random.getrandbits(8) for _ in range(288))), ("s", b"\x16\x03\x03\x00\x7a" + bytes(random.getrandbits(8) for _ in range(122)) + rec(0x14, 1) + rec(0x17, 1100)),
      ("c", rec(0x14, 1) + rec(0x17, 74)), ("c", rec(0x17, 210)), ("s", rec(0x17, 380)), ("c", rec(0x17, 160)), ("s", rec(0x17, 96))]
legacy = [("c", hdr_c), ("s", hdr_s + feat), ("c", b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>[ANONIMIZADO]</auth>"),
          ("s", b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><encryption-required/></failure></stream:stream>")]
conv(1.0, "192.168.50.101", ok); conv(4.0, "192.168.50.108", ok); conv(9.0, "192.168.50.119", legacy)
P.write()
pk = read_pcap(P.path); t0 = ts_of(0, BASE_T)
wr = []
for p in pk:
    pl = p["payload"]
    if not pl: info = f"{p['sport']} → {p['dport']} [{', '.join(n for n, v in F.items() if p['flags'] & v)}]"; proto = "TCP"; col = "tcp"
    elif pl[:1] in (b"\x16", b"\x14", b"\x17"):
        proto = "TLSv1.3"; col = "tls"
        info = {0x16: "Client Hello (SNI=xmpp.lab.test)" if p["dport"] == 5222 else "Server Hello, Change Cipher Spec, Application Data", 0x14: "Change Cipher Spec, Application Data", 0x17: "Application Data"}[pl[0]]
    else:
        proto = "XMPP/XML"; s = pl.decode(errors="replace"); col = "http"
        info = ("STREAM > lab.test" if s.startswith("<?xml") and p["dport"] == 5222 else "STREAM < lab.test; FEATURES: starttls (required)" if s.startswith("<?xml") else
                "STARTTLS" if "<starttls" in s else "PROCEED" if "<proceed" in s else "AUTH (PLAIN) sin TLS" if "<auth" in s else "FAILURE encryption-required" if "<failure" in s else s[:60])
        if "AUTH" in info or "FAILURE" in info: col = "bad"
    wr.append(dict(no=p["no"], time=f"{p['ts']-t0:.6f}", src=p["src"], dst=p["dst"], proto=proto, len=p["len"], info=info, color=col))
wireshark_shot(f"{FIG}/c10_fig3_wireshark_xmpp.png", "C10_xmpp_starttls_lab.pcap", "tcp.port == 5222", wr[:40],
               details=["Antes de <proceed/> sólo viajan cabeceras de stream y features (metadatos). Después, todo es TLS Application Data: el contenido NO es legible.",
                        "Metadatos que SÍ se observan: IP/puertos, SNI, tamaños, tiempos y frecuencia de mensajes → TLS no oculta el patrón de comunicación.",
                        "Cliente .119 (heredado) intenta SASL PLAIN sin TLS → el servidor responde <encryption-required/> (starttls_required: true funcionando)."],
               status=f"Paquetes: {len(pk)} · Mostrados: {min(40, len(wr))}")

# ---------------- revisión de configuración y logs de ejabberd (laboratorio)
cfg = ["analista@xmpp-lab:~$ sudo grep -nE 'port:|module:|starttls|tls|protocol_options|ciphers|certfiles|ip:|request_handlers|/admin' /opt/ejabberd/conf/ejabberd.yml",
       "  12: certfiles:", "  13:   - /opt/ejabberd/conf/certs/xmpp.lab.test.pem", ("  14:   - /opt/ejabberd/conf/certs/conference.lab.test.pem     ← VENCIDO 30-sep-2026", (255, 150, 150)),
       "  31:   -", "  32:     port: 5222", "  33:     ip: \"0.0.0.0\"", "  34:     module: ejabberd_c2s", ("  36:     starttls_required: true", (150, 230, 150)),
       ("  37:     protocol_options: ['no_sslv2','no_sslv3','no_tlsv1','no_tlsv1_1','cipher_server_preference']", (150, 230, 150)),
       "  38:     ciphers: \"ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!SHA1\"", "  45:   -", "  46:     port: 5269", "  48:     module: ejabberd_s2s_in",
       "  52:   -", "  53:     port: 5280", ("  54:     ip: \"0.0.0.0\"                                         ← interfaz admin expuesta a toda la LAN", (255, 150, 150)),
       "  55:     module: ejabberd_http", ("  56:     tls: false                                             ← sin TLS en /admin", (255, 150, 150)), "  58:     request_handlers:", "  60:       /admin: ejabberd_web_admin",
       "  88: s2s_use_starttls: required", "", "analista@xmpp-lab:~$ sudo grep -E 'TLS|certificate|Failed c2s|admin' /opt/ejabberd/logs/ejabberd.log | tail -7",
       "2026-11-05 17:00:01.118 [info] (<0.912.0>) Accepted c2s SASL SCRAM-SHA-256 authentication for estudiante01@lab.test from ::ffff:192.168.50.101",
       "2026-11-05 17:00:09.342 [info] (<0.931.0>) Failed c2s PLAIN authentication: encryption required (::ffff:192.168.50.119)",
       ("2026-11-05 17:02:15.904 [warning] (<0.944.0>) Failed to secure s2s/muc connection for conference.lab.test: certificate has expired", (255, 220, 120)),
       ("2026-11-05 17:04:41.270 [info] (<0.960.0>) Failed c2s SCRAM-SHA-256 authentication for admin@lab.test from ::ffff:192.168.50.66", (255, 220, 120)),
       ("2026-11-05 17:04:43.511 [info] (<0.961.0>) Failed c2s SCRAM-SHA-256 authentication for root@lab.test from ::ffff:192.168.50.66", (255, 220, 120)),
       ("2026-11-05 17:05:02.037 [info] (<0.977.0>) Access to /admin/ from ::ffff:192.168.50.66 (HTTP 401)", (255, 220, 120)),
       "2026-11-05 17:06:12.664 [info] (<0.990.0>) Accepted c2s SASL SCRAM-SHA-256 authentication for estudiante02@lab.test from ::ffff:192.168.50.108"]
console_shot(f"{FIG}/c10_fig4_ejabberd_config_log.png", "analista@xmpp-lab — revisión de ejabberd.yml y ejabberd.log (servidor XMPP de laboratorio 192.168.50.30)", cfg, kind="bash", width=1500)
print(len(pk), sha256(P.path))
