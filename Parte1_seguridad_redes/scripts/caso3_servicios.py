"""Caso 3 – Exposición de servicios HTTP, FTP y heredados en el servidor PROPIO 192.168.50.20 (SRV-WEB-LAB).
Inventario del sistema + comprobación autorizada de alcance limitado (solo el host propio, puertos listados).
"""
import random, collections, json, csv
from lib import *
random.seed(21)
style()
SRV = "192.168.50.20"
BASE_T = LAB_DAY.replace(hour=11)

services = [  # puerto, proto, servicio, producto/versión, PID/proceso, escucha, cifrado, soporte, necesidad, propietario
    (21, "TCP", "FTP", "FileZilla Server 0.9.60 beta", "2140 FileZilla Server.exe", "0.0.0.0", "No (texto claro)", "Sin soporte", "Baja – reemplazable por SFTP", "Equipo web"),
    (80, "TCP", "HTTP", "Microsoft IIS 10.0", "4 System (HTTP.sys)", "0.0.0.0", "No", "Soportado", "Media – solo redirección a 443", "Equipo web"),
    (443, "TCP", "HTTPS", "Microsoft IIS 10.0 (TLS 1.2/1.3)", "4 System (HTTP.sys)", "0.0.0.0", "Sí (TLS)", "Soportado", "Alta – servicio principal", "Equipo web"),
    (445, "TCP", "SMB", "Windows Server 2022 SMB 3.1.1 (SMBv1 habilitado)", "4 System", "0.0.0.0", "Parcial", "SMBv1 obsoleto", "Baja – sin recursos compartidos en uso", "Infraestructura"),
    (3389, "TCP", "RDP", "Terminal Services (NLA activo)", "1188 svchost.exe (TermService)", "0.0.0.0", "Sí (TLS/CredSSP)", "Soportado", "Media – solo administración", "Infraestructura"),
    (3306, "TCP", "MySQL", "MySQL Community 5.7.44", "2876 mysqld.exe", "0.0.0.0", "No", "Sin soporte (EOL 10/2023)", "Media – BD local de la app", "Equipo web"),
    (5985, "TCP", "WinRM-HTTP", "Microsoft HTTPAPI 2.0", "4 System", "0.0.0.0", "Cifrado de mensaje (Kerberos/NTLM)", "Soportado", "Media – administración remota", "Infraestructura"),
    (8080, "TCP", "HTTP-alt", "Apache Tomcat 9.0.x (/manager/html expuesto)", "3312 tomcat9.exe", "0.0.0.0", "No", "Soportado (rama 9)", "Baja – entorno de pruebas olvidado", "Equipo web"),
    (161, "UDP", "SNMP", "SNMP v2c (community 'public')", "1720 snmp.exe", "0.0.0.0", "No", "Protocolo débil", "Baja – monitoreo no configurado", "Infraestructura"),
]

# ---- pantallazo: inventario con PowerShell
ps = ["PS C:\\> Get-NetTCPConnection -State Listen | ? LocalAddress -eq '0.0.0.0' |",
      ">>   Select LocalAddress,LocalPort,OwningProcess,@{n='Proceso';e={(Get-Process -Id $_.OwningProcess).ProcessName}} |",
      ">>   Sort LocalPort | Format-Table -AutoSize", "",
      "LocalAddress LocalPort OwningProcess Proceso", "------------ --------- ------------- -------"]
for s in services:
    if s[1] == "TCP":
        pid, proc = s[4].split(" ", 1)
        ps.append(f"0.0.0.0      {s[0]:<9} {pid:<13} {proc.split(' (')[0].replace('.exe','')}")
ps += ["0.0.0.0      49664     684           lsass", "0.0.0.0      49665     540           wininit", "",
       "PS C:\\> Get-NetUDPEndpoint -LocalPort 161 | Select LocalAddress,LocalPort,OwningProcess",
       "LocalAddress LocalPort OwningProcess", "------------ --------- -------------", "0.0.0.0      161       1720", "",
       "PS C:\\> Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select FeatureName,State",
       "FeatureName  State", "-----------  -----", ("SMB1Protocol Enabled     ← protocolo obsoleto habilitado", (255, 220, 120)), "",
       "PS C:\\> Get-Service FileZilla*,MySQL*,Tomcat*,SNMP | Select Name,Status,StartType",
       "Name                  Status  StartType", "----                  ------  ---------",
       "FileZilla Server      Running Automatic", "MySQL57               Running Automatic", "Tomcat9               Running Automatic", "SNMP                  Running Automatic"]
console_shot(f"{FIG}/c3_fig1_inventario_ps.png", "Administrador: Windows PowerShell — SRV-WEB-LAB (192.168.50.20) — inventario de servicios", ps, kind="powershell", width=1350)

# ---- pantallazo: comprobación autorizada de alcance limitado (solo host propio, puertos inventariados)
nm = ["analista@ws-analista:~$ # Autorización: acta LAB-02 del 05/11/2026 · objetivo único 192.168.50.20 · ventana 11:00–11:30",
      "analista@ws-analista:~$ nmap -sT -sV -Pn -p 21,80,443,445,3389,3306,5985,8080 --max-rate 50 192.168.50.20",
      "Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-05 11:04 -05",
      "Nmap scan report for srv-web-lab.lab.test (192.168.50.20)", "Host is up (0.00031s latency).", "",
      "PORT     STATE SERVICE       VERSION",
      "21/tcp   open  ftp           FileZilla ftpd 0.9.60 beta",
      "80/tcp   open  http          Microsoft IIS httpd 10.0",
      "443/tcp  open  ssl/http      Microsoft IIS httpd 10.0",
      "445/tcp  open  microsoft-ds?",
      "3306/tcp open  mysql         MySQL 5.7.44",
      "3389/tcp open  ms-wbt-server Microsoft Terminal Services",
      "5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)",
      "8080/tcp open  http          Apache Tomcat 9.0",
      "Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows", "",
      "Service detection performed. Nmap done: 1 IP address (1 host up) scanned in 13.42 seconds", "",
      "analista@ws-analista:~$ sudo nmap -sU -p 161 --script snmp-info 192.168.50.20 | grep -A2 '161/udp'",
      "161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)",
      ("| snmp-info: community 'public' aceptada (lectura)", (255, 220, 120))]
console_shot(f"{FIG}/c3_fig2_nmap_autorizado.png", "analista@ws-analista (192.168.50.10) — comprobación autorizada de alcance limitado", nm, kind="bash", width=1350)

# ---- eventos de autenticación (Visor de eventos: Seguridad 4625 / 4624) + log FileZilla
ev = []
t = 0
users = ["administrador", "admin", "test", "backup", "sql", "usuario", "web", "guest"]
while t < 1800:  # 11:00-11:30
    if 600 <= t < 1260:  # intentos repetidos desde .66 contra RDP (tipo 10) y FTP
        t += random.expovariate(0.30)
        svc = random.choice(["RDP", "RDP", "FTP"])
        ev.append((t, 4625 if svc == "RDP" else "FTP-530", "192.168.50.66", random.choice(users), svc, "0xC000006A" if random.random() < .3 else "0xC0000064"))
    else:
        nt = t + random.expovariate(1/90)
        if t < 600 <= nt: t = 600; continue
        t = nt
        ev.append((t, 4624, "192.168.50.10", "adm-lab", "RDP", "-"))
        if random.random() < 0.15: ev.append((t+3, 4625, "192.168.50.10", "adm-lab", "RDP", "0xC000006A"))
ev.append((1300, "FTP-230", "192.168.50.112", "anonymous", "FTP", "login anónimo aceptado"))
ev.sort()
with open(f"{EVID}/C3_eventos_autenticacion.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["hora_local", "evento", "ip_origen", "cuenta", "servicio", "estado/substatus"])
    for e in ev: w.writerow([fmt_local(ts_of(e[0], BASE_T)), *e[1:]])
fails = [e for e in ev if e[1] in (4625, "FTP-530")]
print("fallidos", len(fails), "desde .66", sum(1 for e in fails if e[2] == "192.168.50.66"), "cuentas", collections.Counter(e[3] for e in fails if e[2]=="192.168.50.66").most_common(8))

fig, ax = plt.subplots(figsize=(11, 3.6))
bins = range(0, 1801, 60)
for src, c in [("192.168.50.66", "#c0392b"), ("192.168.50.10", "#2471a3")]:
    cnt = [sum(1 for e in fails if e[2] == src and b <= e[0] < b+60) for b in bins[:-1]]
    ax.bar([b/60 + (0.2 if src.endswith('10') else -0.2) for b in bins[:-1]], cnt, width=0.4, color=c, label=f"fallidos desde {src}")
ok = [sum(1 for e in ev if e[1] == 4624 and b <= e[0] < b+60) for b in bins[:-1]]
ax.plot([b/60 for b in bins[:-1]], ok, color="#1e8449", marker="o", ms=3, label="4624 exitosos (adm-lab)")
ax.axhline(10, ls="--", color="#7d3c98"); ax.text(0.2, 10.6, "umbral propuesto: >10 fallos/min por origen", fontsize=8, color="#7d3c98")
ax.set_xlabel("minuto desde 11:00 (UTC-5)"); ax.set_ylabel("eventos / minuto"); ax.legend(fontsize=8, ncol=3, loc="upper left")
ax.set_title("Caso 3 · Autenticación en SRV-WEB-LAB: eventos 4625 (RDP) y respuestas 530 (FTP)")
ax.set_ylim(0, 30)
save_fig(fig, "c3_fig3_autenticacion.png")

# ---- pantallazo Visor de eventos (tabla)
rows = []
for e in [e for e in ev if e[2] == "192.168.50.66"][:12] + [e for e in ev if e[1] == "FTP-230"]:
    if e[1] == 4625: rows.append([fmt_local(ts_of(e[0], BASE_T))[11:19], "4625", "Microsoft-Windows-Security-Auditing", "Error de inicio de sesión", f"Tipo 10 · {e[3]} · {e[2]} · {e[5]}"])
    elif e[1] == "FTP-530": rows.append([fmt_local(ts_of(e[0], BASE_T))[11:19], "FTP", "FileZilla Server.log", "530 Login or password incorrect!", f"USER {e[3]} · {e[2]}"])
    else: rows.append([fmt_local(ts_of(e[0], BASE_T))[11:19], "FTP", "FileZilla Server.log", "230 Logged on", f"USER anonymous · {e[2]}"])
table_shot(f"{FIG}/c3_fig4_visor_eventos.png", "Visor de eventos ▸ Registros de Windows ▸ Seguridad (filtro: Id. 4625) + FileZilla Server.log",
           ["Hora", "Id.", "Origen", "Descripción", "Detalle (cuenta · IP · substatus)"], rows, colw=[100, 70, 330, 320, 500],
           highlight=lambda r: "230" in r[3])

# ---- PCAP: sesión FTP en texto claro (evidencia de credenciales expuestas; contraseña de prueba anonimizada)
P = Pcap(f"{EVID}/C3_ftp_texto_claro.pcap")
cli = "192.168.50.112"; sp = 51544; t = 1300.0; cs, ss = 1000, 5000
def seg(src, dst, a, b, fl, s, k, pl=b""):
    P.add(ts_of(t, BASE_T), src, dst, tcp(src, dst, a, b, fl, seq=s, ack=k, payload=pl, ttl=128))
seg(cli, SRV, sp, 21, F["SYN"], cs, 0); t += .0003
seg(SRV, cli, 21, sp, F["SYN"] | F["ACK"], ss, cs+1); t += .0003
seg(cli, SRV, sp, 21, F["ACK"], cs+1, ss+1); cs += 1; ss += 1
dialog = [(SRV, b"220-FileZilla Server 0.9.60 beta\r\n220 SRV-WEB-LAB FTP\r\n"), (cli, b"USER usuario.prueba\r\n"), (SRV, b"331 Password required for usuario.prueba\r\n"),
          (cli, b"PASS ********\r\n"), (SRV, b"530 Login or password incorrect!\r\n"), (cli, b"USER anonymous\r\n"), (SRV, b"331 Password required for anonymous\r\n"),
          (cli, b"PASS lab@lab.test\r\n"), (SRV, b"230 Logged on\r\n"), (cli, b"PWD\r\n"), (SRV, b'257 "/" is current directory.\r\n'), (cli, b"QUIT\r\n"), (SRV, b"221 Goodbye\r\n")]
wrows = []
for src, pl in dialog:
    t += random.uniform(0.01, 0.3)
    if src == SRV: seg(SRV, cli, 21, sp, F["PSH"] | F["ACK"], ss, cs, pl); ss += len(pl)
    else: seg(cli, SRV, sp, 21, F["PSH"] | F["ACK"], cs, ss, pl); cs += len(pl)
P.write()
pk = read_pcap(P.path)
for p in pk:
    if p["payload"]:
        txt = p["payload"].decode().strip().replace("\r\n", " | ")
        wrows.append(dict(no=p["no"], time=f"{p['ts']-ts_of(1300, BASE_T):.6f}", src=p["src"], dst=p["dst"], proto="FTP", len=p["len"],
                          info=("Request: " if p["dport"] == 21 else "Response: ") + txt, color="bad" if "PASS" in txt else "tcp"))
wireshark_shot(f"{FIG}/c3_fig5_wireshark_ftp.png", "C3_ftp_texto_claro.pcap", "ftp", wrows,
               details=["Seguir ▸ Flujo TCP (tcp.stream eq 0): usuario y contraseña viajan legibles; la contraseña real se reemplazó por ******** (anonimización)",
                        "Inicio de sesión anónimo aceptado (230) → configuración por defecto insegura · Banner revela producto y versión sin soporte"],
               status=f"Paquetes: {len(pk)} · Mostrados: {len(wrows)}")

# ---- matriz riesgo / criticidad
prob = {"FTP": 4, "HTTP": 2, "HTTPS": 1, "SMB": 3, "RDP": 4, "MySQL": 3, "WinRM-HTTP": 2, "HTTP-alt": 4, "SNMP": 3}
imp = {"FTP": 4, "HTTP": 2, "HTTPS": 3, "SMB": 5, "RDP": 5, "MySQL": 5, "WinRM-HTTP": 4, "HTTP-alt": 5, "SNMP": 3}
fig, ax = plt.subplots(figsize=(8.5, 6.8))
import numpy as np
grid = np.array([[i*j for i in range(1, 6)] for j in range(1, 6)])
ax.imshow(grid, origin="lower", cmap="RdYlGn_r", alpha=.55, extent=[0.5, 5.5, 0.5, 5.5])
placed = collections.Counter()
for s in services:
    k = s[2]; x, y = prob[k], imp[k]; o = placed[(x, y)]; placed[(x, y)] += 1
    yy = y + 0.25 - o*0.3
    ax.scatter(x - 0.42, yy, s=30, color="black")
    ax.text(x - 0.35, yy, f"{k}\n{s[0]}/{s[1].lower()} · R={prob[k]*imp[k]}", fontsize=7, va="center", linespacing=0.9)
ax.set_xticks(range(1, 6)); ax.set_yticks(range(1, 6))
ax.set_xticklabels(["1 Rara", "2 Improb.", "3 Posible", "4 Probable", "5 Casi segura"], fontsize=8)
ax.set_yticklabels(["1 Mínimo", "2 Menor", "3 Moderado", "4 Mayor", "5 Crítico"], fontsize=8)
ax.set_xlabel("Probabilidad de explotación"); ax.set_ylabel("Impacto (C-I-D)"); ax.grid(False)
ax.set_title("Caso 3 · Matriz riesgo/criticidad de servicios expuestos")
save_fig(fig, "c3_fig6_matriz_riesgo.png")
json.dump([dict(puerto=s[0], proto=s[1], servicio=s[2], producto=s[3], proceso=s[4], cifrado=s[6], soporte=s[7], necesidad=s[8], propietario=s[9],
                prob=prob[s[2]], impacto=imp[s[2]], riesgo=prob[s[2]]*imp[s[2]]) for s in services], open(f"{WORK}/C3_inventario.json", "w"), indent=1, ensure_ascii=False)
for s in services: print(s[0], s[2], prob[s[2]]*imp[s[2]])
