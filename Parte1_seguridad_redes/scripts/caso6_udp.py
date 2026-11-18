"""Caso 6 – UDP: reflexión/amplificación DNS, NTP, SSDP.
Por regla del taller NO se genera tráfico de amplificación: se usan CONTADORES AGREGADOS SIMULADOS por segundo
en la interfaz LAN del gateway (192.168.50.1), 10 minutos. Reflectores con direcciones de documentación RFC 5737.
Ráfaga legítima: arranque de 30 VM del laboratorio (DNS/NTP simétrico) en el minuto 1.
Patrón de reflexión: respuestas NO solicitadas hacia 192.168.50.20 en minutos 4–7.
"""
import numpy as np, pandas as pd, json
from lib import *
style()
rng = np.random.default_rng(66)
sec = np.arange(600)
ts = pd.date_range("2026-11-05 14:00:00", periods=600, freq="s", tz="America/Bogota")
rows = []
def add(proto, direction, pps, size_mu, size_sd):
    p = rng.poisson(pps)
    b = p * np.clip(rng.normal(size_mu, size_sd, len(sec)), 60, 1500)
    rows.append(pd.DataFrame({"ts": ts, "protocolo": proto, "sentido": direction, "paquetes": p, "bytes": b.astype(int)}))
# base
add("DNS", "solicitud", np.full(600, 18.0), 78, 8); add("DNS", "respuesta", np.full(600, 18.0), 130, 20)
add("NTP", "solicitud", np.full(600, 0.5), 90, 0); add("NTP", "respuesta", np.full(600, 0.5), 90, 0)
add("SSDP", "solicitud", np.full(600, 0.2), 175, 10); add("SSDP", "respuesta", np.full(600, 0.1), 320, 20)
df = pd.concat(rows)
def bump(proto, direction, s0, s1, pps, size_mu, size_sd):
    m = (df.protocolo == proto) & (df.sentido == direction) & (df.ts >= ts[s0]) & (df.ts < ts[s1])
    n = m.sum(); p = rng.poisson(pps, n)
    df.loc[m, "paquetes"] += p
    df.loc[m, "bytes"] += (p * np.clip(rng.normal(size_mu, size_sd, n), 60, 1500)).astype(int)
# ráfaga legítima (arranque de VMs): simétrica
bump("DNS", "solicitud", 60, 120, 140, 78, 8); bump("DNS", "respuesta", 60, 120, 140, 130, 20)
bump("NTP", "solicitud", 60, 90, 30, 90, 0); bump("NTP", "respuesta", 60, 90, 30, 90, 0)
# reflexión: respuestas no solicitadas grandes
bump("DNS", "respuesta", 240, 420, 900, 1450, 40)    # respuestas ANY/TXT grandes (fragmentadas)
bump("NTP", "respuesta", 255, 400, 600, 468, 2)      # 'monlist' (mode 7) 482 B típicos
bump("SSDP", "respuesta", 270, 410, 450, 330, 25)    # respuestas M-SEARCH
df.to_csv(f"{EVID}/C6_contadores_udp_gateway.csv", index=False)

piv = df.pivot_table(index="ts", columns=["protocolo", "sentido"], values=["paquetes", "bytes"], aggfunc="sum")
# ----- figura pps y Mbps
fig, ax = plt.subplots(2, 1, figsize=(12, 6.6), sharex=True)
cols = {"DNS": "#2471a3", "NTP": "#c0392b", "SSDP": "#7d3c98"}
m = (sec)/60
for pr in ["DNS", "NTP", "SSDP"]:
    ax[0].plot(m, piv[("paquetes", pr, "respuesta")].values, color=cols[pr], lw=1, label=f"{pr} respuestas")
    ax[0].plot(m, piv[("paquetes", pr, "solicitud")].values, color=cols[pr], lw=1, ls=":", label=f"{pr} solicitudes")
    ax[1].plot(m, piv[("bytes", pr, "respuesta")].values*8/1e6, color=cols[pr], lw=1, label=f"{pr} respuestas")
    ax[1].plot(m, piv[("bytes", pr, "solicitud")].values*8/1e6, color=cols[pr], lw=1, ls=":")
for a in ax:
    a.axvspan(1, 2, color="#eafaf1", zorder=0); a.axvspan(4, 7, color="#fdedec", zorder=0)
ax[0].set_ylim(0, 1250)
ax[0].text(1.5, 1100, "arranque de 30 VM\n(legítimo, simétrico)", ha="center", fontsize=8)
ax[0].text(5.5, 1100, "respuestas no solicitadas\n(patrón de reflexión)", ha="center", fontsize=8)
ax[0].set_ylabel("paquetes / s"); ax[0].legend(ncol=3, fontsize=7.5, loc="center left")
ax[1].set_ylabel("Mbit/s"); ax[1].set_xlabel("minuto desde 14:00 (UTC-5) · interfaz LAN del gateway 192.168.50.1")
ax[0].set_title("Caso 6 · Volumen UDP por protocolo y sentido (contadores agregados simulados)")
save_fig(fig, "c6_fig1_pps_bps.png")

# ----- asimetría bytes respuesta / bytes solicitud por minuto
dfm = df.assign(minuto=df.ts.dt.minute).groupby(["minuto", "protocolo", "sentido"])["bytes"].sum().unstack("sentido")
dfm["ratio"] = dfm["respuesta"] / dfm["solicitud"]
ratio = dfm["ratio"].unstack("protocolo")
fig, a = plt.subplots(figsize=(11, 3.8))
w = 0.27
for i, pr in enumerate(["DNS", "NTP", "SSDP"]):
    a.bar(np.arange(10) + (i-1)*w, ratio[pr].values, width=w, color=cols[pr], label=pr)
a.set_yscale("log"); a.axhline(5, ls="--", color="#555"); a.text(-0.4, 5.6, "umbral propuesto: ratio bytes resp/sol > 5 durante 60 s", fontsize=8)
a.set_xticks(range(10)); a.set_xticklabels([f"14:0{i}" for i in range(10)]); a.set_ylabel("bytes respuesta / bytes solicitud (log)")
a.set_title("Caso 6 · Asimetría petición/respuesta por minuto y protocolo"); a.legend(fontsize=8)
save_fig(fig, "c6_fig2_asimetria.png")

# ----- top orígenes (reflectores) durante 14:04-14:07 (simulado; RFC 5737)
refl = []
for pr, port, n in [("DNS", 53, 38), ("NTP", 123, 24), ("SSDP", 1900, 19)]:
    for k in range(n):
        net = rng.choice(["198.51.100", "203.0.113"])
        refl.append((pr, f"{net}.{rng.integers(1,254)}", port))
tot = df[(df.ts >= ts[240]) & (df.ts < ts[420]) & (df.sentido == "respuesta")].groupby("protocolo")[["paquetes", "bytes"]].sum()
summary = {"ventana_reflexion": "14:04:00–14:07:00", "respuestas_por_protocolo": tot.to_dict(),
           "solicitudes_salientes_en_ventana": df[(df.ts >= ts[240]) & (df.ts < ts[420]) & (df.sentido == "solicitud")].groupby("protocolo")["paquetes"].sum().to_dict(),
           "ratio_por_minuto": ratio.round(2).to_dict(), "reflectores_unicos": len(refl)}
json.dump(summary, open(f"{WORK}/C6_resumen.json", "w"), indent=1, ensure_ascii=False, default=str)
print(json.dumps(summary, indent=1, default=str, ensure_ascii=False)[:2500])

# ----- pantallazo: verificación de que los servicios propios NO son reflectores abiertos
L = ["analista@dns-lab:~$ sudo named-checkconf -p | grep -E 'recursion|allow-recursion|allow-query-cache|rate-limit' -A3",
     "        recursion yes;", "        allow-recursion { 127.0.0.1; 192.168.50.0/24; };", "        allow-query-cache { 127.0.0.1; 192.168.50.0/24; };",
     "        rate-limit {", "                responses-per-second 10;", "                window 5;", "        };", "",
     "analista@dns-lab:~$ dig @192.168.50.53 lab.test ANY +norecurse -b 192.168.50.53 | grep -E 'status|MSG SIZE'",
     ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40112", ";; MSG SIZE  rcvd: 212",
     "analista@dns-lab:~$ # desde la interfaz de prueba 'fuera de LAN' (VLAN 99, 10.99.0.5) — simula cliente no autorizado",
     "analista@dns-lab:~$ dig @192.168.50.53 example.test A +recurse -b 10.99.0.5 | grep status",
     (";; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 7745      ← recursión denegada a no autorizados", (140, 230, 140)), "",
     "analista@gw-lab:~$ ntpq -c 'rv 0 version' ; grep -E '^(restrict|disable)' /etc/ntpsec/ntp.conf",
     'version="ntpd ntpsec-1.2.3"', "restrict default kod nomodify noquery limited", "restrict 192.168.50.0 mask 255.255.255.0 nomodify",
     "analista@gw-lab:~$ ntpdc -n -c monlist 192.168.50.1",
     ("192.168.50.1: timed out, nothing received   ← ntpsec no implementa mode 7 (monlist): no amplifica", (140, 230, 140)), "",
     "PS C:\\> Get-Service SSDPSRV,upnphost | Select Name,Status,StartType   # SRV-WEB-LAB",
     "Name     Status  StartType", "----     ------  ---------", "SSDPSRV  Stopped Disabled", "upnphost Stopped Disabled"]
console_shot(f"{FIG}/c6_fig3_config_reflectores.png", "Verificación de servicios propios: DNS (BIND 9), NTP (ntpsec en gateway), SSDP (Windows)", L, kind="bash", width=1400)
json.dump(refl, open(f"{WORK}/C6_reflectores.json", "w"))
