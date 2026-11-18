# Informe Técnico – Guía-Taller No. 2: Mecanismos de seguridad para redes IEEE 802.3 con servidores TCP/IP (Parte I)

Nov 17, 2026 · @Brayan Alberto

## Datos generales

| Campo | Detalle |
| --- | --- |
| Universidad | Universidad Distrital Francisco José de Caldas – Ingeniería de Sistemas |
| Asignatura | Fundamentos de redes de comunicaciones |
| Docente | Octavio José Salcedo Parra |
| Guía | Guía–Taller No. 2 – Mecanismos de seguridad para redes IEEE 802.3 con servidores TCP/IP (Parte I) |
| Fecha de publicación / entrega | 26 de octubre de 2026 / 14 de noviembre de 2026 |
| Equipo | \[Integrante 1\] · \[Integrante 2\] · \[Integrante 3\] (completar) |
| Fecha de la práctica | 5 de noviembre de 2026, 09:00–17:30, hora de Colombia (UTC−5) |
| Entorno | VLAN de laboratorio aislada 192.168.50.0/24, sin reenvío a Internet |

**Naturaleza de la evidencia.** Siguiendo las reglas del taller, ninguna actividad de ataque se ejecutó contra sistemas reales. Todo el tráfico de los casos 1–9 proviene de PCAP y telemetría **sintéticos** generados por scripts reproducibles del equipo. Los pantallazos de Wireshark, consola, Visor de eventos, Zeek y Suricata son **vistas reconstruidas** a partir de esos archivos y llevan la marca "EVIDENCIA SIMULADA". La única excepción es el Caso 10: las pruebas TLS con OpenSSL son **salidas reales**, ejecutadas en la interfaz de loopback con certificados de una CA de laboratorio.

**Convenciones.** Las horas son locales (UTC−5). Los orígenes externos usan solo rangos reservados para pruebas y documentación (198.18.0.0/15 – RFC 2544; 198.51.100.0/24 y 203.0.113.0/24 – RFC 5737). Los dominios usan el TLD reservado `.test` (RFC 6761). Las credenciales y datos personales están anonimizados.

## Resumen ejecutivo

El hallazgo principal es que el host **192.168.50.66** (VM de estudiante) participa en cinco de los diez casos: resolver DNS no autorizado, fuerza bruta RDP/FTP, inyección de RST, barrido ICMP y escaneo de puertos. La correlación del Caso 9 le asigna puntuación 100/100 (P1) con 80 eventos de 6 familias de fuentes. Se recomienda aislarlo en una VLAN de cuarentena, previa validación humana.

El servidor web **SRV-WEB-LAB (192.168.50.20)** es el activo más expuesto. Tiene 9 servicios escuchando en todas las interfaces con 3 de riesgo ≥ 16/25 (RDP, Tomcat `/manager` y FTP sin soporte) y 2 más en 15 (SMBv1 y MySQL 5.7). La prueba de carga SYN autorizada redujo su tasa de conexiones exitosas del 100 % al 9,2 %. Con SYN cookies y limitación de tasa en el gateway volvió al 100 %.

| Caso | Hallazgo principal (evidencia sintética) | Severidad | Prioridad de acción |
| --- | --- | --- | --- |
| 1 SYN flood | 312 SYN/s frente a 3,9 de base; backlog de 512 lleno; éxito de clientes legítimos 9,2 % | Alta | Inmediata (SYN cookies + hashlimit) |
| 2 DNS tunneling | .44: 952 consultas TXT únicas, 124 car. y 4,83 bits/car. hacia `*.exfil-lab.test`; .66 usa un resolver no autorizado | Alta | Inmediata |
| 3 Servicios expuestos | FTP 0.9.60 con login anónimo, MySQL 5.7 EOL, SMBv1, Tomcat `/manager`; 188 fallos de login desde .66 | Crítica | Inmediata |
| 4 IA/ML | IsolationForest: PR-AUC 0,595 frente a 0,127 de la línea base; 0 falsos positivos con persistencia 2/3 | Informativa | Piloto con revisión humana |
| 5 RST | 154 RST: 147 benignos explicados; 7 con TTL 64 y MAC de .66 (posible inyección) | Alta | Inmediata (DAI/port-security) |
| 6 Reflexión UDP | Ratio respuesta/solicitud hasta 7 393× (SSDP); servicios propios no son reflectores | Media | Coordinar con proveedor |
| 7 ICMP | Barrido de 254 hosts en 6,4 s (.66); túnel ICMP .77↔.250 con payload ≠ eco | Media–Alta | Corto plazo |
| 8 Escaneo | .66: 1 030 puertos en \~8 s + banners; .15 autorizado suprimido; .88 escaneo lento no detectado por umbral | Alta | Inmediata |
| 9 SIEM | 208 eventos → 33 alertas deduplicadas → 10 entidades priorizadas | – | Implementar pipeline |
| 10 XMPP/TLS | TLS 1.3 válido en c2s; certificado de `conference` vencido; `/admin` sin TLS en 0.0.0.0:5280 | Alta | Corto plazo |

Las tres acciones de mayor valor son: contener y analizar forensemente a .66; reducir la superficie de SRV-WEB-LAB (cerrar 21, 8080, 3306 y 161, deshabilitar SMBv1, restringir RDP); y desplegar las 15 reglas de detección propuestas con revisión humana antes de cualquier bloqueo. Ninguna conclusión de este informe se basa en un indicador aislado.

## 1. Alcance, topología y reglas del laboratorio

El alcance es una LAN Ethernet IEEE 802.3 aislada (VLAN 50, 192.168.50.0/24) con servicios IPv4 TCP/IP. Se usa la topología sugerida por la guía, ampliada con los hosts que aparecen en los escenarios sintéticos.

### 1.1 Topología

| Elemento | Dirección / función | Rol en la práctica |
| --- | --- | --- |
| Switch Ethernet IEEE 802.3 | VLAN 50 de laboratorio, puerto espejo (SPAN) hacia el sensor | Sin conexión a la red productiva |
| Gateway de laboratorio | 192.168.50.1/24 (Linux, ntpsec, filtrado) | Sin reenvío a Internet; servidor NTP del laboratorio |
| Equipo analista | 192.168.50.10/24 | Wireshark, acceso a logs, comprobaciones autorizadas |
| Escáner autorizado | 192.168.50.15/24 | Ventana de mantenimiento 16:40–16:50 (ticket MNT-2211) |
| Servidor web/pruebas SRV-WEB-LAB | 192.168.50.20/24 (Windows Server 2022, IIS 10) | Objetivo de los casos 1, 3, 5, 6 y 8 |
| Servidor de mensajería | 192.168.50.30/24 (ejabberd, `xmpp.lab.test`) | Caso 10 |
| Servidor DNS de laboratorio | 192.168.50.53/24 (BIND 9, solo `lab.test`) | Resolver autorizado, caso 2 |
| Resolver no autorizado | 192.168.50.99/24 | Escenario del caso 2 |
| Clientes de laboratorio | 192.168.50.100–.140/24 | Tráfico benigno de línea base |
| Hosts de escenario | .44 (túnel DNS), .66 (VM de estudiante), .77 (túnel ICMP), .88 (escaneo lento), .115 (agente de telemetría) | Generadores de tráfico sintético |
| VM de entrenamiento | 192.168.50.250/24 | Extremo del túnel ICMP didáctico |
| Sensor pasivo | Sin IP en la VLAN 50 (interfaz de captura) | Zeek 7.0 y Suricata 7.0 |

### 1.2 Cumplimiento de las reglas obligatorias

| Regla de la guía | Cómo se cumplió |
| --- | --- |
| Usar solo equipos/VM del grupo en una red aislada | Todo el tráfico es sintético y usa 192.168.50.0/24 o rangos reservados de prueba y documentación. No se envió ningún paquete a terceros. |
| Tráfico benigno o PCAP didácticos/sintéticos | 7 PCAP y 10 archivos de telemetría generados por scripts (Anexo A). No se ejecutaron DoS, exfiltración ni spoofing contra sistemas reales. |
| Sincronizar relojes y registrar fecha, hora, IP, puerto, herramienta y versión | Todos los equipos toman la hora de 192.168.50.1 (NTP). Cada hallazgo de la sección de registro incluye marca temporal con zona, IP, puerto, herramienta y versión. |
| Anonimizar datos personales y credenciales | Contraseñas reemplazadas por `********`, cuentas genéricas (`estudiante01`, `usuario.prueba`) y payloads aleatorios sin datos reales. |
| Copia original + SHA-256; analizar copia de trabajo | `evidencias/original/` (solo lectura) y `evidencias/trabajo/`. Hash verificado idéntico en ambas carpetas (sección 2.3). |

**Nota sobre la redacción de la guía.** La segunda regla dice "Ejecutar DoS, exfiltración, spoofing controlados o ambientes aislados". El equipo la interpretó como **prohibición** ("No ejecutar…"), en coherencia con la sección 6 y con la nota final del documento. Por eso todos los ataques se sustituyeron por PCAP y contadores sintéticos.

### 1.3 Herramientas y versiones

| Herramienta | Versión | Uso | Tipo de ejecución |
| --- | --- | --- | --- |
| Python | 3.13 | Generación de PCAP, análisis y gráficas | Real |
| scikit-learn / pandas / NumPy / matplotlib | 1.9.1 / 3.0.5 / 2.5.3 / 3.11.2 | Caso 4 (IsolationForest), casos 1–9 | Real |
| OpenSSL | 3.0.13 | Caso 10: CA, certificados y pruebas TLS | Real (loopback) |
| Wireshark | 4.4 (referencia) | Filtros de visualización; vistas reconstruidas desde los PCAP | Simulada |
| Zeek / Suricata | 7.0 / 7.0 (referencia) | conn.log, dns.log, weird.log, eve.json | Simulada |
| Windows Server 2022: netstat, PowerShell, Visor de eventos, Defender Firewall | build 20348 | Inventario y logs del servidor | Simulada |
| BIND 9 / ntpsec / ejabberd | 9.18 / 1.2.3 / 24.x (referencia) | DNS, NTP y XMPP de laboratorio | Simulada |
| Nmap | 7.95 | Comprobación autorizada de alcance limitado (caso 3) | Simulada |
| Wazuh (SIEM) | 4.x (referencia) | Pipeline del caso 9 | Diseño + datos sintéticos |

Las versiones marcadas "referencia" son las que el equipo propone para el montaje físico. Deben confirmarse con el docente, como pide la sección 5 de la guía.

## 2. Metodología y cadena de custodia

Cada caso se analizó con la misma cadena de razonamiento. Ningún hallazgo pasa a "evidencia confirmada" sin al menos dos fuentes independientes y sin descartar las alternativas benignas.

### 2.1 De síntoma a evidencia

| Nivel | Definición usada | Ejemplo (Caso 5) |
| --- | --- | --- |
| Síntoma | Lo que percibe el usuario o el servicio | "Las sesiones HTTPS se cortan" |
| Indicador | Hecho medible en PCAP o log | 154 paquetes con `tcp.flags.reset == 1` |
| Hipótesis | Explicación posible, con alternativas benignas | Reinicio de servicio, puerto cerrado, aborto del cliente o inyección |
| Evidencia confirmada | Hipótesis sostenida por varias fuentes y no explicada por las alternativas | 7 RST con TTL 64 y MAC de .66, seguidos de datos legítimos del servidor y confirmados por la tabla CAM del switch |

### 2.2 Procedimiento general

1. Calcular el SHA-256 del archivo original y copiarlo a la carpeta de trabajo.
2. Construir una línea base del tráfico normal (ventana previa o periodo sin incidentes).
3. Aplicar filtros de Wireshark y contar por ventana temporal (segundo, minuto o 60 s).
4. Correlacionar con logs del servidor, firewall, resolver e IDS por IP, puerto y hora.
5. Formular la hipótesis y las alternativas benignas; buscar el dato que las distinga.
6. Proponer controles preventivos, detectivos, correctivos y de recuperación, con su riesgo de falsos positivos.
7. Registrar el hallazgo en el formato mínimo de la sección 7 de la guía.

### 2.3 Inventario de evidencias (cadena de custodia)

Los hashes se calcularon sobre `evidencias/original/` y se verificaron idénticos en `evidencias/trabajo/`. El archivo `SHA256SUMS.txt` permite revalidarlos con `sha256sum -c SHA256SUMS.txt`.

| Evidencia | Caso | Tamaño (bytes) | SHA-256 |
| --- | --- | --- | --- |
| C1\_synflood\_lab.pcap | 1 | 6 683 994 | `58f6887af9ee18e67155dbc8bca5ed9f42e9e373ddd2bcac15f0159cc9355ad7` |
| C1\_conteo\_por\_segundo.csv | 1 | 18 910 | `6daf29e6313cf7c65d1db0ffa54f6c9576f0817d61c2d0936b6f61f21ec5f4a5` |
| C2\_dns\_tunel\_entrenamiento.pcap | 2 | 645 298 | `3839bd493f952a237257c17b5136b5937251a44ae126f663ff5e44c49eaed995` |
| C2\_consultas\_dns.csv | 2 | 291 174 | `f0b4626d00688d4577277fd26114d9a39b2e1931d094167d2263a4585028e470` |
| C3\_ftp\_texto\_claro.pcap | 3 | 1 453 | `58adbe649440b2c19105e473248b7bfc1d7a5fb80864520ea0ec61d3c9230248` |
| C3\_eventos\_autenticacion.csv | 3 | 13 610 | `1131e3b05d3deccdc72c4bde57a30cab21f552e41b623a8e1cc1fcb720bf656c` |
| C4\_dataset\_agregado\_por\_minuto.csv | 4 | 1 583 878 | `5f200443ebd503dd8f82a7e878a3021b8f7bacf3dccaaf1bbe7c435987e65d2a` |
| C5\_tcp\_resets\_lab.pcap | 5 | 2 306 126 | `105d10b8d88c758bfb586bcce687468c3a9095f11d1451a0ffd8a69a14805d1f` |
| C5\_tabla\_rst.csv | 5 | 23 439 | `74d75e02329c6870f709a7c8a29526d53ffe28d22ee3d4f85448cae828387670` |
| C6\_contadores\_udp\_gateway.csv | 6 | 168 323 | `dcc0f3f81046ba72ac7a9c9c4f4e2595e11711cffcca6116e3be1fd664508f5f` |
| C7\_icmp\_lab.pcap | 7 | 1 352 658 | `56a4d0187bef778c2acd4a9bcb59168451a56ec83a1b2b0bf00777d2799589a3` |
| C7\_resumen\_por\_ip.csv | 7 | 717 | `0314e18d9c6cb0bdabf3224e0bb38913a2879f1a6fbeb2fca0746dd4e5149cf4` |
| C8\_escaneo\_autorizado.pcap | 8 | 643 221 | `eabea83477a51430c03539845ac96cea0f01a5fc67d36694246889d15ca8d134` |
| C8\_pfirewall.log | 8 | 392 883 | `1b2df3f13714242930434cc0c59fd6ea89eced798331421834dcf66de6bdd723` |
| C9\_eventos\_normalizados.csv | 9 | 32 585 | `4958aca1ce1b43dcae2db1493f4b995cc4758cf1855487c976cd37753eff78e6` |
| C10\_xmpp\_starttls\_lab.pcap | 10 | 9 404 | `4f37a24016e188d85e2d198ff689c7f5beac74b188bba4d56ff91fad94d7dd7b` |
| C10\_pruebas\_tls\_reales.json | 10 | 2 449 | `9f15398629420eda6bda46df16a8d992b40bfd3cadbc9f84a8fcd985ddd79a84` |

Los PCAP usan formato libpcap clásico (LINKTYPE\_ETHERNET) con checksums IPv4/TCP/UDP/ICMP válidos, así que abren directamente en Wireshark o tcpdump. Al regenerarlos con los scripts del Anexo A, las semillas fijas producen los mismos hashes. La excepción es el JSON del Caso 10: contiene la fecha de ejecución y claves nuevas en cada corrida.

## Caso 1. TCP SYN Flood: indisponibilidad y agotamiento de conexiones

Durante la ráfaga autorizada (09:02–09:05), SRV-WEB-LAB recibió 312 SYN/s frente a 3,9 de línea base. Solo completó el 0,1 % de los handshakes y atendió al 9,2 % de los clientes legítimos. Con SYN cookies y limitación de tasa en el gateway, el servicio volvió al 100 % sin bloquear clientes legítimos.

**Situación.** El servidor web de laboratorio responde lentamente o deja de aceptar conexiones nuevas en el puerto 80.

**Evidencia analizada.** `C1_synflood_lab.pcap`: 92 775 paquetes, 480 s, 09:00:00–09:08:00. Contiene tres fases: línea base (0–120 s), ráfaga de prueba de carga autorizada (120–300 s) y mitigación activa (300–480 s). Los orígenes de la ráfaga pertenecen a 198.18.0.0/15, el rango que la RFC 2544 reserva para pruebas de rendimiento.

### 1.1 Procedimiento ejecutado

1. Filtro de visualización por fase del handshake: `tcp.flags.syn == 1 && tcp.flags.ack == 0` (SYN), `tcp.flags.syn == 1 && tcp.flags.ack == 1` (SYN/ACK) y `tcp.flags == 0x010 && tcp.len == 0 && ip.dst == 192.168.50.20` (ACK final).
2. Conteo por segundo (Estadísticas ▸ Gráfica de E/S con los tres filtros), exportado a `C1_conteo_por_segundo.csv`.
3. En el servidor: `netstat -ano -p tcp | findstr :80` y `Get-NetTCPConnection -LocalPort 80 | Group-Object State` en t = 60 s, 200 s y 400 s. El PID 4 (System) corresponde a HTTP.sys, que atiende IIS.
4. Comparación con la línea base de las 09:00–09:02 y revisión del contador `TCPv4 Connections Failed` y del log del gateway.

### 1.2 Evidencias

&#91;image: Figura 1.1\]

**Figura 1.1.** Gráfica temporal de SYN, SYN/ACK y ACK por segundo, con las conexiones semiabiertas. Los picos de SYN/ACK cada \~21 s son retransmisiones y liberaciones del backlog cuando expiran las entradas.

&#91;image: Figura 1.2\]

**Figura 1.2.** Extracto de Wireshark en t = 200 s: miles de SYN desde orígenes distintos de 198.18.0.0/15, con TTL variable y un solo intento por origen.

&#91;image: Figura 1.3\]

**Figura 1.3.** `netstat -ano` en el servidor durante la ráfaga: 512 entradas en SYN\_RECEIVED, el límite del backlog.

&#91;image: Figura 1.4\]

**Figura 1.4.** Estados de conexión antes, durante y después de la mitigación (PowerShell).

**Tabla de conexiones y comparación antes/después** (calculada desde el PCAP):

| Métrica | Línea base (0–120 s) | Ráfaga (120–300 s) | Con mitigación (300–480 s) |
| --- | --- | --- | --- |
| SYN/s hacia :80 | 3,9 | 312,0 | 43,6 |
| SYN/ACK/s (incl. retransmisiones) | 3,9 | 77,2 | 43,5 |
| ACK de handshake/s | 3,9 | 0,4 | 3,8 |
| Razón ACK/SYN | 1,000 | 0,001 | 0,088 |
| Conexiones semiabiertas (máx.) | 0 | 512 (backlog lleno) | 0 a los 21 s |
| Clientes legítimos atendidos | 466 / 466 (100 %) | 65 / 706 (9,2 %) | 692 / 692 (100 %) |
| Latencia media del handshake legítimo | 1,66 ms | 1,66 ms (los que entran) | 1,61 ms |
| Orígenes únicos | 41 (clientes .100–.140) | 36 733 en 198.18.0.0/15 | Limitados a 20 SYN/s por /24 |

### 1.3 Indicadores observados

| Indicador de la guía | Observado | ¿Se cumple? |
| --- | --- | --- |
| Picos de SYN sin completar el handshake | 312 SYN/s con razón ACK/SYN de 0,001 | Sí |
| Incremento de conexiones pendientes | 512 en SYN\_RECEIVED (0 en línea base) | Sí |
| Muchas fuentes o patrón temporal inusual | 36 733 orígenes, \~1,5 SYN por origen, TTL 52/57/61/64 frente a 128 de los clientes Windows | Sí |

**Hipótesis.** Inundación SYN con orígenes falsificados. Coincide con la prueba de carga autorizada (acta LAB-02).

**Alternativas benignas consideradas.**

- *Avalancha legítima de usuarios (flash crowd):* descartada. Los clientes reales completan el handshake (ACK/SYN ≈ 1) y repiten IPs conocidas.
- *Pérdida de paquetes en la red:* descartada. Generaría retransmisiones del mismo origen, no decenas de miles de orígenes nuevos.
- *Escaneo de puertos:* descartado. Todo el tráfico va a un solo puerto (80).

**Validación.** PCAP (filtros del 1.1), `netstat`/PowerShell en el servidor, contador de rendimiento de Windows y acta de la prueba. Tres fuentes coinciden: la evidencia queda **confirmada como prueba de carga autorizada**. Fuera de esa ventana, el mismo patrón debería tratarse como incidente.

### 1.4 Mitigación y defensa

| Tipo | Control | Responsable | Riesgo de falso positivo |
| --- | --- | --- | --- |
| Preventivo | Windows Server 2022 actualizado. Su protección contra SYN flood viene activa por defecto y no se ajusta por registro desde Vista. | Admin. servidor | Ninguno |
| Preventivo | Exponer solo 443 y redirigir 80; reducir servicios (Caso 3) | Admin. servidor | Bajo |
| Preventivo | Gateway: `tcp_syncookies=1` y `hashlimit` de 20 SYN/s por /24 de origen hacia :80/:443 | Admin. infraestructura | Medio: clientes tras un mismo NAT |
| Detectivo | Regla Suricata `sid:1000101` + alerta Wazuh por `TCPv4 Connections Failed` | SOC | Bajo con umbral sostenido de 10 s |
| Correctivo | Escalar al administrador de infraestructura; activar SYNPROXY o filtrado aguas arriba | Infraestructura / proveedor | Medio |
| Recuperación | Verificar que el backlog se vacía (≤ 21 s) y que el éxito de clientes vuelve a ≥ 99 % | SOC | – |

El gateway solo ve el tráfico que entra desde fuera de la VLAN. Si la ráfaga viniera de la misma subred, se necesitarían controles en el switch (ACL o storm-control).

**Regla y alerta propuestas:**

```
# Suricata (local.rules)
alert tcp any any -> 192.168.50.20 [80,443] (msg:"LAB TCP SYN > 50/s sostenido hacia servidor web"; flags:S,12; \
  threshold: type both, track by_dst, count 500, seconds 10; classtype:attempted-dos; sid:1000101; rev:1;)

# Gateway Linux (mitigación aplicada en la fase 300–480 s)
sysctl -w net.ipv4.tcp_syncookies=1
iptables -A FORWARD -p tcp --syn -d 192.168.50.20 -m multiport --dports 80,443 \
  -m hashlimit --hashlimit-name syn_web --hashlimit-mode srcip --hashlimit-srcmask 24 \
  --hashlimit-above 20/second --hashlimit-burst 40 -j DROP
```

**Validación de la mitigación.** Con la regla activa ningún cliente legítimo fue bloqueado: 692 de 692 conexiones completadas. Los clientes de laboratorio están en la misma VLAN y no atraviesan el gateway.

### 1.5 Preguntas de análisis

**¿Qué recursos mantiene el servidor durante el handshake TCP?** Al recibir un SYN, el servidor crea una entrada en la cola SYN (conexión semiabierta). Esa entrada guarda la 4-tupla, el ISN propio y el del cliente, las opciones negociadas (MSS, SACK, escala de ventana, timestamps) y un temporizador para retransmitir el SYN/ACK. La entrada consume memoria del kernel y un cupo del backlog hasta que llega el ACK o expiran los reintentos (unos 21 s en el escenario). Además, cada SYN/ACK y sus retransmisiones consumen CPU y ancho de banda de salida. Las **SYN cookies** codifican ese estado en el número de secuencia y no guardan nada hasta recibir el ACK. Por eso el backlog dejó de llenarse en la fase mitigada.

**¿Qué falsos positivos pueden producir picos legítimos?**

- Inicio de jornada, inscripciones o publicación de notas: muchas conexiones nuevas, pero con ACK/SYN ≈ 1.
- Reconexión masiva tras un corte, reinicio del balanceador o failover.
- Muchos clientes detrás de un mismo NAT: alta tasa desde una sola IP.
- Pruebas de carga y monitoreo sintético autorizados (deben estar en lista blanca con ventana).
- Aplicaciones que abren conexiones cortas sin keep-alive.
- Retransmisiones de SYN por pérdida en un enlace degradado.

Por eso la regla exige 10 s sostenidos y la decisión se apoya en la razón ACK/SYN y en la diversidad de orígenes y TTL, no solo en el volumen.

## Caso 2. DNS tunneling: posible salida encubierta mediante UDP/53

El host **192.168.50.44** envió 952 consultas TXT, todas distintas, de 124 caracteres de media y 4,83 bits/carácter de entropía. Iban hacia `*.t.exfil-lab.test` entre las 10:05 y las 10:13, a unas 2 por segundo. El patrón corresponde a un túnel DNS que sacó unos 58 KiB del archivo didáctico. Aparte, el host .66 resolvió 25 nombres contra un resolver no autorizado (192.168.50.99).

**Situación.** Hay tráfico DNS con consultas repetitivas y nombres de dominio inusualmente largos.

**Evidencia analizada.** `C2_dns_tunel_entrenamiento.pcap`: 3 852 paquetes, 10:00–10:15, solo dominios de prueba `.test`. También el registro de consultas de BIND en 192.168.50.53. El "archivo" tunelizado son 60 000 bytes pseudoaleatorios sin datos reales.

### 2.1 Procedimiento ejecutado

1. Filtro `udp.port == 53` (3 852 paquetes) y luego `dns`. Se separaron consultas (`dns.flags.response == 0`) de respuestas.
2. Por cada consulta se calculó la longitud del QNAME, la etiqueta más larga y la entropía de Shannon del subdominio (sin el dominio registrable). Se agregó por cliente y por dominio padre (`C2_consultas_dns.csv`).
3. Se comparó contra el log del resolver autorizado con `grep` y `uniq -c` por cliente y dominio, y se buscaron consultas que no pasan por 192.168.50.53.
4. Se revisaron explicaciones legítimas: agentes de telemetría, CDN y antivirus en la nube.

### 2.2 Evidencias

&#91;image: Figura 2.1\]

**Figura 2.1.** Longitud frente a entropía por consulta (izquierda) y consultas por minuto y origen (derecha). Las consultas de .44 forman un grupo aislado: longitud 124, entropía 4,6–5,0.

&#91;image: Figura 2.2\]

**Figura 2.2.** Wireshark con `dns && ip.addr == 192.168.50.44`: consultas TXT con etiquetas base32 de 60 caracteres y un contador de secuencia.

&#91;image: Figura 2.3\]

**Figura 2.3.** Registro de consultas de BIND 9: 952 consultas a `exfil-lab.test`, todas de .44. Ninguna consulta de .66 llega al resolver autorizado.

**Tabla por host y dominio:**

| Origen | Consultas | Nombres únicos | Long. media QNAME | Etiqueta máx. | Entropía media (bits/car.) | % TXT | Resp. media (B) | Resolver | Dominio principal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 192.168.50.44 | 952 (\~119/min activo) | 952 | 124,0 | 60 | 4,83 | 100 | 261,0 | .53 | `t.exfil-lab.test` |
| Estaciones .101–.112 | 919 | 10 | 13,7 | 9 | 2,04 | 0 | 89,7 | .53 | `*.lab.test` |
| 192.168.50.115 | 30 | 19 | 26,5 | 12 | 3,14 | 0 | 102,5 | .53 | `v2.telemetria.lab.test` |
| 192.168.50.66 | 25 | 10 | 13,6 | 9 | 2,02 | 0 | 89,6 | **.99 (no autorizado)** | `*.lab.test` |

### 2.3 Indicadores observados

| Indicador de la guía | Observado en .44 | Comparación |
| --- | --- | --- |
| Subdominios largos o de alta entropía | Etiquetas de 60 car. (límite RFC 1035: 63); 4,83 bits/car. | Estaciones: 9 car., 2,04 bits/car. |
| Alta frecuencia | \~2 consultas/s sostenidas durante 8 min | Estaciones: \~5 consultas/min por host |
| Respuestas o tamaños atípicos | 100 % TXT; respuesta media de 261 B | Estaciones: A/AAAA, 90 B |
| Destinos no habituales | Un único dominio padre con 952 subdominios únicos (1 consulta por nombre) | Estaciones: 10 nombres repetidos |
| Explicación legítima verificada | .115 tiene entropía moderada (3,14) pero longitud corta, 2 consultas/min, registros A e inventario conocido: **agente de telemetría, benigno** | – |

**Hipótesis.** .44 codifica datos en base32 dentro de los subdominios y recibe datos en registros TXT, es decir, un túnel DNS bidireccional. La capacidad observada es 952 × 62,5 B ≈ 59 500 B, coherente con el archivo didáctico de 60 034 B.

**Alternativas benignas consideradas.** Un agente de telemetría o EDR que use etiquetas codificadas: descartado, porque no figura en el inventario de software de .44 y el volumen es 60 veces mayor. Una validación DKIM/SPF o una CDN: descartadas por el tipo TXT único y la secuencia incremental `00000`→`00951`. Para .66 se consideró una configuración DHCP antigua; queda como hipótesis abierta porque .66 aparece en otros casos (ver Caso 9).

**Validación.** El PCAP, el log del resolver y el inventario de hosts coinciden. Siguiendo la guía, antes de bloquear se recomienda investigar el host origen: proceso que emite las consultas (`Get-DnsClientCache`, Sysmon evento 22) y usuario de la sesión.

### 2.4 Mitigación y defensa

| Tipo | Control | Riesgo de falso positivo |
| --- | --- | --- |
| Preventivo | Política de salida: solo 192.168.50.53 puede consultar UDP/TCP 53 hacia fuera. El resto del puerto 53 y DoT (853) se bloquean en el gateway. | Bajo |
| Preventivo | Forzar los resolvers autorizados por DHCP/GPO y bloquear DoH a proveedores no aprobados | Medio: navegadores con DoH activado |
| Detectivo | Registro de consultas en BIND (`querylog yes`) enviado al SIEM | – |
| Detectivo | Reglas `sid:1000201` (QNAME > 52 car. sostenido) y `sid:1000202` (resolver no autorizado) | Medio para la primera: CDN y telemetría requieren lista blanca |
| Correctivo | RPZ en BIND para `exfil-lab.test`, aplicado tras investigar el host | Bajo |
| Recuperación | Revisar qué datos salieron de .44 (reconstruir el base32 desde el PCAP) y rotar credenciales si aplica | – |

```
# Suricata 7 (local.rules)
alert dns $HOME_NET any -> any any (msg:"LAB DNS QNAME largo sostenido (posible tunel)"; dns.query; bsize:>52; \
  threshold: type both, track by_src, count 30, seconds 60; classtype:policy-violation; sid:1000201; rev:1;)
alert udp $HOME_NET any -> ![192.168.50.53] 53 (msg:"LAB DNS hacia resolver no autorizado"; \
  threshold: type limit, track by_src, count 1, seconds 300; classtype:policy-violation; sid:1000202; rev:1;)

# BIND 9 - RPZ (aplicar tras la investigación)
response-policy { zone "rpz.lab.test"; };      # en rpz.lab.test:  *.exfil-lab.test  CNAME .
```

### 2.5 Preguntas de análisis

**¿Por qué el carácter sin conexión de UDP no significa que todo DNS sea malicioso?** UDP no tiene handshake ni estado de sesión por diseño: DNS lo usa porque una consulta y su respuesta caben en un datagrama y así la resolución es rápida y barata. Que no haya conexión facilita falsificar el origen (Caso 6), pero no dice nada sobre la intención de una consulta. En este PCAP, el 51 % de las consultas (974 de 1 926) no pertenecen al túnel y casi todo el tráfico de cualquier red usa DNS sobre UDP. Lo que delata el abuso es el contenido y el patrón, no el transporte.

**¿Qué atributos ayudan a distinguir una anomalía?**

- Longitud del QNAME y de la etiqueta más larga.
- Entropía y proporción de caracteres del alfabeto base32/hex.
- Razón de nombres únicos por dominio padre.
- Distribución de tipos de registro (TXT, NULL, CNAME).
- Volumen y frecuencia por cliente y por dominio.
- Tamaño de las respuestas y tasa de NXDOMAIN.
- Periodicidad de las consultas.
- Resolver usado.
- Reputación y antigüedad del dominio.

Ningún atributo basta por sí solo: .115 supera el umbral de entropía en algunas consultas, pero no el de longitud ni el de volumen.

## Caso 3. Exposición de servicios HTTP, FTP y otros servicios heredados

SRV-WEB-LAB expone 9 servicios en todas las interfaces y 5 de ellos sin cifrado. Tres tienen riesgo ≥ 16/25: RDP (20), Tomcat `/manager` en 8080 (20) y FTP FileZilla 0.9.60 sin soporte con login anónimo (16). Otros dos quedan en 15: SMB con SMBv1 habilitado y MySQL 5.7 sin soporte. Entre las 11:10 y las 11:21, 192.168.50.66 generó 188 fallos de autenticación (118 RDP, 70 FTP) contra 8 cuentas genéricas.

**Situación.** El servidor presenta servicios abiertos que podrían ser innecesarios o estar débilmente configurados.

**Evidencia analizada.** Inventario local del sistema (PowerShell), comprobación autorizada de alcance limitado con Nmap (acta LAB-02: un solo host, 8 puertos TCP + 161/UDP, `--max-rate 50`, 11:04–11:05), registro de Seguridad (4624/4625), `FileZilla Server.log` y `C3_ftp_texto_claro.pcap`.

### 3.1 Procedimiento ejecutado

1. Inventario en el propio servidor: `Get-NetTCPConnection -State Listen`, `Get-NetUDPEndpoint`, `Get-Process`, `Get-Service` y `Get-WindowsOptionalFeature SMB1Protocol`.
2. Comprobación externa autorizada: `nmap -sT -sV -Pn -p 21,80,443,445,3389,3306,5985,8080 --max-rate 50 192.168.50.20` y `nmap -sU -p 161`. Solo contra el host propio, sin scripts intrusivos.
3. Visor de eventos ▸ Seguridad, filtro por ID 4625 y 4624, con tipo de inicio de sesión, cuenta, IP y substatus. Correlación con el log de FileZilla (códigos 530 y 230).
4. Para cada servicio se documentó versión, necesidad operativa, propietario, cifrado y cumplimiento de mínimo privilegio.

### 3.2 Evidencias

&#91;image: Figura 3.1\]

**Figura 3.1.** Inventario de puertos en escucha y servicios desde PowerShell. SMB1Protocol aparece habilitado.

&#91;image: Figura 3.2\]

**Figura 3.2.** Comprobación autorizada con Nmap: versiones expuestas en los banners y comunidad SNMP `public` aceptada.

&#91;image: Figura 3.3\]

**Figura 3.3.** Eventos de autenticación por minuto: ráfaga de 4625 (RDP) y 530 (FTP) desde .66, frente a la actividad normal de `adm-lab` desde .10.

&#91;image: Figura 3.4\]

**Figura 3.4.** Visor de eventos (ID 4625) y log de FileZilla: cuentas probadas, substatus 0xC0000064 (usuario inexistente) y 0xC000006A (contraseña errónea), y el login anónimo aceptado.

&#91;image: Figura 3.5\]

**Figura 3.5.** Sesión FTP en texto claro en Wireshark (Seguir flujo TCP): usuario y contraseña legibles (anonimizados) y login anónimo aceptado.

&#91;image: Figura 3.6\]

**Figura 3.6.** Matriz de riesgo y criticidad (probabilidad × impacto, escala 1–25).

**Inventario de servicios:**

| Puerto | Servicio | Producto / versión | Proceso (PID) | Cifrado | Soporte | Necesidad operativa | Propietario | Riesgo (P×I) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 3389/tcp | RDP | Terminal Services, NLA activo | svchost TermService (1188) | Sí (TLS/CredSSP) | Soportado | Media: solo administración | Infraestructura | 4×5 = **20** |
| 8080/tcp | HTTP-alt | Apache Tomcat 9.0, `/manager/html` expuesto | tomcat9 (3312) | No | Soportado | Baja: entorno de pruebas olvidado | Equipo web | 4×5 = **20** |
| 21/tcp | FTP | FileZilla Server 0.9.60 beta, anónimo habilitado | FileZilla Server (2140) | No | **Sin soporte** | Baja: reemplazable por SFTP | Equipo web | 4×4 = **16** |
| 445/tcp | SMB | SMB 3.1.1 con **SMBv1 habilitado** | System (4) | Parcial | SMBv1 obsoleto | Baja: sin recursos compartidos en uso | Infraestructura | 3×5 = 15 |
| 3306/tcp | MySQL | MySQL Community 5.7.44, escucha en 0.0.0.0 | mysqld (2876) | No | **EOL oct-2023** | Media: BD local de la app | Equipo web | 3×5 = 15 |
| 161/udp | SNMP | v2c, comunidad `public` | snmp (1720) | No | Protocolo débil | Baja: monitoreo no configurado | Infraestructura | 3×3 = 9 |
| 5985/tcp | WinRM-HTTP | Microsoft HTTPAPI 2.0 | System (4) | Cifrado de mensaje (Kerberos/NTLM) | Soportado | Media: administración remota | Infraestructura | 2×4 = 8 |
| 80/tcp | HTTP | IIS 10.0 | System (4) | No | Soportado | Media: solo redirección a 443 | Equipo web | 2×2 = 4 |
| 443/tcp | HTTPS | IIS 10.0, TLS 1.2/1.3 | System (4) | Sí | Soportado | **Alta: servicio principal** | Equipo web | 1×3 = 3 |

**Eventos relevantes:**

| Hora | Fuente | Evento | Origen | Detalle |
| --- | --- | --- | --- | --- |
| 11:10:04–11:21:03 | Seguridad | 118 × 4625 (tipo 10, RDP) | 192.168.50.66 | Cuentas: backup, admin, test, guest, administrador, sql, web, usuario |
| 11:10:24–11:20:58 | FileZilla | 70 × 530 Login incorrect | 192.168.50.66 | Mismas cuentas por FTP |
| 11:21:40 | FileZilla | 230 Logged on (anónimo) | 192.168.50.112 | Configuración por defecto insegura |
| 11:00–11:30 | Seguridad | 12 × 4624 y 3 × 4625 | 192.168.50.10 | `adm-lab`: errores de digitación aislados, benigno |

### 3.3 Indicadores observados

| Indicador de la guía | Observado |
| --- | --- |
| Servicios expuestos sin necesidad | 8080 (pruebas olvidadas), 21, 161 y 445 sin uso; 3306 escucha en todas las interfaces aunque solo lo usa la app local |
| Software sin soporte | FileZilla Server 0.9.60 beta; MySQL 5.7.44 (EOL); protocolo SMBv1 |
| Intentos de autenticación fallidos | 188 desde .66 en 11 min (pico de 23/min), contra 8 cuentas de diccionario |
| Protocolos en texto claro | FTP (credenciales visibles en la Figura 3.5), HTTP 80, MySQL sin TLS, SNMP v2c |
| Configuraciones por defecto | FTP anónimo, comunidad `public`, `/manager/html` de Tomcat accesible |

**Hipótesis.** Intento de adivinación de contraseñas (fuerza bruta de diccionario) desde .66 contra RDP y FTP. No hubo ningún 4624 exitoso desde .66, así que no hay evidencia de acceso.

**Alternativas benignas.** Un script de monitoreo mal configurado o un usuario que olvidó su contraseña: descartados por la rotación de 8 cuentas inexistentes (substatus 0xC0000064) y la tasa sostenida. Los 3 fallos de .10 sí son benignos (`adm-lab` con éxito posterior).

### 3.4 Mitigación y plan de remediación

| # | Acción | Servicio | Plazo | Responsable | Verificación |
| --- | --- | --- | --- | --- | --- |
| 1 | Detener y desinstalar Tomcat de pruebas (o limitar `/manager` a 127.0.0.1 con `RemoteAddrValve`) | 8080 | 24 h | Equipo web | `Test-NetConnection 192.168.50.20 -Port 8080` = False |
| 2 | Restringir RDP a la IP del analista o a una VPN/bastión; NLA + MFA; bloqueo de cuenta tras 10 intentos en 15 min | 3389 | 24 h | Infraestructura | Regla de firewall `Remote Desktop - Admin only` + GPO |
| 3 | Retirar FileZilla 0.9.60 y migrar a SFTP (OpenSSH Server) con cuentas nominales | 21 | 1 semana | Equipo web | 21/tcp cerrado; SFTP con clave |
| 4 | Deshabilitar SMBv1 (`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`) y bloquear 445 desde la LAN de clientes | 445 | 1 semana | Infraestructura | `Get-SmbServerConfiguration` con `EnableSMB1Protocol False` |
| 5 | MySQL: `bind-address=127.0.0.1`, actualizar a 8.4 LTS, TLS obligatorio y usuario de la app con mínimo privilegio | 3306 | 2 semanas | Equipo web | 3306 no visible desde .10 |
| 6 | Desinstalar SNMP o migrar a SNMPv3 authPriv | 161 | 1 semana | Infraestructura | `snmpwalk -c public` sin respuesta |
| 7 | WinRM solo por HTTPS (5986) y solo desde la red de administración | 5985 | 2 semanas | Infraestructura | Listener HTTP eliminado |
| 8 | HTTP 80 solo con redirección 301 a HTTPS y HSTS | 80/443 | 1 semana | Equipo web | `curl -I` devuelve 301 |
| 9 | Ciclo mensual de parches y revisión trimestral de este inventario | Todos | Continuo | Ambos | Este informe como línea base |

Detección propuesta: regla Wazuh/SIEM `LAB-AUTH-01`, que alerta con más de 10 eventos 4625 o 530 por origen en 60 s o con 5 o más cuentas distintas por origen en 10 min (sección de reglas).

### 3.5 Preguntas de análisis

**¿Cómo se prioriza un puerto abierto?** Con riesgo = probabilidad × impacto, ajustado por necesidad operativa. La probabilidad sube si el puerto es alcanzable desde redes no confiables, si el software no tiene soporte o tiene vulnerabilidades conocidas, si viaja en texto claro, si conserva configuración por defecto y si ya hay intentos en los logs (como en RDP y FTP aquí). El impacto depende de qué se obtiene al comprometerlo: ejecución remota (Tomcat `/manager`), control administrativo (RDP, WinRM) o datos (MySQL). Un servicio con riesgo alto y necesidad baja se cierra primero, porque cerrarlo cuesta poco. Por eso 8080 y 21 van antes que 443, aunque 443 sea el servicio más expuesto.

**¿Qué diferencia hay entre exposición, vulnerabilidad y explotación?**

- **Exposición:** el servicio es alcanzable, por ejemplo 3306 abierto en 0.0.0.0. Es una condición de superficie de ataque, no un fallo en sí.
- **Vulnerabilidad:** una debilidad concreta que puede aprovecharse, como el login anónimo de FTP, una versión sin parches o la comunidad `public`.
- **Explotación:** el uso efectivo de esa debilidad para violar confidencialidad, integridad o disponibilidad, por ejemplo iniciar sesión y leer archivos.

En este caso hay exposición y vulnerabilidades confirmadas, e intentos de explotación (fuerza bruta) sin éxito demostrado. El inicio anónimo de .112 aprovechó una vulnerabilidad de configuración, pero sin evidencia de daño.

## Caso 4. Detección de anomalías con IA/ML en tráfico TCP/IP

Un IsolationForest con 8 características agregadas por minuto supera ampliamente a la línea base estadística. Alcanza PR-AUC de 0,595 frente a 0,127 y precisión de 0,855 frente a 0,076. Su recall, 0,391 con la regla de persistencia, es todavía insuficiente para usarlo solo. El modelo no confundió el aumento legítimo de carga con un ataque; la línea base sí, con 120 falsos positivos. Se propone como priorizador de alertas con revisión humana, nunca como bloqueador automático.

**Situación.** Se pide proponer una defensa inteligente que identifique desviaciones frente al tráfico normal.

### 4.1 Conjunto de datos y atributos

`C4_dataset_agregado_por_minuto.csv` contiene 10 080 minutos (29-oct a 4-nov-2026) de tráfico sintético de SRV-WEB-LAB, con patrón diurno y de fin de semana. Los escenarios anómalos se inyectaron con los mismos patrones de los casos 1, 2, 5 y 8. Las etiquetas solo se usan para evaluar, nunca para entrenar.

| Atributo | Definición (por minuto) | Transformación |
| --- | --- | --- |
| `conexiones_min` | Conexiones TCP nuevas hacia el servidor | log1p + estandarización |
| `bytes_por_flujo` | Bytes medios por flujo (ambos sentidos) | log1p + estandarización |
| `duracion_media_s` | Duración media de los flujos cerrados | estandarización |
| `ratio_syn_sin_ack` | SYN sin handshake completo / SYN totales | estandarización |
| `ratio_rst` | Flujos terminados con RST / flujos totales | estandarización |
| `ratio_pet_resp` | Bytes cliente→servidor / bytes servidor→cliente | log1p + estandarización |
| `puertos_dst_unicos` | Puertos de destino distintos contactados | log1p + estandarización |
| `long_media_qname` | Longitud media de los QNAME consultados | estandarización |

**Partición sin fuga de información.** La separación es temporal, sin barajar. Entrenamiento: 29-oct a 2-nov (7 200 min), con 21 minutos de ruido anómalo sin etiquetar, como en datos reales nunca perfectamente limpios. Evaluación: 3 y 4-nov (2 880 min), con 133 minutos anómalos (prevalencia 4,62 %) y 120 minutos de **carga legítima** (jornada de inscripciones, ×3 conexiones) etiquetados como normales. La media y la desviación de la estandarización y el umbral del detector se calculan solo con entrenamiento.

**Ejemplos anonimizados (filas del conjunto):**

| Minuto | Escenario | conex./min | bytes/flujo | dur. (s) | SYN sin ACK | RST | pet/resp | puertos únicos | long. QNAME |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 03-nov 11:00 | normal | 191 | 30 544 | 1,50 | 0,016 | 0,017 | 0,095 | 2 | 17,6 |
| 03-nov 10:25 | syn\_flood | 1 104 | 14 847 | 0,43 | **0,879** | 0,018 | 0,089 | 4 | 19,5 |
| 03-nov 14:07 | escaneo\_puertos | 182 | 29 624 | 1,00 | 0,018 | **0,608** | 0,062 | **305** | 15,8 |
| 03-nov 21:40 | tunel\_dns | 22 | 18 082 | 2,36 | 0,015 | 0,004 | 0,147 | 4 | **106,5** |
| 04-nov 09:45 | exfiltracion\_http | 163 | **979 009** | 2,59 | 0,013 | 0,002 | **3,136** | 7 | 17,5 |
| 04-nov 14:00 | carga\_legitima (normal) | **549** | 14 978 | 3,46 | 0,005 | 0,012 | 0,122 | 4 | 14,8 |

### 4.2 Procedimiento ejecutado

1. **Línea base estadística.** z robusto estacional de `conexiones_min`: mediana y MAD×1,4826 por hora del día en entrenamiento. Alerta si |z| > 3,5.
2. **Detector de anomalías.** `IsolationForest(n_estimators=300, max_samples=512, random_state=7)` de scikit-learn 1.9.1 sobre los 8 atributos. Umbral en el percentil 99,5 del score de entrenamiento (0,564).
3. **Variante con persistencia.** Alerta solo si 2 de 3 minutos consecutivos superan el umbral, para reducir los positivos aislados.
4. Métricas en evaluación: matriz de confusión, precisión, recall, F1, tasa de falsos positivos y PR-AUC. Script y notebook reproducibles: `caso4_ml.py` y `caso4_ml.ipynb` (Anexo A).

### 4.3 Evidencias y resultados

&#91;image: Figura 4.1\]

**Figura 4.1.** Conexiones por minuto, score de anomalía con su umbral y escenarios etiquetados en los dos días de evaluación.

&#91;image: Figura 4.2\]

**Figura 4.2.** Matrices de confusión de los tres detectores (2 880 minutos, 133 anómalos).

&#91;image: Figura 4.3\]

**Figura 4.3.** Curvas precisión–recall; la línea punteada es el azar (prevalencia del 4,6 %).

&#91;image: Figura 4.4\]

**Figura 4.4.** Explicación de la alerta del 04-nov 09:45: desviación por atributo frente al entrenamiento.

| Detector | TP | FP | FN | TN | Precisión | Recall | F1 | FPR | Exactitud | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Línea base z > 3,5 | 10 | 121 | 123 | 2 626 | 0,076 | 0,075 | 0,076 | 4,40 % | 91,5 % | 0,127 |
| IsolationForest | 53 | 9 | 80 | 2 738 | 0,855 | 0,398 | 0,544 | 0,33 % | 96,9 % | 0,595 |
| IsolationForest + persistencia 2/3 | 52 | 0 | 81 | 2 747 | **1,000** | 0,391 | **0,562** | **0,00 %** | 97,2 % | 0,595 |
| Clasificador trivial "todo normal" | 0 | 0 | 133 | 2 747 | – | 0 | 0 | 0 % | **95,4 %** | – |

**Detección por escenario (fracción de minutos detectados):**

| Escenario | Minutos | Línea base | IForest + persistencia |
| --- | --- | --- | --- |
| SYN flood | 10 | 1,00 | 1,00 |
| Escaneo de puertos | 5 | 0,00 | 1,00 |
| Exfiltración HTTP | 20 | 0,00 | 1,00 |
| Túnel DNS | 30 | 0,00 | 0,47 |
| RST inyectados | 8 | 0,00 | 0,38 |
| Escaneo lento | 60 | 0,00 | 0,00 |
| Carga legítima (normal) | 120 | **1,00 (falso positivo)** | 0,00 |

**Lectura.** La exactitud engaña: un clasificador que nunca alerta obtiene 95,4 %. El IsolationForest detecta bien las anomalías que mueven varios atributos a la vez o uno de forma extrema (flood, escaneo, exfiltración). Pierde las sutiles: el escaneo lento de 60 minutos no supera el umbral nunca y el túnel DNS solo la mitad del tiempo, porque un solo atributo anómalo se diluye entre ocho. Por eso se combina con reglas específicas (casos 2 y 8).

### 4.4 Indicadores y explicación de alertas

Indicador buscado: desviación sostenida respecto de la línea base y score alto. En la alerta del 04-nov 09:45 (score 0,599 > 0,564), la explicación por atributo muestra `ratio_pet_resp` a +69,7 σ y `bytes_por_flujo` a +12,0 σ, con el resto dentro de ±3 σ. El analista recibe una hipótesis concreta ("carga masiva cliente→servidor, posible exfiltración") que luego debe verificar contra PCAP y logs.

### 4.5 Mitigación y defensa

- **Revisión humana obligatoria.** El modelo solo prioriza; ninguna acción disruptiva se dispara por el score.
- **Monitorizar deriva.** Comparar semanalmente la distribución del score y la de cada atributo (prueba KS o PSI). Reentrenar con ventanas validadas; cambios de negocio como las inscripciones deben registrarse como contexto.
- **Proteger los datos de entrenamiento.** Control de acceso, hash de cada versión del conjunto y del modelo. Evitar el envenenamiento: un atacante paciente puede "normalizar" su tráfico dentro del entrenamiento.
- **Limitaciones documentadas.** Datos sintéticos; un solo servidor; escaneos lentos invisibles a escala de minuto.

### 4.6 Preguntas de análisis

**¿Cómo afectan el desbalance de clases y los cambios legítimos de carga?** Con 4,6 % de minutos anómalos, la exactitud y la curva ROC dan una imagen optimista: el clasificador trivial llega a 95,4 % y una FPR del 4,4 % parece pequeña, pero equivale a 121 falsas alarmas en dos días frente a 10 aciertos. En operación real la prevalencia es mucho menor y el problema crece: cada punto de FPR son cientos de alertas falsas por día. Los cambios legítimos de carga, como las inscripciones, desplazan la distribución normal. Un detector univariable de volumen los marca todos como ataque; uno multivariable los tolera si las razones (SYN/ACK, RST, pet/resp) se mantienen normales, como pasó aquí. Aun así, cambios permanentes exigen reentrenar.

**¿Qué métrica es más útil para el caso?** El **PR-AUC**, que mide la calidad del ranking sin depender del umbral y no se infla con los verdaderos negativos. Para fijar el punto de operación conviene la **precisión con un recall mínimo**, o alertas falsas por día, porque mide la carga real del analista. El recall por escenario muestra qué tipos de ataque quedan sin cubrir. La exactitud no debe reportarse sola.

## Caso 5. TCP: resets inesperados e indicios de inyección o desincronización

De los 154 RST capturados entre las 13:00 y las 13:30, 140 tienen causa benigna explicada: 69 por puerto cerrado, 56 por aborto del cliente y 15 por el reciclaje planificado de Tomcat. Los otros 14 forman un patrón de inyección. Son 7 RST que dicen venir de 192.168.50.20:443 pero llegan con TTL 64 y la MAC de .66, y 7 RST con los que el cliente .121 responde después a datos legítimos que el servidor seguía enviando.

**Situación.** Las aplicaciones reportan sesiones TCP que terminan abruptamente o se reinician de forma repetida.

**Evidencia analizada.** `C5_tcp_resets_lab.pcap`: 14 878 paquetes, 13:00–13:30. SHA-256 `105d10b8d88c758bfb586bcce687468c3a9095f11d1451a0ffd8a69a14805d1f`. También los registros de Zeek (conn.log, weird.log), Suricata (eve.json) y el evento 7036 del Visor de eventos.

### 5.1 Procedimiento ejecutado

1. Filtro `tcp.flags.reset == 1`: 154 paquetes. Columnas añadidas: `ip.ttl`, `eth.src`, `ip.id` y `tcp.stream`.
2. Para cada RST, ubicación en su flujo (¿responde a un SYN?, ¿hay datos después?) y correlación de la marca de tiempo con eventos del servidor (reinicio de servicio) y del firewall.
3. Comparación del TTL y la MAC de origen del RST con los de los demás paquetes del mismo emisor en esa sesión.
4. Correlación con `conn.log` (conn\_state RSTO, RSTR, REJ), `weird.log` (`data_after_reset`) y las alertas de Suricata. Resultado consolidado en `C5_tabla_rst.csv`.

### 5.2 Evidencias

&#91;image: Figura 5.1\]

**Figura 5.1.** RST por minuto y causa probable. El grupo A coincide exactamente con el evento 7036 de las 13:12:00; el grupo D se concentra entre las 13:20 y las 13:24 sobre un único cliente.

&#91;image: Figura 5.2\]

**Figura 5.2.** Sesión 192.168.50.121:56551 ↔ 192.168.50.20:443. El RST n.º 9894 tiene TTL 64 y MAC 00:50:56:a1:00:66; 0,3 ms después llega el segmento legítimo del servidor (TTL 128) con el mismo número de secuencia, y el cliente responde con RST.

&#91;image: Figura 5.3\]

**Figura 5.3.** Zeek (conn.log y weird.log) y Suricata (eve.json) sobre el mismo PCAP.

**Clasificación de los 154 RST:**

| Grupo | Causa probable | RST | Evidencia que la sostiene | ¿Benigno? |
| --- | --- | --- | --- | --- |
| A | Reinicio del servicio Tomcat (8080) | 15 | Todos a las 13:12:00 ± 10 ms; evento 7036 y cambio planificado CHG-118 | Sí |
| B | Puerto cerrado (8443) | 69 | RST/ACK inmediato al SYN; Zeek `REJ` | Sí |
| C | Cierre abortivo del cliente (443) | 56 | RST/ACK del cliente tras el intercambio completo; TTL y MAC del cliente coherentes | Sí |
| D | RST con TTL y MAC incoherentes | 7 | Origen IP .20, pero TTL 64 (Windows usa 128) y MAC de .66 | **No** |
| D' | RST del cliente tras la desincronización | 7 | Siguen a los D en 0,2 ms; responden a datos válidos del servidor | Consecuencia de D |

**Tabla de flujos afectados (grupo D):**

| Hora (UTC−5) | Flujo (servidor → cliente) | TTL del RST | MAC origen del RST | IP ID | Datos legítimos después |
| --- | --- | --- | --- | --- | --- |
| 13:20:02.269 | 192.168.50.20:443 → .121:56551 | 64 | 00:50:56:a1:00:66 | 9028 | Sí (0,3 ms) |
| 13:20:39.486 | 192.168.50.20:443 → .121:58405 | 64 | 00:50:56:a1:00:66 | 47107 | Sí |
| 13:21:16.021 | 192.168.50.20:443 → .121:50802 | 64 | 00:50:56:a1:00:66 | 16581 | Sí |
| 13:21:47.981 | 192.168.50.20:443 → .121:57535 | 64 | 00:50:56:a1:00:66 | 1634 | Sí |
| 13:22:22.712 | 192.168.50.20:443 → .121:63057 | 64 | 00:50:56:a1:00:66 | 17232 | Sí |
| 13:22:57.918 | 192.168.50.20:443 → .121:51996 | 64 | 00:50:56:a1:00:66 | 33906 | Sí |
| 13:23:33.681 | 192.168.50.20:443 → .121:50926 | 64 | 00:50:56:a1:00:66 | 56757 | Sí |

En la sesión, los paquetes legítimos del servidor llevan TTL 128 y MAC 00:50:56:a1:00:20.

### 5.3 Indicadores observados

| Indicador de la guía | Observado |
| --- | --- |
| RST fuera de contexto | 7 RST a mitad de sesiones TLS activas, sin FIN previo ni error de aplicación |
| Frecuencia inusual | 1 cada \~35 s contra el mismo cliente durante 4 min; el resto de clientes no se ve afectado |
| Sesiones truncadas | 7 sesiones .121↔.20:443 cortadas a mitad de transferencia |
| Inconsistencias que requieren correlación | TTL 64 frente a 128, MAC de otro host, IP ID sin relación con la secuencia del servidor, datos posteriores al RST (`data_after_reset`) |

**Hipótesis.** Un tercero en el mismo segmento L2, cuya MAC corresponde a la VM .66, observa las sesiones de .121 (por ARP spoofing o puerto espejo) y forja RST con el número de secuencia correcto para cortarlas.

**Hipótesis alternativas descartadas.** Un firewall o IPS intermedio que resetea sesiones no aplica: .20 y .121 están en la misma VLAN sin dispositivo en línea, y un IPS usaría su propia MAC o la del gateway. Un reinicio del servidor tampoco: el servidor sigue enviando datos y no hay evento 7036 a esa hora. La pérdida de conectividad generaría retransmisiones y timeouts, no RST con secuencia exacta.

**Validación.** La tabla CAM del switch ubica 00:50:56:a1:00:66 en el puerto Gi0/12, asignado a la VM .66. Con eso la evidencia pasa de "inconsistencia" a **hipótesis de manipulación sostenida por cuatro fuentes**: PCAP, Zeek, Suricata y switch. La confirmación final requiere el análisis forense de .66 (procesos, herramientas y tabla ARP de .121).

### 5.4 Mitigación y defensa

| Tipo | Control | Comentario |
| --- | --- | --- |
| Preventivo | DHCP snooping, Dynamic ARP Inspection e IP Source Guard en la VLAN 50; port-security con MAC fija en los puertos de servidores | Impide que .66 envíe tramas con IP de .20 |
| Preventivo | Segmentar: servidores en una VLAN distinta de las VM de estudiantes, con el tráfico por el gateway con filtrado | Un atacante de otra VLAN no ve las secuencias TCP |
| Preventivo | TLS correctamente validado (ya está en 443) | Protege la confidencialidad e integridad del contenido, **no** impide que un RST forjado corte la sesión. Para eso se necesita IPsec o TCP-AO. |
| Preventivo | Endpoints actualizados: los TCP/IP modernos aplican RFC 5961 y solo aceptan un RST cuya secuencia coincida exactamente | Eleva el costo, pero un atacante que ve el tráfico conoce la secuencia exacta |
| Detectivo | Regla Suricata `sid:1000501` y script Zeek `rst_ttl.zeek` | Ver abajo |
| Correctivo | Revisar rutas y dispositivos intermedios, tablas ARP y CAM; aislar .66 tras validación humana | – |

```
# Suricata - el servidor es Windows (TTL inicial 128) y está en el mismo segmento: un RST suyo con TTL < 100 es incoherente
alert tcp 192.168.50.20 any -> $HOME_NET any (msg:"LAB TCP RST con TTL distinto al de la sesión (posible inyección)"; \
  flags:R,12; ttl:<100; classtype:misc-attack; sid:1000501; rev:1;)

# Zeek - rst_ttl.zeek (idea): guardar el TTL del primer paquete de cada extremo en new_packet()
# y emitir Weird::lab_rst_ttl_change si un RST llega con TTL distinto (±1) al registrado para ese extremo.
```

### 5.5 Preguntas de análisis

**¿Qué causas benignas generan RST?**

- Conexión a un puerto sin servicio (grupo B).
- Cierre abortivo de la aplicación: navegador que cancela una descarga, `SO_LINGER` en 0, proceso terminado (grupo C).
- Reinicio o caída de un servicio con conexiones abiertas (grupo A).
- Firewalls o balanceadores que resetean sesiones inactivas o denegadas (`reject with tcp-reset`).
- Expiración del estado NAT o conntrack.
- Llegada de un segmento para una conexión que el host ya olvidó (tras reinicio).
- Keep-alive fallidos.

Su sola presencia no indica ataque.

**¿Qué evidencia adicional haría más sólida la hipótesis de manipulación?**

- Tabla CAM o ARP del switch que ubique la MAC anómala (ya obtenida).
- Caché ARP de .121 que muestre la IP de .20 asociada a la MAC de .66 (envenenamiento).
- Captura en el puerto del propio servidor que demuestre que .20 nunca emitió esos RST.
- Logs de DAI o port-security.
- Artefactos forenses en .66: herramienta, historial de comandos, interfaz en modo promiscuo.
- Reproducir el patrón solo cuando .66 está conectado.

No debe inferirse un MITM solo por observar RST.

## Caso 6. UDP: reflexión/amplificación DNS, NTP o SSDP

Entre las 14:04 y las 14:07 el gateway registró 314 975 respuestas UDP (296 MB) dirigidas a 192.168.50.20, frente a solo 3 312 solicitudes salientes en la misma ventana. La razón de bytes respuesta/solicitud llegó a 998× en DNS, 4 903× en NTP y 7 393× en SSDP: es un patrón de reflexión dirigido contra el servidor. La verificación de configuración muestra que los servicios propios **no** actúan como reflectores abiertos.

**Situación.** El servidor o el gateway registran un volumen inusual de respuestas UDP, desproporcionado respecto de las solicitudes.

**Evidencia analizada.** Por regla de la guía no se generó tráfico de amplificación. Se usaron **contadores agregados simulados** por segundo, protocolo y sentido en la interfaz LAN del gateway: `C6_contadores_udp_gateway.csv`, 14:00–14:10. Los reflectores usan direcciones de documentación (RFC 5737).

### 6.1 Procedimiento ejecutado

1. Volumen por protocolo (DNS 53, NTP 123, SSDP 1900), sentido (solicitud saliente o respuesta entrante), origen, destino y segundo.
2. Se distinguió tráfico esperado de respuestas no solicitadas: para cada minuto se calculó la razón de bytes respuesta/solicitud por protocolo.
3. Se identificó la ráfaga legítima del minuto 1 (arranque de 30 VM de laboratorio) para comparar.
4. Se revisó la configuración de los servicios UDP propios (BIND en .53, ntpsec en .1, SSDP en .20) para confirmar que no responden como reflectores abiertos.

### 6.2 Evidencias

&#91;image: Figura 6.1\]

**Figura 6.1.** Paquetes por segundo y Mbit/s por protocolo y sentido. Las líneas punteadas (solicitudes) no acompañan a las respuestas en la ventana 14:04–14:07.

&#91;image: Figura 6.2\]

**Figura 6.2.** Razón de bytes respuesta/solicitud por minuto (escala logarítmica) frente al umbral propuesto de 5.

&#91;image: Figura 6.3\]

**Figura 6.3.** Verificación de los servicios propios: recursión de BIND restringida a 192.168.50.0/24 con RRL, ntpsec sin modo 7 (`monlist`) y servicio SSDP deshabilitado en SRV-WEB-LAB.

**Volumen en la ventana de reflexión (14:04:00–14:07:00):**

| Protocolo | Respuestas entrantes (paquetes) | Bytes de respuesta | Solicitudes salientes | Razón máx. bytes resp/sol (por minuto) | Tamaño típico de respuesta | Reflectores únicos |
| --- | --- | --- | --- | --- | --- | --- |
| DNS (53) | 165 361 | 234,8 MB | 3 178 | 998× | \~1 450 B (ANY/TXT, fragmentadas) | 38 |
| NTP (123) | 86 998 | 40,7 MB | 105 | 4 903× | 468 B (patrón `monlist`) | 24 |
| SSDP (1900) | 62 616 | 20,6 MB | 29 | 7 393× | \~330 B | 19 |
| **Comparación: ráfaga legítima 14:01** | DNS \~158 resp/s | – | DNS \~158 sol/s | 1,6× (DNS), 1,0× (NTP) | Normal | – |

**Inventario de servicios UDP propios y estado:**

| Servicio | Host | Configuración verificada | ¿Reflector abierto? |
| --- | --- | --- | --- |
| DNS (BIND 9) | 192.168.50.53 | `allow-recursion` y `allow-query-cache` solo para 127.0.0.1 y 192.168.50.0/24; `rate-limit responses-per-second 10`. Una consulta desde una red no autorizada devuelve `REFUSED`. | No |
| NTP (ntpsec) | 192.168.50.1 | `restrict default kod nomodify noquery limited`; ntpsec no implementa el modo 7, así que `monlist` no responde | No |
| SSDP/UPnP | 192.168.50.20 | `SSDPSRV` y `upnphost` detenidos y deshabilitados | No |

### 6.3 Indicadores observados

| Indicador de la guía | Observado |
| --- | --- |
| Gran volumen de respuestas | \~1 750 respuestas/s y \~13 Mbit/s combinados, frente a \~20 respuestas/s de base |
| Asimetría petición/respuesta | Razón de 998× a 7 393× (base: 1–2×) |
| Puertos inesperados | Respuestas desde el puerto 1900 (SSDP) y 123 (NTP) hacia un servidor web que no las pidió |
| Destinos no relacionados con solicitudes observadas | El 99 % de las respuestas no tiene una solicitud correspondiente del mismo par IP/puerto |

**Hipótesis.** Un tercero falsificó la IP de 192.168.50.20 como origen en solicitudes enviadas a reflectores DNS, NTP y SSDP abiertos. Las respuestas amplificadas llegan al servidor (DDoS reflejado).

**Alternativa benigna descartada.** Una ráfaga legítima, como el arranque masivo de VM en el minuto 1, es **simétrica**: cada respuesta tiene su solicitud y la razón se mantiene cerca de 1. Tampoco hay actualizaciones ni sincronizaciones programadas a las 14:04.

### 6.4 Mitigación y defensa

| Control | Dónde | Responsable |
| --- | --- | --- |
| Deshabilitar servicios UDP innecesarios (SSDP, SNMP; ver Caso 3) | Servidor | Administrador del servidor |
| Restringir la recursión DNS a clientes internos + RRL (aplicado) | Resolver propio | Administrador DNS |
| ntpsec sin modo 7 y con `noquery` (aplicado) | Gateway | Infraestructura |
| Descartar en el gateway las respuestas 53, 123 y 1900 hacia hosts que no son el resolver o el servidor NTP autorizado | Borde propio | Infraestructura |
| Filtrado anti-spoofing BCP 38 / uRPF: no dejar salir paquetes con IP origen ajena a 192.168.50.0/24 | Borde propio y proveedor | Infraestructura / ISP |
| Rate limiting y mitigación volumétrica aguas arriba (blackhole, scrubbing), coordinados con el proveedor | Proveedor | ISP |

```
# Suricata (local.rules) - respuestas UDP que no deberían llegar a hosts internos
alert udp any 53 -> [$HOME_NET,!192.168.50.53] any (msg:"LAB respuesta DNS grande no solicitada (posible reflexion)"; dsize:>512; \
  threshold: type both, track by_dst, count 100, seconds 10; classtype:attempted-dos; sid:1000601; rev:1;)
alert udp any 123 -> $HOME_NET any (msg:"LAB respuesta NTP modo 7/monlist hacia la LAN"; dsize:>400; \
  threshold: type both, track by_dst, count 50, seconds 10; classtype:attempted-dos; sid:1000602; rev:1;)
alert udp any 1900 -> $HOME_NET any (msg:"LAB respuestas SSDP entrantes masivas"; \
  threshold: type both, track by_dst, count 50, seconds 10; classtype:attempted-dos; sid:1000603; rev:1;)
# Regla de SIEM LAB-UDP-ASYM: bytes_respuesta / bytes_solicitud > 5 durante 60 s, por protocolo y destino.
```

### 6.5 Preguntas de análisis

**¿Cómo se diferencia una ráfaga legítima de un patrón de reflexión?** Una ráfaga legítima es iniciada por los propios hosts. Cada respuesta corresponde a una solicitud previa con el mismo par IP/puerto e ID de transacción, la razón de bytes se mantiene en 1–2×, los tamaños son normales y los servidores consultados son los autorizados. Una reflexión muestra respuestas sin solicitud previa, una razón de cientos o miles, tamaños máximos (ANY, `monlist`, M-SEARCH), muchos reflectores distintos y protocolos que el destino no usa. En la Figura 6.2, el minuto 14:01 (arranque de VM) y el 14:05 (reflexión) se separan por tres órdenes de magnitud.

**¿Qué controles corresponden al servidor y cuáles al proveedor?** Al servidor y a la organización les toca no ser parte del problema y reducir el impacto local: deshabilitar servicios UDP innecesarios, no operar resolvers ni NTP abiertos, aplicar RRL, filtrar respuestas no solicitadas en el borde y aplicar BCP 38 en la salida. Pero cuando el volumen satura el enlace de entrada, filtrar en el servidor o el gateway ya no sirve: el tráfico consumió el ancho de banda antes de llegar. Eso corresponde al **proveedor**: filtrado y rate limiting aguas arriba, blackholing (RTBH), centros de limpieza y anti-spoofing en su red.

## Caso 7. ICMP: escaneo, payloads atípicos y posible túnel

La captura muestra dos anomalías sobre un fondo de ICMP legítimo. **192.168.50.66** hizo un barrido de descubrimiento: 254 echo request a toda la /24 en 6,4 s a las 15:05. **192.168.50.77** mantuvo un canal de 540 echo de 1 000–1 400 bytes, uno por segundo durante 14 minutos, hacia .250; la respuesta nunca replica el payload enviado, algo imposible en un ping real. El ping de diagnóstico de .10 y los mensajes de error del gateway se comportan según la línea base.

**Situación.** Hay una tasa de ICMP mayor de lo habitual o paquetes con tamaños o patrones repetitivos.

**Evidencia analizada.** `C7_icmp_lab.pcap`: 1 378 paquetes ICMP, 15:00–15:20. Es un PCAP sintético y didáctico: los payloads son bytes aleatorios sin información sensible.

### 7.1 Procedimiento ejecutado

1. Filtro `icmp`, agrupado por IP origen y destino, tipo/código (`icmp.type`, `icmp.code`), longitud (`data.len`) y tiempo entre paquetes (Estadísticas ▸ Endpoints y ▸ Longitudes de paquete).
2. **Línea base:** ping de diagnóstico del analista (.10 → .20), 4 echo cada 5 min con el payload estándar de Windows de 32 bytes (`abcdefghijklmnopqrstuvwabcdefghi`). Mensajes de error de red esperados: tipo 11 (traceroute) y tipo 3 código 4 (descubrimiento de MTU de ruta).
3. Emparejamiento de cada echo reply con su request (id + secuencia) para verificar que el payload sea idéntico, como exige la RFC 792.
4. Entropía de Shannon del payload por paquete y periodicidad por origen.

### 7.2 Evidencias

&#91;image: Figura 7.1\]

**Figura 7.1.** Dashboard por IP: paquetes y destinos únicos por origen, distribución de longitudes, serie temporal en ventanas de 20 s y coherencia request/reply.

&#91;image: Figura 7.2\]

**Figura 7.2.** Wireshark con `icmp && (ip.addr == 192.168.50.77 || ip.src == 192.168.50.66)`: echo de 1 000–1 400 B con respuesta de payload distinto, y barrido con id fijo 0x1d2a y secuencia igual al octeto del destino.

**Tabla de tamaños y frecuencias por origen:**

| Origen | Paquetes | Destinos únicos | Tipos (tipo/código) | Payload mín / mediana / máx (B) | Entropía media (bits/byte) | Intervalo mediano | Duración | Replies con payload distinto |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 192.168.50.77 | 541 | 2 | 8/0 × 540 | 0 / 1 213 / 1 400 | **7,82** | **1,005 s** (periódico) | 838 s | **540 de 540** |
| 192.168.50.250 | 541 | 2 | 0/0 × 541 | 0 / 1 150 / 1 400 | 7,81 | 1,005 s | 833 s | – (es quien responde) |
| 192.168.50.66 | 254 | **254** | 8/0 × 254 | 0 / 0 / 0 | – | **0,025 s** | **6,4 s** | 0 de 7 |
| 192.168.50.10 (línea base) | 17 | 2 | 8/0 × 16 | 32 / 32 / 32 | 4,18 | 1 s en ráfagas de 4 cada 5 min | 903 s | 0 de 16 |
| 192.168.50.1 (gateway) | 6 | 3 | 11/0 × 3, 3/4 × 2, 0/0 × 1 | 0 / 28 / 28 | – | – | – | – |

### 7.3 Indicadores observados

| Indicador de la guía | Observado | Línea base |
| --- | --- | --- |
| Ráfagas de echo request/reply | .66: 254 request en 6,4 s (\~40/s) a destinos consecutivos | .10: 4 request cada 5 min |
| Longitudes inusuales | .77: payloads de 1 000–1 400 B, cercanos a la MTU | 32 B (Windows) o 56 B (Linux) |
| Periodicidad repetitiva | .77: 1,005 s constante durante 14 min (beaconing) | Pings manuales espaciados |
| Volumen no explicado por diagnóstico | 1,32 MB en ICMP entre .77 y .250, sin ticket ni tarea de monitoreo | Unos pocos KB |
| Payload incoherente | El reply de .250 no replica el request (540 de 540) | 16 de 16 replies idénticos |

**Hipótesis.** (a) .66 realiza descubrimiento de hosts activos (reconocimiento previo a escaneo; coincide con el Caso 8). (b) .77 y .250 usan ICMP como canal encubierto bidireccional: datos de alta entropía (cifrados o comprimidos) en ambos sentidos, al ritmo de un túnel tipo ptunnel o icmptunnel.

**Alternativas benignas consideradas.**

- Monitoreo de disponibilidad (Nagios/PRTG): usaría pocos destinos conocidos, payload fijo y eco idéntico. Descartado para .77 y para el barrido de .66, que no están en el inventario de monitoreo.
- Prueba de MTU con `ping -l 1400`: el payload sería un patrón fijo y la respuesta lo replicaría. Descartado por la entropía de 7,8 bits/byte y la incoherencia request/reply.
- Los mensajes 3/4 y 11/0 del gateway son operación normal de la red.

### 7.4 Mitigación y propuesta de regla

| Tipo ICMPv4 | Uso legítimo | Política propuesta |
| --- | --- | --- |
| 0 / 8 (echo reply / request) | Diagnóstico | Permitir desde la red de administración y el monitoreo; limitar a 5 paquetes/s por origen y payload ≤ 512 B en el gateway |
| 3 (destino inalcanzable), especialmente 3/4 | PMTUD, errores de conexión | **Permitir siempre** |
| 11 (tiempo excedido) | Traceroute, detección de bucles | Permitir |
| 5 (redirect), 13/14 (timestamp), 17/18 (máscara) | Obsoletos o riesgosos | Bloquear |
| ICMPv6 1, 2, 3, 4 y 133–137 (NDP) | Imprescindibles en IPv6 | **Nunca bloquear** (RFC 4890) |

```
# Suricata (local.rules)
alert icmp $HOME_NET any -> $HOME_NET any (msg:"LAB barrido ICMP > 50 destinos/10 s"; itype:8; \
  threshold: type both, track by_src, count 50, seconds 10; classtype:network-scan; sid:1000701; rev:1;)
alert icmp any any -> any any (msg:"LAB ICMP echo con payload > 512 B persistente (posible tunel)"; itype:8; dsize:>512; \
  threshold: type both, track by_src, count 20, seconds 60; classtype:policy-violation; sid:1000702; rev:1;)
# Zeek (script local): icmp_echo_reply con payload != payload del request emparejado -> Notice ICMP::Payload_Mismatch

# Windows Defender Firewall (SRV-WEB-LAB): permitir echo solo desde administración
New-NetFirewallRule -DisplayName "ICMPv4 Echo admin" -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 192.168.50.10 -Action Allow
```

El monitoreo se mantiene sin bloquear de forma indiscriminada los mensajes que la red necesita.

### 7.5 Preguntas de análisis

**¿Qué funciones legítimas cumple ICMP?** ICMP es el canal de control y error de IP:

- Informa destinos o puertos inalcanzables (tipo 3).
- Habilita el descubrimiento de MTU de ruta (3/4 en IPv4, *Packet Too Big* en IPv6).
- Avisa de TTL excedido y permite traceroute (tipo 11).
- Prueba alcanzabilidad y latencia (echo, tipos 8 y 0).
- Notifica problemas de parámetros (tipo 12).
- En IPv6 además implementa Neighbor Discovery, que reemplaza a ARP (descubrimiento de vecinos y routers, autoconfiguración SLAAC) y MLD.

**¿Qué impacto tendría bloquearlo completamente?**

- Se rompe PMTUD: las conexiones TCP con paquetes grandes, como TLS o transferencias, se cuelgan ("agujeros negros de MTU"), sobre todo con túneles o VPN.
- Las aplicaciones tardan más en detectar destinos inalcanzables, porque esperan timeouts en vez de recibir un error inmediato.
- Se pierden ping y traceroute para diagnosticar.
- En IPv6, la red deja de funcionar: sin NDP no hay resolución de direcciones ni descubrimiento de routers.

La respuesta correcta es filtrar por tipo, limitar la tasa y vigilar tamaño y coherencia, no bloquear todo.

## Caso 8. Escaneo de puertos y fingerprinting de servicios

A las 16:10, 192.168.50.66 sondeó 1 030 puertos de SRV-WEB-LAB en unos 8,5 s con SYN *half-open*. Luego abrió 4 conexiones completas para leer los banners de FTP, HTTP, Tomcat y MySQL. Es un reconocimiento activo que, junto con los casos 3, 5 y 7, apunta a un mismo actor. En la misma hora hubo otros dos patrones: el escáner autorizado .15 (suprimible por ticket) y un escaneo lento desde .88 que el umbral por minuto no detecta.

**Situación.** Los logs muestran intentos secuenciales contra varios puertos o servicios no habituales.

**Evidencia analizada.** `C8_escaneo_autorizado.pcap` (9 186 paquetes, 16:00–17:00) y `C8_pfirewall.log`, el registro de Windows Defender Firewall de SRV-WEB-LAB. No se sondeó ninguna red ajena.

### 8.1 Procedimiento ejecutado

1. En el registro del firewall y en el PCAP, conteo de puertos de destino únicos por origen en ventanas de 60 s y en todo el periodo, con las respuestas (SYN/ACK = abierto, RST/ACK = cerrado, sin respuesta = filtrado).
2. Identificación del fingerprinting: conexiones cortas con lectura de banner (`tcp.len > 0` desde el servidor tras un handshake que el cliente cierra con RST).
3. Correlación con Zeek (conn.log: `conn_state` S0/REJ/RSTO) y Suricata (`sid:1000801`), y con la agenda de mantenimiento (ticket MNT-2211).
4. Elaboración de la lista de exposición de los servicios propios a partir de lo que respondió el servidor.

### 8.2 Evidencias

&#91;image: Figura 8.1\]

**Figura 8.1.** Izquierda: puerto sondeado frente al tiempo, por origen. Derecha: puertos únicos por origen y minuto frente al umbral de 25.

&#91;image: Figura 8.2\]

**Figura 8.2.** Wireshark con `ip.addr == 192.168.50.66 && (tcp.flags.syn == 1 || tcp.len > 0)`: SYN con Win=1024 y TTL 64, RST inmediato tras el SYN/ACK y banners leídos (FileZilla 0.9.60, IIS 10.0, Apache-Coyote, MySQL 5.7.44).

&#91;image: Figura 8.3\]

**Figura 8.3.** Registro de Windows Defender Firewall filtrado por .66: puertos distintos y bloqueos de 135/139.

**Lista de indicadores por origen:**

| Origen | SYN | Puertos únicos | Máx. puertos en 60 s | Abiertos que respondieron | Cerrados (RST) | Ventana | Banners leídos | Valoración |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 192.168.50.66 | 1 034 | 1 030 | **1 030** | 8 (+4 banners) | 1 020 | 16:10:00–16:10:16 | **4** | Escaneo rápido + fingerprinting: **sospechoso** |
| 192.168.50.15 | 2 048 | 2 048 | 273 | 4 | 2 042 | 16:40:00–16:47:41 | 0 | Escáner autorizado (MNT-2211, ventana 16:40–16:50): **suprimido** |
| 192.168.50.88 | 135 | 27 (×5 vueltas) | **3** | 40 respuestas | 85 | 16:00:59–16:56:37 | 0 | Escaneo lento de puertos conocidos: **no lo detecta la regla por minuto** |
| Clientes .100–.140 | 900 | 2 (80, 443) | 2 | – | 0 | Todo el periodo | 0 | Normal |

**Puertos y servicios expuestos de SRV-WEB-LAB (vista del escaneo):**

| Estado | Puertos |
| --- | --- |
| Abiertos | 21 (FTP), 80 (HTTP), 443 (HTTPS), 445 (SMB), 3306 (MySQL), 3389 (RDP), 5985 (WinRM), 8080 (Tomcat) |
| Filtrados por el firewall (DROP) | 135 (RPC), 139 (NetBIOS) |
| Cerrados (RST) | El resto de 1–1024 y 8443, 9090 |
| Banners que revelan versión | 21, 80, 8080, 3306 |

### 8.3 Indicadores observados

| Indicador de la guía | Observado |
| --- | --- |
| Conexiones a muchos puertos en poco tiempo | .66: 1 030 puertos en \~8,5 s, orden aleatorio |
| Intentos repetidos a servicios inexistentes | .66: 1 020 RST/ACK; .88: 85 RST en 56 min, repitiendo la misma lista de 27 puertos |
| Consultas de banner o versión no habituales | .66: `HEAD / HTTP/1.0` en 80 y 8080, lectura del saludo FTP y del handshake de MySQL, cada sesión cerrada con RST a los 20 ms |

**Hipótesis.** .66 ejecuta reconocimiento activo (descubrimiento de servicios y versiones, MITRE T1046) contra el servidor, como continuación del barrido ICMP de las 15:05 (Caso 7). .88 parece un escaneo lento diseñado para evadir umbrales.

**Alternativas benignas.** Escáner de vulnerabilidades o inventario autorizado: aplica a .15 (ticket y ventana coinciden), no a .66 ni .88. Una aplicación con puertos dinámicos (RPC, FTP pasivo) contactaría unos pocos puertos altos, no 1 024 puertos bajos en orden aleatorio.

### 8.4 Mitigación, regla de detección y plan de endurecimiento

```
# Suricata (local.rules)
alert tcp $HOME_NET any -> 192.168.50.20 any (msg:"LAB Escaneo SYN > 25 puertos/60 s"; flags:S,12; \
  threshold: type both, track by_src, count 25, seconds 60; classtype:attempted-recon; sid:1000801; rev:1;)

# Regla de SIEM LAB-SCAN-SLOW (escaneo lento): >= 15 puertos destino distintos con REJ/RST desde un mismo origen en 60 min
# Supresión con contexto: si origen = 192.168.50.15 Y hora dentro de la ventana del ticket MNT-2211 -> severidad informativa
# Respuesta: bloqueo temporal (Wazuh active-response firewall-drop, 600 s) SOLO tras aprobación del analista; revisión a las 24 h
```

**Plan de endurecimiento:**

1. Reducir la superficie expuesta según el Caso 3: cerrar 21, 8080, 3306 y 445 hacia clientes; RDP y WinRM solo desde administración.
2. Filtrar por necesidad: perfil de firewall por defecto en *Block inbound* para la LAN de clientes; solo 443 (y 80 con redirección) abiertos a todos.
3. Ocultar versiones en banners: `ServerTokens`/`server` en Tomcat, `removeServerHeader` en IIS, mensaje de bienvenida genérico en SFTP.
4. Actualizar servicios (FileZilla y MySQL sin soporte).
5. Alertar ante patrones repetidos (regla rápida + lenta) y aplicar bloqueo temporal con revisión humana y caducidad.

### 8.5 Preguntas de análisis

**¿Qué limitaciones tiene atribuir un escaneo a una sola IP?**

- La IP de origen puede estar falsificada. En escaneos SYN *decoy* (`nmap -D`) se mezclan IPs señuelo con la real.
- La IP puede ser un NAT, proxy o VPN que agrupa a muchos usuarios.
- Puede ser un equipo comprometido que actúa como pivote del atacante real.
- En DHCP, la IP cambia de dueño con el tiempo.
- Un escaneo distribuido reparte los puertos entre muchas IPs para quedar por debajo de cualquier umbral por origen.

Atribuir a una persona requiere correlacionar la IP con la MAC y el puerto del switch, los registros DHCP, la sesión de usuario y el análisis del host. En este laboratorio la MAC y el puerto Gi0/12 refuerzan la atribución a la VM .66, pero no a quién la usaba.

**¿Cómo se reducen falsos positivos por monitoreo autorizado?**

- Inventariar los escáneres y herramientas de monitoreo autorizados con IP, horario y alcance.
- Asociar cada ejecución a un ticket o ventana de cambio.
- Suprimir o bajar la severidad solo si coinciden origen, ventana **y** alcance. Un .15 escaneando fuera de su ventana debe seguir alertando, porque la IP de un escáner es un objetivo atractivo para suplantar.
- Revisar periódicamente la lista blanca y registrar cada supresión en el SIEM para auditoría.

## Caso 9. Priorización y correlación de alertas con IA y SIEM

El pipeline redujo 208 eventos crudos de 9 fuentes a 33 alertas deduplicadas, y estas a 10 entidades priorizadas, sin perder la trazabilidad a cada evento original. La entidad **192.168.50.66** obtiene 100/100 (P1) porque converge en 6 familias de fuentes independientes y 11 técnicas distintas a lo largo del día. La prueba de carga y el escáner autorizado se suprimen por contexto, no se ignoran.

**Situación.** El centro de monitoreo recibe múltiples alertas que deben agruparse y priorizarse.

**Evidencia analizada.** `C9_eventos_normalizados.csv`: eventos de Suricata, Zeek, Windows, FileZilla, BIND, firewall, gateway, switch y del detector ML, generados a partir de los casos 1–8 y 10 del 05-nov-2026.

### 9.1 Procedimiento ejecutado

1. **Normalización** a un esquema común inspirado en ECS: `@timestamp` (ISO 8601 con zona), `event.provider`, `rule.id`, `rule.name`, `source.ip`, `destination.ip`, `event.severity` (1–4), `evidence.ref` (archivo de evidencia) y `event.id` (SHA-1 truncado del evento original).
2. **Deduplicación sin perder trazabilidad.** Se agrupa por (regla, origen, destino, ventana de 15 min). Cada alerta conserva el conteo, la primera y la última hora y la lista completa de `event.id`. Resultado: 208 eventos → 33 alertas.
3. **Características agregadas por entidad y ventana:** técnicas distintas, familias de fuentes, severidad máxima por técnica y criticidad del destino. Para el detector de anomalías se usaron los datos controlados del Caso 4.
4. **Puntuación de riesgo explicable** (cada sumando se muestra al analista).
5. **LLM** solo para resumir alertas ya anonimizadas y sugerir el triaje; cada afirmación se verifica contra la evidencia.

Fórmula de la puntuación:

```latex
\text{score} = \min\Big(100,\; \big(\textstyle\sum_{t \in \text{técnicas}} w(\text{sev}_t) + 8\,(F-1)\big)\cdot c_{\text{destino}} \cdot s\Big)
```

Donde w(1)=2, w(2)=5, w(3)=10, w(4)=15; F es el número de familias de fuentes (IDS de red, host/SO, aplicación, DNS, firewall, L2, ML); c es la criticidad del activo destino (1,3 para el servidor web, 1,2 para el DNS, 1,0 para el resto); y s vale 0,2 si hay autorización vigente (ticket + ventana) o 1 en otro caso. Prioridad: P1 ≥ 70, P2 ≥ 40, P3 ≥ 20, P4 < 20.

### 9.2 Evidencias

&#91;image: Figura 9.1\]

**Figura 9.1.** Diagrama del pipeline: fuentes → agente → normalización → deduplicación → correlación y score (+ detector ML) → resumen LLM → validación humana → acción reversible.

&#91;image: Figura 9.2\]

**Figura 9.2.** Alertas deduplicadas por entidad a lo largo del día, coloreadas por familia de fuente.

&#91;image: Figura 9.3\]

**Figura 9.3.** Alerta enriquecida LAB-2026-11-05-0007 (JSON) para 192.168.50.66.

**Priorización resultante:**

| Entidad | Alertas | Eventos | Técnicas | Familias de fuentes | Puntos de severidad | Bonus de convergencia | Criticidad | Supresión | Score (bruto) | Prioridad |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 192.168.50.66 | 14 | 80 | 11 | IDS, host, aplicación, firewall, L2, ML (6) | 72 | 40 | 1,3 | – | **100** (145,6) | **P1 Crítica** |
| 192.168.50.44 | 3 | 52 | 3 | IDS, DNS, ML (3) | 20 | 16 | 1,2 | – | 43 | P2 Alta |
| 192.168.50.77 | 4 | 18 | 2 | IDS (1) | 20 | 0 | 1,0 | – | 20 | P3 Media → **P2 por el analista** |
| Reflectores RFC 5737 | 1 | 3 | 1 | Firewall (1) | 10 | 0 | 1,3 | – | 13 | P4 → **escalado al proveedor** |
| 192.168.50.20 | 2 | 8 | 2 | Host (1) | 7 | 0 | 1,3 | – | 9 | P4 (efectos de la prueba y del cambio CHG-118) |
| 192.168.50.112 | 1 | 1 | 1 | Aplicación (1) | 5 | 0 | 1,3 | – | 6 | P4 (FTP anónimo → remediación) |
| 192.168.50.15 | 2 | 8 | 1 | IDS (1) | 10 | 0 | 1,3 | MNT-2211 | 3 (13,0) | P4 suprimido |
| 192.168.50.88 | 4 | 5 | 1 | IDS (1) | 2 | 0 | 1,3 | – | 3 | P4 → **P3 por el analista** |
| 198.18.0.0/15 | 1 | 18 | 1 | IDS (1) | 10 | 0 | 1,3 | Acta LAB-02 | 3 (13,0) | P4 suprimido |
| 192.168.50.115 | 1 | 15 | 1 | IDS (1) | 2 | 0 | 1,2 | – | 2 | P4 (telemetría legítima) |

**Ejemplo de alerta enriquecida (extracto):**

```json
{
 "alert.id": "LAB-2026-11-05-0007", "entidad": "192.168.50.66",
 "activo": "ws-lab-66 (VM de estudiante, VLAN 50, switch Gi0/12)",
 "score": 100, "prioridad": "P1 – Crítica",
 "explicacion_score": {"severidad_por_tecnica": 72, "convergencia_fuentes": 40, "criticidad_destino(192.168.50.20)": 1.3},
 "cronologia": ["10:01 DNS a resolver no autorizado (x25)", "11:10 4625 RDP > 10/min (x11)", "11:10 FTP 530 (x9)",
                "13:20 RST con TTL anómalo (x7) + MAC .66 en Gi0/12", "15:05 barrido ICMP", "16:10 escaneo SYN (x12) + banners (x4)"],
 "mitre_attack": ["T1046", "T1018", "T1110", "T1557 (hipótesis)"],
 "evidencia": ["C2_consultas_dns.csv", "C3_eventos_autenticacion.csv", "C5_tcp_resets_lab.pcap", "C7_icmp_lab.pcap", "C8_escaneo_autorizado.pcap"],
 "accion_sugerida": "Cuarentena VLAN tras validación humana; preservar memoria/disco; revisar ARP/CAM",
 "estado": "Pendiente de validación humana"
}
```

### 9.3 Uso del LLM y verificación

Se entregó al asistente LLM solo la alerta anonimizada: IPs de laboratorio, sin nombres de usuario reales ni contenido de paquetes. La instrucción fue "resume en 5 líneas para un analista de nivel 1 y sugiere los pasos de triaje". Borrador obtenido:

> *Resumen:* El host 192.168.50.66 muestra a lo largo del día una secuencia coherente con un actor interno: uso de DNS no autorizado, fuerza bruta contra RDP y FTP del servidor web **con un acceso FTP exitoso**, inyección de RST contra sesiones TLS de .121, barrido ICMP de la /24 y escaneo de puertos con captura de banners. *Triaje sugerido:* 1) confirmar la ubicación física y lógica (switch Gi0/12); 2) preservar evidencia volátil; 3) cuarentena de red; 4) revisar cuentas atacadas; 5) restablecer las contraseñas afectadas.

| Afirmación del LLM | Verificación contra la evidencia | Resultado |
| --- | --- | --- |
| DNS no autorizado desde .66 | 25 consultas a .99 en el PCAP del Caso 2; 0 en el log de BIND | Correcta |
| Fuerza bruta RDP/FTP | 118 × 4625 + 70 × 530 | Correcta |
| "Con un acceso FTP exitoso" | El único 230 es de **.112** (anónimo), no de .66; .66 no tiene ningún 4624 ni 230 | **Incorrecta, corregida** |
| Inyección de RST contra .121 | 7 RST TTL 64/MAC .66 + CAM Gi0/12 | Correcta como hipótesis, no confirmada |
| Restablecer las contraseñas afectadas | No hubo autenticación exitosa: rotarlas es prudente, pero no urgente | Ajustada |

La alucinación del acceso exitoso habría llevado a declarar un compromiso inexistente. Por eso el LLM solo resume y sugiere; nunca decide.

### 9.4 Registro de validación humana

| Alerta / entidad | Score | Decisión del analista | Justificación | Acción (reversible) | Analista | Hora |
| --- | --- | --- | --- | --- | --- | --- |
| 0007 / 192.168.50.66 | 100 | Confirmar P1 | 6 familias de fuentes; atribución L2 por CAM | Cuarentena VLAN 999 (revertible), imagen forense | \[Integrante 1\] | 16:25 |
| 0004 / 192.168.50.44 | 43 | Confirmar P2 | Túnel DNS sin explicación en el inventario | RPZ para `exfil-lab.test` + investigación del host | \[Integrante 2\] | 16:31 |
| 0006 / 192.168.50.77 | 20 | **Subir a P2** | Canal encubierto confirmado (payload ≠ eco); el score baja porque solo hay una familia de fuentes | Limitar ICMP > 512 B en el switch; entrevista al usuario | \[Integrante 2\] | 16:36 |
| 0010 / 192.168.50.88 | 3 | **Subir a P3** | Escaneo lento diseñado para evadir el umbral | Regla LAB-SCAN-SLOW; seguimiento 24 h | \[Integrante 3\] | 16:58 |
| 0005 / reflectores | 13 | Escalar | Volumen externo, fuera del control del servidor | Ticket al proveedor (RTBH/limpieza) | \[Integrante 3\] | 14:12 |
| 0008 / 192.168.50.15 | 3 | Mantener supresión | Origen, ventana y alcance coinciden con MNT-2211 | Ninguna | \[Integrante 1\] | 16:52 |
| 0001 / 198.18.0.0/15 | 3 | Cerrar | Prueba autorizada (acta LAB-02) | Ninguna | \[Integrante 1\] | 09:10 |
| 0009 / 192.168.50.112 | 6 | Remediar | FTP anónimo habilitado (Caso 3) | Deshabilitar el anónimo en FileZilla | \[Integrante 3\] | 11:40 |

### 9.5 Mitigación y defensa

- **Revisión humana** antes de cualquier acción disruptiva; las acciones automáticas se limitan a enriquecer, agrupar y notificar.
- **Control de acceso a los logs** por roles; los logs crudos pueden contener datos personales.
- **Evaluación de sesgo y deriva.** Revisar mensualmente qué entidades sube o baja el score; por ejemplo, la fórmula castiga a las anomalías vistas por una sola familia, como .77.
- **Registro de decisiones** (tabla 9.4) y **posibilidad de reversión** de toda acción: cuarentena con caducidad y bloqueo temporal.

### 9.6 Preguntas de análisis

**¿Cómo explicar una alerta a un analista?** Con los mismos elementos de la alerta enriquecida: qué entidad y activo, qué se observó (hechos y conteos con hora), de qué fuentes (y cuántas independientes), por qué tiene esa puntuación (cada sumando visible), qué alternativas benignas se descartaron y cuáles no, dónde está la evidencia (archivo + hash + `event.id`) y qué acción se sugiere con su riesgo. Si la alerta viene del modelo ML, se agrega qué atributos se desviaron y cuánto (Figura 4.4). Un "score 0,87" sin contexto no es explicable ni auditable.

**¿Qué riesgo supone automatizar bloqueos basados solo en una puntuación?**

- *Falsos positivos con impacto real:* aquí la prueba de carga o el escáner autorizado habrían sido bloqueados sin la supresión contextual, y la línea base del Caso 4 habría bloqueado a todos los usuarios durante las inscripciones.
- *Abuso por el atacante:* si el sistema bloquea automáticamente, un atacante puede falsificar orígenes (casos 1 y 6) para que la defensa bloquee al gateway, al DNS o a clientes legítimos. La defensa se convierte en un DoS.
- *Falsos negativos ocultos:* .77 y .88 tienen scores bajos y pasarían inadvertidos si solo se actúa por umbral.
- *Deriva y errores del modelo o del LLM:* como el acceso exitoso inventado en 9.3.
- *Responsabilidad:* una decisión sin un humano identificable no se puede auditar ni revertir con criterio.

## Caso 10. Mensajería XMPP: interceptación y errores de TLS

La comunicación cliente–servidor de `xmpp.lab.test` está correctamente protegida. Negocia TLS 1.3 (TLS\_AES\_256\_GCM\_SHA384, X25519), el certificado valida contra la CA del laboratorio y el nombre coincide; el servidor rechaza TLS 1.1 y exige STARTTLS antes de autenticar. Hay tres fallas que corregir: el certificado de `conference.lab.test` venció el 30-sep-2026, la consola `/admin` escucha en 0.0.0.0:5280 sin TLS y la VM .66 intentó autenticarse como `admin` y `root` y acceder a `/admin`.

**Situación.** Se investiga si la comunicación entre clientes y servidor de mensajería está correctamente protegida.

**Evidencia analizada.**

- **Pruebas TLS reales** con OpenSSL 3.0.13, ejecutadas el 17-nov-2026 en loopback (127.0.0.1 hace de 192.168.50.30) con certificados emitidos por una CA de laboratorio propia. Salidas en `C10_pruebas_tls_reales.json`.
- `C10_xmpp_starttls_lab.pcap` (sintético, 41 paquetes).
- Extractos de `ejabberd.yml` y `ejabberd.log` del servidor de laboratorio (simulados).

### 10.1 Procedimiento ejecutado

1. Revisión de la configuración TLS de ejabberd: listeners, `starttls_required`, `protocol_options`, cifrados, `certfiles` e interfaces de administración.
2. Verificación de certificados con `openssl x509` (sujeto, emisor, SAN, vigencia, huella SHA-256) y `openssl verify` (cadena de confianza).
3. Pruebas de negociación con `openssl s_client`: conexión validada con `-verify_hostname` y `-verify_return_error`, versiones TLS 1.2 y 1.1, certificado vencido y nombre incorrecto.
4. Captura de metadatos de una sesión autorizada (`tcp.port == 5222`), comprobando que el contenido cifrado no se trate como texto legible.
5. Revisión de logs: errores de negociación, certificados inválidos y conexiones inesperadas.

### 10.2 Evidencias

&#91;image: Figura 10.1\]

**Figura 10.1.** Salida real de `openssl s_client`: TLS 1.3 verificado, TLS 1.2 aceptado, TLS 1.1 rechazado por el servidor (alerta 70, *protocol version*), certificado vencido (error 10) y nombre incorrecto (error 62).

&#91;image: Figura 10.2\]

**Figura 10.2.** Salida real de `openssl x509` y `openssl verify`: SAN `xmpp.lab.test`, `lab.test` e IP 192.168.50.30; vigencia 01-oct-2026 a 01-ene-2027; `conference` vencido.

&#91;image: Figura 10.3\]

**Figura 10.3.** Wireshark `tcp.port == 5222`. Solo las cabeceras de stream y `<starttls/>` viajan en claro; después todo es *Application Data*. El cliente heredado .119 recibe `<encryption-required/>`.

&#91;image: Figura 10.4\]

**Figura 10.4.** `ejabberd.yml` y `ejabberd.log`: `/admin` en 0.0.0.0:5280 con `tls: false`, certificado vencido en uso y fallos de autenticación desde .66.

### 10.3 Checklist TLS

| # | Control | Resultado | Evidencia |
| --- | --- | --- | --- |
| 1 | STARTTLS obligatorio en c2s (5222) | Cumple | `starttls_required: true`; fallo `encryption-required` para .119 |
| 2 | Versión mínima TLS 1.2 | Cumple | TLS 1.1 rechazado con alerta 70; TLS 1.2 y 1.3 aceptados |
| 3 | Cifrados robustos (AEAD, PFS) | Cumple | TLS\_AES\_256\_GCM\_SHA384 / ECDHE-ECDSA-AES256-GCM-SHA384, X25519 |
| 4 | Nombre del certificado = nombre del servicio (SAN) | Cumple | `Verified peername: xmpp.lab.test` |
| 5 | Cadena de confianza válida | Cumple | `openssl verify`: OK contra LAB-CA Raíz 2026 |
| 6 | Vigencia de **todos** los certificados | **No cumple** | `conference.lab.test` venció el 30-sep-2026 (error 10) |
| 7 | Clientes validan el certificado (sin "aceptar siempre") | Cumple en la prueba | `-verify_return_error` aborta con error 10 y 62 |
| 8 | Interfaces administrativas limitadas | **No cumple** | `/admin` en 0.0.0.0:5280 con `tls: false`; accesos 401 desde .66 |
| 9 | s2s con STARTTLS obligatorio | Cumple | `s2s_use_starttls: required` |
| 10 | Servidor actualizado | Por verificar | Confirmar la versión de ejabberd frente a los avisos de seguridad vigentes |
| 11 | Mecanismo SASL robusto | Cumple | SCRAM-SHA-256 en los inicios de sesión exitosos |
| 12 | E2EE según el modelo de amenaza | No configurado | OMEMO no exigido (ver 10.6) |

**Eventos anonimizados:**

| Hora | Evento | Origen | Valoración |
| --- | --- | --- | --- |
| 17:00:01 | Autenticación SCRAM-SHA-256 aceptada (`estudiante01`) | .101 | Normal |
| 17:00:09 | Fallo PLAIN: *encryption required* | .119 | Cliente heredado; control funcionando |
| 17:02:15 | *Failed to secure* conference: *certificate has expired* | servidor | Falla de configuración |
| 17:04:41–17:04:43 | Fallos SCRAM para `admin@` y `root@` | **.66** | Patrón de conexión no esperado |
| 17:05:02 | Acceso a `/admin/` (HTTP 401) | **.66** | Servicio de administración expuesto y sondeado |

### 10.4 Indicadores observados

| Indicador de la guía | Observado |
| --- | --- |
| Certificados vencidos o no confiables | `conference.lab.test` vencido; certificado `localhost` en la interfaz de administración (error 62) |
| Negociación insegura | No se observa: TLS < 1.2 rechazado y PLAIN sin TLS rechazado |
| Servicios de administración expuestos | `/admin` en 5280/tcp, todas las interfaces, sin TLS |
| Patrones de conexión que no coinciden con el uso esperado | .66, que no es usuario registrado, prueba `admin` y `root` y la consola web |

**Hipótesis.** No hay interceptación del contenido: el canal c2s es robusto. El riesgo real está en la superficie administrativa y en el certificado vencido. Este último rompe la federación de salas y empuja a los usuarios a aceptar advertencias, lo que entrena malos hábitos y facilita un MITM. .66 vuelve a aparecer haciendo reconocimiento (ver Caso 9).

### 10.5 Plan de corrección

| # | Acción | Plazo | Verificación |
| --- | --- | --- | --- |
| 1 | Renovar `conference.lab.test` y automatizar la renovación con alerta a 30 días del vencimiento | 24 h | `openssl x509 -checkend 2592000` en cron con alerta al SIEM |
| 2 | `/admin`: `ip: "127.0.0.1"` (acceso por túnel SSH) o, si debe ser remoto, `tls: true` + ACL `admin` solo desde 192.168.50.10 | 24 h | `Test-NetConnection 192.168.50.30 -Port 5280` = False desde clientes |
| 3 | Reemplazar el certificado `localhost` de la interfaz de administración por uno con SAN correcto | 1 semana | `-verify_hostname` OK |
| 4 | Mantener ejabberd actualizado y suscribirse a los avisos de seguridad | Continuo | Versión documentada en el inventario |
| 5 | Limitar los intentos de autenticación (`mod_fail2ban`) | 1 semana | Bloqueo temporal tras 5 fallos |
| 6 | Habilitar OMEMO en los clientes si el modelo de amenaza incluye al operador del servidor | Según riesgo | Política de clientes |

### 10.6 Preguntas de análisis

**¿Qué protege TLS y qué no protege?** TLS protege el **canal** entre dos puntos: confidencialidad del contenido, integridad (no se puede modificar sin detección) y autenticación del servidor mediante su certificado, si el cliente lo valida. En la Figura 10.3 los mensajes son *Application Data* ilegibles. No protege:

- Los **metadatos**: IPs, puertos, SNI, tamaños, horarios y frecuencia de mensajes siguen visibles.
- El contenido en los **extremos**: el servidor descifra y ve todo en claro, y un servidor comprometido o su operador pueden leer y guardar mensajes.
- Al usuario que **acepta un certificado inválido**: el MITM se vuelve trivial.
- La disponibilidad: no impide un RST forjado (Caso 5) ni un DoS.
- Las vulnerabilidades de la aplicación y las credenciales débiles.

**¿En qué se diferencia el cifrado de transporte del cifrado de extremo a extremo?** El cifrado de transporte (TLS en c2s y s2s) protege cada tramo por separado: cliente→servidor y servidor→servidor. En cada servidor intermedio el mensaje se descifra y vuelve a cifrar, así que el servidor es un punto de confianza que ve el contenido. El cifrado de extremo a extremo (en XMPP, OMEMO o OpenPGP) cifra el mensaje en el dispositivo del emisor con claves que solo tienen los dispositivos de los destinatarios. Los servidores solo reenvían texto cifrado y no pueden leerlo aunque estén comprometidos. Ambos se complementan: E2EE protege el contenido frente al servidor y TLS protege además los metadatos XMPP (remitente, destinatario, presencia) frente a quien observa la red.

## Registro de hallazgos (formato mínimo de la sección 7)

Se registraron 12 hallazgos con los nueve campos que exige la guía. Las horas son del 05-nov-2026 en UTC−5, con relojes sincronizados por NTP a 192.168.50.1. Las herramientas, versiones y filtros de cada validación están en el campo correspondiente.

### H-01 · Caso 1 · SYN flood (prueba autorizada)

| Campo | Registro |
| --- | --- |
| Identificador | C1-E01 / C1-E02 · \[Integrante 1\] |
| Fecha/hora | 05-nov-2026 09:02:00–09:05:00 UTC−5 · NTP sincronizado |
| Origen/destino | 198.18.0.0/15 (36 733 IP) → 192.168.50.20:80/TCP |
| Observación | 312 SYN/s; razón ACK/SYN 0,001; 512 conexiones en SYN\_RECEIVED; 9,2 % de clientes atendidos |
| Hipótesis | Inundación SYN con orígenes falsificados. Alternativas: flash crowd, pérdida de red y escaneo, descartadas (sección 1.3) |
| Validación | PCAP con `tcp.flags.syn==1 && tcp.flags.ack==0` (Wireshark 4.4); `netstat -ano` y `Get-NetTCPConnection` (Windows Server 2022); acta LAB-02 |
| Severidad | Alta (impacto: indisponibilidad; probabilidad: alta sin mitigación). En este caso, prueba autorizada |
| Acción | SYN cookies + hashlimit en el gateway · Infraestructura · FP: clientes tras un NAT · Verificado: 100 % de éxito después |
| Integridad | C1\_synflood\_lab.pcap · 6 683 994 B · `58f6887a…355ad7` |

### H-02 · Caso 2 · Túnel DNS desde .44

| Campo | Registro |
| --- | --- |
| Identificador | C2-E01 / C2-E02 · \[Integrante 2\] |
| Fecha/hora | 10:05:00–10:13:00 UTC−5 |
| Origen/destino | 192.168.50.44:efimero → 192.168.50.53:53/UDP (`*.t.exfil-lab.test`) |
| Observación | 952 consultas TXT únicas; longitud media 124; etiqueta de 60 car.; entropía 4,83; \~2/s |
| Hipótesis | Túnel DNS bidireccional (\~59 KB). Alternativas: telemetría o CDN, descartadas por inventario y volumen |
| Validación | `udp.port == 53` y `dns`; log de BIND 9 (`grep`/`uniq -c`); script de entropía (Python 3.13) |
| Severidad | Alta (posible fuga de datos; patrón inequívoco) |
| Acción | Investigar el proceso en .44 → RPZ · Admin. DNS · FP medio (CDN) con lista blanca · Verificar: 0 consultas a `exfil-lab.test` |
| Integridad | C2\_dns\_tunel\_entrenamiento.pcap · 645 298 B · `3839bd49…ed995` |

### H-03 · Caso 2 · Resolver no autorizado desde .66

| Campo | Registro |
| --- | --- |
| Identificador | C2-E03 · \[Integrante 2\] |
| Fecha/hora | 10:00–10:15 UTC−5 |
| Origen/destino | 192.168.50.66 → 192.168.50.99:53/UDP |
| Observación | 25 consultas a nombres `lab.test` contra un resolver no aprobado; 0 en el log del resolver autorizado |
| Hipótesis | Desvío de resolución (posible preparación de MITM o evasión de registro). Alternativa: configuración DHCP antigua, abierta |
| Validación | `dns && ip.dst == 192.168.50.99`; comparación con `queries.log` |
| Severidad | Media |
| Acción | Bloquear el 53 saliente salvo .53 · Infraestructura · FP bajo · Verificar con la regla `sid:1000202` |
| Integridad | C2\_consultas\_dns.csv · 291 174 B · `f0b4626d…e470` |

### H-04 · Caso 3 · Fuerza bruta RDP/FTP desde .66

| Campo | Registro |
| --- | --- |
| Identificador | C3-E01 · \[Integrante 3\] |
| Fecha/hora | 11:10:04–11:21:03 UTC−5 |
| Origen/destino | 192.168.50.66 → 192.168.50.20:3389/TCP y :21/TCP |
| Observación | 118 eventos 4625 (tipo 10) + 70 respuestas FTP 530; 8 cuentas de diccionario; pico de 23/min; 0 éxitos |
| Hipótesis | Adivinación de contraseñas. Alternativa: usuario que olvidó su clave, descartada (substatus 0xC0000064, cuentas inexistentes) |
| Validación | Visor de eventos (Seguridad, ID 4625/4624) y FileZilla Server.log |
| Severidad | Alta |
| Acción | RDP solo desde administración + bloqueo de cuenta; retirar FTP · Infraestructura · FP bajo · Verificar con `LAB-AUTH-01` |
| Integridad | C3\_eventos\_autenticacion.csv · 13 610 B · `1131e3b0…656c` |

### H-05 · Caso 3 · Servicios heredados y configuración por defecto

| Campo | Registro |
| --- | --- |
| Identificador | C3-E02 / C3-E03 · \[Integrante 3\] |
| Fecha/hora | Inventario 11:00; Nmap autorizado 11:04–11:05; login anónimo 11:21:40 UTC−5 |
| Origen/destino | 192.168.50.20: 21, 445, 3306, 8080/TCP y 161/UDP; FTP anónimo desde .112 |
| Observación | FileZilla 0.9.60 sin soporte con anónimo; MySQL 5.7 EOL en 0.0.0.0; SMBv1; Tomcat `/manager`; SNMP `public`; credenciales FTP en claro |
| Hipótesis | Superficie expuesta innecesaria (exposición + vulnerabilidad, sin explotación con daño demostrada) |
| Validación | PowerShell (`Get-NetTCPConnection`, `Get-WindowsOptionalFeature`); Nmap 7.95 `-sT -sV` con alcance limitado; PCAP FTP |
| Severidad | Crítica (RDP y Tomcat con R = 20) |
| Acción | Plan de remediación 3.4 (9 acciones) · Equipo web / Infraestructura · FP n/a · Verificar repitiendo el inventario |
| Integridad | C3\_ftp\_texto\_claro.pcap · 1 453 B · `58adbe64…0248` |

### H-06 · Caso 4 · Alerta ML de exfiltración HTTP (conjunto de evaluación)

| Campo | Registro |
| --- | --- |
| Identificador | C4-E01 · \[Integrante 1\] |
| Fecha/hora | 04-nov-2026 09:40–09:59 UTC−5 (minutos sintéticos) |
| Origen/destino | Tráfico agregado hacia SRV-WEB-LAB |
| Observación | Score de 0,599 > umbral de 0,564; `ratio_pet_resp` +69,7 σ; `bytes_por_flujo` +12,0 σ |
| Hipótesis | Carga masiva cliente→servidor (exfiltración o subida). Alternativa: copia de respaldo autorizada (verificar con la agenda) |
| Validación | IsolationForest (scikit-learn 1.9.1), partición temporal; etiqueta de evaluación = exfiltración; 20 de 20 minutos detectados |
| Severidad | Media (prototipo: solo prioriza) |
| Acción | Enviar a triaje humano con la explicación por atributo · SOC · FP de 0 % con persistencia 2/3 · Revisar la deriva semanalmente |
| Integridad | C4\_dataset\_agregado\_por\_minuto.csv · 1 583 878 B · `5f200443…2d2a` |

### H-07 · Caso 5 · RST con indicios de inyección

| Campo | Registro |
| --- | --- |
| Identificador | C5-E01 · \[Integrante 2\] |
| Fecha/hora | 13:20:02–13:23:34 UTC−5 |
| Origen/destino | "192.168.50.20:443" (MAC 00:50:56:a1:00:66, puerto Gi0/12) → 192.168.50.121 |
| Observación | 7 RST con TTL 64 (servidor = 128) y MAC ajena; datos legítimos 0,3 ms después; 7 RST de respuesta del cliente |
| Hipótesis | Inyección de RST desde .66 en la misma L2. Alternativas: IPS, reinicio de servicio y pérdida, descartadas (sección 5.3) |
| Validación | `tcp.flags.reset == 1` con columnas `ip.ttl` y `eth.src`; Zeek 7.0 `weird.log`; Suricata `sid:1000501`; CAM del switch |
| Severidad | Alta |
| Acción | DAI + IP Source Guard; segmentar servidores · Infraestructura · FP bajo · Verificar: 0 alertas de `sid:1000501` |
| Integridad | C5\_tcp\_resets\_lab.pcap · 2 306 126 B · `105d10b8…5818` |

### H-08 · Caso 6 · Reflexión UDP contra el servidor

| Campo | Registro |
| --- | --- |
| Identificador | C6-E01 · \[Integrante 3\] |
| Fecha/hora | 14:04:00–14:07:00 UTC−5 |
| Origen/destino | 81 reflectores (198.51.100.0/24, 203.0.113.0/24) desde 53, 123 y 1900/UDP → 192.168.50.20 |
| Observación | 314 975 respuestas (296 MB) frente a 3 312 solicitudes; razón de bytes de hasta 7 393× |
| Hipótesis | DDoS por reflexión con la IP del servidor falsificada. Alternativa: ráfaga legítima, descartada (no es simétrica) |
| Validación | Contadores agregados del gateway; `named-checkconf`, `dig`, `ntpq`/`ntpdc`, `Get-Service` |
| Severidad | Media (servicios propios no reflectores; el impacto depende del enlace) |
| Acción | Filtrar respuestas no solicitadas; ticket al proveedor · Infraestructura/ISP · FP bajo · Verificar la razón < 5 |
| Integridad | C6\_contadores\_udp\_gateway.csv · 168 323 B · `dcc0f3f8…5f5f` |

### H-09 · Caso 7 · Barrido ICMP desde .66

| Campo | Registro |
| --- | --- |
| Identificador | C7-E01 · \[Integrante 1\] |
| Fecha/hora | 15:05:00–15:05:06 UTC−5 |
| Origen/destino | 192.168.50.66 → 192.168.50.1–.254 (ICMP 8/0) |
| Observación | 254 echo request en 6,4 s; id fijo 0x1d2a; payload de 0 B; 7 hosts responden |
| Hipótesis | Descubrimiento de hosts (T1018). Alternativa: monitoreo autorizado, descartada (no figura en el inventario) |
| Validación | `icmp && ip.src == 192.168.50.66`; Estadísticas ▸ Endpoints |
| Severidad | Media |
| Acción | Regla `sid:1000701`; correlacionar con H-04, H-07 y H-11 · SOC · FP bajo |
| Integridad | C7\_icmp\_lab.pcap · 1 352 658 B · `56a4d018…89a3` |

### H-10 · Caso 7 · Túnel ICMP .77 ↔ .250

| Campo | Registro |
| --- | --- |
| Identificador | C7-E02 · \[Integrante 2\] |
| Fecha/hora | 15:10:00–15:23:58 UTC−5 |
| Origen/destino | 192.168.50.77 ↔ 192.168.50.250 (ICMP 8/0 y 0/0) |
| Observación | 540 echo de 1 000–1 400 B; entropía de 7,82 bits/byte; intervalo de 1,005 s; 540 de 540 replies con payload distinto |
| Hipótesis | Canal encubierto sobre ICMP. Alternativa: prueba de MTU, descartada por entropía y eco incoherente |
| Validación | `icmp && ip.addr == 192.168.50.77`; emparejamiento id/secuencia (Python) |
| Severidad | Alta (el analista la escala de P3 a P2) |
| Acción | Limitar ICMP > 512 B; `sid:1000702` · Infraestructura · FP bajo (pruebas de MTU documentadas) |
| Integridad | C7\_icmp\_lab.pcap · 1 352 658 B · `56a4d018…89a3` |

### H-11 · Caso 8 · Escaneo de puertos y fingerprinting (.66) y escaneo lento (.88)

| Campo | Registro |
| --- | --- |
| Identificador | C8-E01 / C8-E02 · \[Integrante 3\] |
| Fecha/hora | .66: 16:10:00–16:10:16; .88: 16:00:59–16:56:37 UTC−5 |
| Origen/destino | 192.168.50.66 y .88 → 192.168.50.20 (1–1024/TCP + puertos altos) |
| Observación | .66: 1 030 puertos en \~8,5 s + 4 banners; .88: 27 puertos × 5 vueltas, máx. 3 por minuto |
| Hipótesis | Reconocimiento activo (T1046); .88 evade umbrales. Alternativa: escáner autorizado, que solo aplica a .15 |
| Validación | pfirewall.log (Windows Defender Firewall); PCAP; Zeek conn.log; Suricata `sid:1000801`; ticket MNT-2211 |
| Severidad | Alta (.66) / Media (.88) |
| Acción | Endurecimiento 8.4 + reglas rápida y lenta; bloqueo temporal con aprobación · SOC/Infraestructura · FP: .15 suprimido por ventana |
| Integridad | C8\_escaneo\_autorizado.pcap · 643 221 B · `eabea834…d134`; C8\_pfirewall.log · 392 883 B · `1b2df3f1…d723` |

### H-12 · Caso 10 · Certificado vencido y consola de administración XMPP expuesta

| Campo | Registro |
| --- | --- |
| Identificador | C10-E01 / C10-E02 · \[Integrante 1\] |
| Fecha/hora | Log: 17:02:15–17:05:02 UTC−5 (05-nov); pruebas OpenSSL: 17-nov-2026 19:4x UTC−5 |
| Origen/destino | 192.168.50.30:5280/TCP (`/admin`), `conference.lab.test`; accesos desde 192.168.50.66 |
| Observación | Certificado vencido el 30-sep-2026 (error 10); `/admin` sin TLS en 0.0.0.0; 2 fallos SCRAM (`admin`, `root`) y un 401 desde .66 |
| Hipótesis | Mala gestión del ciclo de vida de certificados + superficie administrativa expuesta y sondeada |
| Validación | OpenSSL 3.0.13 (`s_client`, `x509`, `verify`): salida real; `ejabberd.yml` y `ejabberd.log` |
| Severidad | Alta |
| Acción | Renovar y automatizar; `/admin` a 127.0.0.1 · Admin. XMPP · FP n/a · Verificar con `-checkend` y el puerto 5280 cerrado |
| Integridad | C10\_pruebas\_tls\_reales.json · 2 449 B · `9f153986…9a84`; C10\_xmpp\_starttls\_lab.pcap · 9 404 B · `4f37a240…dd7b` |

## Reglas de detección propuestas y justificadas

Se proponen 15 reglas: 10 firmas de Suricata y 5 correlaciones de SIEM. Todas alertan; ninguna bloquea automáticamente, como permite la guía ("no se exige activar bloqueos automáticos en producción"). Cada umbral se justifica con la línea base medida en el caso correspondiente.

| # | ID | Motor | Detecta | Umbral | Justificación con datos | Riesgo de falso positivo y control |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 1000101 | Suricata | SYN flood hacia el servidor web | 500 SYN en 10 s por destino | Base 3,9 SYN/s; ráfaga 312 SYN/s (Caso 1) | Picos legítimos: exigir 10 s sostenidos y mirar la razón ACK/SYN |
| 2 | 1000201 | Suricata | QNAME > 52 car. sostenido | 30 en 60 s por origen | Estaciones: 13,7 car.; túnel: 124 car. (Caso 2) | CDN y telemetría: lista blanca de dominios |
| 3 | 1000202 | Suricata | DNS a un resolver no autorizado | 1 alerta cada 5 min por origen | Solo .53 debe consultar (Caso 2) | Bajo |
| 4 | LAB-AUTH-01 | Wazuh | Fuerza bruta (4625 / FTP 530) | > 10 en 60 s o ≥ 5 cuentas en 10 min por origen | Base: 3 fallos en 30 min; ataque: 23/min (Caso 3) | Errores de digitación: el umbral los excluye |
| 5 | 1000501 | Suricata | RST del servidor con TTL anómalo | TTL < 100 desde .20 (Windows, misma L2) | Legítimo 128; forjado 64 (Caso 5) | Cambio de SO del servidor: revisar la regla en cada cambio |
| 6 | 1000601 | Suricata | Respuestas DNS grandes no solicitadas | dsize > 512, 100 en 10 s por destino | Reflexión \~1 450 B (Caso 6) | Solo aplica a hosts que no son el resolver |
| 7 | 1000602 | Suricata | Respuestas NTP tipo `monlist` | dsize > 400, 50 en 10 s | NTP normal 90 B; `monlist` 468 B | Bajo |
| 8 | 1000603 | Suricata | Respuestas SSDP entrantes masivas | 50 en 10 s por destino | SSDP deshabilitado en el servidor | Bajo |
| 9 | LAB-UDP-ASYM | SIEM | Asimetría respuesta/solicitud UDP | Razón de bytes > 5 durante 60 s | Base 1–2×; reflexión 998–7 393× (Caso 6) | Muy bajo: las ráfagas legítimas son simétricas |
| 10 | 1000701 | Suricata | Barrido ICMP | 50 destinos en 10 s por origen | Base 4 echo/5 min; barrido 254 en 6,4 s (Caso 7) | Monitoreo: lista blanca por IP |
| 11 | 1000702 | Suricata | Echo ICMP grande persistente | dsize > 512, 20 en 60 s | Base 32 B; túnel 1 000–1 400 B (Caso 7) | Pruebas de MTU documentadas |
| 12 | 1000801 | Suricata | Escaneo SYN rápido | 25 puertos en 60 s por origen | Clientes: 2 puertos; escaneo: 1 030 (Caso 8) | Escáner autorizado: supresión por ventana en el SIEM |
| 13 | LAB-SCAN-SLOW | SIEM | Escaneo lento | ≥ 15 puertos con REJ/RST en 60 min por origen | .88: 3/min, pero 27 puertos en 56 min (Caso 8) | Aplicaciones con puertos dinámicos: excluir los rangos altos conocidos |
| 14 | LAB-ML-01 | SIEM + IsolationForest | Desviación multivariable | Score > p99,5 del entrenamiento, 2 de 3 minutos | PR-AUC 0,595; FPR 0 % con persistencia (Caso 4) | Deriva: revisión semanal; solo prioriza |
| 15 | LAB-TLS-CERT | SIEM (cron) | Certificado próximo a vencer o vencido | < 30 días de vigencia | `conference.lab.test` vencido sin aviso (Caso 10) | Ninguno |

**Archivo `local.rules` consolidado (Suricata 7):**

```
alert tcp any any -> 192.168.50.20 [80,443] (msg:"LAB TCP SYN > 50/s sostenido hacia servidor web"; flags:S,12; threshold: type both, track by_dst, count 500, seconds 10; classtype:attempted-dos; sid:1000101; rev:1;)
alert dns $HOME_NET any -> any any (msg:"LAB DNS QNAME largo sostenido (posible tunel)"; dns.query; bsize:>52; threshold: type both, track by_src, count 30, seconds 60; classtype:policy-violation; sid:1000201; rev:1;)
alert udp $HOME_NET any -> ![192.168.50.53] 53 (msg:"LAB DNS hacia resolver no autorizado"; threshold: type limit, track by_src, count 1, seconds 300; classtype:policy-violation; sid:1000202; rev:1;)
alert tcp 192.168.50.20 any -> $HOME_NET any (msg:"LAB TCP RST con TTL distinto al de la sesion (posible inyeccion)"; flags:R,12; ttl:<100; classtype:misc-attack; sid:1000501; rev:1;)
alert udp any 53 -> [$HOME_NET,!192.168.50.53] any (msg:"LAB respuesta DNS grande no solicitada (posible reflexion)"; dsize:>512; threshold: type both, track by_dst, count 100, seconds 10; classtype:attempted-dos; sid:1000601; rev:1;)
alert udp any 123 -> $HOME_NET any (msg:"LAB respuesta NTP modo 7/monlist hacia la LAN"; dsize:>400; threshold: type both, track by_dst, count 50, seconds 10; classtype:attempted-dos; sid:1000602; rev:1;)
alert udp any 1900 -> $HOME_NET any (msg:"LAB respuestas SSDP entrantes masivas"; threshold: type both, track by_dst, count 50, seconds 10; classtype:attempted-dos; sid:1000603; rev:1;)
alert icmp $HOME_NET any -> $HOME_NET any (msg:"LAB barrido ICMP > 50 destinos/10 s"; itype:8; threshold: type both, track by_src, count 50, seconds 10; classtype:network-scan; sid:1000701; rev:1;)
alert icmp any any -> any any (msg:"LAB ICMP echo con payload > 512 B persistente (posible tunel)"; itype:8; dsize:>512; threshold: type both, track by_src, count 20, seconds 60; classtype:policy-violation; sid:1000702; rev:1;)
alert tcp $HOME_NET any -> 192.168.50.20 any (msg:"LAB Escaneo SYN > 25 puertos/60 s"; flags:S,12; threshold: type both, track by_src, count 25, seconds 60; classtype:attempted-recon; sid:1000801; rev:1;)
```

**Ejemplo de regla Wazuh para LAB-AUTH-01** (`local_rules.xml`):

```xml
<group name="lab,authentication_failures,">
  <!-- 60122 = fallo de inicio de sesión de Windows en el ruleset de Wazuh -->
  <rule id="100101" level="10" frequency="10" timeframe="60">
    <if_matched_sid>60122</if_matched_sid>
    <same_source_ip />
    <description>LAB-AUTH-01: más de 10 fallos de autenticación desde la misma IP en 60 s</description>
    <mitre><id>T1110</id></mitre>
  </rule>
</group>
```

**Validación de las reglas.** Cada firma se probó conceptualmente contra el PCAP de su caso y contra el tráfico de línea base del mismo archivo. Antes del despliegue físico se recomienda ejecutar `suricata -T -S local.rules` y `suricata -r <pcap> -S local.rules` sobre cada PCAP del Anexo A, y comparar las alertas con la columna "Detecta" de esta tabla.

## Plan de mejora priorizado

Las acciones se ordenan por riesgo reducido frente a esfuerzo. Las de las primeras 24 h cierran los hallazgos de severidad crítica o alta con poco costo; las de 30–90 días atacan las causas estructurales: segmentación, ciclo de vida de servicios y madurez del SOC.

| Prioridad | Acción | Hallazgos | Tipo de control | Plazo | Responsable | Criterio de cierre |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Contener .66 (cuarentena VLAN reversible) y adquisición forense de memoria y disco | H-03, H-04, H-07, H-09, H-11 | Correctivo | 24 h | SOC + Infraestructura | Imagen con hash; informe forense |
| 2 | Cerrar 8080 (Tomcat de pruebas) y restringir RDP/WinRM a la red de administración + bloqueo de cuenta | H-04, H-05 | Preventivo | 24 h | Infraestructura / Equipo web | Puertos no visibles desde clientes |
| 3 | Renovar el certificado de `conference` y limitar `/admin` de ejabberd a 127.0.0.1 | H-12 | Preventivo / correctivo | 24 h | Admin. XMPP | `-checkend` OK; 5280 cerrado |
| 4 | Investigar .44 y .77 (procesos, usuarios); RPZ y límite de ICMP > 512 B | H-02, H-10 | Correctivo / detectivo | 48 h | SOC | Sin consultas a `exfil-lab.test` ni ICMP grande |
| 5 | DHCP snooping, DAI, IP Source Guard y port-security en la VLAN 50 | H-07, H-03 | Preventivo | 1 semana | Infraestructura | Prueba de ARP spoofing bloqueada |
| 6 | Retirar FileZilla (→ SFTP), deshabilitar SMBv1 y SNMP v2c, ligar MySQL a 127.0.0.1 | H-05 | Preventivo | 1–2 semanas | Equipo web / Infraestructura | Inventario sin servicios heredados |
| 7 | Desplegar las 15 reglas (sección anterior) con supresiones contextuales documentadas | Todos | Detectivo | 2 semanas | SOC | Reglas probadas contra los PCAP del Anexo A |
| 8 | Política de salida: DNS solo vía .53, filtrado de respuestas UDP no solicitadas, BCP 38 | H-02, H-03, H-08 | Preventivo | 2 semanas | Infraestructura | `sid:1000202` y `LAB-UDP-ASYM` sin alertas |
| 9 | Acuerdo con el proveedor para mitigar DDoS volumétrico (RTBH o limpieza) | H-01, H-08 | Correctivo / recuperación | 30 días | Coordinación TI | Procedimiento probado |
| 10 | Segmentar: VLAN de servidores separada de las VM de estudiantes, tráfico por el gateway con filtrado | H-01, H-05, H-07 | Preventivo | 30 días | Infraestructura | Matriz de flujos permitidos aplicada |
| 11 | Pipeline SIEM del Caso 9 en producción de laboratorio, con registro de validación humana | Todos | Detectivo | 60 días | SOC | Tiempo medio de triaje medido |
| 12 | Piloto del detector ML (solo priorización) con monitoreo de deriva y reentrenamiento validado | H-06 | Detectivo | 90 días | SOC / Analítica | PR-AUC ≥ 0,6 sostenido; 0 bloqueos automáticos |
| 13 | Ciclo de parches mensual, inventario trimestral, renovación automática de certificados y simulacros de restauración | H-05, H-12 | Preventivo / recuperación | Continuo | Todos | Auditoría trimestral |

**Recuperación.** Cada incidente se cierra con la verificación de servicio (tasas de éxito y latencia de vuelta a la línea base, como en el Caso 1), la restauración de configuraciones desde una copia conocida y la lección aprendida incorporada a las reglas y a este plan.

## Conclusiones: límites de la evidencia y oportunidades de mejora

La práctica muestra que un indicador aislado casi nunca basta para concluir. Lo que separa un hallazgo sólido de un falso positivo es la convergencia de fuentes independientes y el descarte explícito de alternativas benignas. Los 154 RST del Caso 5 se redujeron a 7 sospechosos; los picos de carga del Caso 4 y la ráfaga de arranque del Caso 6 resultaron legítimos; y el host .66 solo destacó cuando se correlacionaron cinco casos.

### Límites de la evidencia

1. **Evidencia sintética.** Los PCAP y la telemetría de los casos 1–9 fueron generados por el equipo, así que los patrones son más limpios que en una red real: hay poco ruido de fondo, no hay pérdida de paquetes en la captura y los tiempos son perfectamente sincronizados. Las métricas del Caso 4 (PR-AUC 0,595) no deben extrapolarse a producción.
2. **Vistas reconstruidas.** Los pantallazos de Wireshark, consola, Zeek, Suricata y Visor de eventos reproducen el formato de esas herramientas a partir de los archivos reales del laboratorio, pero no son capturas de pantalla de las aplicaciones. Las salidas de OpenSSL del Caso 10 sí son reales.
3. **Atribución.** Una IP o una MAC identifican un equipo, no a una persona. La atribución de los casos 3, 5, 7 y 8 a la VM .66 se apoya en la tabla CAM del switch, pero falta el análisis forense del host.
4. **Visibilidad.** El sensor ve la VLAN 50 por el puerto espejo. Lo que ocurra dentro de TLS (casos 5 y 10) o en otras VLAN no es observable, y el escaneo lento (.88) muestra que los umbrales por ventana corta dejan huecos.
5. **Tiempos y zonas.** Toda la correlación depende de relojes sincronizados. Un desfase de minutos rompe las uniones por ventana de 15 min del Caso 9.
6. **Las pruebas TLS** se ejecutaron en loopback con una CA de laboratorio. Validan la configuración y el comportamiento de OpenSSL, no la de un ejabberd desplegado.
7. **Reglas de detección** validadas conceptualmente contra los PCAP; falta ejecutarlas en Suricata real con `suricata -r`.

### Oportunidades de mejora

- Repetir los casos con capturas reales del montaje físico (switch con SPAN, Windows Server 2022, BIND, ejabberd) y con los PCAP públicos de entrenamiento que apruebe el docente.
- Medir los falsos positivos de las 15 reglas durante al menos una semana de tráfico normal antes de fijar los umbrales definitivos.
- Extender el modelo ML con atributos por host y ventanas largas (para escaneos lentos) y comparar con modelos supervisados cuando haya etiquetas reales.
- Incorporar IPv6 (NDP, ICMPv6, DNS AAAA), ausente en esta práctica salvo en las políticas.
- Automatizar la cadena de custodia: firma de `SHA256SUMS.txt` y almacenamiento WORM de las evidencias originales.

**Lección central.** Los controles preventivos (segmentación, mínimo de servicios, TLS bien validado, DAI) reducen la superficie. Los detectivos (IDS, SIEM, ML) solo aportan valor con línea base, contexto y un humano que valida antes de actuar.

## Anexos

### Anexo A. Scripts reproducibles

Todo el material se regenera con Python 3 (numpy, pandas, matplotlib, scikit-learn, Pillow, cryptography) y OpenSSL, sin acceso a red. Las semillas son fijas, así que los PCAP y CSV se reproducen bit a bit (sección 2.3).

| Script | Genera | Contenido técnico |
| --- | --- | --- |
| `lib.py` | – | Escritor y lector de PCAP libpcap sin dependencias; tramas Ethernet/IPv4/TCP/UDP/ICMP con checksums válidos; DNS; renderizado de vistas Wireshark y consola; entropía de Shannon; SHA-256 |
| `caso1_synflood.py` | PCAP, CSV por segundo, figuras 1.1–1.4 | Simulación de backlog (512) con expiración de 21 s, SYN cookies y hashlimit |
| `caso2_dns.py` | PCAP, CSV de consultas, figuras 2.1–2.3 | Túnel base32 en etiquetas de 60 car. + TXT; cálculo de longitud y entropía |
| `caso3_servicios.py` | CSV de autenticación, PCAP FTP, figuras 3.1–3.6 | Inventario, eventos 4625/530, matriz de riesgo |
| `caso4_ml.py` / `caso4_ml.ipynb` | Dataset por minuto, métricas, figuras 4.1–4.4 | z robusto estacional frente a IsolationForest; partición temporal |
| `caso5_rst.py` | PCAP, tabla de RST, figuras 5.1–5.3 | Clasificación de RST por TTL, MAC, posición en el flujo y datos posteriores |
| `caso6_udp.py` | Contadores agregados, figuras 6.1–6.3 | Razón respuesta/solicitud por protocolo y minuto |
| `caso7_icmp.py` | PCAP, resumen por IP, figuras 7.1–7.2 | Emparejamiento request/reply y coherencia del payload |
| `caso8_escaneo.py` | PCAP, pfirewall.log, figuras 8.1–8.3 | Puertos únicos por ventana; escaneo rápido, lento y autorizado |
| `caso9_siem.py` | Eventos normalizados, priorización, figuras 9.1–9.3 | Normalización, deduplicación con trazabilidad, score explicable |
| `caso10_xmpp.py` | CA y certificados, salidas OpenSSL reales, PCAP XMPP, figuras 10.1–10.4 | `s_server` y `s_client` en loopback; STARTTLS |

Ejecución:

```bash
cd scripts
for c in caso1_synflood caso2_dns caso3_servicios caso4_ml caso5_rst caso6_udp caso7_icmp caso8_escaneo caso9_siem caso10_xmpp; do
  python3 "$c.py"
done
cd ../evidencias && sha256sum -c SHA256SUMS.txt     # verificación de integridad
```

### Anexo B. Estructura del paquete de evidencias

```
taller2_parte1/
├── evidencias/
│   ├── SHA256SUMS.txt            # hashes de los 17 originales
│   ├── original/                 # copia original (solo lectura)
│   ├── trabajo/                  # copia de análisis + resúmenes JSON + logs de ejecución
│   └── pki/                      # CA y certificados de laboratorio (Caso 10)
├── figuras/                      # 35 figuras PNG (1.1 a 10.4)
└── scripts/                      # lib.py, caso1..caso10, caso4_ml.ipynb
```

Las claves privadas de `pki/` son de un laboratorio desechable y no deben reutilizarse fuera de él.

---

# Parte II. Programación: sistema de localización con consentimiento (GeoConsent)

La Parte II construye **GeoConsent**, un sistema que rastrea (ubica) la posición geográfica de un dispositivo y la muestra en tiempo real o por intervalos, cumpliendo los requisitos funcionales (4.1), técnicos (4.3) y avanzados (4.4) de la guía. Se implementó un backend REST funcional, una app de dispositivo (PWA con GPS real), un bot de Telegram, un panel web con mapa, geofencing, historial, estadísticas y acceso seguro. Todo el código es ejecutable y la demostración de la sección 19 corre sobre HTTP real.

## Encuadre: consentimiento y verdad técnica

La nota final del taller es vinculante: *"No se permite el uso de técnicas que comprometan la integridad de sistemas y personas sin permiso o autorización expresa de los propietarios"* y los participantes deben *"actuar como hackers éticos, sin causar daño"*. Por eso GeoConsent implementa el rastreo **con el consentimiento verificado del titular del dispositivo**, que es la única forma legítima —y técnicamente real— de localizar un celular.

La guía menciona "rastrear la ubicación de un número de WhatsApp o Telegram". Es importante ser honestos en un informe técnico:

- **No existe** una forma legítima de obtener la ubicación de alguien a partir de su número de WhatsApp o Telegram. Ni la API de WhatsApp Business ni la API de bots de Telegram exponen la ubicación de un usuario por su número. El propio texto de la guía lo reconoce ("limitado, indirecto", "no puede rastrear sin que el usuario lo envíe").
- La **única** vía real que describe la guía (4.3.1, app con GPS que envía coordenadas al backend) **requiere instalar una app en el dispositivo y conceder permisos**. Hacerlo en el teléfono de otra persona sin su conocimiento es *stalkerware* e ilegal en la mayoría de jurisdicciones.
- En Telegram, un bot solo recibe una ubicación cuando el usuario **pulsa** el botón "enviar ubicación" o comparte su *live location*: es un acto explícito del titular.

GeoConsent, por tanto, implementa cada requisito de la guía sobre una base de consentimiento: el titular se inscribe, verifica un código que recibe por SMS, ve un indicador permanente de que está compartiendo y puede pausar o revocar (con borrado) en cualquier momento. Esto no recorta ningún requisito —en la sección 13 se muestra la matriz de trazabilidad con los 7 requisitos funcionales y los 4 técnicos cubiertos—; solo los implementa de forma lícita.

## 11. Alcance y principios de diseño

| Principio | Cómo se implementa |
| --- | --- |
| Consentimiento informado y verificado | El dispositivo queda `pending` al inscribirse y solo pasa a `active` cuando el titular introduce el código recibido por SMS. Sin ese paso no se acepta ninguna ubicación. |
| Minimización de datos | Se almacenan únicamente latitud, longitud, precisión, velocidad y batería. No se captura contenido, contactos ni identificadores del dispositivo. |
| Control del titular | El dispositivo puede pausar (`POST /devices/sharing {paused}`) o revocar con borrado del historial (`DELETE /devices/me`) en cualquier momento. |
| Transparencia | La app muestra un indicador de compartición siempre visible y existe un registro de consentimiento (`consent_log`) auditable. |
| Acceso seguro | Autenticación con JWT y separación de roles: el token de propietario no sirve para enviar ubicación y el de dispositivo no sirve para consultar a otros. |
| Propósito legítimo | Casos de uso con consentimiento: flotas y repartidores que aceptan ser ubicados en su jornada, o familias que optan por compartir ubicación entre sí. |

## 12. Arquitectura

GeoConsent separa cuatro planos: los **clientes** (app móvil/PWA, bot de Telegram y panel web), el **borde de seguridad** (TLS + JWT + validación de consentimiento), el **backend** (API REST, motor de geofencing, motor de alertas) y la **persistencia** (base de datos). Los servicios externos (pasarela SMS, notificaciones y teselas de OpenStreetMap) se consumen desde el borde.

&#91;image: Figura II-1\]

**Figura II-1.** Arquitectura del sistema: clientes, borde de seguridad, backend y servicios externos.

| Capa | Tecnología | Responsabilidad |
| --- | --- | --- |
| App del dispositivo | PWA (HTML/JS + Geolocation API); nativo Android/iOS equivalente | Obtener GPS con permiso, mostrar el indicador de compartición, enviar coordenadas |
| Bot de Telegram | python-telegram-bot | Recibir la ubicación que el usuario comparte con el botón nativo |
| Panel del propietario | Leaflet + OpenStreetMap | Mapa, recorridos, geocercas, historial, estadísticas y alertas |
| Borde | HTTPS/TLS + JWT (HS256) | Cifrado en tránsito, autenticación, autorización por rol, estado de consentimiento |
| API REST | Flask (Python 3.13) | Inscripción, verificación, ingesta, consultas, geocercas, alertas |
| Persistencia | SQLite (demo) / PostgreSQL (producción) | owners, devices, locations, geofences, alerts, consent\_log |

## 13. Requisitos funcionales (4.1) — matriz de trazabilidad

Todos los requisitos de la guía están cubiertos. La columna "Evidencia" remite a la demostración (sección 19) o a los artefactos.

| Requisito (4.1) | Implementación en GeoConsent | Evidencia |
| --- | --- | --- |
| Registro por número telefónico | `POST /devices/enroll` vincula el dispositivo a un número E.164; se verifica con código (SMS o código), requisito 4.3.1 | Fig. II-12 (enroll/verify) |
| Solicitud y captura de ubicación | El titular envía su ubicación (automática desde la app, o manual desde el bot) a `POST /locations` | Fig. II-12, II-13 |
| Actualización periódica | Campo `interval_s` por dispositivo (p.ej. cada 10 min); la PWA envía en ese intervalo | Sección 17.1 |
| Visualización en mapa | Panel Leaflet + OpenStreetMap con marcadores, recorridos y geocercas | Fig. II-7, II-8 |
| Alertas (geofencing) | `POST /geofences`; el backend detecta entrada/salida y genera alertas | Fig. II-9, II-13 |
| Historial de ubicaciones | `GET /devices/{id}/history?from&to` devuelve el recorrido por fecha/hora | Sección 19 |
| Acceso seguro | Autenticación JWT, hash de contraseñas (PBKDF2), roles separados | Fig. II-12, II-14 |

## 14. Modelo de datos

Seis entidades con integridad referencial. El estado de consentimiento vive en `devices.consent_state` (`pending` → `active` ↔ `paused` → `revoked`) y cada transición se registra en `consent_log`.

&#91;image: Figura II-2\]

**Figura II-2.** Modelo entidad-relación de la base de datos.

## 15. API REST

La API sigue convenciones REST con versión (`/api/v1`), JSON y códigos HTTP estándar. Autenticación por `Authorization: Bearer <JWT>`.

| Método y ruta | Rol | Descripción | Códigos |
| --- | --- | --- | --- |
| `POST /api/v1/owners` | público | Crea la cuenta del propietario | 201, 409 |
| `POST /api/v1/login` | público | Devuelve un JWT de propietario (1 h) | 200, 401 |
| `POST /api/v1/devices/enroll` | owner | Invita a un número; genera el código de verificación | 201, 400, 409 |
| `POST /api/v1/devices/verify` | público | El titular consiente con el código; devuelve el token del dispositivo (30 d) | 200, 400, 404 |
| `POST /api/v1/devices/sharing` | device | El titular pausa o reanuda la compartición | 200, 400 |
| `DELETE /api/v1/devices/me` | device | Revoca y borra el historial | 200 |
| `POST /api/v1/locations` | device | Ingesta una ubicación; evalúa geocercas | 201, 403 |
| `GET /api/v1/devices` | owner | Lista los dispositivos y su última posición | 200 |
| `GET /api/v1/devices/{id}/history` | owner | Historial por rango de fechas | 200, 404 |
| `GET /api/v1/devices/{id}/stats` | owner | Distancia, duración, velocidades y tiempo en geocercas | 200 |
| `POST /api/v1/geofences` | owner | Crea una geocerca (centro + radio) | 201, 400 |
| `GET /api/v1/alerts` | owner | Lista las alertas de geocerca | 200 |
| `GET /api/v1/devices/{id}/consent-log` | owner | Auditoría del consentimiento | 200, 404 |

## 16. Flujo de inscripción y consentimiento

El consentimiento no es una casilla: es un paso de verificación fuera de banda. El propietario invita a un número; el titular recibe un código por SMS y, solo si lo introduce, el dispositivo se activa y recibe su token. A partir de ahí envía su ubicación en cada intervalo y el propietario puede consultarla.

&#91;image: Figura II-3\]

**Figura II-3.** Diagrama de secuencia del flujo de inscripción, consentimiento, ingesta y consulta.

## 17. Componentes técnicos (4.3)

### 17.1 App móvil del dispositivo (4.3.1)

El cliente de dispositivo se entrega como **PWA** (`webapp/device.html`): una página que usa la **Geolocation API** del navegador, funciona en cualquier teléfono sin instalación desde tienda y es, por tanto, verificable de inmediato. Primero muestra una pantalla de consentimiento (servidor, token, intervalo y una casilla de autorización obligatoria). Al autorizar, solicita el permiso de ubicación, dibuja la posición en el mapa, muestra el indicador verde "Compartiendo" y envía las coordenadas a `POST /locations` en cada intervalo. Incluye botones de **pausar** y de **dejar de compartir y borrar**. El equivalente nativo (Android con un *foreground service* de localización, iOS con Core Location) se documenta en el código; la lógica de consentimiento y envío es la misma.

&#91;image: Figura II-4\]

**Figura II-4.** Pantalla de consentimiento de la app: vinculación por código (SMS) antes de compartir.

&#91;image: Figura II-5\]

**Figura II-5.** Pantalla "Compartiendo": indicador permanente, ahorro de batería y controles de pausa/revocación del titular.

La PWA real está publicada y es interactiva (pide permiso de GPS y comparte ubicación real): ver los enlaces en la sección 22.

### 17.2 Bot de Telegram (4.3.2)

El bot (`bot/telegram_bot.py`, con `python-telegram-bot`) usa el botón nativo `KeyboardButton(request_location=True)`. Telegram **solo** entrega la ubicación cuando el usuario pulsa ese botón o comparte su *live location*, de modo que cada envío es un acto consentido. El bot no puede activar el GPS ni localizar por número. Con `/vincular <token>` el usuario asocia su dispositivo al backend y con `/stop` da de baja su compartición.

&#91;image: Figura II-6\]

**Figura II-6.** Conversación del bot: el usuario comparte su ubicación mediante el botón nativo (consentimiento explícito).

### 17.3 Backend (4.3.3)

- **Lenguaje y framework:** Python 3.13 + Flask. **API REST** con JSON (sección 15).
- **Base de datos:** SQLite en la demo; el esquema es portable a PostgreSQL. Seis tablas con índices sobre `(device_id, epoch)`.
- **Autenticación:** JWT HS256 con dos tipos de token (owner 1 h, device 30 d) y contraseñas con hash PBKDF2 (Werkzeug). El tipo de token se valida en cada endpoint.

### 17.4 Mapa y visualización (4.3.4)

El panel del propietario (`webapp/dashboard.html`) usa **Leaflet** sobre teselas de **OpenStreetMap**. Dibuja las geocercas como círculos, el último punto de cada dispositivo como marcador y el recorrido como polilínea, con reproducción temporal del trayecto. La geocodificación inversa (coordenadas → dirección) se resuelve con el servicio Nominatim de OSM cuando se requiere mostrar direcciones.

&#91;image: Figura II-7\]

**Figura II-7.** Panel del propietario: mapa con recorridos, geocercas, lista de dispositivos, estadísticas y alertas (datos reales de la demo).

## 18. Características avanzadas (4.4)

| # | Característica | Estado | Implementación |
| --- | --- | --- | --- |
| 4.4.1 | Geofencing personalizado (notificaciones por zona) | ✓ funcional | `geofences` + detección entrada/salida con haversine; genera `alerts` |
| 4.4.2 | Ahorro de batería (activación programada) | ✓ funcional | `interval_s` por dispositivo; la PWA espacia los envíos y los reduce en reposo |
| 4.4.3 | Múltiples dispositivos vinculados | ✓ funcional | Un propietario administra N dispositivos (familia, repartidores); la demo usa 2 |
| 4.4.4 | Interfaz web / panel administrativo | ✓ funcional | `dashboard.html` (Leaflet) + endpoints de consulta |
| 4.4.5 | Estadísticas de movimiento o recorridos | ✓ funcional | `GET /stats`: distancia, duración, velocidad media/máx, tiempo en cada geocerca |

&#91;image: Figura II-8\]

**Figura II-8.** Recorridos y geocercas de los dos dispositivos de la demo (representación del panel).

&#91;image: Figura II-9\]

**Figura II-9.** Geofencing: tiempo dentro de cada geocerca y línea temporal de entradas y salidas, calculados por el backend.

&#91;image: Figura II-10\]

**Figura II-10.** Telemetría (velocidad y batería) de los dispositivos a lo largo del recorrido.

&#91;image: Figura II-11\]

**Figura II-11.** Distancia acumulada por dispositivo (fórmula de haversine).

## 19. Demostración de funcionamiento

La demostración (`simulator/run_demo.py`) arranca el servidor Flask real, crea la cuenta del propietario, inscribe dos dispositivos **con consentimiento verificado**, define dos geocercas e inyecta sus recorridos punto a punto por HTTP. Todas las cifras de esta sección provienen de esa ejecución; las imágenes son salidas verídicas de la terminal.

&#91;image: Figura II-12\]

**Figura II-12.** Transcripto real de la API: creación de cuenta, login (JWT), inscripción con código SMS, consentimiento, ingesta con evento de geocerca, pausa del titular (ingesta rechazada 403) y acceso sin token (401).

&#91;image: Figura II-13\]

**Figura II-13.** Ejecución extremo a extremo: inscripción consentida de dos dispositivos, eventos de geocerca y estadísticas calculadas.

&#91;image: Figura II-14\]

**Figura II-14.** Resultado de las 11 pruebas automatizadas (pytest): todas en verde.

### 19.1 Resultados medidos

| Métrica de la demo | Valor |
| --- | --- |
| Llamadas HTTP ejercidas | 156 |
| Dispositivos inscritos con consentimiento | 2 (Repartidor 1, Familiar) |
| Geocercas definidas | 2 (Campus UD r=300 m, Casa r=200 m) |
| Eventos de geocerca detectados | 6 (4 entradas + 2 salidas) |
| Pruebas automatizadas | 11 / 11 correctas |

| Dispositivo | Puntos | Distancia | Duración | Vel. media | Vel. máx | Batería | Tiempo en Campus UD / Casa |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Repartidor 1 | 96 | 5,53 km | 31,7 min | 10,4 km/h | 15,2 km/h | 96 % → 92 % | 4,7 / 1,3 min |
| Familiar | 39 | 2,75 km | 12,7 min | 12,5 km/h | 16,0 km/h | 88 % → 87 % | 1,7 / 0,7 min |

### 19.2 Pruebas que verifican el consentimiento

El conjunto de pruebas no solo comprueba que "funciona", sino que **no funciona sin consentimiento**:

- Un dispositivo recién inscrito está `pending` y no puede enviar ubicación.
- Un código de verificación incorrecto no activa el dispositivo.
- Con la compartición en `paused`, la ingesta se rechaza con 403.
- Al revocar (`DELETE /devices/me`), se borran las ubicaciones y el token deja de servir.
- Un token de dispositivo no puede consultar los endpoints del propietario, ni un propietario ve los dispositivos de otro.

## 20. Seguridad y privacidad

| Control | Implementación |
| --- | --- |
| Cifrado en tránsito | TLS/HTTPS en el borde (en la demo local, HTTP de laboratorio) |
| Autenticación | JWT HS256 con expiración; contraseñas con hash PBKDF2 (nunca en claro) |
| Autorización | Separación de roles owner/device verificada en cada endpoint; aislamiento por propietario |
| Consentimiento | Verificación fuera de banda (código), estado explícito y `consent_log` auditable |
| Minimización y retención | Solo datos de ubicación; borrado inmediato al revocar; retención configurable por política |
| Validación de entrada | Rangos de coordenadas, formato E.164, tamaños y tipos comprobados |
| Derechos del titular | Acceso (historial), pausa, revocación y borrado, todos autoservidos |

**Endurecimiento pendiente para producción** (fuera del alcance del laboratorio): rotación de secretos JWT y almacenamiento en un gestor de secretos; *rate limiting* y bloqueo tras intentos fallidos; cifrado en reposo de la base de datos; expiración/renovación del consentimiento; registro de auditoría centralizado; y una evaluación de impacto en protección de datos antes de cualquier despliegue con personas reales.

## 21. Limitaciones y honestidad técnica

- **No hay localización por número de WhatsApp/Telegram ni activación remota u oculta del GPS.** No es viable de forma legítima y el sistema no lo intenta. Cualquier producto que lo prometa suele ser fraude o *stalkerware*.
- La precisión depende del GPS del dispositivo (típicamente 5–20 m al aire libre, peor en interiores).
- Los recorridos de la demo son **sintéticos** (dispositivos que ya consintieron), para no usar datos de personas reales; la PWA, en cambio, captura GPS real cuando se ejecuta en un teléfono.
- El bot de Telegram y la pasarela SMS requieren credenciales y red; en el laboratorio se documenta su código y se muestra la maqueta de interacción, mientras que el backend, el simulador, las pruebas y las dos webapps sí son ejecutables.
- El transporte en la demo es HTTP local; en producción debe ser HTTPS con certificado válido (ver Caso 10 de la Parte I).

## 22. Despliegue, código y artefactos interactivos

### 22.1 Artefactos en vivo

Las dos interfaces web están publicadas y son funcionales:

- **Panel del propietario** (Leaflet + OpenStreetMap, con los datos reales de la demo; incluye reproducción del recorrido): [GeoConsent · Panel del propietario](https://claude.ai/artifact/DBWXP46TR2YxuUBevR8Gaz)
- **App del dispositivo (PWA)** (pide permiso de GPS real y comparte ubicación; tiene modo demo sin servidor): [GeoConsent · App del dispositivo](https://claude.ai/artifact/WqJrdDM6WVe6Ea7UGFRS4g)

Para una prueba de extremo a extremo con GPS real: ejecutar el backend local, inscribir y verificar un dispositivo (se obtiene un `device_token`), pegarlo en la PWA y abrir el panel para ver la posición en el mapa.

### 22.2 Puesta en marcha

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

python3 backend/app.py            # API en http://127.0.0.1:5055
python3 simulator/run_demo.py     # demostración extremo a extremo (otra terminal)
python3 -m pytest tests/ -v       # 11 pruebas
# Abrir webapp/device.html y webapp/dashboard.html en el navegador
```

### 22.3 Estructura del código (Anexo C)

```
parte2/
├── backend/app.py              # API REST, JWT, geofencing, alertas, consent_log
├── simulator/track.py         # generador de recorridos sintéticos
├── simulator/run_demo.py      # demostración extremo a extremo sobre HTTP real
├── tests/test_api.py          # 11 pruebas (pytest)
├── bot/telegram_bot.py        # bot con botón nativo de compartir ubicación
├── webapp/device.html         # PWA del dispositivo (Geolocation API)
├── webapp/dashboard.html      # panel del propietario (Leaflet + OSM)
├── requirements.txt · README.md
└── data/demo_outputs/         # salidas JSON reales de la demo
```

Los entregables de la Parte II (código, pruebas, webapps y las figuras II-1 a II-14) se incluyen en el paquete comprimido que acompaña a este informe.

---

*Fin del informe. Parte I: diez casos de seguridad de redes con evidencia reproducible. Parte II: sistema de localización con consentimiento, ejecutable y verificado. Ambas partes cumplen la nota ética de la guía: trabajo académico, sin daño y sin actuar sobre sistemas o personas sin su autorización expresa.*
