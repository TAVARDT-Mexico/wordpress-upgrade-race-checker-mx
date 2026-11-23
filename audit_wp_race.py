#!/usr/bin/env python3
"""
TAVARDT México: Auditor de Race Condition en Actualización de WordPress y RCE (CLI)
Herramienta de auditoría de seguridad para detectar exposición y riesgos de ejecución
en directorios transitorios de actualización de WordPress (wp-content/upgrade/).
"""

import sys
import json
import urllib.request
import urllib.error
import ssl

def check_route(target_url, path):
    full_url = target_url.rstrip("/") + "/" + path.lstrip("/")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(
        full_url,
        headers={"User-Agent": "TAVARDT-WordPress-Race-Auditor/1.0 (+https://ag.tavardt.com/mx/ciberseguridad/)"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            status_code = response.getcode()
            body = response.read(2048).decode("utf-8", errors="ignore")
            is_index_of = "Index of" in body or "<title>Index of" in body
            return {
                "path": path,
                "url": full_url,
                "status": status_code,
                "accessible": True,
                "directory_listing": is_index_of,
                "risk": "CRÍTICO" if is_index_of or status_code == 200 else "BAJO"
            }
    except urllib.error.HTTPError as e:
        return {
            "path": path,
            "url": full_url,
            "status": e.code,
            "accessible": False,
            "directory_listing": False,
            "risk": "PROTEGIDO" if e.code in [403, 404] else "ATENCIÓN"
        }
    except Exception as e:
        return {
            "path": path,
            "url": full_url,
            "status": 0,
            "accessible": False,
            "directory_listing": False,
            "risk": "ERROR_CONEXIÓN",
            "error": str(e)
        }

def audit_wordpress(target_url):
    paths = [
        "wp-content/upgrade/",
        "wp-content/upgrade/test.php",
        "wp-content/uploads/",
        "wp-content/uploads/test.php"
    ]
    
    results = []
    for p in paths:
        results.append(check_route(target_url, p))
    
    upgrade_dir = next((r for r in results if r["path"] == "wp-content/upgrade/"), None)
    is_vulnerable = False
    if upgrade_dir and (upgrade_dir["directory_listing"] or upgrade_dir["status"] == 200):
        is_vulnerable = True
        
    assessment = {
        "target": target_url,
        "is_vulnerable": is_vulnerable,
        "posture": "VULNERABLE" if is_vulnerable else "PROTEGIDO",
        "routes": results,
        "remediation": [
            "Definir WP_TEMP_DIR fuera de la raíz pública DocumentRoot en wp-config.php: define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');",
            "Bloquear la ejecución de scripts PHP en wp-content/upgrade/ y wp-content/uploads/ en Nginx o Apache.",
            "Configurar una regla de Cloudflare WAF para descartar peticiones dirigidas a /wp-content/upgrade/.",
            "Activar DISALLOW_FILE_MODS para forzar implementaciones exclusivamente mediante pipelines de CI/CD."
        ]
    }
    return assessment

def print_remediation():
    print("""
================================================================================
  DIRECTRICES DE REMEDIACIÓN ARQUITECTÓNICA: WORDPRESS UPGRADE RACE CONDITION
================================================================================
1. Hardening en wp-config.php:
   Agregar antes de "/* That's all, stop editing! */":
   define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
   define('DISALLOW_FILE_MODS', true);
   define('DISALLOW_FILE_EDIT', true);

2. Bloqueo en Nginx (nginx.conf):
   location ~* /wp-content/upgrade/ {
       deny all;
       return 403;
   }
   location ~* ^/wp-content/(uploads|upgrade)/.*\.php$ {
       deny all;
       return 403;
   }

3. Bloqueo en Apache (.htaccess en wp-content/upgrade/):
   <FilesMatch "\.(php|phtml|php[0-9]|sh|cgi)$">
       Require all denied
   </FilesMatch>
   Options -Indexes
================================================================================
""")

def main():
    if len(sys.argv) < 2:
        print("Uso: python wordpress_upgrade_checker.py <URL_O_DOMINIO> [--json] [--remediate]")
        print("Ejemplo: python wordpress_upgrade_checker.py https://sitio-corporativo.com")
        sys.exit(1)
        
    target = sys.argv[1].strip()
    if target in ["--help", "-h"]:
        print("Uso: python wordpress_upgrade_checker.py <URL_O_DOMINIO> [--json] [--remediate]")
        sys.exit(0)
        
    if target == "--remediate":
        print_remediation()
        sys.exit(0)
        
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
        
    is_json = "--json" in sys.argv
    show_remediate = "--remediate" in sys.argv
    
    data = audit_wordpress(target)
    
    if is_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return
        
    print("=" * 80)
    print("  TAVARDT MÉXICO: AUDITOR DE RACE CONDITION EN WORDPRESS")
    print("=" * 80)
    print(f"Objetivo: {target}")
    print(f"Postura General: {data['posture']}")
    print("-" * 80)
    print("Rutas Inspeccionadas:")
    for r in data["routes"]:
        status = r["status"] if r["status"] != 0 else "Fallo de Conexión"
        list_flag = " [DIRECTORY LISTING DETECTADO]" if r.get("directory_listing") else ""
        print(f" * [{r['risk']}] {r['path']} -> HTTP {status}{list_flag}")
        
    print("-" * 80)
    if data["is_vulnerable"]:
        print("[ALERTA CRÍTICA] El servidor presenta brechas de exposición en wp-content/upgrade/.")
        print("Los atacantes pueden aprovechar ventanas de concurrencia para ejecutar scripts PHP temporales.")
    else:
        print("[CONFORME] El directorio wp-content/upgrade/ se encuentra protegido contra acceso directo.")
        
    if show_remediate:
        print_remediation()
    else:
        print("Consejo: Ejecute con --remediate para visualizar las configuraciones de remediación.")
    print("=" * 80)

if __name__ == "__main__":
    main()
