# Auditor de Race Condition en Actualización de WordPress y RCE | TAVARDT México

> Auditoría de Resiliencia Empresarial contra Condición de Carrera en Actualizaciones de WordPress, Exposición de Directorios Temporales y Ejecución Remota de Código (RCE)

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Active-brightgreen)](https://tavardt-mexico.github.io/wordpress-upgrade-race-checker-mx/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: CIS WordPress](https://img.shields.io/badge/Security-CIS%20WordPress%20%7C%20OWASP-red.svg)](https://owasp.org/)

## Visión General de la Vulnerabilidad y Arquitectura Defensiva

El flujo estándar de actualización de componentes en WordPress (núcleo, temas y plugins) gestionado por `class-wp-upgrader.php` descarga archivos comprimidos en formato ZIP y los extrae en el directorio temporal `wp-content/upgrade/` mediante `unzip_file()`.

Durante el intervalo de tiempo entre la extracción en disco y el traslado atómico definitivo hacia las carpetas de destino, se abre una ventana crítica de condición de carrera (Race Condition) dentro de la raíz web pública. Si el servidor carece de reglas de restricción perimetral o filtrado de Web Application Firewall (WAF), cualquier solicitud no autenticada puede acceder a los archivos extraídos en `wp-content/upgrade/`. Si el runtime PHP (FastCGI/PHP-FPM) compila scripts en esa carpeta, los atacantes logran Ejecución Remota de Código (RCE) bajo los privilegios del servidor web.

Este repositorio proporciona una herramienta web interactiva de diagnóstico perimetral y un escáner CLI en Python sin dependencias externas para auditorías de seguridad automatizadas.

## Aplicación Web Interactiva

Acceda a la herramienta web alojada en GitHub Pages:
[https://tavardt-mexico.github.io/wordpress-upgrade-race-checker-mx/](https://tavardt-mexico.github.io/wordpress-upgrade-race-checker-mx/)

Características de la aplicación web:
* Verificación en tiempo real de accesibilidad perimetral y medición de latencia.
* Detección de exposición en `wp-content/upgrade/` y listado de directorios.
* Matriz comparativa arquitectónica (Topología vulnerable vs. Servidor blindado).
* Generador automatizado de configuraciones defensivas para Nginx, Apache (.htaccess), wp-config.php y Cloudflare WAF.
* Interfaz responsiva optimizada para dispositivos móviles y de escritorio.

## Uso del Escáner CLI en Python

El script `wordpress_upgrade_checker.py` no requiere librerías de terceros y funciona en cualquier entorno con Python 3.8+:

```bash
# Ejecutar auditoría directa contra un dominio
python wordpress_upgrade_checker.py https://sitio-corporativo.com

# Ejecutar auditoría en formato JSON para pipelines de CI/CD
python wordpress_upgrade_checker.py https://sitio-corporativo.com --json

# Mostrar bloques de configuración para remediación y hardening
python wordpress_upgrade_checker.py --remediate
```

## Controles Arquitectónicos y Mitigaciones Defensivas

Para neutralizar de forma definitiva las superficies de ataque de condición de carrera y RCE en WordPress, aplique defensa en profundidad en 4 capas:

1. **Aislamiento de Temporales (wp-config.php):**
   Configure `WP_TEMP_DIR` apuntando a una ruta aislada fuera del `DocumentRoot` público:
   ```php
   define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
   define('DISALLOW_FILE_MODS', true);
   define('DISALLOW_FILE_EDIT', true);
   ```

2. **Bloqueo en Nginx (nginx.conf):**
   Deniegue solicitudes HTTP hacia la carpeta de actualización y prohíba la compilación de scripts `.php`:
   ```nginx
   location ~* /wp-content/upgrade/ {
       deny all;
       return 403;
   }
   location ~* ^/wp-content/(uploads|upgrade)/.*\.php$ {
       deny all;
       return 403;
   }
   ```

3. **Protección en Apache (.htaccess):**
   Aplique reglas estrictas en `wp-content/upgrade/.htaccess`:
   ```apache
   <FilesMatch "\.(php|phtml|php[0-9]|sh|cgi)$">
       Require all denied
   </FilesMatch>
   Options -Indexes
   ```

4. **Regla Personalizada en Cloudflare WAF:**
   Cree una regla descartando peticiones donde `(http.request.uri.path contains "/wp-content/upgrade/")`.

## Portales Oficiales

* **Portal Corporativo TAVARDT México:** [https://ag.tavardt.com/mx/](https://ag.tavardt.com/mx/)
* **Servicios de Ciberseguridad:** [https://ag.tavardt.com/mx/ciberseguridad/](https://ag.tavardt.com/mx/ciberseguridad/)
* **Hub de Herramientas Defensivas:** [https://tools.tavardt.com/mx/](https://tools.tavardt.com/mx/)
* **Organización GitHub:** [https://github.com/TAVARDT-Mexico](https://github.com/TAVARDT-Mexico)

## Licencia

Distribuido bajo licencia MIT. Consulte `LICENSE` para más información.
