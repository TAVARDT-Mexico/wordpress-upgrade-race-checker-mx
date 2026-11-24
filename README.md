# Central de Hardening y Auditoría WordPress Upgrade Race Condition

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-mexico.github.io/wordpress-upgrade-race-checker-mx/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Vulnerability](https://img.shields.io/badge/Vulnerability-Race%20Condition-red.svg)](https://tavardt-mexico.github.io/wordpress-upgrade-race-checker-mx/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Repositorio oficial y documentación técnica corporativa para la mitigación de la vulnerabilidad de **Race Condition en la Actualización de WordPress y Ejecución Remota de Código (RCE)**.

***

## 1. Resumen de la Vulnerabilidad

Durante la actualización del core, temas o plugins, WordPress descarga y descomprime archivos ZIP temporalmente en `wp-content/upgrade/` antes de su validación y traslado definitivo.

Si la configuración del servidor web permite la ejecución de scripts PHP en subdirectorios de contenido, un atacante puede invocar los archivos recién extraídos durante la ventana de concurrencia, obteniendo Ejecución Remota de Código (RCE) con los privilegios del servidor web.

### Factores de Riesgo Crítico:
* Exposición pública vía HTTP de `wp-content/upgrade/`
* Ejecución activa de FastCGI/PHP en uploads y upgrade
* Ausencia de la constante `WP_TEMP_DIR` fuera del DocumentRoot

***

## 2. Auditoría Determinística vía CLI

Dado que los navegadores web imponen restricciones de CORS y sandbox que impiden inspecciones de red profundas, utilice la herramienta oficial de Python directamente en su terminal o pipeline de CI/CD:

```bash
# 1. Obtener la utilidad oficial de auditoría
curl -sO https://raw.githubusercontent.com/TAVARDT/wordpress-upgrade-race-checker-mx/main/audit_wp_race.py

# 2. Ejecutar auditoría directa contra su dominio
python audit_wp_race.py https://su-dominio.com
```

### Parámetros Soportados:
* Argumento posicional objetivo o `-u https://dominio-objetivo.com`
* `-t <segundos>` : Timeout en segundos (por defecto: 5)
* `-j` : Salida estructurada en JSON para pipelines automáticos

***

## 3. Blueprints de Mitigación

### A. Nginx (`nginx.conf`)
```nginx
location ~* /wp-content/upgrade/ {
    deny all;
    return 403;
}

location ~* ^/wp-content/(uploads|upgrade|languages|mu-plugins)/.*\.php$ {
    deny all;
    return 403;
}
```

### B. Apache (`.htaccess`)
```apache
<IfModule mod_authz_core.c>
    <FilesMatch "\.(php|php[0-9]|phtml|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>
</IfModule>
Options -Indexes
```

### C. WordPress (`wp-config.php`)
```php
define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
```

### D. Cloudflare WAF Rule
```cloudflare
(http.request.uri.path contains "/wp-content/upgrade/") or
(http.request.uri.path contains "/wp-content/uploads/" and http.request.uri.path contains ".php")
```

***

## 4. Consulta Online

Acceda a la guía técnica interactiva en producción:  
[https://tavardt-mexico.github.io/wordpress-upgrade-race-checker-mx/](https://tavardt-mexico.github.io/wordpress-upgrade-race-checker-mx/)

***

## Enlaces Útiles

* **Portal Corporativo:** https://ag.tavardt.com/mx/
* **Suite de Diagnósticos:** https://tools.tavardt.com/mx/
* **Contacto Técnico:** https://ag.tavardt.com/mx/contacto/

***

© 2026 TAVARDT. Todos los derechos reservados.
