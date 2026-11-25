# Central de Hardening y Auditoría WordPress Upgrade Race Condition

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-mexico.github.io/wordpress-upgrade-race-checker-mx/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Vulnerability](https://img.shields.io/badge/Vulnerability-Race%20Condition-red.svg)](https://tavardt-mexico.github.io/wordpress-upgrade-race-checker-mx/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Especificación técnica de ingeniería defensiva, modelos de configuración para producción y utilidad determinista de auditoría CLI para mitigar condiciones de carrera y Ejecución Remota de Código (RCE) durante actualizaciones en WordPress.

***

## Resumen Técnico: La Condición de Carrera en Actualizaciones de WordPress

WordPress impulsa más del 40 por ciento de los sitios web en el mundo. Durante los ciclos de actualización del núcleo, temas o complementos, la plataforma descomprime archivos ZIP en una carpeta transitoria antes de transferir los archivos a sus ubicaciones permanentes.

Por defecto, esta extracción se lleva a cabo en `wp-content/upgrade/`, un directorio ubicado directamente dentro del DocumentRoot accesible desde internet.

Cuando la configuración del servidor web permite la ejecución de scripts PHP en subdirectorios de contenido, un atacante puede ejecutar archivos recién extraídos durante la ventana temporal de descompresión:
* El atacante monitoriza o induce un ciclo de actualización en el sitio objetivo.
* Los archivos PHP temporales resultan ejecutables antes de la aplicación definitiva de permisos.
* Peticiones HTTP directas hacia estos archivos provocan la Ejecución Remota de Código (RCE) bajo los privilegios del servidor web (`www-data` o `nginx`).

Este repositorio proporciona configuraciones validadas para servidores en producción, modelos de aislamiento perimetral y una utilidad determinista en Python (`audit_wp_race.py`) para verificar la postura de seguridad.

***

## Superficies Críticas de Riesgo en Directorios de WordPress

### 1. La Ruta Pública de Extracción `wp-content/upgrade/`
La vulnerabilidad principal se origina al ubicar carpetas temporales de descompresión en rutas accesibles vía HTTP:
* **Ventana de Exposición:** En servidores compartidos o con alta carga, la descompresión de archivos voluminosos puede demorar varios segundos.
* **Vector de Ataque:** El adversario emite ráfagas concurrentes de peticiones HTTP dirigidas a los archivos antes de su traslado o borrado.
* **Directriz Defensiva:** Denegar todo acceso HTTP directo al directorio `wp-content/upgrade/` y reubicar la carpeta temporal fuera del DocumentRoot.

### 2. Ejecución Irrestricta de PHP en Carpetas de Contenido
Los servidores web suelen reenviar cualquier solicitud terminada en `.php` hacia FastCGI sin verificar el directorio contenedor:
* **Ventana de Exposición:** Las carpetas `uploads` y `upgrade` requieren permisos de escritura para gestionar medios y actualizaciones.
* **Vector de Ataque:** La combinación de permisos de escritura con autorización de ejecución de scripts crea un riesgo inmediato de ejecución arbitraria.
* **Directriz Defensiva:** Bloquear explícitamente la ejecución de scripts PHP en las carpetas `uploads`, `upgrade`, `languages` y `mu-plugins` a nivel de servidor web.

### 3. Listado Automático de Archivos Activo (Directory Listing)
Servidores web con configuración por defecto que no suprimen el listado de directorios muestran el contenido de las carpetas:
* **Ventana de Exposición:** Permite a terceros visualizar en tiempo real los nombres de archivos temporales creados durante la actualización.
* **Directriz Defensiva:** Desactivar la directiva de listado automático de directorios en todos los hosts virtuales.

***

## Modelos de Mitigación Defensiva en Producción

Aplique estas configuraciones comprobadas para proteger servidores web en producción:

### 1. Configuración para Nginx (`nginx.conf`)
Bloquea el acceso directo a la carpeta temporal y suprime la ejecución de PHP en rutas de contenido:

```nginx
# 1. Denegar acceso directo a la carpeta de upgrade temporal
location ~* /wp-content/upgrade/ {
    deny all;
    return 403;
}

# 2. Impedir ejecucion de PHP en rutas de contenido estatico
location ~* ^/wp-content/(uploads|upgrade|languages|mu-plugins)/.*\.php$ {
    deny all;
    return 403;
}
```

### 2. Configuración para Apache (`.htaccess`)
Inserte esta regla en los archivos `.htaccess` dentro de `/wp-content/upgrade/` y `/wp-content/uploads/`:

```apache
# Denegar ejecucion de cualquier extension de script
<IfModule mod_authz_core.c>
    <FilesMatch "\.(php|php[0-9]|phtml|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>
</IfModule>

# Desactivar listado de directorios
Options -Indexes
```

### 3. Configuración en WordPress (`wp-config.php`)
Reubica los archivos temporales fuera del DocumentRoot y restringe modificaciones desde el panel:

```php
/* Reubicar la carpeta temporal fuera de la raiz publica web */
define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');

/* Restringir edicion y modificacion de archivos desde el panel */
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
```

### 4. Regla Perimetral en Cloudflare WAF
Regla perimetral para descarte inmediato de solicitudes maliciosas:

```text
(http.request.uri.path contains "/wp-content/upgrade/") or
(http.request.uri.path contains "/wp-content/uploads/" and http.request.uri.path contains ".php")
Accion: Block (Descartar conexion inmediatamente)
```

***

## Herramienta Oficial de Auditoría CLI

Los navegadores web imponen restricciones estrictas de sandbox y políticas de CORS que impiden comprobaciones directas de sockets y lectura irrestricta de cabeceras HTTP. Para facilitar evaluaciones técnicas reproducibles y sin telemetría, TAVARDT desarrolló una herramienta en Python diseñada para terminales locales y flujos de integración continua.

### Fases del Análisis Determinista

La utilidad (`audit_wp_race.py`) ejecuta un ciclo de diagnóstico estructurado:
* **Saneamiento de Entrada y Conectividad:** Valida la estructura de la URL, normaliza protocolos y comprueba la conexión con el servidor.
* **Huella Digital de WordPress:** Confirma la presencia de la plataforma mediante la API REST, recursos canónicos y páginas de autenticación.
* **Detección de Enrutador SPA:** Distingue códigos 403/404 legítimos de respuestas genéricas emitidas por Single Page Applications.
* **Sondeo de Rutas Críticas:** Evalúa `/wp-content/upgrade/` y rutas de prueba PHP para verificar el bloqueo en el servidor.
* **Puntuación Automática:** Emite una calificación técnica estructurada de 100 (Blindado) a 25 (Vulnerable).

### Instrucciones de Uso

Descargue y ejecute la herramienta determinista contra el dominio WordPress objetivo:

```bash
# 1. Obtener el script oficial del repositorio
curl -sO https://raw.githubusercontent.com/TAVARDT/wordpress-upgrade-race-checker-mx/wordpress-upgrade-race-checker-mx/main/audit_wp_race.py

# 2. Ejecutar auditoria directa contra el dominio
python audit_wp_race.py https://su-dominio.com

# 3. Generar resultado en formato JSON
python audit_wp_race.py https://su-dominio.com -j
```

***

## Preguntas Frecuentes sobre Arquitectura (FAQ Técnico)

### 1. ¿Qué provoca la condición de carrera durante las actualizaciones de WordPress?
Durante las actualizaciones del núcleo, temas o complementos, WordPress descomprime paquetes ZIP en la carpeta temporal `wp-content/upgrade/` antes de reubicar los archivos definitivos. Si el servidor permite la ejecución de scripts en carpetas de contenido, un atacante puede solicitar archivos PHP durante este intervalo, logrando Ejecución Remota de Código bajo los privilegios del servidor web.

### 2. ¿Por qué es fundamental bloquear el acceso HTTP al directorio wp-content/upgrade?
La carpeta `wp-content/upgrade/` fue concebida exclusivamente para procesos internos locales de PHP. Los usuarios externos en internet no tienen ninguna necesidad operativa de acceder a esta ruta, por lo que permitir peticiones públicas expone archivos temporales a intentos automatizados de explotación.

### 3. ¿De qué manera reubicar la constante WP_TEMP_DIR neutraliza este riesgo?
Definir `WP_TEMP_DIR` fuera del DocumentRoot (por ejemplo, en `/var/www/tmp/` en lugar de `/wp-content/upgrade/`) impide que los archivos descomprimidos sean accesibles vía web. Incluso si un atacante conoce el nombre de los archivos temporales, el servidor web no podrá servirlos ni ejecutarlos al encontrarse fuera de la raíz pública.

### 4. ¿Cómo previenen Nginx y Apache la ejecución de scripts en carpetas de contenido?
Nginx utiliza bloques de ubicación con expresiones regulares que devuelven el código HTTP 403 para solicitudes terminadas en `.php` dentro de estas carpetas. En Apache, se configuran directivas `<FilesMatch>` dentro de archivos `.htaccess` junto con `Options -Indexes` para prohibir la ejecución y el listado de archivos.

### 5. ¿La herramienta de auditoría en Python genera sobrecarga o lentitud en el sitio evaluado?
No. La utilidad opera como un diagnóstico pasivo que emite únicamente solicitudes HTTP GET y HEAD estándar para verificar los códigos de respuesta. Comprueba si las rutas devuelven HTTP 403 o 404 en lugar de un código HTTP 200 abierto, evaluando la seguridad perimetral sin alterar archivos ni registros de la base de datos.

***

## Marcos de Cumplimiento y Estándares de Seguridad

Arquitectura defensiva y controles de seguridad alineados con la Ley Federal de Proteccion de Datos Personales en Posesion de los Particulares (LFPDPPP) y las guias de ciberseguridad del INAI.

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
