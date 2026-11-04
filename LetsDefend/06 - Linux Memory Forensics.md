# 🛡️ GUÍA COMPLETA DE MEMORIA FORENSE EN LINUX: ADQUISICIÓN CON LIME Y ANÁLISIS CON VOLATILITY 3
### *Manual Extensivo y Guía de Consulta Técnica – Certificación eJPT / DFIR*

---

> **Estructura y Metodología del Manual:** Este documento ofrece una guía didáctica y operativa de nivel avanzado sobre el análisis forense de memoria volátil (*Linux Memory Forensics*). A lo largo de sus secciones se desglosan los fundamentos de la RAM en entornos Linux, la preparación del entorno de compilación, el procedimiento paso a paso para la adquisición segura mediante **LiME (Linux Memory Extractor)**, la generación de tablas de símbolos **ISF (Intermediate Symbol Format)** mediante **dwarf2json**, y la ejecución exhaustiva de los plugins de **Volatility 3** para detectar procesos ocultos, artefactos de red, inyecciones de código y controladores del sistema. Toda la exposición se presenta en prosa técnica continua sin esquemas de listas de viñetas fuera de bloques de código o tablas.

---

## 🚀 Matriz de Consulta Rápida (Cheat Sheet de Memoria Forense en Linux)

| Fase / Objetivo Operativo | Mecánica y Causa Raíz | Herramienta / Comando / Plugin Clave | Indicador de Éxito / Resultado |
| :--- | :--- | :--- | :--- |
| **Adquisición RAM con LiME** | Inserción de un módulo de kernel LKM para volcar el espacio físico de memoria sin alterar el estado del sistema. | `insmod lime.ko "path=/mnt/usb/ram.lime format=lime"` | Generación del archivo `.lime` o `.raw` con el tamaño equivalente a la memoria RAM. |
| **Generación Símbolos ISF** | Conversión del archivo DWARF de símbolos del kernel (`vmlinux`) a JSON para Volatility 3. | `./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-... > ubuntu.json` | Archivo JSON ubicar en `volatility3/symbols/linux/` para permitir el parsing del volcado. |
| **Listado de Procesos** | Recorrido de la lista circular doblemente enlazada `tasks_struct` en la memoria del kernel. | `python3 vol.py -f ram.lime linux.pslist.PsList` | Muestra PID, PPID, nombre del ejecutable, UID, GID y marca temporal de inicio. |
| **Árbol de Procesos** | Reconstrucción de la jerarquía de procesos padre e hijo en formato estructurado. | `python3 vol.py -f ram.lime linux.pstree.PsTree` | Visualización en árbol arborescente de procesos y subprocesos para detectar anomalías. |
| **Escanear Procesos Ocultos** | Escaneo heurístico de la memoria física en busca de estructuras `task_struct` desenlazadas. | `python3 vol.py -f ram.lime linux.psscan.PsScan` | Revela procesos ocultados que se desvincularon de la lista global. |
| **Conexiones de Red** | Inspección de las estructuras de sockets del kernel (`sock`, `inet_sock`). | `python3 vol.py -f ram.lime linux.netstat.Netstat` | Muestra dirección IP local, remota, puerto, protocolo (TCP/UDP), estado y PID asociado. |
| **Archivos Abiertos (FD)** | Identificación de descriptores de archivo asociados a cada proceso en la tabla `files_struct`. | `python3 vol.py -f ram.lime linux.lsof.Lsof` | Lista archivos, sockets y tuberías abiertos por PID con su ruta absoluta en disco. |
| **Histórico de Comandos Bash** | Búsqueda de las estructuras en memoria de las sesiones de terminal `bash` activas o pasadas. | `python3 vol.py -f ram.lime linux.bash.Bash` | Recupera comandos ejecutados por los usuarios antes del volcado de memoria. |
| **Detección de Inyecciones** | Identificación de páginas de memoria ejecutables y con permisos de escritura (rwx) o código anómalo. | `python3 vol.py -f ram.lime linux.malfind.Malfind` | Muestra bloques de memoria sospechosos con desensamblado de instrucciones de código. |
| **Extracción de Módulos (LKM)** | Inspección de la lista de módulos de kernel cargados (`modules` list). | `python3 vol.py -f ram.lime linux.lsmod.Lsmod` | Identifica controladores y módulos cargados en el espacio de kernel. |


## 1. Introducción a la Memoria Forense de Linux

### 1.1. Concepto y Relevancia de la Memoria Volátil
El análisis forense de memoria o *Memory Forensics* consiste en la extracción e inspección científica de la memoria física de acceso aleatorio (RAM) de un sistema informático. En el ámbito del análisis forense digital y respuesta a incidentes (DFIR), la RAM representa la fuente de evidencia más volátil según el orden de volatilidad definido por el estándar RFC 3227. Mientras que el almacenamiento secundario en disco conserva datos estáticos en estado de reposo, la memoria volátil captura el estado operativo exacto del sistema en el instante preciso del incidente. Cuando un atacante ejecuta cargas útiles directamente en memoria sin tocar el disco (*fileless execution*), realiza llamadas a la API del sistema, establece túneles de comunicación cifrados o emplea técnicas de evasión, la RAM se convierte en el único entorno donde residen los rastros sin alterar de dichas actividades. Por lo tanto, dominar la adquisición y el análisis de la memoria física en sistemas Linux es una competencia crítica para determinar la causa raíz de una intrusión, desvelar comportamientos anómalos y evaluar el impacto real de un compromiso.

### 1.2. Casos de Uso y Artefactos Presentes en la RAM
La memoria RAM alberga una cantidad masiva de información dinámica que desaparece por completo al reiniciar o apagar el equipo objetivo. Entre los artefactos forenses de mayor valor recuperables desde un volcado de memoria en Linux destacan los procesos en ejecución y aquellos ocultos mediante la manipulación de estructuras de datos del kernel; las conexiones de red activas, inactivas o en espera junto con sus correspondientes sockets y direcciones IP asociadas; la totalidad de los descriptores de archivos abiertos en el sistema; las claves de cifrado en texto plano de volúmenes LUKS o sesiones SSL/TLS; el historial de comandos ejecutados en sesiones de terminal Bash incluso si se deshabilitó el archivo `.bash_history`; los módulos de kernel (LKM) legítimos y anómalos inyectados; las variables de entorno de cada proceso conteniendo tokens de autenticación o secretos de infraestructura; y trozos de código inyectado en la memoria virtual. Esta riqueza informativa convierte a la memoria forense en el recurso definitivo para el análisis de incidentes, la investigación de fuga de datos, el diagnóstico de fallos graves del sistema y el rastreo detallado de la línea de tiempo operativa de un incidente.

## 2. Herramientas Fundamentales: LiME y Volatility

### 2.1. Arquitectura de LiME (Linux Memory Extractor)
LiME (Linux Memory Extractor) es una herramienta de código abierto pionera diseñada específicamente para la adquisición forense de memoria volátil en sistemas operativos Linux y dispositivos Android. Su arquitectura operativa se basa en la implementación de un Módulo de Kernel Cargable (*Loadable Kernel Module* o LKM). Al ejecutarse dentro del espacio de kernel (*kernel space*), LiME adquiere acceso directo a la totalidad del direccionamiento de memoria física del sistema operativo, puenteando las restricciones del espacio de usuario (*user space*) y evitando la corrupción de datos que generaban métodos legados obsoletos como la lectura de `/dev/mem` o `/dev/kmem`. Una de las principales fortalezas arquitectónicas de LiME es su capacidad de transmitir el volcado de memoria a través de la red utilizando sockets TCP nativos o de escribirlo directamente en un medio de almacenamiento secundario (como una unidad USB externa). Además, LiME soporta formatos de volcado estructurados como el formato `lime` (que incluye encabezados con la dirección física de cada bloque) y el formato `raw` (imagen binaria plana de la memoria).

### 2.2. Arquitectura de Volatility 3
Volatility es el marco de trabajo de código abierto líder a nivel mundial para el análisis forense de volcados de memoria RAM. Su versión moderna, **Volatility 3**, representa una reestructuración completa del motor original (Volatility 2) reescrito desde cero en Python 3. La arquitectura de Volatility 3 abandona la necesidad de construir perfiles monolíticos rígidos basados en archivos ZIP (que requerían compilar mapas de símbolos y estructuras C en la misma máquina o kernel exacto). En su lugar, Volatility 3 adopta una arquitectura basada en un motor de traducción de símbolos universales utilizando archivos de formato de símbolos intermedios en formato JSON (*Intermediate Symbol Format* o ISF). Esta mejora arquitectónica permite que Volatility 3 analice cualquier volcado de memoria de Linux siempre que disponga del archivo de símbolos de la versión exacta del kernel analizado, ofreciendo un rendimiento significativamente superior, mejor gestión de memoria al procesar imágenes gigantestas y una API modular extensible mediante plugins especializados para la inspección del kernel, procesos, red y componentes de seguridad.

## 3. Captura y Extracción de Volcados de Memoria con LiME

### 3.1. Requisitos Previos y Preparación del Entorno de Compilación
Dado que LiME funciona como un módulo de kernel LKM, debe ser compilado específicamente contra los encabezados (*kernel headers*) de la versión exacta del kernel del sistema que se va a auditar. Si se realiza una auditoría en caliente (*live forensics*) directamente sobre la máquina sospechosa, se deben instalar previamente los paquetes de desarrollo mínimos indispensables. No obstante, en procedimientos forenses rigurosos, se recomienda compilar el módulo `lime.ko` en una máquina de laboratorio idéntica (misma distribución, arquitectura y versión de kernel) para minimizar la huella en el sistema auditado (*forensic footprint*). Para verificar la versión exacta del kernel en ejecución se utiliza el comando `uname -r`.

```bash
# Verificación de la versión del kernel en el sistema objetivo
uname -r

# Instalación de dependencias de compilación en Debian/Ubuntu (solo en laboratorio o si es estrictamente necesario)
sudo apt update && sudo apt install -y build-essential linux-headers-$(uname -r) git
```


### 3.2. Descarga, Compilación y Generación del Módulo Kernel (.ko)
El código fuente de LiME se obtiene desde el repositorio oficial del proyecto.
Una vez descargado el repositorio, el proceso de compilación se inicia dentro del directorio src.
Al ejecutar la orden de compilación, el sistema de construcción de módulos de Linux invoca el compilador GCC y genera el archivo binario ejecutable del kernel denominado lime.ko.



```bash
# Obtención del repositorio de LiME y compilación del módulo
git clone https://<repositorio_lime_github>
cd LiME/src
make
```



### 3.3. Parámetros de Inserción y Modos de Adquisición
El módulo compilado `lime.ko` se inserta en el kernel en ejecución utilizando el comando `insmod`. Durante la inserción, es obligatorio pasar argumentos de configuración clave que definen la ubicación de salida del volcado, el formato del archivo generado y el comportamiento del módulo en caso de errores de lectura en rangos de memoria reservados.

El parámetro `path` especifica la ruta de destino del archivo de salida (por ejemplo, `/mnt/usb/ram_dump.lime`) o una configuración de red (por ejemplo, `tcp:4444` para transmitir el volcado a un oyente en la máquina del investigador). El parámetro `format` define la estructura interna del archivo, siendo `lime` la opción recomendada porque preserva la estructura de rangos de memoria física y sus direcciones de inicio, mientras que `raw` genera un volcado binario continuo. El parámetro `dio` (*Direct I/O*) optimiza la escritura evitando usar la caché de disco del propio sistema.

```bash
# Sintaxis general de inserción de LiME para guardado en disco
sudo insmod lime-$(uname -r).ko "path=/ruta/de/destino/volcado_memoria.lime format=lime dio=1"

# Ejemplo práctico de inserción redirigiendo el volcado a un montaje USB externo
sudo insmod lime.ko "path=/media/forensic_usb/ubuntu_ram.lime format=lime"
```

### 3.4. Procedimiento Paso a Paso de Captura y Verificación de Integridad
Para garantizar el cumplimiento de los estándares forenses, el proceso de adquisición debe seguir una secuencia metódica. Primero, se conecta un medio de almacenamiento externo previamente formateado (por ejemplo en exFAT o Ext4) e inalterado. Segundo, se ejecuta el comando `insmod` apuntando la salida hacia dicho dispositivo. Tercero, se confirma la finalización del volcado descargando el módulo de la memoria con `rmmod`. Cuarto, se genera inmediatamente el hash de integridad criptográfica (SHA-256) del archivo `.lime` resultante para documentar la cadena de custodia.

```bash
# Paso 1: Creación del punto de montaje y conexión de la unidad USB forense
sudo mkdir -p /mnt/forensic_usb
sudo mount /dev/sdb1 /mnt/forensic_usb

# Paso 2: Inserción de LiME e inicio del volcado directo de memoria RAM
sudo insmod lime-5.15.0-88-generic.ko "path=/mnt/forensic_usb/evidencia_ram.lime format=lime"

# Paso 3: Confirmación del desembarco del módulo de kernel tras completar el volcado
sudo rmmod lime

# Paso 4: Generación y registro del hash SHA-256 de integridad
sha256sum /mnt/forensic_usb/evidencia_ram.lime | tee /mnt/forensic_usb/evidencia_ram.lime.sha256

# Paso 5: Desmontaje seguro del medio de almacenamiento
sudo umount /mnt/forensic_usb
```


## 4. Configuración y Análisis de Volcados con Volatility 3

### 4.1. Fundamentos de Volatility 3 y la Evolución desde Volatility 2
A diferencia de Volatility 2, que requería compilar un perfil de memoria específico ejecutando herramientas como `dwarfdump` en la propia máquina objetivo para empacar las estructuras en un archivo `.zip`, Volatility 3 revoluciona la metodología de análisis forense. Volatility 3 utiliza una biblioteca centralizada de archivos de símbolos en formato JSON (archivos ISF). Estos archivos contienen la definición técnica exacta de las estructuras de datos del kernel C (`task_struct`, `mm_struct`, `files_struct`, `inet_sock`, etc.) y sus desplazamientos de memoria (*offsets*). Gracias a esta abstracción, el investigador puede analizar cualquier volcado de memoria de Linux desde su propia estación de trabajo forense sin modificar la máquina víctima, simplemente asegurándose de que Volatility 3 tenga acceso al archivo JSON de símbolos correspondiente a la versión del kernel analizada.

### 4.2. Generación de Símbolos ISF (Intermediate Symbol Format) con dwarf2json
Para que Volatility 3 pueda interpretar el volcado de memoria de una distribución Linux, requiere el archivo de símbolos ISF. La herramienta oficial desarrollada por el equipo de Volatility para generar estos archivos es **dwarf2json**. Esta utilitaria toma como entrada el archivo binario del kernel de Linux con información de depuración DWARF (usualmente ubicado en `/usr/lib/debug/boot/vmlinux-$(uname -r)` en paquetes de depuración `dbgsym` o `debuginfo`) o el archivo `System.map`, y lo procesa produciendo un esquema JSON ligero estructurado que Volatility 3 consume automáticamente.

### 4.3. Instalación y Configuración de dwarf2json en Ubuntu 22.04
A continuación se detalla el procedimiento técnico completo para compilar e instalar `dwarf2json` en un sistema analista basado en Ubuntu 22.04, y generar la tabla de símbolos a partir del archivo del kernel con símbolos de depuración.

```bash
# Paso 1: Instalación del lenguaje Go (requerido para compilar dwarf2json)
sudo apt update
sudo apt install -y golang-go git

# Paso 2: Clonado del repositorio oficial de dwarf2json
git clone https://<repositorio_dwarf2json>
cd dwarf2json

# Paso 3: Compilación del ejecutable binario
go build

# Paso 4: Obtención del archivo vmlinux con símbolos de depuración (ejemplo para kernel de Ubuntu)
# Se debe descargar o copiar el archivo vmlinux correspondiente exactamente a la versión del kernel del volcado
# En Debian/Ubuntu se obtiene instalando el paquete linux-image-$(uname -r)-dbgsym

# Paso 5: Generación del archivo JSON de símbolos ISF con dwarf2json
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-5.15.0-88-generic > Ubuntu_5.15.0-88-generic.json

# Paso 6: Ubicación del archivo de símbolos en el directorio correspondiente de Volatility 3
mkdir -p /ruta/a/volatility3/volatility3/framework/symbols/linux/
cp Ubuntu_5.15.0-88-generic.json /ruta/a/volatility3/volatility3/framework/symbols/linux/
```

### 4.4. Catálogo Integrado de Plugins Forenses de Linux en Volatility 3
Volatility 3 organiza sus capacidades analíticas en módulos especializados denominados plugins. Los plugins diseñados para entornos Linux comienzan con el prefijo `linux.` y permiten inspeccionar aspectos cuantitativos y cualitativos de la RAM.

| Plugin de Volatility 3 | Descripción Técnica y Función Forense |
| :--- | :--- |
| `linux.pslist.PsList` | Recorre la lista enlazada principal de procesos (`task_struct`) para listar los procesos activos en el momento del volcado. |
| `linux.pstree.PsTree` | Muestra la estructura arborescente de procesos, permitiendo visualizar relaciones padre e hijo para detectar anomalías jerárquicas. |
| `linux.psscan.PsScan` | Escanea heurísticamente la memoria física buscando estructuras `task_struct` aisladas o desvinculadas por utilidades de ocultación. |
| `linux.lsof.Lsof` | Enumera los archivos, tuberías, sockets y dispositivos abiertos por cada proceso en el sistema. |
| `linux.netstat.Netstat` | Reconstruye la tabla de sockets de red del kernel, mostrando IPs locales/remotas, puertos y estado de conexión. |
| `linux.bash.Bash` | Escanea la memoria de los procesos `bash` para extraer las cadenas de texto del historial de comandos ejecutados. |
| `linux.malfind.Malfind` | Escanea regiones de memoria virtual con permisos de ejecución y escritura (`rwx`) en busca de inyecciones de código. |
| `linux.lsmod.Lsmod` | Muestra los módulos de kernel (LKM) cargados actualmente en el sistema operativo. |
| `linux.check_syscall.Check_syscall` | Inspecciona la tabla de llamadas al sistema (`sys_call_table`) para detectar ganchos (*hooks*) modificados. |
| `linux.envars.Envars` | Extrae las variables de entorno de todos los procesos en ejecución, exponiendo claves y configuraciones. |


## 5. Análisis Básico y Avanzado de Memoria Volátil

### 5.1. Inspección de Procesos y Árbol de Ejecución (PsList, PsTree, Psscan)
El análisis forense de procesos es el primer paso obligatorio durante la investigación de un volcado de RAM. Mediante el uso del plugin `linux.pslist.PsList`, el investigador obtiene la nómina completa de los procesos presentes en la lista enlazada del kernel. Se deben inspeccionar meticulosamente los nombres de los ejecutables, los identificadores de proceso (PID y PPID), las fechas de creación y los identificadores de usuario (UID).

Complementariamente, el plugin `linux.pstree.PsTree` organiza estos resultados en un formato arborescente. Esto permite detectar anomalías estructurales severas, como por ejemplo un proceso `bash` o `sh` ejecutándose como hijo no natural de un servidor web `apache2` o `nginx`, lo cual es un indicador claro de la explotación con éxito de una vulnerabilidad de Ejecución Remota de Código (RCE). Por último, la ejecución de `linux.psscan.PsScan` es indispensable para identificar código ejecutable avanzado o procesos ocultos que utilizan técnicas de desvinculación de la lista doblemente enlazada (*DKOM - Direct Kernel Object Manipulation*) para ocultarse de la vista estándar del comando `ps` o `pslist`.

```bash
# Listado estándar de procesos activos
python3 vol.py -f /evidencias/memoria.lime linux.pslist.PsList

# Representación en árbol arborescente de la jerarquía de procesos
python3 vol.py -f /evidencias/memoria.lime linux.pstree.PsTree

# Escaneo profundo de estructuras de procesos desvinculadas en memoria física
python3 vol.py -f /evidencias/memoria.lime linux.psscan.PsScan
```

### 5.2. Análisis de Archivos Abiertos y Conexiones de Red (Lsof, Netstat)
Una vez identificados los procesos sospechosos, el siguiente nivel de análisis consiste en examinar su interacción con el sistema de archivos y la infraestructura de red. El plugin `linux.lsof.Lsof` revela los descriptores de archivo asociados a cada PID. Esto permite identificar qué binarios ejecutables reales fueron cargados desde el disco, qué archivos de configuración están consumiendo o qué archivos temporales fueron creados en directorios volátiles como `/tmp` o `/dev/shm`.

Por otro lado, el plugin `linux.netstat.Netstat` rastrea la memoria del kernel en busca de estructuras de red. Este análisis es fundamental para descubrir artefactos de comunicación maliciosa, como conexiones de shell inverso (*reverse shells*) dirigidas hacia direcciones IP externas, actividades de botnets, exfiltración de información sensible o puertos locales puestos en escucha (*bind shells*) por puertas traseras.

```bash
# Enumeración de archivos abiertos por procesos
python3 vol.py -f /evidencias/memoria.lime linux.lsof.Lsof

# Filtrado de archivos abiertos por un PID específico (ejemplo PID 1420)
python3 vol.py -f /evidencias/memoria.lime linux.lsof.Lsof | grep "1420"

# Reconstrucción de conexiones de red activas e inactivas
python3 vol.py -f /evidencias/memoria.lime linux.netstat.Netstat
```

### 5.3. Extracción de Artefactos de Usuario y Comandos Ejecutados (Bash, Environment)
Los atacantes que obtienen acceso interactivo a un sistema Linux suelen utilizar la shell predeterminada del sistema (`bash`). Aunque el atacante intente eliminar su rastro borrando el archivo `.bash_history` o ejecutando `unset HISTFILE`, las cadenas de texto ingresadas en la terminal permanecen almacenadas en la memoria virtual asignada al proceso `bash`.

El plugin `linux.bash.Bash` analiza las estructuras de memoria del interprete Bash para reconstruir las líneas de comando ejecutadas secuencialmente. Asimismo, el plugin `linux.envars.Envars` extrae el bloque de variables de entorno de cada proceso, lo cual resulta crítico para recuperar datos de sesión, tokens de API, rutas de ejecutables modificadas (`PATH`), o credenciales pasadas explícitamente mediante variables de entorno antes de la toma del volcado.

```bash
# Recuperación de comandos ejecutados en sesiones de terminal Bash
python3 vol.py -f /evidencias/memoria.lime linux.bash.Bash

# Extracción de variables de entorno de los procesos
python3 vol.py -f /evidencias/memoria.lime linux.envars.Envars
```

### 5.4. Detección de Inyecciones y Código Malicioso en Memoria (Malfind)
El análisis de código malicioso en memoria volátil requiere identificar regiones de memoria virtual que presenten configuraciones anómalas de seguridad. El plugin `linux.malfind.Malfind` escanea las tablas de páginas de los procesos buscando segmentos de memoria que tengan simultáneamente permisos de Lectura, Escritura y Ejecución (`rwx`), o que contengan encabezados ejecutables (como el formato ELF) en ubicaciones no mapeadas contra archivos legítimos en disco.

Cuando `malfind` detecta una región sospechosa, muestra la dirección de memoria virtual, el tamaño del bloque, una vista hexadecimal de los primeros bytes y el desensamblado básico en lenguaje ensamblador (código de instrucciones como `nop`, `push`, `call` o `syscall`). Esto permite confirmar la presencia de *shellcode* inyectado mediante técnicas como inyección de código dinámico o desbordamientos de búfer.

```bash
# Escaneo de regiones de memoria para identificar código malicioso inyectado
python3 vol.py -f /evidencias/memoria.lime linux.malfind.Malfind

# Volcado de la región de memoria sospechosa a un archivo en disco para análisis en IDA o Ghidra
python3 vol.py -f /evidencias/memoria.lime linux.malfind.Malfind --dump
```

## 6. Estudios de Casos y Ejemplos Prácticos

### 6.1. Caso Práctico 1: Detección e Investigación de un Shell Inverso (Reverse Shell)
En este escenario de estudio, un servidor web de producción basado en Linux sufrió una intrusión no autorizada a través de la explotación de un fallo de subida de archivos arbitrarios. El equipo de seguridad identificó una anomalía en el consumo de recursos y procedió inmediatamente a realizar una captura de memoria RAM utilizando LiME antes de aislar la máquina de la red.

El procedimiento analítico paso a paso para investigar la intrusión mediante Volatility 3 se desarrolló de la siguiente manera:

Primero, se ejecutó el plugin `linux.pstree.PsTree` para inspeccionar la jerarquía de procesos. En el resultado arbolado se identificó que el proceso con PID `2150` correspondiente a `apache2` había generado un proceso hijo inusual con PID `3412` ejecutando `/bin/sh`, el cual a su vez había invocado un proceso hijo con PID `3413` ejecutando `nc` (Netcat).

Segundo, se aplicó el plugin `linux.netstat.Netstat` para determinar la actividad de red asociada a dichos procesos. El análisis reveló que el proceso `nc` (PID `3413`) mantenía una conexión TCP activa en estado `ESTABLISHED` desde el puerto local `49152` hacia una dirección IP externa remota (`198.51.100.45`) en el puerto `4444`. Esto confirmó la presencia de un *reverse shell* activo hacia la infraestructura del atacante.

Tercero, se ejecutó el plugin `linux.bash.Bash` para evaluar los comandos interactivos ejecutados por el intruso. Se recuperaron secuencias de comandos donde el atacante exploró el sistema operativo (`whoami`, `id`, `uname -a`), buscó archivos con permisos SUID (`find / -perm -4000 2>/dev/null`) e intentó descargar un script de escalada de privilegios desde un servidor HTTP externo mediante `curl`.

Cuarto, se utilizó el plugin `linux.lsof.Lsof` filtrando por el PID `3412` para identificar los archivos temporales creados por el atacante en el directorio `/tmp`, procediendo a su extracción para el análisis de firmas antimalware.

```bash
# Paso 1: Identificación de la jerarquía anómala del proceso web
python3 vol.py -f ram_incidente.lime linux.pstree.PsTree

# Output interpretado:
# ...
# └── apache2 (PID: 2150)
#     └── sh (PID: 3412)
#         └── nc (PID: 3413)

# Paso 2: Verificación de la conexión de red del proceso Netcat
python3 vol.py -f ram_incidente.lime linux.netstat.Netstat | grep "3413"

# Output interpretado:
# TCP  10.0.0.15:49152  198.51.100.45:4444  ESTABLISHED  3413/nc

# Paso 3: Extracción de comandos ejecutados en la shell interceptada
python3 vol.py -f ram_incidente.lime linux.bash.Bash
```

### 6.2. Caso Práctico 2: Identificación y Extracción de un Módulo Kernel Oculto (LKM)
En este segundo escenario de estudio, un servidor crítico comenzó a presentar comportamientos anómalos. Aunque las herramientas tradicionales de monitorización de procesos (`ps`, `top`) y red (`netstat`) no mostraban ninguna actividad sospechosa, los registros de cortafuegos perimetrales indicaban tráfico saliente constante hacia direcciones IP no autorizadas. Se sospechó la presencia de un módulo de kernel manipulado (LKM) diseñado para ocultar procesos y conexiones.

El flujo metodológico de investigación forense en memoria se ejecutó de la siguiente forma:

Primero, se realizó el volcado físico de memoria mediante LiME y se cargó en Volatility 3. Al ejecutar el plugin estándar `linux.pslist.PsList`, no se observó ningún proceso anómalo. Sin embargo, al ejecutar el plugin `linux.psscan.PsScan` (que escanea la memoria física buscando firmas de `task_struct` sin confiar en la lista doblemente enlazada del kernel), se descubrió un proceso oculto con PID `5890` correspondiente a un ejecutable malicioso denominado `backdoor_proc`. La disparidad entre `pslist` y `psscan` confirmó que la lista de procesos había sido manipulada mediante la técnica DKOM.

Segundo, se ejecutó el plugin `linux.lsmod.Lsmod` para revisar los módulos de kernel cargados. La inspección reveló un módulo de kernel no firmado denominado `stealth_mod.ko`.

Tercero, se ejecutó el plugin `linux.check_syscall.Check_syscall` para auditar la integridad de la tabla de llamadas al sistema (`sys_call_table`). El análisis confirmó que varias llamadas clave como `sys_read`, `sys_getdents64` (utilizada para listar directorios) y `sys_packet` habían sido interceptadas y desviadas hacia direcciones de memoria pertenecientes a la región del módulo `stealth_mod.ko`.

Cuarto, mediante el plugin de volcado de módulos, se extrajo el archivo binario del módulo directamente desde la memoria RAM para su posterior análisis e ingeniería inversa en un entorno sandbox aislado.

```bash
# Paso 1: Detección del proceso oculto mediante comparación entre PsList y PsScan
python3 vol.py -f ram_rootkit.lime linux.pslist.PsList > pslist.txt
python3 vol.py -f ram_rootkit.lime linux.psscan.PsScan > psscan.txt
diff pslist.txt psscan.txt

# Paso 2: Inspección de módulos de kernel cargados para localizar el LKM sospechoso
python3 vol.py -f ram_rootkit.lime linux.lsmod.Lsmod

# Paso 3: Verificación de ganchos (hooks) en la tabla de llamadas al sistema (sys_call_table)
python3 vol.py -f ram_rootkit.lime linux.check_syscall.Check_syscall
```

