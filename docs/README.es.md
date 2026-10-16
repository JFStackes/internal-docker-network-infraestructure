# Private Infrastructure

DNS privado, autoridad certificadora y entrada HTTPS reutilizables y definidos mediante configuración para servidores conectados por una **VPN existente**. Mantenido por JFStack; los nombres, direcciones y aplicaciones no dependen de JFStack.

[Read in English](../README.md)

**Versión 0.1.0: base implementada, pendiente de aceptación en un despliegue real.** Incluye comprobaciones automatizadas locales. El arranque Docker, el comportamiento real de DNS, la emisión/renovación ACME y el firewall deben superar la [lista de aceptación](VALIDATION.md) antes de producción. Clonar este repositorio no despliega nada automáticamente.

## Arquitectura

| Perfil de despliegue | Ejecuta | Responsabilidad |
|---|---|---|
| `central` | AdGuard Home + Smallstep step-ca | DNS privado y CA intermedia operativa |
| `node` | Traefik con File Provider | Entrada HTTPS por servidor y certificados ACME |
| Fuera del proyecto | WireGuard existente, firewall, aplicaciones | Conectividad y autorización de red/aplicación |

Un nombre como `app.node01.client.internal` resuelve a la **IP VPN del nodo**. El navegador conecta con el puerto TCP 443 de ese nodo a través del router VPN. DNS no es un proxy HTTP. El servidor central sigue en el recorrido remoto: distribuir los proxies no evita consumir su ancho de banda VPN.

**No hay etiquetas Docker, montajes del socket Docker ni descubrimiento automático.** Un inventario genera las reglas DNS, la política de nombres de la CA y el `routes.yml` centralizado de cada nodo. El proxy público no se modifica. Cada cliente debe disponer de VPN, inventario, CA y estado propios, reutilizando el mismo código.

## Contenido

- Plantillas Compose independientes para central/node, generador determinista, validación estricta y ejemplos genérico/JFStack.
- Herramientas PKI con raíz offline e intermedia online; importación de confianza por huella; certificados individuales mediante ACME TLS-ALPN-01.
- CLI local con ejecución explícita, comprobaciones previas, sincronización de configuración con servicios detenidos y diagnóstico DNS/TLS.
- Copia/restauración en frío cifrada con `age`, extracción segura y sin arranque automático.
- Pruebas, CI, documentación de entrada bilingüe y procedimientos de despliegue, seguridad y recuperación.

No incluye instalación de WireGuard, cambios de firewall, orquestación SSH remota, despliegue de aplicaciones, directorio de usuarios, SSO, CA multiinquilino ni alta disponibilidad.

## Requisitos

Base objetivo: **Debian 12/13 o Ubuntu 24.04 LTS, Docker Engine >= 28 en Linux con daemon rootful, plugin Compose >= 2.24**, Python >= 3.11, OpenSSL 3, `iproute2` y `htpasswd` (`apache2-utils`). `age` solo es necesario para copias/restauraciones cifradas. Es una matriz objetivo, no una afirmación de pruebas en cada sistema. Rootless Docker, Swarm, Docker Desktop y despliegues IPv6 quedan fuera de v0.1.

La VPN debe proporcionar enrutamiento entre peers, rutas de retorno, conservación de IP de origen y reglas de firewall. La hora del sistema debe ser correcta. Cada instancia necesita un directorio operativo protegido fuera del repositorio. Los contenedores utilizan UID/GID `10000:10000`; revisa su compatibilidad con cada host.

## Empezar validando y generando archivos

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
mkdir -p local
cp examples/inventory.example.yaml local/site.yaml
# Edit local/site.yaml for this installation before rendering.
.venv/bin/python bin/private-infra validate --inventory local/site.yaml
.venv/bin/python bin/private-infra render --inventory local/site.yaml \
  --profile central --output /tmp/private-infra-central-preview
.venv/bin/python bin/private-infra render --inventory local/site.yaml \
  --profile node --node node01 --output /tmp/private-infra-node-preview
```

La generación solo escribe archivos, rechaza destinos no vacíos y no crea claves ni arranca Docker. El `.env.example` principal es informativo: **el contrato de configuración es el inventario YAML**, no una segunda fuente de datos. Los Compose generados contienen valores concretos.

Para la topología JFStack de esta conversación utiliza `examples/inventory.jfstack.yaml`. Incluye `10.77.0.1`, `10.77.0.2` y `radarr.dust01.internal`. La IP del portátil es propuesta, no un peer existente. qBittorrent y File Browser permanecen desactivados hasta configurar su conectividad desde el proxy. Jellyfin/Seerr conservan su publicación pública existente.

## Flujo de despliegue

Sigue [DEPLOYMENT](DEPLOYMENT.md) y [PKI](PKI.md) en este orden:

1. Verifica por separado VPN y firewall; genera los archivos en un directorio protegido del host correspondiente.
2. Ejecuta `prepare` en central y genera su CSR intermedio. Crea/firma con la raíz en un equipo offline; importa solamente certificados públicos comprobando una huella SHA-256 independiente.
3. Arranca central explícitamente; valida DNS, estado de la CA privada y exposición externa.
4. Genera/prepara el nodo, importa la raíz verificada y arranca Traefik explícitamente. Instala la raíz pública en los almacenes de confianza de los clientes.
5. Prueba emisión inicial, renovación, ACL por origen y conectividad con aplicaciones antes de aceptar el despliegue.

`bin/private-infra --help` muestra todos los comandos. `compose`, `sync-config`, `backup` y `restore` muestran una vista previa por defecto y requieren `--execute`; `compose --action up` también exige `--ack-firewall`. La generación, preparación y las operaciones PKI sí escriben localmente: no son simulaciones.

## Configuración y mantenimiento

Edita el inventario privado, valídalo, genera directorios staging nuevos y usa `sync-config` en una ventana de mantenimiento. No edites los archivos generados ni uses la interfaz de AdGuard como segunda fuente de configuración. La sincronización exige detener el perfil afectado, conserva credenciales/estado y guarda la configuración anterior. No es una migración transaccional de bases de datos ni un rollback automático de imágenes.

Una aplicación nueva necesita actualizar su ruta en el nodo **y la lista exacta de nombres autorizados de la CA central**; la regla DNS del nodo ya la cubre. Un nodo nuevo necesita cambios de DNS/CA centrales y su propio despliegue. No hace falta cambiar los demás nodos ni el proxy público. Consulta [CONFIGURATION](CONFIGURATION.md).

## Límites de seguridad

Los puertos se publican solamente en direcciones VPN privadas. **La vinculación a una IP privada no sustituye al firewall.** Hay que revisar forwarding/NAT de Docker y reglas del host; conectarse a WireGuard no autoriza a cualquier peer. El panel administrativo utiliza HTTP en TCP 3000 solo por VPN, protegido por WireGuard y una contraseña bcrypt, no HTTPS de navegador. Nunca lo expongas en redes compartidas o no fiables. Las aplicaciones de los nodos se publican exclusivamente por HTTPS.

La clave raíz permanece offline. La clave intermedia, su secreto local de apertura, las cuentas ACME y las claves de aplicaciones son datos sensibles, excluidos de Git. Protege los hosts y las copias cifradas, además de los permisos. El certificado raíz es público, pero concede confianza: verifica su huella por un canal independiente.

La política CA de esta edición es **global a la autoridad**, restringida a nombres declarados; TLS-ALPN-01 demuestra el control del endpoint del nodo. Las cuentas ACME diferentes **no** implementan aislamiento de clientes por cuenta. No mezcles clientes que no confíen entre sí en una misma CA. No se implementan altas EAB ni políticas por cuenta.

## Desarrollo y verificación

```bash
.venv/bin/python scripts/check_repository.py
PATH="$PWD/.venv/bin:$PATH" ./scripts/test.sh
```

Las pruebas requieren OpenSSL y htpasswd, pero no arrancan Docker ni contactan con producción. [VALIDATION](VALIDATION.md) detalla lo comprobado y las integraciones pendientes. El workflow opcional de GitHub solo verifica el repositorio; los mismos comandos sirven en un Git interno.

## Documentación

[Arquitectura](ARCHITECTURE.md) - [Despliegue](DEPLOYMENT.md) - [PKI](PKI.md) - [Inventario](CONFIGURATION.md) - [Operación/recuperación](OPERATIONS.md) - [Seguridad](../SECURITY.md) - [Validación](VALIDATION.md) - [Fuentes](SOURCES.md).

## Licencia

Esta entrega es privada/propietaria, no tiene licencia de código abierto. Consulta [LICENSE](../LICENSE). Las dependencias conservan sus propias licencias; consulta [THIRD_PARTY_NOTICES](../THIRD_PARTY_NOTICES.md). Define la distribución y licencia comercial antes de publicar un repositorio público.
