<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <b>🇪🇸 Español</b><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# Sheet-License-Broker

<p align="center">
  <strong>Pasarela Serverless de Autenticación, Asignación de Licencias y Base de Datos NoSQL Impulsada por Google Sheets y Google Apps Script</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Licencia: MIT">
  <img src="https://img.shields.io/badge/version-v1.5.0-emerald.svg" alt="Versión: v1.5.0">
  <img src="https://img.shields.io/badge/anomaly-Z--Score%20%26%20SIEM%20Topology-F59E0B.svg" alt="Anomalías de Comportamiento y Grafo SIEM">
  <img src="https://img.shields.io/badge/pqc-NIST%20FIPS%20204%20ML--DSA-7C3AED.svg" alt="Criptografía Poscuántica">
  <img src="https://img.shields.io/badge/sso-SAML%202.0%20%26%20OIDC-blueviolet.svg" alt="SSO SAML y OIDC">
  <img src="https://img.shields.io/badge/scim-RFC%207643%20%2F%207644%20SCIM%202.0-10B981.svg" alt="Aprovisionamiento de Directorio SCIM 2.0">
  <img src="https://img.shields.io/badge/zkp-pedersen%20%26%20sigma%20proofs-10B981.svg" alt="Pruebas de Conocimiento Cero">
  <img src="https://img.shields.io/badge/stream-websocket%20telemetry%20%26%20kill--switch-10B981.svg" alt="Streaming WebSocket y Kill-Switch">
  <img src="https://img.shields.io/badge/consensus-raft%20quorum%20%26%20CRDT-blue.svg" alt="Consenso Distribuido">
  <img src="https://img.shields.io/badge/security-rate%20limits%20%26%20SIEM%20audit-blueviolet.svg" alt="Seguridad y Limitación de Tasa">
  <img src="https://img.shields.io/badge/attestation-TPM%202.0%20%26%20Enclave-0284C7.svg" alt="Atestación de Hardware">
  <img src="https://img.shields.io/badge/tiers-dynamic%20flags-8B5CF6.svg" alt="Feature Flags y Medición de Niveles">
  <img src="https://img.shields.io/badge/go-%3E%3D1.22-00ADD8.svg" alt="Versión de Go">
  <img src="https://img.shields.io/badge/high--availability-active--standby-059669.svg" alt="Alta Disponibilidad">
  <img src="https://img.shields.io/badge/metrics-prometheus-E6522C.svg" alt="Métricas de Prometheus">
  <img src="https://img.shields.io/badge/cloudflare-edge%20worker-F38020.svg" alt="Cloudflare Workers">
  <img src="https://img.shields.io/badge/google--apps--script-deployed-34A853.svg" alt="Google Apps Script">
  <img src="https://img.shields.io/badge/hosting-0%24%2Fmo-10B981.svg" alt="Coste de Hospedaje">
</p>

</div>

---

## 💡 Descripción General

**`sheet-license-broker`** convierte cualquier hoja de cálculo de Google Spreadsheet en un backend serverless autenticado y listo para producción para aplicaciones de escritorio, utilidades CLI y herramientas SaaS independientes (indie SaaS). 

En lugar de pagar costosas instancias de bases de datos en la nube o administrar contenedores Docker únicamente para gestionar inicios de sesión de usuarios y claves de licencia de software, `sheet-license-broker` combina un motor en la nube basado en **Google Apps Script (GAS)** con un **puente de alta velocidad en Go, cadenas de firmas poscuánticas ML-DSA, consenso distribuido por quórum Raft, sincronización de conjuntos LWW-Element-Set CRDT, Cloudflare Edge Gateway, atestación criptográfica de hardware (TPM 2.0 y Enclaves), espacios de nombres multiinquilino (multi-tenant), alta disponibilidad activo-pasivo con doble hoja, feature flags dinámicos y medición de uso, almacenamiento en cola cifrado en disco (spool), métricas de Prometheus, verificación criptográfica antimanipulación HMAC, almacenamiento en caché local resiliente y una interfaz web embebida**.

### ¿Por qué utilizar Google Sheets como Backend?
- **Cero Coste ($0/mes)**: Aprovecha las cuotas gratuitas de Google Drive y Apps Script (hasta 20.000 solicitudes/día).
- **Criptografía Poscuántica y Cadenas de Firmas ML-DSA (NIST FIPS 204)**: Verificación de firmas digitales modulares sobre retículos resistentes a computación cuántica (ML-DSA-44 / ML-DSA-65) con cadenas de firmas híbridas duales ECDSA clásica / retículo (`Hybrid-P256-MLDSA65`), ventanas de gracia para rotación de claves sin tiempo de inactividad (zero-downtime) y difusión instantánea de revocación de emergencia mediante kill-switch.
- **Detección de Anomalías de Comportamiento y Puntuación de Riesgo Adaptativa**: Seguimiento estadístico de deriva de latidos (heartbeat drift) mediante Z-Score en ventana deslizante (tolerancia de fluctuación/jitter de &plusmn;15%), detección de viajes imposibles mediante velocidad Haversine (&gt;950 km/h o subredes /24 concurrentes), cálculo de puntuación de riesgo adaptativo con decaimiento nominal progresivo, escalamiento automatizado de desafíos de re-atestación con puntuación de riesgo &ge; 50, cuarentena automática zero-trust con puntuación de riesgo &ge; 85 y exportador de grafo topológico de incidentes de seguridad estandarizado (`siem-topology-v1`) para ingesta en SIEM empresarial.
- **Inicio de Sesión Único Empresarial (SSO) y Aprovisionamiento de Directorio SCIM 2.0**: Federaciones de identidad SAML 2.0 y OIDC, sincronización de directorio RFC 7643/7644, asignación automatizada de puestos de licencia y revocación instantánea ante desaprovisionamiento.
- **Verificación Anónima con Pruebas de Conocimiento Cero (ZKP)**: Compromisos de Pedersen sobre NIST P-256 con generadores independientes deterministas hash-to-curve, pruebas de presentación Sigma no interactivas (transformadas mediante Fiat-Shamir) y registros de defensa contra repetición de nulificadores gastados que protegen la privacidad del hardware del cliente.
- **Consenso Distribuido de Quórum Raft y Malla CRDT**: Elección de líder ligera, quórum de registro por mayoría, replicación de estado libre de conflictos LWW-Element-Set y resúmenes de estado mediante árboles de Merkle SHA-256 para sincronización anti-entropía entre nodos brokers distribuidos.
- **Limitación de Tasa Empresarial y Retroceso Progresivo**: Regulación de tráfico en ventana deslizante segura para hilos por IP y HWID con demoras de penalización progresivas y encabezados estándar `X-RateLimit-*`.
- **Caché de Reputación IP/HWID en Ventana Deslizante**: Bloqueos temporales automáticos y alertas por webhook de incidentes de alta prioridad ante infracciones de seguridad reiteradas.
- **Exportación de Paquetes de Auditoría Cifrados para SIEM**: Paquetes de auditoría cifrados conformes con AES-256-GCM sellados con firmas HMAC para ingesta en Splunk, Datadog y AWS CloudWatch.
- **Atestación Criptográfica de Hardware y Enlace a Enclaves**: Verificación de citas PCR de TPM 2.0 y atestación de claves de hardware con Apple Secure Enclave / Windows Hello, evitando ataques por clonación.
- **Telemetría Antidepuración y Antimanipulación de Memoria del Cliente**: Puntuación de integridad continua con bloqueo automático instantáneo mediante kill-switch para dispositivos que presenten acoplamiento de depuradores o modificaciones en secciones de código.
- **Feature Flags Dinámicos y Medición de Niveles Basada en Uso**: Niveles de suscripción Free, Pro y Enterprise con restricción de características en tiempo de ejecución (`client.isFeatureEnabled("analytics")`) y seguimiento atómico de cuotas de consumo guardadas directamente en Google Sheets.
- **Replicación Activo-Pasivo en Doble Hoja**: Conmutación por error automática entre hojas primaria y de respaldo con reconciliación bidireccional libre de colisiones.
- **Almacenamiento Local en Cola Cifrado en Disco (Spool)**: Cola de diario cifrada con AES-256-GCM (`spool.bin`) que garantiza cero pérdida de datos durante interrupciones de red.
- **Telemetría Prometheus de Nivel Empresarial (`/metrics`)**: Endpoint scraper incorporado que expone contadores, medidores (gauges) y latencias en formato Prometheus.
- **Webhooks de Alerta de Incidentes**: Notificaciones enriquecidas de incidentes de seguridad inmediatas enviadas a canales de Discord y Slack.
- **Espacios de Nombres Multiinquilino (Multi-Tenant)**: Aísle productos e inquilinos distintos con prefijos personalizados (ej. `ACME-LIC-XXXX-YYYY`) y políticas independientes.
- **Cloudflare Edge Gateway**: Verificación de licencias en el borde en submilisegundos mediante Cloudflare Workers y Workers KV con la API Web Crypto.
- **Panel de Administración Legible por Humanos**: Su hoja de Google Sheets es su base de datos. Visualice, edite, bloquee u otorgue licencias directamente en tiempo real.
- **Protección Bloqueada por Hardware (HWID)**: Vincula las claves de licencia a identificadores de hardware específicos de la máquina en el primer inicio.
- **Seguridad Antimanipulación Criptográfica HMAC-SHA256**: Protege el tráfico entrante del cliente contra inspecciones MITM y suplantación de cargas útiles por ingeniería inversa.
- **Mitigación de Repetición con Nonce en Ventana Deslizante**: Previene ataques de repetición de solicitudes con una ventana de tolerancia de desincronización de reloj de 5 minutos.
- **Revocación Remota Instantánea y Lista Negra de Dispositivos**: Inhabilite licencias o bloquee identificadores de hardware comprometidos directamente desde la consola web o la pestaña de Google Sheets.
- **Copia de Seguridad y Recuperación ante Desastres Automatizadas**: Exportación y restauración de estado a un punto en el tiempo protegidas con sumas de comprobación SHA-256 y cifrado AES-256-GCM.
- **Webhooks de Ciclo de Vida en Tiempo Real**: Despachadores de eventos con colas de trabajadores y entrega de webhooks firmados con HMAC a endpoints de inquilinos y globales.
- **Autenticación SHA-256 con Salt**: Las contraseñas se protegen criptográficamente con sal y hash antes de persistirse.
- **Almacenamiento en Caché Local Resiliente y Período de Gracia Offline**: Licencias y documentos clave-valor almacenados en caché de memoria protegen contra los límites de tasa de la API de Google (HTTP 429) y caídas temporales de red.
- **Consola de Administración Web Embebida**: Binario único y autónomo (`sheet-license-broker.exe`) con una consola de administración oscura en tonos esmeralda.

---

## 🏛️ Arquitectura

```mermaid
flowchart TD
    Client["App de Escritorio / CLI / WebApp"] -->|HTTPS REST + HMAC-SHA256| Guard["Guardia Antimanipulación y Caché de Nonces"]
    Guard --> Limiter["Limitador de Tasa y Puerta de Reputación IP"]
    Limiter --> Broker["sheet-license-broker (Pasarela en Go)"]
    Broker -->|//go:embed| WebUI["Consola de Admin Embebida (Puerto 9082)"]
    Broker -->|Scrape| Prom["Monitorización con Prometheus (/metrics)"]
    Broker -->|Diario Cifrado en Disco| Spool["Spool en Disco Local (AES-256-GCM)"]
    Broker -->|Exportación SIEM| SIEM["Canal de Exportación para Auditoría (AES-256-GCM)"]
    Broker -->|Alertas| Alerts["Webhooks de Seguridad (Discord y Slack)"]
    Broker -->|RPC Raft y Sincronización CRDT| Peers["Malla de Nodos Pares del Clúster (Anti-Entropía)"]
    Broker -->|Caché TTL en Memoria| Cache["Caché Local (Cuotas y Respaldo Offline)"]
    Broker -->|Rol Activo| Primary["Aplicación Web GAS Primaria (Code.gs)"]
    Broker -.->|Conmutación Automática (Failover)| Standby["Aplicación Web GAS de Respaldo (Code.gs)"]
    Primary --> Sheets1["BD Google Sheet Primaria"]
    Standby -.-> Sheets2["BD Google Sheet de Respaldo"]

    subgraph Base de Datos de Google Sheets
        Sheets1 --> Tab1["Pestaña: Users (Auth Hash con Sal)"]
        Sheets1 --> Tab2["Pestaña: Licenses (Bloqueo HWID y Expiración)"]
        Sheets1 --> Tab3["Pestaña: Blacklist (Revocaciones y HWIDs Bloqueados)"]
        Sheets1 --> Tab4["Pestaña: Audit_Logs (Registro de Auditoría de Seguridad y Bloqueos)"]
        Sheets1 --> Tab5["Pestaña: Attestations (Citas y Declaraciones TPM)"]
        Sheets1 --> Tab6["Pestaña: KV_Database (Almacén NoSQL)"]
        Sheets1 --> Tab7["Pestaña: ConsensusNodes (Descubrimiento de Pares y Latidos)"]
    end
```

---

## 🚀 Inicio Rápido

### 1. Ejecutar la Pasarela Local y la Consola

Asegúrese de tener instalado Go 1.22+ en su estación de trabajo:

```bash
# Clonar el repositorio
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# Compilar y ejecutar el binario único en modo autónomo
go run .
```

Abra su navegador en **`http://localhost:9082`** para acceder a la consola de administración en vivo.

### 2. Conectar a Google Sheets en Vivo (Modo Proxy)

Para conectar la pasarela con su aplicación web de Google Apps Script desplegada:

```bash
# Establezca la URL de su aplicación web de Apps Script
export GAS_WEBAPP_URL="https://script.google.com/macros/s/.../exec"
export CACHE_TTL_SECONDS="600" # Opcional: 10 minutos de TTL de caché

# Iniciar la pasarela
./sheet-license-broker.exe
```

El servidor detecta automáticamente la URL remota, reenvía las consultas entrantes, almacena los resultados en la caché local y recurre de manera transparente a los datos en caché durante interrupciones de red.

---

## 📋 Configuración de Google Sheets y Despliegue con Clasp

### Opción A: Despliegue con un Solo Clic usando Clasp CLI

Si utiliza la CLI `@google/clasp`:

```bash
# 1. Inicie sesión en su cuenta de Google
npx @google/clasp login

# 2. Despliegue mediante el script automatizado
node scripts/deploy_clasp.mjs --script-id <YOUR_APPS_SCRIPT_ID>
```

Consulte [`gas/README.md`](file:///gas/README.md) para obtener instrucciones completas sobre la creación y configuración de proyectos de Clasp.

### Opción B: Configuración Manual (3 Minutos)

1. Abra [Google Sheets](https://sheets.new) y cree una nueva hoja de cálculo en blanco.
2. En el menú superior, diríjase a **Extensiones > Apps Script**.
3. Reemplace el código predeterminado con el contenido de [`gas/Code.gs`](file:///gas/Code.gs).
4. Haga clic en **Implementar > Nueva implementación**:
   - Tipo: **Aplicación web**
   - Ejecutar como: **Yo (su correo electrónico)**
   - Quién tiene acceso: **Cualquier usuario**
5. Haga clic en **Implementar** y copie su **URL de la aplicación web** (`https://script.google.com/macros/s/.../exec`).

Su hoja de Google Sheets generará automáticamente tres pestañas dedicadas en la primera solicitud:
- **`Users`**: `user_id`, `username`, `password_hash`, `salt`, `role`, `created_at`
- **`Licenses`**: `license_key`, `bound_hwid`, `max_devices`, `status`, `expires_at`, `created_at`
- **`KV_Database`**: `collection`, `doc_id`, `payload`, `updated_at`

---

## 📡 Especificación de la API REST

### Salud y Diagnóstico

#### Obtener Estado de Salud del Servicio y del Proxy
```http
GET /api/health
```

#### Hacer Ping al Backend
```http
GET /api/proxy/ping
```

---

### Autenticación

#### Registrar Usuario
```http
POST /api/users/register
Content-Type: application/json

{
  "username": "developer",
  "password": "SecurePassword123!",
  "role": "admin"
}
```

#### Autenticar / Iniciar Sesión
```http
POST /api/users/login
Content-Type: application/json

{
  "username": "developer",
  "password": "SecurePassword123!"
}
```

---

### Gestión de Licencias

#### Emitir Clave de Licencia
```http
POST /api/licenses
Content-Type: application/json

{
  "days": 30,
  "max_devices": 1
}
```
**Respuesta:**
```json
{
  "license_key": "KEY-7F2A-9C4B-E108",
  "bound_hwid": "",
  "max_devices": 1,
  "status": "ACTIVE",
  "expires_at": "2026-11-12T12:00:00Z",
  "created_at": "2026-10-13T12:00:00Z"
}
```

#### Validar y Vincular HWID
```http
POST /api/licenses/validate
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid": "WIN-B829-94AA-0123"
}
```
**Respuesta:**
```json
{
  "valid": true,
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid_bound": "WIN-B829-94AA-0123",
  "expires_at": "2026-11-12T12:00:00Z",
  "source": "remote_gas"
}
```

*Nota: Si la licencia está activa y no vinculada, se bloquea al `hwid` enviado. Las llamadas posteriores desde hardware coincidente tienen éxito; las llamadas desde hardware no coincidente son rechazadas. Las respuestas también indican si el resultado fue servido desde `cache`, `remote_gas` u `offline_cache`.*

---

### Seguridad y Antimanipulación

#### Firma de Solicitudes HMAC-SHA256
Cuando `HMAC_ENFORCE=true` (o cuando `HMAC_SECRET` está configurado), los clientes protegen las solicitudes contra la interceptación MITM utilizando encabezados estándar:
- `X-Signature`: Firma HMAC-SHA256 codificada en hexadecimal calculada sobre `METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(BODY)`.
- `X-Timestamp`: Marca de tiempo Unix actual en segundos (aplica una ventana de desincronización de reloj de 5 minutos).
- `X-Nonce`: Cadena de nonce criptográfico único por solicitud (previene ataques de repetición).

#### Revocar Clave de Licencia
```http
POST /api/licenses/revoke
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "reason": "Payment refunded"
}
```

#### Bloquear Identificador de Hardware del Dispositivo (HWID) en Lista Negra
```http
POST /api/security/blacklist
Content-Type: application/json

{
  "type": "device",
  "target": "WIN-B829-94AA-0123",
  "reason": "Fraudulent key sharing"
}
```

#### Listar Entradas de Lista Negra y Revocaciones
```http
GET /api/security/blacklist
```

---

### Almacén Clave-Valor NoSQL

#### Almacenar Documento
```http
POST /api/docs
Content-Type: application/json

{
  "collection": "user_settings",
  "doc_id": "usr_9918",
  "payload": "{\"dark_mode\":true,\"telemetry\":false}"
}
```

#### Obtener Todos los Documentos
```http
GET /api/docs
```

---

### Espacios de Nombres Multiinquilino

#### Registrar Inquilino
```http
POST /api/tenants/register
Content-Type: application/json

{
  "id": "tenant-gamehub",
  "name": "GameHub Studio",
  "namespace_prefix": "GHUB",
  "max_licenses": 100,
  "webhook_url": "https://api.gamehub.com/webhooks"
}
```

#### Emitir Licencia con Espacio de Nombres de Inquilino
```http
POST /api/licenses
Content-Type: application/json
X-Tenant-ID: tenant-gamehub

{
  "days": 60,
  "max_devices": 2
}
```
*Genera claves formateadas conforme a `GHUB-LIC-XXXX-YYYY`.*

---

### Copia de Seguridad Automatizada y Recuperación ante Desastres

#### Exportar Copia de Seguridad Cifrada (AES-256-GCM + Integridad SHA-256)
```http
POST /api/backup/export
Content-Type: application/json

{
  "secret_key": "your-backup-master-passphrase"
}
```

#### Restaurar desde Instantánea
```http
POST /api/backup/restore
Content-Type: application/json

{
  "secret_key": "your-backup-master-passphrase",
  "encrypted_payload": "<hex-encoded-ciphertext>"
}
```

---

### Feature Flags Dinámicos y Medición de Niveles Basada en Uso

#### Listar Catálogo Estándar de Características y Niveles
```http
GET /api/features
```
**Respuesta:**
```json
{
  "tiers": {
    "free": {
      "name": "free",
      "features": ["basic_access"],
      "daily_quotas": { "api_calls": 500, "export_rows": 100 }
    },
    "pro": {
      "name": "pro",
      "features": ["basic_access", "analytics", "csv_export", "extended_logs"],
      "daily_quotas": { "api_calls": 50000, "export_rows": 100000 }
    },
    "enterprise": {
      "name": "enterprise",
      "features": ["basic_access", "analytics", "csv_export", "extended_logs", "sso", "audit_export", "unlimited_seats", "priority_support"],
      "daily_quotas": { "api_calls": 10000000, "export_rows": 50000000 }
    }
  }
}
```

#### Comprobar Asignación de Característica de Licencia
```http
POST /api/features/check
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "feature": "analytics"
}
```
**Respuesta:**
```json
{
  "license_key": "KEY-7F2A-9C4B-E108",
  "feature": "analytics",
  "tier": "pro",
  "allowed": true
}
```

#### Registrar Uso y Aplicar Cuotas de Nivel
```http
POST /api/usage/record
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "metric": "api_calls",
  "units": 1
}
```
**Respuesta:**
```json
{
  "license_key": "KEY-7F2A-9C4B-E108",
  "metric": "api_calls",
  "units": 1,
  "current_usage": 42,
  "daily_quota": 50000,
  "quota_exceeded": false,
  "success": true
}
```

#### Consultar Estadísticas de Uso
```http
GET /api/usage/stats?license_key=KEY-7F2A-9C4B-E108
```
**Respuesta:**
```json
{
  "license_key": "KEY-7F2A-9C4B-E108",
  "date": "2026-10-14",
  "tier": "pro",
  "metrics": {
    "api_calls": 42
  }
}
```

---

### Atestación de Hardware y Telemetría Antimanipulación

#### Solicitar Nonce de Desafío TPM / Enclave
```http
POST /api/attestation/challenge
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid": "WIN-B829-94AA-0123"
}
```
**Respuesta:**
```json
{
  "status": "success",
  "challenge_id": "9a4f2b1c8e3d",
  "nonce": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "expires_at": "2026-10-14T12:05:00Z"
}
```

#### Verificar Cita PCR de TPM 2.0
```http
POST /api/attestation/verify
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid": "WIN-B829-94AA-0123",
  "challenge_id": "9a4f2b1c8e3d",
  "attestation_type": "tpm2",
  "tpm_quote": {
    "pcr_values": {
      "0": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "7": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    "pcr_selection": [0, 7],
    "composite_digest": "4a5b6c7d8e9f...",
    "signature": "3045022100...",
    "ak_public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
  }
}
```

#### Transmitir Telemetría Antidepuración e Integridad
```http
POST /api/attestation/telemetry
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid": "WIN-B829-94AA-0123",
  "report": {
    "debugger_present": false,
    "memory_integrity": true,
    "sandbox_detected": false,
    "hooks_detected": false,
    "process_checksum": "a1b2c3d4e5f6...",
    "execution_uptime_s": 3600
  }
}
```

---

### 🛡️ Limitación de Tasa Empresarial y Exportación de Auditoría para SIEM

#### Telemetría del Limitador de Tasa y Reputación IP
```http
GET /api/security/ratelimit/status
GET /api/security/reputation
```

#### Imponer / Listar Restricciones Temporales
```http
# Listar bloqueos temporales activos
GET /api/security/bans

# Imponer restricción temporal
POST /api/security/bans
Content-Type: application/json

{
  "key": "198.51.100.24",
  "reason": "Repeated failed validation attempts",
  "duration_minutes": 15
}

# Levantar restricción temporal
POST /api/security/bans/unban
Content-Type: application/json

{
  "key": "198.51.100.24"
}
```

#### Exportar Paquete de Auditoría Cifrado (para Ingesta en SIEM / SOC)
```http
POST /api/security/audit/export
Content-Type: application/json

{
  "secret_key": "enterprise-compliance-secret",
  "limit": 500
}
```

#### Verificar y Descifrar Paquete de Auditoría
```http
POST /api/security/audit/verify
Content-Type: application/json

{
  "secret_key": "enterprise-compliance-secret",
  "bundle": { ... }
}
```

---

### 🌐 Consenso Distribuido y Sincronización de Quórum Multirregión

#### Estado del Clúster y Topología de Pares
```http
GET /api/consensus/status
GET /api/consensus/peers
```

Respuesta:
```json
{
  "node_id": "node-1",
  "role": "Leader",
  "current_term": 1,
  "commit_index": 4,
  "peer_count": 2,
  "healthy_peers": 2,
  "has_quorum": true,
  "merkle_digest": "4a7d1ed414474e4033ac29ccb8653d9b...",
  "element_count": 128
}
```

#### Unirse a Par del Clúster
```http
POST /api/consensus/peers/join
Content-Type: application/json

{
  "node_id": "node-2",
  "address": "http://192.168.1.50:9082"
}
```

#### Desencadenar Sincronización de Estado Anti-Entropía
```http
POST /api/consensus/sync/trigger
```

---

### ⚡ Streaming WebSocket en Tiempo Real y Envío de Telemetría

#### Flujo Bidireccional de Telemetría por WebSocket
Conecte clientes WebSocket persistentes a `/api/stream/ws` para transmisión de telemetría en tiempo real y envíos de kill-switch en submilisegundos:

```http
GET /api/stream/ws?license_key=SLB-XXXX-XXXX&hwid=HWID-1234 HTTP/1.1
Host: localhost:9082
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

#### Consultar Clientes de Streaming Conectados y Telemetría
```http
# Listar sesiones de streaming activas
GET /api/stream/clients

# Consultar métricas de streaming y registro de auditoría de eventos recientes
GET /api/stream/telemetry
```

#### Ejecutar Kill-Switch Remoto Instantáneo
```http
POST /api/stream/kill
Content-Type: application/json

{
  "target": "SLB-XXXX-XXXX",
  "reason": "Suspected device cloning or fraud",
  "immediate": true
}
```
*Nota: El objetivo (target) puede ser una clave de licencia específica, un HWID de dispositivo, un ID de cliente o `"ALL"` para la ejecución de un kill-switch de difusión de emergencia. Las señales se envían a los sockets de clientes coincidentes con entrega en submilisegundos.*

---

### 🕵️ Verificación Anónima con Pruebas de Conocimiento Cero (ZKP)

#### Obtener Parámetros Públicos y Generadores NIST P-256
```http
GET /api/zkp/params
```

#### Emitir Credencial Cieguera Anónima
```http
POST /api/zkp/credential/issue
Content-Type: application/json

{
  "license_key": "LIC-ENTERPRISE-001",
  "tenant_id": "default",
  "hwid": "WIN-B829-94AA-0123",
  "tier": "enterprise",
  "max_seats": 5
}
```

#### Verificar Prueba de Presentación de Conocimiento Cero (Protocolo Sigma)
```http
POST /api/zkp/verify
Content-Type: application/json

{
  "credential": { ... },
  "required_tier": "enterprise"
}
```

#### Inspeccionar Estado de Nulificador Gastado
```http
GET /api/zkp/nullifiers/check?nullifier=7f2a9c4b...
```

---

### 🔐 Inicio de Sesión Único Empresarial (SSO) y Aprovisionamiento de Directorio SCIM 2.0

#### Metadatos de Proveedor de Servicios SAML 2.0
Descargue el XML estándar de metadatos SP para Okta, Azure AD o PingFederate:
```http
GET /api/sso/saml/metadata?entity_id=urn:sheet-license-broker:sp
```

#### Servicio de Consumidor de Aserciones (ACS) SAML 2.0
Procese aserciones SAML entrantes y emita tokens de sesión autenticados:
```http
POST /api/sso/saml/acs
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PHNhbWxwOlJlc3BvbnNlIHhtbG5z...
```

#### Devolución de Llamada de OpenID Connect (OIDC)
Valide tokens de ID y declaraciones desde Google Workspace, Auth0 o Keycloak:
```http
POST /api/sso/oidc/callback
Content-Type: application/json

{
  "sub": "usr_9918",
  "email": "alice@company.com",
  "iss": "https://accounts.google.com",
  "aud": "sheet-license-broker",
  "exp": 1776250000
}
```

#### Gestión de Proveedores de Identidad (IdP)
```http
# Registrar nuevo IdP SAML u OIDC
POST /api/sso/idp
Content-Type: application/json

{
  "id": "okta-corp",
  "protocol": "saml",
  "entity_id": "http://www.okta.com/exk123456",
  "sso_url": "https://company.okta.com/app/sso",
  "tenant_id": "default",
  "enabled": true
}

# Listar IdPs registrados
GET /api/sso/idp
```

#### Aprovisionamiento de Directorio SCIM 2.0 (RFC 7644)
Integre el aprovisionamiento del ciclo de vida de usuarios corporativos directamente con Okta, Microsoft Entra ID (Azure AD) o OneLogin:

```http
# Configuración del Proveedor de Servicios
GET /scim/v2/ServiceProviderConfig

# Listar usuarios del directorio (paginado)
GET /scim/v2/Users?startIndex=1&count=50

# Aprovisionar usuario (asigna automáticamente un puesto de licencia)
POST /scim/v2/Users
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "alice@corp.com",
  "emails": [{ "value": "alice@corp.com", "primary": true }],
  "roles": [{ "value": "operator" }],
  "active": true
}

# Desaprovisionar usuario (revoca instantáneamente el puesto de licencia asignado y envía el kill-switch)
DELETE /scim/v2/Users/usr-okta-8821
```

#### Tokens de Sesión RBAC Efímeros
```http
# Acuñar token efímero
POST /api/sso/token/mint
Content-Type: application/json

{
  "user_id": "usr_9918",
  "email": "alice@corp.com",
  "role": "admin",
  "scopes": ["license:read", "license:write", "sso:manage"]
}

# Introspeccionar token y aplicar permisos de alcance (scopes)
POST /api/sso/token/introspect
Content-Type: application/json

{
  "token": "sso_tok_7f2a9c4b...",
  "required_scope": "license:write"
}
```

---

### ⚛️ Criptografía Poscuántica y Firmas Híbridas ML-DSA

#### Obtener Parámetros de Retículos NIST FIPS 204 e Información de Clave Activa
```http
GET /api/pqc/params
```
**Respuesta:**
```json
{
  "status": "success",
  "lattice": { "dimension": 256, "modulus": 8380417, "d": 13 },
  "primary_algorithm": "ML-DSA-65",
  "active_key_id": "pqc-key-9b0d-e626",
  "grace_window_days": 7
}
```

#### Listar Claves Públicas de Verificación
```http
GET /api/pqc/keys
```

#### Emitir Firma de Licencia Híbrida Resistente a Computación Cuántica
```http
POST /api/pqc/sign
Content-Type: application/json

{
  "license_key": "LIC-PRO-2026-99",
  "hwid": "HWID-9B0D-E626-C8D9-6D4B",
  "payload": "entitlement-v1-pro-tier"
}
```
**Respuesta:**
```json
{
  "status": "success",
  "signature": {
    "algorithm": "Hybrid-P256-MLDSA65",
    "key_id": "pqc-key-9b0d-e626",
    "classical_sig_b64": "MEUCIQD...",
    "pqc_sig_hex": "1f8e2a...",
    "payload_hash_hex": "e3b0c44...",
    "created_at": "2026-10-16T19:30:00Z"
  }
}
```

#### Verificar Firmas Duales Clásica y de Retículos
```http
POST /api/pqc/verify
Content-Type: application/json

{
  "payload": "entitlement-v1-pro-tier",
  "signature": {
    "algorithm": "Hybrid-P256-MLDSA65",
    "key_id": "pqc-key-9b0d-e626",
    "classical_sig_b64": "MEUCIQD...",
    "pqc_sig_hex": "1f8e2a..."
  }
}
```
**Respuesta:**
```json
{
  "status": "success",
  "result": {
    "valid": true,
    "algorithm": "Hybrid-P256-MLDSA65",
    "key_id": "pqc-key-9b0d-e626",
    "classical_valid": true,
    "pqc_valid": true
  }
}
```

#### Rotación Atómica de Claves con Período de Gracia
```http
POST /api/pqc/rotate
Content-Type: application/json

{
  "algorithm": "ML-DSA-65",
  "grace_days": 7,
  "reason": "Routine cryptographic key rollover"
}
```

#### Revocación de Clave de Emergencia por Compromiso
```http
POST /api/pqc/revoke
Content-Type: application/json

{
  "key_id": "pqc-key-old-compromised",
  "reason": "Private key leakage detected"
}
```

---

### 🛡️ Detección de Anomalías de Comportamiento y Puntuación de Riesgo Adaptativa

`sheet-license-broker` incluye un motor de anomalías de comportamiento de nivel empresarial que realiza un seguimiento estadístico de la deriva de latidos, viajes geográficos imposibles y puntuación de riesgo dinámica en todas las aplicaciones cliente.

#### Política de Gobernanza Adaptativa
- **Puntuación 0 – 49 (Nominal)**: Operación normal, acceso sin restricciones. La actividad nominal reduce progresivamente los puntos de riesgo acumulados con el tiempo.
- **Puntuación 50 – 84 (Sospechoso)**: Requiere escalamiento de desafío. Aplica un desafío criptográfico de re-atestación de un solo uso de 5 minutos (`POST /api/anomaly/challenge/issue` y `/verify`).
- **Puntuación 85 – 100 (Alto Riesgo / Comprometido)**: Cuarentena inmediata zero-trust. Las llamadas de verificación (`POST /api/licenses/verify`) se rechazan automáticamente con HTTP 403 Forbidden y se difunden alertas a los webhooks de seguridad.

#### Registrar Observación de Telemetría del Cliente
```http
POST /api/anomaly/record
Content-Type: application/json

{
  "license_key": "SLB-PRO-2026-99",
  "hwid": "HWID-9B0D-E626-C8D9-6D4B",
  "ip": "198.51.100.24",
  "latitude": 37.5665,
  "longitude": 126.9780
}
```
**Respuesta:**
```json
{
  "status": "recorded",
  "risk_score": {
    "entity_id": "SLB-PRO-2026-99",
    "score": 0,
    "classification": "NOMINAL",
    "challenge_required": false,
    "quarantined": false,
    "last_assessed": "2026-10-16T21:30:00Z"
  }
}
```

#### Consultar Puntuación de Riesgo Adaptativa
```http
GET /api/anomaly/score?license_key=SLB-PRO-2026-99
```

#### Emitir y Verificar Desafío de Re-Atestación
```http
# Emitir token de desafío
POST /api/anomaly/challenge/issue
Content-Type: application/json

{
  "license_key": "SLB-PRO-2026-99",
  "hwid": "HWID-9B0D-E626-C8D9-6D4B"
}

# Verificar token de desafío
POST /api/anomaly/challenge/verify
Content-Type: application/json

{
  "challenge_token": "ch_7f2a9c4b..."
}
```

#### Exportar Grafo de Incidentes de Seguridad (Feed Estándar SIEM)
Exporte nodos y aristas topológicas de incidentes conformes con RFC formateados para Splunk, Datadog, Elastic y Microsoft Sentinel:
```http
GET /api/anomaly/graph?min_score=50&limit=50
```
**Respuesta:**
```json
{
  "schema_version": "siem-topology-v1",
  "generated_at": "2026-10-16T21:30:00Z",
  "nodes": [
    { "id": "SLB-PRO-2026-99", "type": "CLIENT", "risk_score": 60, "first_seen": "...", "last_seen": "..." },
    { "id": "198.51.100.0/24", "type": "SUBNET", "risk_score": 30, "first_seen": "...", "last_seen": "..." }
  ],
  "edges": [
    { "id": "edge-1", "source_id": "SLB-PRO-2026-99", "target_id": "198.51.100.0/24", "relationship": "OBSERVED_IN_SUBNET", "weight": 60, "timestamp": "..." }
  ],
  "total_incidents": 1
}
```

#### Estado de Telemetría del Motor
```http
GET /api/anomaly/status
```

---

## ⚡ Cloudflare Edge Gateway

Para una verificación de licencias en el borde distribuida globalmente y en submilisegundos, despliegue el Cloudflare Worker ubicado en `edge/cloudflare/`:

```bash
cd edge/cloudflare
wrangler deploy
```

- **Verificación POP en Menos de 10 ms**: Comprueba licencias válidas directamente desde la caché de Cloudflare Workers KV.
- **Web Crypto por Hardware**: Firma HMAC-SHA256 en el borde y prevención de repetición antes de alcanzar el origen.
- **Respaldo Automatizado al Origen**: Las consultas no almacenadas en caché, vinculaciones de claves y revocaciones se reenvían de forma transparente al servidor de origen.

---

## 💻 SDKs de Cliente Multilenguaje

`sheet-license-broker` incluye SDKs de cliente listos para producción en el directorio `sdk/` que admiten vinculación automática de dispositivos mediante identificador de hardware (HWID) y firma criptográfica de solicitudes HMAC-SHA256.

### 🐍 Cliente Python (`sdk/python/sheet_license_client.py`)

Cero dependencias externas (utiliza las bibliotecas estándar `urllib` y `hashlib`):

```python
from sheet_license_client import SheetLicenseClient, get_machine_hwid

client = SheetLicenseClient(base_url="http://localhost:9082", secret_key="your-hmac-secret")

# 1. Verificar clave de licencia (adjunta automáticamente el HWID del equipo local)
res = client.verify_license("SLB-XXXX-XXXX-XXXX")
if res.get("valid"):
    print("Licencia verificada. Nivel:", res.get("tier"))

    # 2. Comprobar asignación de feature flag dinámico
    if client.is_feature_enabled("SLB-XXXX-XXXX-XXXX", "analytics"):
        print("¡Módulo de analítica habilitado!")

    # 3. Registrar consumo frente a cuotas de nivel
    client.record_usage("SLB-XXXX-XXXX-XXXX", "api_calls", 1)

    # 4. Comprobación de token de directorio empresarial SSO y SCIM
    sso_status = client.get_sso_status()
    token_info = client.introspect_session_token("sso_tok_...", required_scope="license:write")

    # 5. Telemetría de anomalías de comportamiento y puntuación de riesgo
    client.record_anomaly_telemetry("SLB-XXXX-XXXX-XXXX", latitude=37.5665, longitude=126.9780)
    risk = client.get_anomaly_risk_score(license_key="SLB-XXXX-XXXX-XXXX")
else:
    print("Denegado:", res.get("message"))
```

### ⚡ C# / .NET y Unity (`sdk/csharp/SheetLicenseClient.cs`)

Asistente en un solo archivo compatible con Unity Mono/IL2CPP, WPF y .NET Desktop:

```csharp
using SheetLicenseBroker;

var client = new SheetLicenseClient("http://localhost:9082", "your-hmac-secret");

// Verificar licencia y comprobar asignación de nivel
var result = await client.VerifyLicenseAsync("SLB-XXXX-XXXX-XXXX");
if (result.Valid) {
    Console.WriteLine($"¡Acceso concedido! Nivel: {result.Tier}, Expiración: {result.ExpirationDate}");

    // Restricción dinámica de características (Feature gating)
    if (await client.IsFeatureEnabledAsync("SLB-XXXX-XXXX-XXXX", "analytics")) {
        Console.WriteLine("Analítica inicializada.");
    }

    // Registrar uso
    await client.RecordUsageAsync("SLB-XXXX-XXXX-XXXX", "api_calls", 1);

    // Comprobación de token de directorio empresarial SSO y SCIM
    var ssoStatus = await client.GetSSOStatusAsync();
    var tokenInfo = await client.IntrospectSessionTokenAsync("sso_tok_...", "license:write");

    // Telemetría de anomalías de comportamiento y puntuación de riesgo
    await client.RecordAnomalyTelemetryAsync("SLB-XXXX-XXXX-XXXX", 37.5665, 126.9780);
    var risk = await client.GetAnomalyRiskScoreAsync("SLB-XXXX-XXXX-XXXX");
}
```

### 🟩 TypeScript y Node.js (`@sheet-license/client`)

Paquete ESM nativo sin dependencias para backends Node.js y aplicaciones Electron:

```typescript
import { SheetLicenseClient } from '@sheet-license/client';

const client = new SheetLicenseClient({
  baseUrl: 'http://localhost:9082',
  secretKey: 'your-hmac-secret',
});

const result = await client.verifyLicense('SLB-XXXX-XXXX-XXXX');
if (result.valid) {
  console.log('Licencia activa. Nivel:', result.tier);

  // Restricción dinámica de características (Feature gating)
  const hasAnalytics = await client.isFeatureEnabled('SLB-XXXX-XXXX-XXXX', 'analytics');
  if (hasAnalytics) {
    console.log('Característica de analítica habilitada para el cliente');
  }

  // Registrar métricas de uso
  await client.recordUsage('SLB-XXXX-XXXX-XXXX', 'api_calls', 1);

  // Comprobación de token de directorio empresarial SSO y SCIM
  const ssoStatus = await client.getSSOStatus();
  const tokenInfo = await client.introspectSessionToken('sso_tok_...', 'license:write');

  // Telemetría de anomalías de comportamiento y puntuación de riesgo
  await client.recordAnomalyTelemetry('SLB-XXXX-XXXX-XXXX', { latitude: 37.5665, longitude: 126.9780 });
  const risk = await client.getAnomalyRiskScore('SLB-XXXX-XXXX-XXXX');
}
```

### 🔷 Cliente Go (`sdk/go/client.go`)

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/kLauncher1/sheet-license-broker/sdk/go"
)

func main() {
	client := sdk.NewClient("http://localhost:9082", []byte("your-hmac-secret"), 5*time.Second)

	res, err := client.VerifyLicense(context.Background(), "SLB-XXXX-XXXX-XXXX", "")
	if err == nil && res.Valid {
		fmt.Printf("Licencia válida (Nivel: %s). Iniciando aplicación...\n", res.Tier)

		// Restricción dinámica de características (Feature gating)
		allowed, _ := client.IsFeatureEnabled(context.Background(), "SLB-XXXX-XXXX-XXXX", "analytics")
		if allowed {
			fmt.Println("Característica de analítica habilitada.")
		}

		// Registrar consumo de uso
		_ = client.RecordUsage(context.Background(), "SLB-XXXX-XXXX-XXXX", "api_calls", 1)

		// Comprobación de token de directorio empresarial SSO y SCIM
		ssoStatus, _ := client.GetSSOStatus(context.Background())
		tokenInfo, _ := client.IntrospectSessionToken(context.Background(), "sso_tok_...", "license:write")
		_ = ssoStatus
		_ = tokenInfo

		// Telemetría de anomalías de comportamiento y puntuación de riesgo
		_ = client.RecordAnomalyTelemetry(context.Background(), sdk.ClientObservation{
			LicenseKey: "SLB-XXXX-XXXX-XXXX",
			Latitude:   37.5665,
			Longitude:  126.9780,
		})
		risk, _ := client.GetAnomalyRiskScore(context.Background(), "SLB-XXXX-XXXX-XXXX", "")
		_ = risk
	}
}
```

---

## 🛠️ Pruebas y Compilación

Ejecute la suite de pruebas automatizadas:

```bash
# Ejecutar pruebas unitarias en todos los paquetes
go test -v ./...

# Compilar binario de producción independiente
go build -ldflags="-s -w" -o sheet-license-broker.exe .
```

---

## 📄 Licencia

Licenciado bajo la [Licencia MIT](LICENSE).
