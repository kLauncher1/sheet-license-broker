<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <b>🇪🇸 Español</b><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📑 Sheet-License-Broker

<p align="center">
  <strong>Pasarela de autenticación sin servidor, asignación de licencias y base de datos NoSQL impulsada por Google Sheets y Google Apps Script</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/version-v1.7.0-emerald.svg" alt="Version: v1.7.0">
  <img src="https://img.shields.io/badge/anycast-Global%20POPs%20%26%20Sub--ms%20Cache-0284C7.svg" alt="Geo Anycast & Sub-ms Cache">
  <img src="https://img.shields.io/badge/enclave-Intel%20SGX%20%26%20AMD%20SEV--SNP-059669.svg" alt="Confidential Enclaves">
  <img src="https://img.shields.io/badge/anomaly-Z--Score%20%26%20SIEM%20Topology-F59E0B.svg" alt="Behavioral Anomaly & SIEM Graph">
  <img src="https://img.shields.io/badge/pqc-NIST%20FIPS%20204%20ML--DSA-7C3AED.svg" alt="Post-Quantum Cryptography">
  <img src="https://img.shields.io/badge/sso-SAML%202.0%20%26%20OIDC-blueviolet.svg" alt="SAML & OIDC SSO">
  <img src="https://img.shields.io/badge/scim-RFC%207643%20%2F%207644%20SCIM%202.0-10B981.svg" alt="SCIM 2.0 Directory Provisioning">
  <img src="https://img.shields.io/badge/zkp-pedersen%20%26%20sigma%20proofs-10B981.svg" alt="Zero-Knowledge Proofs">
  <img src="https://img.shields.io/badge/stream-websocket%20telemetry%20%26%20kill--switch-10B981.svg" alt="WebSocket Streaming & Kill-Switch">
  <img src="https://img.shields.io/badge/consensus-raft%20quorum%20%26%20CRDT-blue.svg" alt="Distributed Consensus">
  <img src="https://img.shields.io/badge/security-rate%20limits%20%26%20SIEM%20audit-blueviolet.svg" alt="Security & Rate Limiting">
  <img src="https://img.shields.io/badge/attestation-TPM%202.0%20%26%20Enclave-0284C7.svg" alt="Hardware Attestation">
  <img src="https://img.shields.io/badge/tiers-dynamic%20flags-8B5CF6.svg" alt="Feature Flags & Tier Metering">
  <img src="https://img.shields.io/badge/go-%3E%3D1.22-00ADD8.svg" alt="Go Version">
  <img src="https://img.shields.io/badge/high--availability-active--standby-059669.svg" alt="High Availability">
  <img src="https://img.shields.io/badge/metrics-prometheus-E6522C.svg" alt="Prometheus Metrics">
  <img src="https://img.shields.io/badge/cloudflare-edge%20worker-F38020.svg" alt="Cloudflare Workers">
  <img src="https://img.shields.io/badge/google--apps--script-deployed-34A853.svg" alt="Google Apps Script">
  <img src="https://img.shields.io/badge/hosting-0%24%2Fmo-10B981.svg" alt="Hosting Cost">
</p>
</div>

---

<br />

<details open>
<summary><h3>💡 Descripción General y Arquitectura Central</h3></summary>

**`sheet-license-broker`** convierte cualquier hoja de cálculo de Google Spreadsheet en un backend sin servidor autenticado y listo para producción para aplicaciones de escritorio, utilidades CLI y herramientas SaaS independientes.

En lugar de pagar costosas instancias de bases de datos en la nube o gestionar complejos contenedores Docker simplemente para gestionar inicios de sesión de usuarios y licencias de software, `sheet-license-broker` combina un motor en la nube de **Google Apps Script (GAS)** con un **puente Go de alta velocidad, enrutamiento perimetral Anycast geodistribuido y caché L1 de sub-milisegundo, puentes de enclave de computación confidencial Intel SGX / AMD SEV-SNP, cadenas de firmas post-cuánticas ML-DSA, consenso distribuido Raft quorum, sincronización CRDT LWW-Element-Set, Cloudflare Edge Gateway, atestación criptográfica de hardware (TPM 2.0 y Enclaves), aislamiento multi-inquilino, alta disponibilidad activo-espera de doble hoja, flags de características dinámicas y medición de uso, cola de disco cifrada, métricas de Prometheus, verificación anti-manipulación HMAC, caché local resistente sin conexión y una consola de administración Web integrada**.


### 🏛️ Topología de la Arquitectura del Sistema

```mermaid
flowchart TD
    Client["Desktop App / CLI / WebApp"] -->|HTTPS REST + HMAC-SHA256| Guard["Anti-Tamper Security Guard & Nonce Cache"]
    Guard --> Limiter["Rate Limiter & IP Reputation Gate"]
    Limiter --> Broker["sheet-license-broker (Go Gateway)"]
    Broker -->|//go:embed| WebUI["Embedded Admin Console (Port 9082)"]
    Broker -->|Scrape| Prom["Prometheus Monitoring (/metrics)"]
    Broker -->|Encrypted Disk Journal| Spool["Local Disk Spool (AES-256-GCM)"]
    Broker -->|SIEM Export| SIEM["Audit Export Pipeline (AES-256-GCM)"]
    Broker -->|Alerts| Alerts["Security Webhooks (Discord & Slack)"]
    Broker -->|Raft RPC & CRDT Sync| Peers["Cluster Peer Mesh (Anti-Entropy)"]
    Broker -->|In-Memory TTL Cache| Cache["Local Cache (Quota & Offline Fallback)"]
    Broker -->|Active Role| Primary["Primary GAS Web App (Code.gs)"]
    Broker -.->|Automatic Failover| Standby["Standby GAS Web App (Code.gs)"]
    Primary --> Sheets1["Primary Google Sheet DB"]
    Standby -.-> Sheets2["Standby Google Sheet DB"]

    subgraph Google Sheets Database
        Sheets1 --> Tab1["Tab: Users (Salted Hash Auth)"]
        Sheets1 --> Tab2["Tab: Licenses (HWID Lock & Expiry)"]
        Sheets1 --> Tab3["Tab: Blacklist (Revocations & Banned HWIDs)"]
        Sheets1 --> Tab4["Tab: Audit_Logs (Security Audit Trail & Bans)"]
        Sheets1 --> Tab5["Tab: Attestations (TPM Quotes & Claims)"]
        Sheets1 --> Tab6["Tab: KV_Database (NoSQL Store)"]
        Sheets1 --> Tab7["Tab: ConsensusNodes (Peer Discovery & Heartbeats)"]
    end
```

</details>

<br />

<details open>
<summary><h3>⚡ Matriz Completa de Características y Puntos Clave</h3></summary>

### ¿Por qué Google Sheets como backend?
- **Zero Cost ($0/mo)**: Leverages Google Drive and Apps Script free quotas (up to 20,000 requests/day).
- **Geo-Distributed Edge CDN Anycast Routing & Sub-Millisecond L1 Cache**: Routes global requests to the nearest healthy Point of Presence (POP across Ashburn, San Jose, Frankfurt, Tokyo, Singapore, Sao Paulo) via Haversine spherical distance and dynamic active RTT telemetry. Delivers cached license lookups in under 100 microseconds with asynchronous Stale-While-Revalidate (SWR) and issues HMAC-signed emergency mitigation leases during network partitions.
- **Confidential Computing & Hardware Enclave Attestation Bridge**: Cryptographically validates Intel SGX Quote v3/v4 ECDSA P-256 signatures and AMD SEV-SNP 1184-byte signed attestation reports against MREnclave/MRSigner/ISVSVN policies. Negotiates ephemeral ECDH P-256 encrypted tunnels with RFC 5869 HKDF-SHA256 key expansion and AES-256-GCM, enabling zero-plaintext in-enclave evaluation where the host OS, hypervisor, and broker transit layers never observe cleartext keys.
- **Post-Quantum Cryptography & ML-DSA Signature Chains (NIST FIPS 204)**: Quantum-resistant module-lattice digital signature verification (ML-DSA-44 / ML-DSA-65) with dual classical ECDSA / lattice hybrid signature chains (`Hybrid-P256-MLDSA65`), zero-downtime key rotation grace windows, and instant emergency revocation kill-switch broadcasts.
- **Behavioral Anomaly Detection & Adaptive Risk Scoring**: Statistical sliding-window Z-Score heartbeat drift tracking (&plusmn;15% jitter tolerance), Haversine velocity impossible travel detection (&gt;950 km/h or concurrent /24 subnets), adaptive risk score calculation with progressive nominal decay, automated re-attestation challenge escalation at risk score &ge; 50, zero-trust automatic quarantine at risk score &ge; 85, and standardized security incident topology graph exporter (`siem-topology-v1`) for enterprise SIEM ingestion.
- **Enterprise Single Sign-On (SSO) & SCIM 2.0 Directory Provisioning**: SAML 2.0 & OIDC identity federation, RFC 7643/7644 directory synchronization, automated license seat allocation, and instant deprovisioning revocation.
- **Zero-Knowledge Proof (ZKP) Anonymous Verification**: Pedersen commitments over NIST P-256 with deterministic hash-to-curve independent generators, non-interactive Sigma presentation proofs (Fiat-Shamir transformed), and spent nullifier replay defense registries protecting client hardware privacy.
- **Distributed Raft Quorum Consensus & CRDT Mesh**: Lightweight leader election, majority log quorum, conflict-free LWW-Element-Set state replication, and SHA-256 Merkle tree state digests for anti-entropy sync across distributed broker nodes.
- **Enterprise Rate-Limiting & Progressive Backoff**: Thread-safe sliding-window throttling per IP and HWID with progressive penalty delays and standard `X-RateLimit-*` headers.
- **Sliding-Window IP/HWID Reputation Cache**: Automatic temporary bans and high-priority incident webhook alerts upon repeated security infractions.
- **Encrypted Audit Token Export for SIEM**: Compliant AES-256-GCM encrypted audit bundles sealed with HMAC signatures for Splunk, Datadog, and AWS CloudWatch ingest.
- **Cryptographic Hardware Attestation & Enclave Binding**: TPM 2.0 PCR quote verification and Apple Secure Enclave / Windows Hello hardware key attestation preventing clone attacks.
- **Client Anti-Debugging & Memory-Tamper Telemetry**: Continuous integrity scoring with instant kill-switch auto-banning devices exhibiting debugger attachment or code section modifications.
- **Dynamic Feature Flags & Usage-Based Tier Metering**: Free, Pro, and Enterprise subscription tiers with runtime feature gating (`client.isFeatureEnabled("analytics")`) and atomic consumption quota tracking persisted directly in Google Sheets.
- **Dual-Sheet Active-Standby Replication**: Automatic failover between primary and standby sheets with collision-free bidirectional reconciliation.
- **Encrypted Local Disk Spool**: AES-256-GCM encrypted journal queue (`spool.bin`) guaranteeing zero data loss during network disruptions.
- **Enterprise Prometheus Telemetry (`/metrics`)**: Built-in scraper endpoint exposing counters, gauges, and latencies in Prometheus format.
- **Incident Alert Webhooks**: Immediate rich security incident notifications dispatched to Discord and Slack channels.
- **Multi-Tenant Namespacing**: Isolate distinct products and tenants with custom prefixes (e.g., `ACME-LIC-XXXX-YYYY`) and independent policies.
- **Cloudflare Edge Gateway**: Sub-millisecond edge license verification via Cloudflare Workers and Workers KV with Web Crypto API.
- **Human-Readable Admin Panel**: Your Google Sheet is your database. View, edit, ban, or grant licenses directly in real-time.
- **Hardware-Locked Protection (HWID)**: Locks license keys to specific machine hardware IDs on first boot.
- **Cryptographic HMAC-SHA256 Anti-Tamper**: Protects incoming client traffic against MITM inspection and reverse-engineered payload spoofing.
- **Sliding-Window Nonce Replay Mitigation**: Prevents request replay attacks with a 5-minute time-drift tolerance window.
- **Instant Remote Revocation & Device Blacklisting**: Kill licenses or ban compromised hardware IDs directly from the web console or Google Sheets tab.
- **Automated Backup & Disaster Recovery**: Point-in-time state export and restore protected with SHA-256 data checksums and AES-256-GCM encryption.
- **Real-Time Lifecycle Webhooks**: Event dispatchers with worker queues and HMAC-signed webhook delivery to tenant and global endpoints.
- **Salted SHA-256 Authentication**: Passwords are cryptographically salted and hashed before persistence.
- **Resilient Local Caching & Offline Grace**: Memory-cached licenses and KV documents protect against Google API rate limits (HTTP 429) and network blips.
- **Embedded Web Dashboard**: Self-contained single binary (`sheet-license-broker.exe`) with an emerald-dark management console.

### 📊 Matriz de Características y Niveles de Capacidad

| Característica / Especificación | Nivel Gratuito (Free) | Nivel Pro (Pro) | Nivel Empresarial (Enterprise) |
| :--- | :---: | :---: | :---: |
| **Alojamiento e Infraestructura Base** | $0/mo (GAS Quota) | $0/mo | $0/mo |
| **Dispositivos Máximos por Licencia (Bloqueo HWID)** | 1 Device | 5 Devices | Unlimited / Configurable |
| **TTL en Memoria y Caché sin Conexión** | ✅ (600s TTL) | ✅ (Configurable) | ✅ (Sub-ms Fast-Path) |
| **Firma Criptográfica HMAC-SHA256** | ✅ | ✅ | ✅ Enforced |
| **Ventana Nonce Anti-Replay** | ✅ (5-min drift) | ✅ | ✅ |
| **Almacén de Clave-Valor (KV) NoSQL** | ✅ | ✅ | ✅ |
| **Aislamiento de Espacios Multi-Inquilino** | ❌ (Single) | ✅ (Custom Prefix) | ✅ (Full Isolation) |
| **Conmutación por Error Automática de Doble Hoja HA** | ❌ | ✅ | ✅ |
| **Cola de Disco Cifrada Local (AES-256-GCM)** | ❌ | ✅ | ✅ |
| **Pasarela Perimetral Cloudflare (Sub-10ms)** | ❌ | ✅ | ✅ |
| **Enrutamiento Anycast Geodistribuido (6 POPs Globales)** | ❌ | ✅ | ✅ Sub-100µs L1 Cache |
| **Computación Confidencial (Intel SGX / AMD SEV)** | ❌ | ❌ | ✅ Zero-Plaintext Tunnels |
| **Criptografía Post-Cuántica (NIST FIPS 204 ML-DSA)** | ❌ | ❌ | ✅ NIST FIPS 204 Hybrid |
| **Detección de Anomalías de Comportamiento (Z-Score)** | ❌ | ❌ | ✅ SIEM Topology Feed |
| **SSO Empresarial (SAML 2.0 / OIDC)** | ❌ | ❌ | ✅ Okta, Azure AD, Google |
| **Aprovisionamiento de Directorio SCIM 2.0** | ❌ | ❌ | ✅ Automated Lifecycle |
| **Pruebas de Conocimiento Cero (NIST P-256 Sigma)** | ❌ | ❌ | ✅ Hardware Privacy |
| **Consenso Raft Distribuido y Malla CRDT** | ❌ | ❌ | ✅ Multi-Node Consensus |
| **Telemetría de Prometheus (`/metrics`)** | ❌ | ✅ | ✅ Extended Metrics |
| **Webhooks de Incidentes de Seguridad (Discord y Slack)** | ❌ | ✅ | ✅ High-Priority Alerting |

</details>

<br />

<details open>
<summary><h3>🚀 Guía de Inicio Rápido y Despliegue</h3></summary>

### 1. Ejecutar la Pasarela Local y el Panel de Control

Asegúrese de tener instalado Go 1.22+ en su estación de trabajo:

```bash
# Clonar el repositorio
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# Compilar y ejecutar el binario único en modo autónomo
go run .
```

Abra su navegador en **`http://localhost:9082`** para acceder a la consola de administración en vivo.

### 2. Conectar a Google Sheets Real (Modo Proxy)

Para conectar la pasarela a su Web App de Google Apps Script desplegada:

```bash
# Establecer la URL de su Web App de Apps Script
export GAS_WEBAPP_URL="https://script.google.com/macros/s/.../exec"
export CACHE_TTL_SECONDS="600" # Opcional: TTL de caché de 10 minutos

# Iniciar la pasarela
./sheet-license-broker.exe
```

El servidor detecta automáticamente la URL remota, reenvía las consultas entrantes, almacena los resultados localmente y recurre de manera transparente a los datos en caché durante interrupciones de red.

---

### 3. Configuración de Google Sheets y Despliegue con Clasp

### Opción A: Despliegue Automatizado con Clasp CLI

Si utiliza la interfaz CLI `@google/clasp`:

```bash
# 1. Iniciar sesión en su cuenta de Google
npx @google/clasp login

# 2. Desplegar usando el script automatizado
node scripts/deploy_clasp.mjs --script-id <YOUR_APPS_SCRIPT_ID>
```

See [`gas/README.md`](file:///gas/README.md) for full instructions on creating and configuring Clasp projects.

### Opción B: Configuración Manual (3 Minutos)

1. Abra [Google Sheets](https://sheets.new) y cree una nueva hoja de cálculo en blanco.
2. En el menú superior, navegue a **Extensiones > Apps Script**.
3. Reemplace el código predeterminado con el contenido de [`gas/Code.gs`](../../gas/Code.gs).
4. Haga clic en **Implementar > Nueva implementación**:
   - Tipo: **Aplicación web (Web app)**
   - Ejecutar como: **Yo (su correo electrónico)**
   - Quién tiene acceso: **Cualquiera (Anyone)**
5. Haga clic en **Implementar** y copie su **URL de aplicación web** (`https://script.google.com/macros/s/.../exec`).

Su hoja de cálculo generará automáticamente 3 pestañas dedicadas en la primera solicitud:
- **`Users`**: `user_id`, `username`, `password_hash`, `salt`, `role`, `created_at`
- **`Licenses`**: `license_key`, `bound_hwid`, `max_devices`, `status`, `expires_at`, `created_at`
- **`KV_Database`**: `collection`, `doc_id`, `payload`, `updated_at`

---

### 4. Despliegue de Pasarela Perimetral en Cloudflare

Para una verificación de licencias perimetral ultrarrápida a nivel global, despliegue el Worker ubicado en `edge/cloudflare/`:

```bash
cd edge/cloudflare
wrangler deploy
```

- **Sub-10ms POP Verification**: Checks valid licenses directly from Cloudflare Workers KV cache.
- **Hardware Web Crypto**: Edge HMAC-SHA256 signature and replay prevention before hitting origin.
- **Automated Origin Fallback**: Uncached queries, key binds, and revocations transparently proxy to the origin server.

---

### 5. Verificación de Pruebas y Compilación de Binario

Ejecute la suite de pruebas unitarias y compile el binario de producción:

```bash
# Ejecutar pruebas unitarias en todos los paquetes
go test -v ./...

# Compilar binario autónomo para producción
go build -ldflags="-s -w" -o sheet-license-broker.exe .
```

</details>

<br />

<details>
<summary><h3>🛡️ Computación Confidencial y Atestación de Enclave de Hardware</h3></summary>

### 🔒 Computación Confidencial y Puente de Atestación de Enclave de Hardware

`sheet-license-broker` includes a hardware-rooted confidential computing bridge supporting Intel SGX Quote v3/v4 and AMD SEV-SNP 1184-byte cryptographically signed attestation reports with ephemeral ECDH P-256 encrypted tunnels.

#### Garantías de Arquitectura y Seguridad
- **Hardware-Rooted Trust**: Verifies Intel SGX Quote v3/v4 ECDSA P-256 signatures against MREnclave, MRSigner, and ISVSVN security version policies. Verifies AMD SEV-SNP ECDSA P-384 / P-256 reports against launch measurement digests and guest debug policies (bit 17 enforcement).
- **Ephemeral ECDH Tunnel & HKDF Expansion**: Derives independent client and server 32-byte session keys using native RFC 5869 HKDF Extract-and-Expand with SHA-256 and authenticated AES-256-GCM encryption.
- **Replay Protection**: Strictly monotonic 64-bit sequence counters reject out-of-order or duplicate requests.
- **Zero-Plaintext In-Enclave Evaluation**: Sensitive license keys, hardware identifiers, and feature entitlement policies are evaluated inside secure memory. Neither untrusted host OS, hypervisors, nor intermediary broker transit networks observe cleartext license keys.

#### Solicitar Nonce de Desafío de Un Solo Uso
```http
POST /api/enclave/challenge
Content-Type: application/json

{}
```
**Response:**
```json
{
  "challenge": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "expires_in": 300
}
```

#### Atestar Quote de Enclave de Hardware
```http
POST /api/enclave/attest
Content-Type: application/json

{
  "platform": "intel_sgx",
  "quote": "<quote-hex-bytes>",
  "nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "policy_id": "pol-prod-sgx-01"
}
```
**Response:**
```json
{
  "valid": true,
  "attestation": {
    "valid": true,
    "platform": "intel_sgx",
    "mr_enclave": "aabbccddeeff...",
    "mr_signer": "112233445566...",
    "svn": 2,
    "debug": false,
    "report_data_hex": "..."
  }
}
```

#### Establecer Túnel Cifrado Mutuo Efímero ECDH
```http
POST /api/enclave/tunnel/handshake
Content-Type: application/json

{
  "platform": "intel_sgx",
  "quote": "<quote-hex-bytes>",
  "nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "client_public_key": "04..."
}
```
**Response:**
```json
{
  "established": true,
  "session_id": "enclave-sess-...",
  "broker_public_key": "04...",
  "expires_at": "2026-10-18T20:30:00Z"
}
```

#### Enviar Solicitud de Evaluación Cifrada de Cero Texto Plano
```http
POST /api/enclave/tunnel/evaluate
Content-Type: application/json

{
  "session_id": "enclave-sess-...",
  "sequence": 1,
  "nonce": "<12-byte-hex-iv>",
  "payload": "<aes-256-gcm-ciphertext-hex>"
}
```
**Response:**
```json
{
  "session_id": "enclave-sess-...",
  "sequence": 1,
  "nonce": "<12-byte-hex-iv>",
  "payload": "<aes-256-gcm-encrypted-result-hex>"
}
```

#### Consultar Estado y Telemetría del Enclave
```http
GET /api/enclave/status
```

---

### Atestación de Hardware y Telemetría Anti-Manipulación

#### Solicitar Nonce de Desafío TPM / Enclave
```http
POST /api/attestation/challenge
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid": "WIN-B829-94AA-0123"
}
```
**Response:**
```json
{
  "status": "success",
  "challenge_id": "9a4f2b1c8e3d",
  "nonce": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "expires_at": "2026-10-14T12:05:00Z"
}
```

#### Verificar Integridad de Cotización PCR de TPM 2.0
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

#### Transmitir Telemetría Anti-Depuración e Integridad
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

</details>

<br />

<details>
<summary><h3>🔐 Criptografía Post-Cuántica (PQC) y Firmas Híbridas ML-DSA</h3></summary>

### ⚛️ Criptografía Post-Cuántica y Firmas Híbridas ML-DSA

#### Obtener Parámetros de Retícula NIST FIPS 204 y Claves Activas
```http
GET /api/pqc/params
```
**Response:**
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
**Response:**
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

#### Verificar Firmas Duales Clásicas y de Retícula
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
**Response:**
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

#### Revocación de Emergencia por Compromiso de Clave (Kill-Switch)
```http
POST /api/pqc/revoke
Content-Type: application/json

{
  "key_id": "pqc-key-old-compromised",
  "reason": "Private key leakage detected"
}
```

</details>

<br />

<details>
<summary><h3>👁️ Detección de Anomalías de Comportamiento y Gráfico de Seguridad SIEM</h3></summary>

### 🛡️ Detección de Anomalías de Comportamiento y Puntuación Adaptativa de Riesgo

`sheet-license-broker` includes an enterprise-grade behavioral anomaly engine that tracks statistical heartbeat drift, impossible geographic travel, and dynamic risk scoring across client applications.

#### Política de Gobernanza de Seguridad Adaptativa
- **Score 0 – 49 (Nominal)**: Normal operation, unrestricted access. Nominal activity progressively decays accumulated risk points over time.
- **Score 50 – 84 (Suspicious)**: Requires challenge escalation. Enforces a 5-minute single-use cryptographic re-attestation challenge (`POST /api/anomaly/challenge/issue` and `/verify`).
- **Score 85 – 100 (High Risk / Compromised)**: Immediate zero-trust quarantine. Verification calls (`POST /api/licenses/verify`) are automatically rejected with HTTP 403 Forbidden, and alerts are broadcast to security webhooks.

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
**Response:**
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

#### Consultar Puntuación de Riesgo Adaptativa en Tiempo Real
```http
GET /api/anomaly/score?license_key=SLB-PRO-2026-99
```

#### Emitir y Verificar Desafío de Re-Atestación
```http
# Issue challenge token
POST /api/anomaly/challenge/issue
Content-Type: application/json

{
  "license_key": "SLB-PRO-2026-99",
  "hwid": "HWID-9B0D-E626-C8D9-6D4B"
}

# Verify challenge token
POST /api/anomaly/challenge/verify
Content-Type: application/json

{
  "challenge_token": "ch_7f2a9c4b..."
}
```

#### Exportar Gráfico de Incidentes de Seguridad (Canal Estándar SIEM)
Export RFC-compliant topological incident nodes and edges formatted for Splunk, Datadog, Elastic, and Microsoft Sentinel:
```http
GET /api/anomaly/graph?min_score=50&limit=50
```
**Response:**
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

#### Estado de Funcionamiento del Motor de Anomalías
```http
GET /api/anomaly/status
```

</details>

<br />

<details>
<summary><h3>🔑 SSO Empresarial (SAML/OIDC) y Aprovisionamiento de Directorio SCIM 2.0</h3></summary>

### 🔐 Inicio de Sesión Único Empresarial (SSO) y Aprovisionamiento SCIM 2.0

#### Metadatos del Proveedor de Servicios (SP) SAML 2.0
Download standard SP metadata XML for Okta, Azure AD, or PingFederate:
```http
GET /api/sso/saml/metadata?entity_id=urn:sheet-license-broker:sp
```

#### Servicio de Consumidor de Aserciones (ACS) SAML 2.0
Process inbound SAML assertions and issue authenticated session tokens:
```http
POST /api/sso/saml/acs
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PHNhbWxwOlJlc3BvbnNlIHhtbG5z...
```

#### Devolución de Llamada de OpenID Connect (OIDC)
Validate ID tokens and claims from Google Workspace, Auth0, or Keycloak:
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

#### Registro y Gestión de Proveedores de Identidad (IdP)
```http
# Register new SAML or OIDC IdP
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

# List registered IdPs
GET /api/sso/idp
```

#### Aprovisionamiento de Directorio SCIM 2.0 (RFC 7644)
Integrate corporate user lifecycle provisioning directly with Okta, Microsoft Entra ID (Azure AD), or OneLogin:

```http
# Service Provider Configuration
GET /scim/v2/ServiceProviderConfig

# List directory users (paginated)
GET /scim/v2/Users?startIndex=1&count=50

# Provision user (automatically allocates license seat)
POST /scim/v2/Users
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "alice@corp.com",
  "emails": [{ "value": "alice@corp.com", "primary": true }],
  "roles": [{ "value": "operator" }],
  "active": true
}

# Deprovision user (instantly revokes allocated license seat and pushes kill-switch)
DELETE /scim/v2/Users/usr-okta-8821
```

#### Emisión e Introspección de Tokens de Sesión RBAC
```http
# Mint ephemeral token
POST /api/sso/token/mint
Content-Type: application/json

{
  "user_id": "usr_9918",
  "email": "alice@corp.com",
  "role": "admin",
  "scopes": ["license:read", "license:write", "sso:manage"]
}

# Introspect token and enforce scope permissions
POST /api/sso/token/introspect
Content-Type: application/json

{
  "token": "sso_tok_7f2a9c4b...",
  "required_scope": "license:write"
}
```

</details>

<br />

<details>
<summary><h3>🕵️ Arquitectura de Pruebas de Conocimiento Cero (ZKP)</h3></summary>

### 🕵️ Verificación Anónima con Pruebas de Conocimiento Cero (ZKP)

#### Obtener Parámetros Públicos y Generadores NIST P-256
```http
GET /api/zkp/params
```

#### Emitir Credencial Ciega Anónima (Blinded Credential)
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

#### Inspeccionar Estado de Nullifier Utilizado
```http
GET /api/zkp/nullifiers/check?nullifier=7f2a9c4b...
```

</details>

<br />

<details>
<summary><h3>🌐 Consenso Distribuido Raft Quorum y Sincronización de Malla CRDT</h3></summary>

### 🌐 Consenso Distribuido y Sincronización de Quórum Multi-Región

#### Estado del Clúster y Topología de Pares
```http
GET /api/consensus/status
GET /api/consensus/peers
```

Response:
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

#### Unirse como Nodo Par al Clúster
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

### ⚡ Transmisión WebSocket en Tiempo Real y Desconexión Remota

#### Transmisión de Telemetría Bidireccional por WebSocket
Connect persistent WebSocket clients to `/api/stream/ws` for real-time telemetry streaming and sub-second kill-switch pushes:

```http
GET /api/stream/ws?license_key=SLB-XXXX-XXXX&hwid=HWID-1234 HTTP/1.1
Host: localhost:9082
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

#### Consultar Clientes Conectados y Registro de Telemetría
```http
# List active streaming sessions
GET /api/stream/clients

# Query streaming metrics and recent event audit log
GET /api/stream/telemetry
```

#### Ejecutar Interruptor de Desconexión Remoto Instantáneo (Kill-Switch)
```http
POST /api/stream/kill
Content-Type: application/json

{
  "target": "SLB-XXXX-XXXX",
  "reason": "Suspected device cloning or fraud",
  "immediate": true
}
```
*Note: Target can be a specific License Key, Device HWID, Client ID, or `"ALL"` for emergency broadcast kill-switch execution. Signals are pushed to matching client sockets with sub-second delivery.*

---

### 🌐 Enrutamiento Perimetral Anycast Geodistribuido y Caché L1 Sub-Milisegundo

`sheet-license-broker` includes an enterprise-grade Geo-Distributed Anycast Edge Routing and Sub-Millisecond L1 Cache engine (`internal/anycast/`) designed to route incoming global license queries to the lowest-latency healthy Point of Presence (POP) and deliver cached verifications in under 100 microseconds.

#### Capacidades Arquitectónicas Principales
- **Global 6-Node POP Registry**: Ashburn (IAD / us-east), San Jose (SJC / us-west), Frankfurt (FRA / eu-central), Tokyo (NRT / ap-northeast), Singapore (SIN / ap-southeast), and Sao Paulo (GRU / sa-east).
- **Great-Circle Haversine Routing**: Computes spherical distances from client coordinates (`lat`, `lon`), blends active dynamic telemetry probes (RTT latency, jitter, packet loss), and outputs optimal healthy POP selections with alternative fallbacks.
- **Cryptographically Signed Routing Tokens**: Issues and verifies HMAC-SHA256 signed routing tokens guaranteeing edge affinity and tamper protection.
- **Sub-Millisecond In-Memory L1 Cache**: Serves license checks in <100 microseconds with asynchronous Stale-While-Revalidate (SWR) background cache refreshes to eliminate latency spikes.
- **Geographic Partition Mitigation & Emergency Leases**: During upstream cloud outages or localized network disconnects, automatically issues HMAC-signed emergency lease tokens to keep client applications running smoothly without lockouts.

#### Calcular Ruta Anycast Más Cercana
```http
GET /api/anycast/route?lat=37.7749&lon=-122.4194&ip=198.51.100.1&region=us-west
```
**Response:**
```json
{
  "selected_pop": {
    "id": "sjc",
    "name": "San Jose SJC",
    "region": "us-west",
    "country": "US",
    "latitude": 37.3382,
    "longitude": -121.8863,
    "endpoint_url": "https://sjc.edge.broker.internal",
    "weight": 100,
    "avg_rtt_ms": 12.4,
    "status": "healthy"
  },
  "fallback_pops": [
    { "id": "iad", "name": "Ashburn IAD", "region": "us-east", "status": "healthy" }
  ],
  "estimated_latency_ms": 12.4,
  "signed_routing_token": "anycast-tok-7f2a...",
  "timestamp": "2026-10-18T21:40:00Z"
}
```

#### Ingestar Sonda Dinámica de Latencia RTT
```http
POST /api/anycast/probe
Content-Type: application/json

{
  "target_pop_id": "sjc",
  "rtt_ms": 14.2,
  "jitter_ms": 0.8,
  "packet_loss": 0.0,
  "source_ip": "198.51.100.1"
}
```

#### Verificación Rápida de Licencias en Sub-Milisegundo (Caché L1)
```http
POST /api/anycast/verify
Content-Type: application/json

{
  "license_key": "SLB-PRO-2026-99",
  "hwid": "HWID-9B0D-E626-C8D9-6D4B",
  "preferred_pop": "sjc"
}
```

#### Consultar Telemetría de Caché Perimetral y Tasas de Acierto
```http
GET /api/anycast/cache/stats
```
**Response:**
```json
{
  "hits": 1420,
  "misses": 38,
  "revalidations": 12,
  "lookup_latency_us": 84.5,
  "hit_ratio": 0.973,
  "cached_tier_entries": 4
}
```

#### Consultar Estado Global de Nodos Anycast
```http
GET /api/anycast/status
```

</details>

<br />

<details>
<summary><h3>📡 Referencia Completa de REST API y Especificación de Cargas Útiles</h3></summary>

### 🧭 Referencia Maestra de Enrutamiento de Endpoints REST

| Method | Path | Subsystem | Description | Authentication / Headers |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Diagnostics | System health, proxy status, consensus & subsystem telemetry | Public |
| `GET` | `/api/proxy/ping` | Diagnostics | Active Google Apps Script connectivity probe | Public |
| `POST` | `/api/users/register` | Authentication | Register a new administrative or standard user | Salted SHA-256 |
| `POST` | `/api/users/login` | Authentication | Authenticate user credentials and return role | Salted SHA-256 |
| `POST` | `/api/licenses` | Licensing | Issue new software license key (supports multi-tenant) | Admin / `X-Tenant-ID` |
| `POST` | `/api/licenses/validate` | Licensing | Verify license key & lock/bind machine HWID | `X-Signature` HMAC |
| `POST` | `/api/licenses/revoke` | Licensing | Administratively revoke license key | Admin / Reason |
| `GET` | `/api/security/blacklist` | Security | List all revoked license keys and banned hardware IDs | Admin |
| `POST` | `/api/security/blacklist` | Security | Blacklist hardware ID (HWID) or key | Admin |
| `POST` | `/api/docs` | NoSQL KV | Store or update JSON document in collection | HMAC / Admin |
| `GET` | `/api/docs` | NoSQL KV | Fetch all documents from Google Sheets `KV_Database` | HMAC / Admin |
| `POST` | `/api/tenants/register` | Multi-Tenant | Register isolated tenant product namespace | Admin |
| `POST` | `/api/backup/export` | Disaster Recovery | Export encrypted database snapshot (AES-256-GCM) | Master Passphrase |
| `POST` | `/api/backup/restore` | Disaster Recovery | Restore spreadsheet database from encrypted snapshot | Master Passphrase |
| `GET` | `/api/features` | Entitlement | List feature catalogue and subscription tier definitions | Public |
| `POST` | `/api/features/check` | Entitlement | Verify whether license is entitled to specific feature | License Key |
| `POST` | `/api/usage/record` | Entitlement | Atomically record usage consumption towards tier quotas | License Key |
| `GET` | `/api/usage/stats` | Entitlement | Query real-time daily usage consumption statistics | License Key |
| `GET` | `/api/security/ratelimit/status` | Rate Limiter | Query thread-safe sliding window rate limit metrics | Admin |
| `GET` | `/api/security/reputation` | Rate Limiter | Inspect IP & HWID reputation tracking scores | Admin |
| `GET` | `/api/security/bans` | Rate Limiter | Query active temporary rate-limiting bans | Admin |
| `POST` | `/api/security/bans` | Rate Limiter | Impose temporary ban on suspicious IP or HWID | Admin |
| `POST` | `/api/security/bans/unban` | Rate Limiter | Lift temporary ban from IP or HWID | Admin |
| `POST` | `/api/security/audit/export` | Compliance | Export sealed AES-256-GCM audit log bundle for SIEM | Compliance Secret |
| `POST` | `/api/security/audit/verify` | Compliance | Decrypt and verify HMAC integrity of audit bundle | Compliance Secret |
| `GET` | `/metrics` | Monitoring | Prometheus 0.0.4 scraper metrics endpoint | Public / Scraper |

---

### Diagnóstico y Estado del Servicio

#### Obtener Estado de Salud del Servicio y Conectividad Proxy
```http
GET /api/health
```

#### Comprobar Conectividad con Backend (Ping)
```http
GET /api/proxy/ping
```

---

### Autenticación de Usuarios

#### Registrar Nuevo Usuario
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

#### Emitir Nueva Clave de Licencia
```http
POST /api/licenses
Content-Type: application/json

{
  "days": 30,
  "max_devices": 1
}
```
**Response:**
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

#### Validar Licencia y Vincular Identificador de Hardware (HWID)
```http
POST /api/licenses/validate
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid": "WIN-B829-94AA-0123"
}
```
**Response:**
```json
{
  "valid": true,
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid_bound": "WIN-B829-94AA-0123",
  "expires_at": "2026-11-12T12:00:00Z",
  "source": "remote_gas"
}
```

*Note: If the license is active and unbound, it locks to the submitted `hwid`. Subsequent calls from matching hardware succeed; calls from mismatched hardware are rejected. Responses also indicate whether the result was served from `cache`, `remote_gas`, or `offline_cache`.*

---

### Seguridad y Anti-Manipulación

#### Verificación de Firma de Solicitud HMAC-SHA256
When `HMAC_ENFORCE=true` (or when `HMAC_SECRET` is configured), clients protect requests from MITM interception using standard headers:
- `X-Signature`: Hex-encoded HMAC-SHA256 signature calculated over `METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(BODY)`.
- `X-Timestamp`: Current Unix timestamp in seconds (enforces a sliding 5-minute clock drift window).
- `X-Nonce`: Unique cryptographic nonce string per request (prevents replay attacks).

#### Revocar Clave de Licencia Inmediatamente
```http
POST /api/licenses/revoke
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "reason": "Payment refunded"
}
```

#### Bloquear Identificador de Hardware (HWID) en Lista Negra
```http
POST /api/security/blacklist
Content-Type: application/json

{
  "type": "device",
  "target": "WIN-B829-94AA-0123",
  "reason": "Fraudulent key sharing"
}
```

#### Listar Registros de Bloqueos y Revocaciones
```http
GET /api/security/blacklist
```

---

### Almacén de Documentos NoSQL Clave-Valor (KV)

#### Guardar / Actualizar Documento (Upsert)
```http
POST /api/docs
Content-Type: application/json

{
  "collection": "user_settings",
  "doc_id": "usr_9918",
  "payload": "{\"dark_mode\":true,\"telemetry\":false}"
}
```

#### Obtener Todos los Documentos de una Colección
```http
GET /api/docs
```

---

### Espacios de Nombres Multi-Inquilino

#### Registrar Nuevo Inquilino
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

#### Emitir Licencia con Espacio de Nombres del Inquilino
```http
POST /api/licenses
Content-Type: application/json
X-Tenant-ID: tenant-gamehub

{
  "days": 60,
  "max_devices": 2
}
```
*Generates formatted keys conforming to `GHUB-LIC-XXXX-YYYY`.*

---

### Copia de Seguridad Automatizada y Recuperación ante Desastres (DR)

#### Exportar Copia de Seguridad Cifrada (AES-256-GCM + SHA-256)
```http
POST /api/backup/export
Content-Type: application/json

{
  "secret_key": "your-backup-master-passphrase"
}
```

#### Restaurar Sistema desde Instantánea
```http
POST /api/backup/restore
Content-Type: application/json

{
  "secret_key": "your-backup-master-passphrase",
  "encrypted_payload": "<hex-encoded-ciphertext>"
}
```

---

### Flags de Funcionalidad Dinámica y Medición de Niveles

#### Listar Catálogo Estándar de Características y Niveles
```http
GET /api/features
```
**Response:**
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

#### Verificar Asignación de Características de Licencia
```http
POST /api/features/check
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "feature": "analytics"
}
```
**Response:**
```json
{
  "license_key": "KEY-7F2A-9C4B-E108",
  "feature": "analytics",
  "tier": "pro",
  "allowed": true
}
```

#### Registrar Consumo y Aplicar Cuotas de Nivel
```http
POST /api/usage/record
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "metric": "api_calls",
  "units": 1
}
```
**Response:**
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

#### Consultar Estadísticas de Uso de Funciones
```http
GET /api/usage/stats?license_key=KEY-7F2A-9C4B-E108
```
**Response:**
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

### 🛡️ Límite de Tasa Empresarial y Exportación de Auditoría SIEM

#### Telemetría de Limitador de Tasa y Reputación de IP
```http
GET /api/security/ratelimit/status
GET /api/security/reputation
```

#### Imponer Restricciones Temporales y Ver Sanciones
```http
# List active temporary bans
GET /api/security/bans

# Impose temporary restriction
POST /api/security/bans
Content-Type: application/json

{
  "key": "198.51.100.24",
  "reason": "Repeated failed validation attempts",
  "duration_minutes": 15
}

# Lift temporary restriction
POST /api/security/bans/unban
Content-Type: application/json

{
  "key": "198.51.100.24"
}
```

#### Exportar Paquete de Auditoría Cifrado (para SIEM / SOC)
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

</details>

<br />

<details>
<summary><h3>⚙️ Variables de Entorno y Matriz de Configuración de Producción</h3></summary>

### 📋 Matriz de Configuración de Variables de Entorno

| Variable de Entorno | Tipo | Valor Predeterminado | Descripción de Uso | Obligatorio / Opcional |
| :--- | :---: | :---: | :--- | :---: |
| `PORT` | `integer` | `9082` | HTTP port for gateway server & embedded web dashboard | Optional |
| `GAS_WEBAPP_URL` | `string` | *(empty)* | Primary Google Apps Script Web App exec URL (`https://script.google.com/macros/s/.../exec`) | Optional (Runs offline if omitted) |
| `GAS_STANDBY_WEBAPP_URL` | `string` | *(empty)* | Standby Google Apps Script Web App exec URL for active-standby HA failover | Optional |
| `HA_AUTO_FAILOVER` | `boolean` | `true` | Automatically failover to standby sheet when primary returns errors or timeouts | Optional |
| `OFFLINE_MODE` | `boolean` | `true` | Enforce standalone offline mode (operates purely on local cache and memory DB) | Optional |
| `CACHE_TTL_SECONDS` | `integer` | `600` | In-memory TTL cache expiration duration (in seconds) for license verifications | Optional |
| `HMAC_SECRET` | `string` | *(empty)* | Master cryptographic signing secret for HMAC-SHA256 anti-tamper verification (min 32 chars) | Recommended |
| `HMAC_ENFORCE` | `boolean` | `false` | Strictly reject incoming requests lacking valid `X-Signature` headers | Optional |
| `GLOBAL_WEBHOOK_URL` | `string` | *(empty)* | Endpoint for real-time lifecycle event webhook delivery (license binds, revokes, bans) | Optional |
| `GLOBAL_WEBHOOK_SECRET` | `string` | *(empty)* | Cryptographic HMAC secret for signing outgoing webhook notification payloads | Optional |
| `DISCORD_ALERT_WEBHOOK_URL` | `string` | *(empty)* | Discord webhook URL for high-priority security alerts and quarantine notifications | Optional |
| `SLACK_ALERT_WEBHOOK_URL` | `string` | *(empty)* | Slack incoming webhook URL for enterprise security alerts | Optional |
| `SPOOL_PATH` | `string` | `spool.bin` | Local path to encrypted journal queue file for zero-data-loss network spooling | Optional |
| `SPOOL_SECRET` | `string` | *(empty)* | 32-byte AES-256-GCM encryption key for local disk spool journal | Optional |
| `NODE_ID` | `string` | `node-1` | Unique node identifier for distributed Raft quorum consensus | Optional |
| `CLUSTER_REGION` | `string` | `us-east` | Geographic region code for node (e.g., `us-east`, `us-west`, `eu-central`, `ap-northeast`) | Optional |
| `CLUSTER_ADDRESS` | `string` | `http://localhost:9082` | Advertised HTTP/RPC listening address for consensus peer discovery | Optional |
| `CLUSTER_PEERS` | `string` | *(empty)* | Comma-separated list of peer cluster addresses for initial bootstrap discovery | Optional |

### 🛠️ Archivo de Configuración de Ejemplo `.env` para Producción

```env
# Configuración Básica de Servidor y Red
PORT=9082
CACHE_TTL_SECONDS=600
OFFLINE_MODE=false

# Backend de Google Apps Script (Alta Disponibilidad Primaria y Secundaria)
GAS_WEBAPP_URL=https://script.google.com/macros/s/AKfycb.../exec
GAS_STANDBY_WEBAPP_URL=https://script.google.com/macros/s/AKfycb_standby.../exec
HA_AUTO_FAILOVER=true

# Protección Criptográfica Anti-Manipulación (HMAC-SHA256)
HMAC_SECRET=your-secure-hmac-master-secret-min-32-chars-long
HMAC_ENFORCE=true

# Cola de Disco Cifrada (Cero Pérdida de Datos en Interrupciones)
SPOOL_PATH=spool.bin
SPOOL_SECRET=your-spool-encryption-key-32-bytes-long!

# Webhooks de Alertas de Incidentes de Seguridad (Discord y Slack)
DISCORD_ALERT_WEBHOOK_URL=https://discord.com/api/webhooks/...
SLACK_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...

# Webhooks Globales de Eventos de Ciclo de Vida
GLOBAL_WEBHOOK_URL=https://api.yourdomain.com/webhooks/licenses
GLOBAL_WEBHOOK_SECRET=your-webhook-signing-secret

# Consenso Distribuido Raft y Sincronización de Malla
NODE_ID=node-1
CLUSTER_REGION=us-east
CLUSTER_ADDRESS=http://192.168.1.10:9082
CLUSTER_PEERS=http://192.168.1.11:9082,http://192.168.1.12:9082
```

</details>

<br />

<details>
<summary><h3>💻 SDKs de Cliente Multilenguaje (Python, C#, TypeScript, Go)</h3></summary>

`sheet-license-broker` includes production-ready client SDKs under `sdk/` supporting automatic hardware ID (HWID) device binding and cryptographic HMAC-SHA256 request signing.

### 🐍 Cliente Python (`sdk/python/sheet_license_client.py`)

Zero external dependencies (uses standard library `urllib` & `hashlib`):

```python
from sheet_license_client import SheetLicenseClient, get_machine_hwid

client = SheetLicenseClient(base_url="http://localhost:9082", secret_key="your-hmac-secret")

# 1. Verify license key (automatically attaches local machine HWID)
res = client.verify_license("SLB-XXXX-XXXX-XXXX")
if res.get("valid"):
    print("License verified. Tier:", res.get("tier"))

    # 2. Check dynamic feature flag entitlement
    if client.is_feature_enabled("SLB-XXXX-XXXX-XXXX", "analytics"):
        print("Analytics module enabled!")

    # 3. Record consumption towards tier quotas
    client.record_usage("SLB-XXXX-XXXX-XXXX", "api_calls", 1)

    # 4. Enterprise SSO & SCIM directory token check
    sso_status = client.get_sso_status()
    token_info = client.introspect_session_token("sso_tok_...", required_scope="license:write")

    # 5. Behavioral anomaly telemetry & risk scoring
    client.record_anomaly_telemetry("SLB-XXXX-XXXX-XXXX", latitude=37.5665, longitude=126.9780)
    risk = client.get_anomaly_risk_score(license_key="SLB-XXXX-XXXX-XXXX")
else:
    print("Denied:", res.get("message"))
```

### ⚡ Cliente C# / .NET & Unity (`sdk/csharp/SheetLicenseClient.cs`)

Single-file helper compatible with Unity Mono/IL2CPP, WPF, and .NET Desktop:

```csharp
using SheetLicenseBroker;

var client = new SheetLicenseClient("http://localhost:9082", "your-hmac-secret");

// Verify license and check tier entitlement
var result = await client.VerifyLicenseAsync("SLB-XXXX-XXXX-XXXX");
if (result.Valid) {
    Console.WriteLine($"Access granted! Tier: {result.Tier}, Expiry: {result.ExpirationDate}");

    // Dynamic feature gating
    if (await client.IsFeatureEnabledAsync("SLB-XXXX-XXXX-XXXX", "analytics")) {
        Console.WriteLine("Analytics initialized.");
    }

    // Record usage
    await client.RecordUsageAsync("SLB-XXXX-XXXX-XXXX", "api_calls", 1);

    // Enterprise SSO & SCIM directory token check
    var ssoStatus = await client.GetSSOStatusAsync();
    var tokenInfo = await client.IntrospectSessionTokenAsync("sso_tok_...", "license:write");

    // Behavioral anomaly telemetry & risk scoring
    await client.RecordAnomalyTelemetryAsync("SLB-XXXX-XXXX-XXXX", 37.5665, 126.9780);
    var risk = await client.GetAnomalyRiskScoreAsync("SLB-XXXX-XXXX-XXXX");
}
```

### 🟩 Cliente TypeScript & Node.js (`@sheet-license/client`)

Zero-dependency native ESM package for Node.js backends and Electron apps:

```typescript
import { SheetLicenseClient } from '@sheet-license/client';

const client = new SheetLicenseClient({
  baseUrl: 'http://localhost:9082',
  secretKey: 'your-hmac-secret',
});

const result = await client.verifyLicense('SLB-XXXX-XXXX-XXXX');
if (result.valid) {
  console.log('License active. Tier:', result.tier);

  // Dynamic feature gating
  const hasAnalytics = await client.isFeatureEnabled('SLB-XXXX-XXXX-XXXX', 'analytics');
  if (hasAnalytics) {
    console.log('Analytics feature enabled for client');
  }

  // Record usage metrics
  await client.recordUsage('SLB-XXXX-XXXX-XXXX', 'api_calls', 1);

  // Enterprise SSO & SCIM directory token check
  const ssoStatus = await client.getSSOStatus();
  const tokenInfo = await client.introspectSessionToken('sso_tok_...', 'license:write');

  // Behavioral anomaly telemetry & risk scoring
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
		fmt.Printf("License valid (Tier: %s). Launching application...\n", res.Tier)

		// Dynamic feature gating
		allowed, _ := client.IsFeatureEnabled(context.Background(), "SLB-XXXX-XXXX-XXXX", "analytics")
		if allowed {
			fmt.Println("Analytics feature enabled.")
		}

		// Record usage consumption
		_ = client.RecordUsage(context.Background(), "SLB-XXXX-XXXX-XXXX", "api_calls", 1)

		// Enterprise SSO & SCIM directory token check
		ssoStatus, _ := client.GetSSOStatus(context.Background())
		tokenInfo, _ := client.IntrospectSessionToken(context.Background(), "sso_tok_...", "license:write")
		_ = ssoStatus
		_ = tokenInfo

		// Behavioral anomaly telemetry & risk scoring
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

</details>

<br />

---

## 📄 Licencia

Distribuido bajo la [Licencia MIT](../../LICENSE).

<div align="center">
  <sub>Distribuido bajo la <b>Licencia MIT</b> · Desarrollado por <b>kLauncher1</b></sub>
</div>

