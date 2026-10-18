<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <b>🇪🇸 Español</b><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📑 Sheet-License-Broker

**Pasarela de autenticación sin servidor, autorización de licencias y base de datos NoSQL basada en Google Sheets y Google Apps Script**

[![Release](https://img.shields.io/badge/Release-v1.7.0-emerald.svg?style=flat)](https://github.com/kLauncher1/sheet-license-broker/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-quick-start)

<sub>Creado por **kLauncher1** · Diseñado para desarrolladores independientes, aplicaciones de escritorio y microservicios con costo mensual de $0</sub>

</div>

---

## ⚡ Características Principales

- **Infraestructura 100% Serverless sin costo ($0/mes)**: Aprovecha las cuotas gratuitas de Google Drive y Google Apps Script (hasta 20,000 solicitudes por día).
- **Enrutamiento Anycast Geo-Distribuido y Caché L1 Sub-Milisegundo**: Distribución global en nodos PoP clave (Ashburn, San José, Frankfurt, Tokio, Singapur, São Paulo).
- **Computación Confidencial (Intel SGX / AMD SEV-SNP)**: Verificación criptográfica de atestaciones de hardware con túneles ECDH P-256 sin texto plano.
- **Criptografía Post-Cuántica (PQC) ML-DSA (NIST FIPS 204)**: Cadenas de firma digital híbridas cuántico-resistentes.
- **Detección de Anomalías de Comportamiento y Puntuación de Riesgo Adaptativa**: Detección de viajes imposibles (>950 km/h) y cuarentena automática.
- **Single Sign-On (SSO) Empresarial y Aprovisionamiento SCIM 2.0**: Integración federada con SAML 2.0 y OIDC.
- **Pruebas de Conocimiento Cero (ZKP)**: Verificación anónima que protege la privacidad del hardware mediante compromisos Pedersen.
- **Panel Web Embebido con Diseño Glassmorphism**: El dashboard web se compila directamente en el binario único de Go mediante `//go:embed`.

---

## 🚀 Inicio Rápido

### 1. Clonar y Ejecutar
```bash
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# Ejecutar en modo local
go run .
```

Acceso a la consola web: 👉 **`http://localhost:9082`**

### 2. Compilar Binario Único
```bash
go build -ldflags="-s -w" -o sheet-license-broker.exe .
./sheet-license-broker.exe
```

---

## 📡 Endpoints REST API Principales


| HTTP Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | System health, proxy status, consensus & subsystem telemetry |
| `GET` | `/api/proxy/ping` | Active Google Apps Script connectivity probe |
| `GET` | `/api/licenses` | List active licenses (tenant-aware) |
| `POST` | `/api/licenses` | Issue new software license key |
| `POST` | `/api/licenses/validate` | Verify license key & bind client machine HWID |
| `POST` | `/api/licenses/revoke` | Instant administrative revocation |
| `GET` / `POST` | `/api/security/blacklist` | Query and manage banned devices or keys |
| `POST` | `/api/anomaly/record` | Ingest telemetry for behavioral anomaly detection |
| `POST` | `/api/enclave/attest` | Verify Intel SGX / AMD SEV-SNP attestation quote |
| `GET` | `/metrics` | Prometheus 0.0.4 metrics scraper endpoint |


---

## ⚙️ Configuración de Variables de Entorno


```env
PORT=9082
GAS_WEBAPP_URL=https://script.google.com/macros/s/AKfycb.../exec
GAS_STANDBY_WEBAPP_URL=https://script.google.com/macros/s/AKfycb_standby.../exec
OFFLINE_MODE=true
HMAC_SECRET=your-secure-hmac-secret-min-32-chars
HMAC_ENFORCE=false
CACHE_TTL_SECONDS=600
HA_AUTO_FAILOVER=true
SPOOL_PATH=spool.bin
SPOOL_SECRET=your-spool-encryption-key-32-bytes
```


---

<div align="center">
  <sub>Distributed under the <b>MIT License</b> · Crafted by <b>kLauncher1</b></sub>
</div>
