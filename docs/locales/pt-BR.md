<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <b>🇧🇷 Português</b> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📑 Sheet-License-Broker

**Gateway de autenticação sem servidor, autorização de licenças e banco de dados NoSQL baseado no Google Sheets e Google Apps Script**

[![Release](https://img.shields.io/badge/Release-v1.7.0-emerald.svg?style=flat)](https://github.com/kLauncher1/sheet-license-broker/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-quick-start)

<sub>Desenvolvido por **kLauncher1** · Sistema de licenciamento de alta disponibilidade a custo zero ($0/mês)</sub>

</div>

---

## ⚡ Recursos Principais

- **Infraestrutura 100% Serverless Gratuita ($0/mês)**: Aproveita as cotas gratuitas do Google Drive e Google Apps Script (até 20.000 requisições/dia).
- **Roteamento Anycast Geo-Distribuído e Cache L1 Sub-Milissegundo**: Distribuição global de latência ultrabaixa.
- **Computação Confidencial com Enclaves Intel SGX e AMD SEV-SNP**: Validação criptográfica sem texto puro.
- **Criptografia Pós-Quântica (PQC) ML-DSA (NIST FIPS 204)**: Assinaturas digitais híbridas resistentes a computadores quânticos.
- **Detecção de Anomalias de Comportamento e Avaliação de Risco**: Rastreamento de viagens impossíveis (>950 km/h) e quarentena automática.
- **Single Sign-On (SSO) Corporativo e SCIM 2.0**: Federação de identidades via SAML 2.0, OIDC e provisionamento automático.
- **Provas de Conhecimento Zero (ZKP)**: Validação anônima que resguarda a privacidade do hardware do cliente.
- **Painel Web Integrado Glassmorphism**: Compilado diretamente no executável único em Go com `//go:embed`.

---

## 🚀 Início Rápido

### 1. Clonar e Executar
```bash
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# Executar localmente
go run .
```

Console Web: 👉 **`http://localhost:9082`**

### 2. Compilar Binário Único
```bash
go build -ldflags="-s -w" -o sheet-license-broker.exe .
./sheet-license-broker.exe
```

---

## 📡 Principais Endpoints REST API


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

## ⚙️ Variáveis de Ambiente


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
