<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <b>🇫🇷 Français</b> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📑 Sheet-License-Broker

**Passerelle d'authentification sans serveur, gestion de licences et base NoSQL propulsée par Google Sheets et Google Apps Script**

[![Release](https://img.shields.io/badge/Release-v1.7.0-emerald.svg?style=flat)](https://github.com/kLauncher1/sheet-license-broker/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-quick-start)

<sub>Conçu par **kLauncher1** · Solution haute disponibilité à 0$/mois pour développeurs indépendants et microservices</sub>

</div>

---

## ⚡ Points Forts

- **Infrastructure Serverless à 0$/mois**: Exploite les quotas gratuits de Google Drive et Apps Script (jusqu'à 20 000 requêtes/jour).
- **Routage Anycast Géo-Distribué et Cache L1 Sub-Milliseconde**: Répartition mondiale sur les points de présence clés.
- **Pont d'Attestation d'Enclave Sécurisée (Intel SGX / AMD SEV-SNP)**: Validation cryptographique garantissant le zéro texte en clair.
- **Cryptographie Post-Quantique (PQC) ML-DSA (NIST FIPS 204)**: Chaînes de signatures hybrides résistantes aux attaques quantiques.
- **Détection d'Anomalies Comportementales**: Calcul adaptatif du score de risque et détection des voyages impossibles (>950 km/h).
- **SSO d'Entreprise et SCIM 2.0**: Gestion d'identité SAML 2.0 et OIDC avec synchronisation d'annuaire automatisée.
- **Preuves à Divulgation Nulle de Connaissance (ZKP)**: Vérification anonyme préservant la vie privée du matériel client.
- **Console Web Intégrée Glassmorphism**: Embarquée directement dans le binaire Go via `//go:embed`, sans dépendance Node.js.

---

## 🚀 Démarrage Rapide

### 1. Cloner et Exécuter
```bash
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# Exécution locale
go run .
```

Console Web: 👉 **`http://localhost:9082`**

### 2. Compiler en Binaire Unique
```bash
go build -ldflags="-s -w" -o sheet-license-broker.exe .
./sheet-license-broker.exe
```

---

## 📡 Points de Terminaison REST API


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

## ⚙️ Variables d'Environnement


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
