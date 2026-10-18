<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <b>🇷🇺 Русский</b> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📑 Sheet-License-Broker

**Бессерверный шлюз аутентификации, лицензирования и NoSQL баз данных на базе Google Таблиц и Google Apps Script**

[![Release](https://img.shields.io/badge/Release-v1.7.0-emerald.svg?style=flat)](https://github.com/kLauncher1/sheet-license-broker/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-quick-start)

<sub>Разработано **kLauncher1** · Высоконадежная система управления лицензиями с нулевой стоимостью ($0/мес)</sub>

</div>

---

## ⚡ Ключевые возможности

- **Бессерверная инфраструктура за $0/мес**: Полное использование бесплатных квот Google Drive и Google Apps Script (до 20 000 запросов в день).
- **Геораспределенная Anycast-маршрутизация и субмиллисекундный L1 кэш**: Оптимизированный глобальный доступ через ключевые узлы PoP.
- **Аппаратная аттестация анклавов Intel SGX и AMD SEV-SNP**: Криптографическая верификация отчетов без утечки ключей в открытом виде.
- **Постквантовая криптография (PQC) ML-DSA (NIST FIPS 204)**: Квантово-устойчивые гибридные цепочки цифровой подписи.
- **Поведенческий анализ аномалий и адаптивный скоринг рисков**: Обнаружение невозможных перемещений (>950 км/ч) и автоматическая изоляция.
- **Корпоративный SSO и синхронизация каталогов SCIM 2.0**: Полная интеграция с SAML 2.0, OIDC и RFC 7643/7644.
- **Доказательства с нулевым разглашением (ZKP)**: Анонимная проверка лицензий на основе обязательств Педерсена без передачи HWID.
- **Встроенная веб-панель управления в стиле Glassmorphism**: Консоль встроена в единый бинарный файл через `//go:embed`.

---

## 🚀 Быстрый старт

### 1. Клонирование и запуск
```bash
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# Запуск в автономном режиме
go run .
```

Веб-панель: 👉 **`http://localhost:9082`**

### 2. Сборка единого бинарного файла
```bash
go build -ldflags="-s -w" -o sheet-license-broker.exe .
./sheet-license-broker.exe
```

---

## 📡 Основные REST API эндпоинты


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

## ⚙️ Переменные окружения


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
