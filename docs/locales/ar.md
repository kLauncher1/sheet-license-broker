<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <b>🇸🇦 العربية</b> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📑 Sheet-License-Broker

**بوابة المصادقة بدون خادم وإدارة التراخيص وقواعد بيانات NoSQL المدعومة بجداول بيانات Google و Google Apps Script**

[![Release](https://img.shields.io/badge/Release-v1.7.0-emerald.svg?style=flat)](https://github.com/kLauncher1/sheet-license-broker/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-quick-start)

<sub>تم التطوير بواسطة **kLauncher1** · نظام إدارة تراخيص عالي التوافر بتكلفة 0 دولار شهرياً</sub>

</div>

---

## ⚡ الميزات الرئيسية

- **بنية تحتية بدون خادم بتكلفة صفرية ($0/شهرياً)**: الاستفادة الكاملة من الحصص المجانية لجداول بيانات Google (تصل إلى 20000 طلب يومياً).
- **توجيه جغرافي Anycast وذاكرة تخزين مؤقت L1 فائقة السرعة**: تغطية عالمية عبر نقاط الحضور الرئيسية.
- **الحوسبة السرية والتحقق من الجيوب الأمنية (Intel SGX / AMD SEV-SNP)**: تشفير كامل بدون نصوص واضحة.
- **التشفير لما بعد عصر الحوسبة الكمومية (PQC) ML-DSA**: سلاسل توقيع هجينة مقاومة للكم وفق معايير NIST FIPS 204.
- **اكتشاف السلوك الشاذ وتقييم المخاطر التكيفي**: كشف التنقل المستحيل (> 950 كم/ساعة) والحجر التلقائي للحماية.
- **تسجيل الدخول الموحد (SSO) ومزامنة الدليل SCIM 2.0**: دعم كامل لـ SAML 2.0 و OIDC.
- **إثباتات المعرفة الصفرية (ZKP)**: التحقق من التراخيص بدون الكشف عن معرّف أجهزة العملاء.
- **لوحة تحكم ويب مدمجة بتصميم Glassmorphism**: مضمنة مباشرة داخل الملف الثنائي الموحد بواسطة `//go:embed`.

---

## 🚀 البدء السريع

### 1. استنساخ المستودع والتشغيل
```bash
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# تشغيل محلي
go run .
```

لوحة تحكم الويب: 👉 **`http://localhost:9082`**

### 2. بناء ملف تنفيذي موحد
```bash
go build -ldflags="-s -w" -o sheet-license-broker.exe .
./sheet-license-broker.exe
```

---

## 📡 نقاط نهاية واجهة برمجة التطبيقات REST API


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

## ⚙️ متغيرات البيئة


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
