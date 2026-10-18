<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <b>🇮🇳 हिन्दी</b>
</p>

# 📑 Sheet-License-Broker

**Google Sheets और Google Apps Script द्वारा संचालित सर्वरलेस प्रमाणीकरण, लाइसेंस पात्रता और NoSQL डेटाबेस गेटवे**

[![Release](https://img.shields.io/badge/Release-v1.7.0-emerald.svg?style=flat)](https://github.com/kLauncher1/sheet-license-broker/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-quick-start)

<sub>**kLauncher1** द्वारा निर्मित · इंडी डेवलपर्स, डेस्कटॉप ऐप्स और माइक्रोसर्विसेज के लिए $0/माह का उच्च-उपलब्धता लाइसेंस इंजन</sub>

</div>

---

## ⚡ मुख्य विशेषताएं

- **शून्य लागत ($0/माह) सर्वरलेस इन्फ्रास्ट्रक्चर**: Google Drive और Google Apps Script के मुफ्त कोटा (प्रति दिन 20,000 अनुरोध तक) का पूर्ण उपयोग।
- **एनीकास्ट एज रूटिंग और सब-मिलीसेकंड L1 कैश**: वैश्विक प्रमुख PoP नोड्स के माध्यम से न्यूनतम विलंबता प्रतिक्रिया।
- **गोपनीय कंप्यूटिंग (Intel SGX / AMD SEV-SNP) सत्यापन**: हार्डवेयर एन्क्लेव रिपोर्टों का क्रिप्टोग्राफ़िक सत्यापन।
- **पोस्ट-क्वांटम क्रिप्टोग्राफी (PQC) ML-DSA (NIST FIPS 204)**: क्वांटम-प्रतिरोधी हाइब्रिड डिजिटल हस्ताक्षर श्रृंखलाएं।
- **व्यवहार विसंगति पहचान और अनुकूली जोखिम स्कोरिंग**: 950 किमी/घंटा से अधिक की असंभव यात्रा का वास्तविक समय में पता लगाना और स्वचालित संगरोध।
- **एंटरप्राइज़ सिंगल साइन-ऑन (SSO) और SCIM 2.0**: SAML 2.0, OIDC और स्वचालित उपयोगकर्ता प्रावधान।
- **शून्य-ज्ञान प्रमाण (ZKP) अनाम सत्यापन**: क्लाइंट HWID को उजागर किए बिना लाइसेंस वैधता का सत्यापन।
- **ग्लासमॉर्फिज्म वेब डैशबोर्ड**: Go `//go:embed` के माध्यम से सीधे सिंगल बाइनरी में एम्बेडेड।

---

## 🚀 त्वरित शुरुआत

### 1. क्लोन करें और चलाएं
```bash
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# सीधे चलाएं
go run .
```

वेब कंसोल: 👉 **`http://localhost:9082`**

### 2. एकल बाइनरी का निर्माण करें
```bash
go build -ldflags="-s -w" -o sheet-license-broker.exe .
./sheet-license-broker.exe
```

---

## 📡 प्रमुख REST API एंडपॉइंट्स


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

## ⚙️ पर्यावरण चर (Environment Variables)


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
