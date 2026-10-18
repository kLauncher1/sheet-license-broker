<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <b>🇨🇳 简体中文</b> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📑 Sheet-License-Broker

**基于 Google Sheets 与 Google Apps Script 的无服务器身份验证、软件许可证授权与 NoSQL 数据库网关**

[![Release](https://img.shields.io/badge/Release-v1.7.0-emerald.svg?style=flat)](https://github.com/kLauncher1/sheet-license-broker/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-quick-start)

<sub>由 **kLauncher1** 构建 · 专为独立开发者、桌面应用与微服务打造的高可用、零维护、0元月租授权引擎</sub>

</div>

---

## ⚡ 核心特性

- **零成本（$0/月）无服务器基础设施**: 充分利用 Google Drive 与 Apps Script 免费配额（每日最高 20,000 次请求）。
- **全球泛播（Anycast）边缘路由与亚毫秒级 L1 缓存**: 在全球核心 PoP 节点（Ashburn、San Jose、Frankfurt、Tokyo、Singapore、Sao Paulo）之间实现亚毫秒级低延迟响应。
- **机密计算（Confidential Computing）飞地证明桥接**: 支持 Intel SGX Quote v3/v4 与 AMD SEV-SNP 证明报告的密码学验证，建立宿主操作系统和虚拟机监视器均无法窥视明文密钥的零泄露加密隧道。
- **后量子密码学（PQC）ML-DSA 签名链**: 采用符合 NIST FIPS 204 标准的抗量子模块格签名（ML-DSA-44 / 65）与传统 ECDSA 构成的混合双签名链。
- **行为异常检测与自适应风险评分**: 基于滑动窗口 Z-Score 统计心跳漂移检测、大于 950 km/h 的不可思议旅行（Impossible Travel）实时拦截与自动化风险分级处置。
- **企业级单点登录（SSO）与 SCIM 2.0 目录集成**: 全面支持 SAML 2.0、OIDC 与 RFC 7643/7644 目录同步协议，实现许可证席位自动化分配与即时吊销。
- **零知识证明（ZKP）匿名许可证验证**: 借助 Pedersen 承诺与非交互式 Sigma 证明，在不向服务器暴露硬件指纹（HWID）明文的前提下验证设备合法性。
- **内置毛玻璃设计风格 Web 管理控制台**: 借助 Go 语言的 `//go:embed` 技术，Web 控制台直接编译进单二进制文件中，无需 Node.js 环境即可独立运行。

---

## 🚀 快速上手

### 1. 克隆并运行
```bash
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# 本地运行（默认启用独立离线模式）
go run .
```

Web 控制台访问入口: 👉 **`http://localhost:9082`**

### 2. 编译为单独立二进制文件
```bash
go build -ldflags="-s -w" -o sheet-license-broker.exe .
./sheet-license-broker.exe
```

---

## 📡 核心 REST API 接口


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

## ⚙️ 环境变量配置


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
