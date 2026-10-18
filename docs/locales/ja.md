<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <b>🇯🇵 日本語</b> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📑 Sheet-License-Broker

**Google スプレッドシート ＆ Google Apps Script を活用したサーバーレス認証・ライセンス認可・NoSQL データベース ゲートウェイ**

[![Release](https://img.shields.io/badge/Release-v1.7.0-emerald.svg?style=flat)](https://github.com/kLauncher1/sheet-license-broker/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-quick-start)

<sub>kLauncher1 制作 · インディー開発者、デスクトップアプリ、マイクロサービス向け月額0円の高可用性ライセンス管理基盤</sub>

</div>

---

## ⚡ 主な機能

- **月額0円（$0/月）サーバーレス基盤**: Google ドライブおよび Google Apps Script の無料クォータ（1日あたり最大20,000リクエスト）を最大限に活用。
- **Anycast エッジルーティング＆サブミリ秒 L1 キャッシュ**: 世界主要 PoP（Ashburn、San Jose、Frankfurt、Tokyo、Singapore、Sao Paulo）間で球面距離と RTT に基づく最適な低遅延ルーティングを提供。
- **コンフィデンシャル コンピューティング（Intel SGX / AMD SEV-SNP）検証**: 署名付きアテステーション レポートを暗号学的に検証し、ハイパーバイザやホスト OS に平文鍵を一切開示しないセキュア トンネルを確立。
- **耐量子計算機暗号（PQC）ML-DSA 署名チェーン**: NIST FIPS 204 規格の格子暗号署名（ML-DSA-44 / 65）と従来の ECDSA を組み合わせたハイブリッド暗号チェーン。
- **行動異常検知＆適応型リスクスコアリング**: Z-Score による統計的ハートビート監視、時速 950km 超の移動検知（Impossible Travel）、リスク値 85 以上でのゼロトラスト自動隔離。
- **エンタープライズ SSO ＆ SCIM 2.0**: SAML 2.0、OIDC 連携および RFC 7643/7644 規格に基づくディレクトリ同期機能。
- **ゼロ知識証明（ZKP）匿名ライセンス検証**: Pedersen コミットメントを活用し、クライアントの HWID を平文で公開することなく正当性を証明。
- **グラスモーフィズム Web ダッシュボード内蔵**: Go の `//go:embed` を使用し、Web コンソールを単一バイナリ内に直接格納。Node.js 不要で即座に動作。

---

## 🚀 クイックスタート

### 1. クローンと実行
```bash
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# ローカル単独実行
go run .
```

Web 管理画面: 👉 **`http://localhost:9082`**

### 2. シングルバイナリのビルド
```bash
go build -ldflags="-s -w" -o sheet-license-broker.exe .
./sheet-license-broker.exe
```

---

## 📡 主な REST API エンドポイント


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

## ⚙️ 環境変数設定


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
