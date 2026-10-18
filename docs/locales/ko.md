<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <b>🇰🇷 한국어</b> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📑 Sheet-License-Broker

**Google 스프레드시트 & Google Apps Script 기반의 서버리스 인증, 라이선스 권한 관리 및 NoSQL 데이터베이스 게이트웨이**

[![Release](https://img.shields.io/badge/Release-v1.7.0-emerald.svg?style=flat)](https://github.com/kLauncher1/sheet-license-broker/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-quick-start)

<sub>제작: **kLauncher1** · 인디 개발자, 데스크톱 앱 및 마이크로서비스를 위한 월 0원 고가용성 라이선스 엔진</sub>

</div>

---

## ⚡ 주요 핵심 기능

- **월 0원($0/mo) 서버리스 인프라**: Google 드라이브 및 Google Apps Script(GAS)의 무료 쿼터(일일 최대 20,000건)를 100% 활용.
- **지리 분산 애니캐스트(Anycast) 라우팅 & 서브밀리초 L1 캐시**: 전 세계 주요 엣지 거점(Ashburn, San Jose, Frankfurt, Tokyo, Singapore, Sao Paulo) 간 활성 RTT를 기반으로 100µs 미만의 초고속 캐시 응답 제공.
- **기밀 컴퓨팅(Confidential Computing) 엔클레이브 검증**: Intel SGX Quote v3/v4 및 AMD SEV-SNP 원격 증명 보고서를 암호학적으로 검증하고, 호스트 OS나 하이퍼바이저가 평문 키를 절대 열람할 수 없는 제로 평문 격리 터널 협상.
- **포스트 양자 암호화(PQC) ML-DSA 서명 체인**: NIST FIPS 204 표준의 양자 내성 모듈 격자 디지털 서명(ML-DSA-44 / 65) 및 전통적 ECDSA 결합 하이브리드 서명 체인.
- **행동 이상 징후 탐지 & 적응형 위험 점수**: Z-Score 기반 통계적 심박 드리프트 추적, 시속 950km 초과 불가능 이동(Impossible Travel) 실시간 탐지, 위험 점수 85 이상 시 자동 제로 트러스트 격리 및 SIEM 토폴로지 익스포트.
- **엔터프라이즈 SSO 및 SCIM 2.0**: SAML 2.0, OIDC 연동 및 RFC 7643/7644 표준 디렉터리 동기화를 통한 사용자 자동 프로비저닝.
- **영지식 증명(ZKP) 익명 라이선스 검증**: 클라이언트 하드웨어 식별자(HWID)를 서버에 평문으로 공개하지 않는 페더슨 커밋(Pedersen Commitment) 및 비대화형 시그마 증명.
- **분산 Raft 쿼럼 합의 & CRDT 동기화**: 독립된 브로커 노드 간 충돌 없는 LWW-Element-Set 상태 복제 및 경량 리더 선출 메커니즘.
- **글래스모피즘 웹 관리 대시보드 내장**: Go `//go:embed` 기능으로 웹 콘솔이 바이너리에 직접 내장되어 Node.js 없이 단일 파일로 즉시 구동.

---

## 🚀 빠른 시작

### 1. 저장소 복제 및 실행
```bash
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# 로컬 독립 실행 (오프라인 모드 기본 활성화)
go run .
```

내장 웹 콘솔 접속: 👉 **`http://localhost:9082`**

### 2. 단일 독립 바이너리 빌드
```bash
go build -ldflags="-s -w" -o sheet-license-broker.exe .
./sheet-license-broker.exe
```

---

## 📡 주요 REST API 엔드포인트


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

## ⚙️ 환경 변수 설정


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
