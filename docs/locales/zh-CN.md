<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <b>🇨🇳 简体中文</b> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# Sheet-License-Broker

<p align="center">
  <strong>基于 Google 表格与 Google Apps Script 构建的无服务器认证、软件授权分发与 NoSQL 数据库网关</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/version-v1.5.0-emerald.svg" alt="Version: v1.5.0">
  <img src="https://img.shields.io/badge/anomaly-Z--Score%20%26%20SIEM%20Topology-F59E0B.svg" alt="行为异常检测与 SIEM 拓扑图">
  <img src="https://img.shields.io/badge/pqc-NIST%20FIPS%20204%20ML--DSA-7C3AED.svg" alt="后量子密码学">
  <img src="https://img.shields.io/badge/sso-SAML%202.0%20%26%20OIDC-blueviolet.svg" alt="SAML 与 OIDC SSO">
  <img src="https://img.shields.io/badge/scim-RFC%207643%20%2F%207644%20SCIM%202.0-10B981.svg" alt="SCIM 2.0 目录配置">
  <img src="https://img.shields.io/badge/zkp-pedersen%20%26%20sigma%20proofs-10B981.svg" alt="零知识证明">
  <img src="https://img.shields.io/badge/stream-websocket%20telemetry%20%26%20kill--switch-10B981.svg" alt="WebSocket 流式传输与紧急阻断">
  <img src="https://img.shields.io/badge/consensus-raft%20quorum%20%26%20CRDT-blue.svg" alt="分布式共识">
  <img src="https://img.shields.io/badge/security-rate%20limits%20%26%20SIEM%20audit-blueviolet.svg" alt="安全与速率限制">
  <img src="https://img.shields.io/badge/attestation-TPM%202.0%20%26%20Enclave-0284C7.svg" alt="硬件证明">
  <img src="https://img.shields.io/badge/tiers-dynamic%20flags-8B5CF6.svg" alt="功能标志与分级计量">
  <img src="https://img.shields.io/badge/go-%3E%3D1.22-00ADD8.svg" alt="Go 版本">
  <img src="https://img.shields.io/badge/high--availability-active--standby-059669.svg" alt="高可用主备架构">
  <img src="https://img.shields.io/badge/metrics-prometheus-E6522C.svg" alt="Prometheus 监控指标">
  <img src="https://img.shields.io/badge/cloudflare-edge%20worker-F38020.svg" alt="Cloudflare Workers">
  <img src="https://img.shields.io/badge/google--apps--script-deployed-34A853.svg" alt="Google Apps Script">
  <img src="https://img.shields.io/badge/hosting-0%24%2Fmo-10B981.svg" alt="托管成本">
</p>

</div>

---

## 💡 概述

**`sheet-license-broker`** 将任意 Google 电子表格转化为适用于桌面应用程序、CLI 工具和独立 SaaS 产品的生产级无服务器后端。

无需为了处理用户登录和软件授权密钥而支付昂贵的云数据库账单或维护复杂的 Docker 容器，`sheet-license-broker` 将 **Google Apps Script (GAS)** 云端引擎与**高性能 Go 桥接网关、后量子 ML-DSA 签名链、分布式 Raft 法定人数共识、CRDT LWW-Element-Set 状态同步、Cloudflare Edge 网关、密码学硬件证明 (TPM 2.0 & Enclave)、多租户命名空间隔离、双表格双活主备高可用、动态功能标志与用量计量、加密磁盘 Spool 队列、Prometheus 监控指标、HMAC 密码学防篡改校验、弹性离线缓存以及内嵌 Web 控制台**完美融合。

### 为什么选择 Google 表格作为后端？
- **零成本 ($0/月)**: 充分利用 Google Drive 与 Apps Script 免费配额（每日高达 20,000 次请求）。
- **后量子密码学与 ML-DSA 签名链 (NIST FIPS 204)**: 基于模格（Module-Lattice）的抗量子数字签名验证（ML-DSA-44 / ML-DSA-65），搭配传统 ECDSA 与格密码混合双签名链（`Hybrid-P256-MLDSA65`），支持零停机密钥轮换宽限期以及即时紧急吊销广播熔断。
- **行为异常检测与自适应风险评分**: 统计滑动窗口 Z-Score 心跳漂移追踪（&plusmn;15% 抖动容差），Haversine 测地距离不可能物理位移检测（&gt;950 km/h 或并发 /24 子网异地接入），基于平滑指数衰减的自适应风险评分计算，风险分 &ge; 50 时自动升级密码学二次证明挑战，风险分 &ge; 85 时执行零信任自动隔离，并为企业级 SIEM 平台提供标准安全拓扑图导出（`siem-topology-v1`）。
- **企业级单点登录 (SSO) 与 SCIM 2.0 目录配置**: 支持 SAML 2.0 与 OIDC 身份联合认证，兼容 RFC 7643/7644 目录用户生命周期同步，实现席位自动分配与注销时即时联动吊销。
- **零知识证明 (ZKP) 匿名验证**: 基于 NIST P-256 曲线与确定性 Hash-to-Curve 独立生成元的 Pedersen 承诺，非交互式 Sigma 身份陈述证明（Fiat-Shamir 变换），以及消耗性 Nullifier 防重放注册表，全方位保护客户端硬件隐私。
- **分布式 Raft 法定人数共识与 CRDT 网格**: 轻量级 Leader 选举、多数派日志 Quorum 提交、无冲突 LWW-Element-Set 状态复制，以及跨分布式 Broker 节点的 SHA-256 Merkle 树抗熵（Anti-Entropy）状态同步。
- **企业级速率限制与渐进式退避**: 针对 IP 与 HWID 维度的线程安全滑动窗口限流，提供递增惩罚延迟以及标准 `X-RateLimit-*` 响应头。
- **滑动窗口 IP/HWID 信誉缓存**: 遭遇连续安全违规行为时自动执行临时封禁，并向安全 Webhook 发送高优先级告警通知。
- **面向 SIEM 的加密审计令牌导出**: 输出符合企业合规标准的 AES-256-GCM 加密审计数据包，附带 HMAC 签名封印，可无缝对接 Splunk、Datadog 与 AWS CloudWatch。
- **密码学硬件证明与安全飞地绑定**: 验证 TPM 2.0 PCR Quote 测量值，支持 Apple Secure Enclave 与 Windows Hello 硬件密钥证明，杜绝虚拟机克隆与设备伪造攻击。
- **客户端反调试与内存防篡改遥测**: 持续评估客户端代码完整性评分，一旦检测到调试器挂钩或代码段被补丁篡改，立即自动触发紧急阻断（Kill-Switch）。
- **动态功能标志与基于用量的分级计量**: 提供 Free、Pro 和 Enterprise 订阅层级，支持运行时功能门控（`client.isFeatureEnabled("analytics")`）与直接原子化持久记录至 Google 表格的消费配额追踪。
- **双表格主备热容灾高可用**: 主备 Google 表格之间支持秒级自动故障切换（Failover），具备无冲突的双向状态对齐与合并能力。
- **加密本地磁盘 Spool 队列**: 采用 AES-256-GCM 加密的日志暂存队列（`spool.bin`），确保网络中断期间写入事务零丢失。
- **企业级 Prometheus 遥测指标 (`/metrics`)**: 内置抓取端点，以标准 Prometheus 文本格式暴露计数器、仪表盘与延迟直方图指标。
- **安全事件告警 Webhook**: 遇到安全威胁或异常状态时，即时向 Discord 与 Slack 频道派发富文本告警卡片。
- **多租户命名空间隔离**: 支持按租户/产品定制密钥前缀（例如 `ACME-LIC-XXXX-YYYY`）并实施独立的策略约束。
- **Cloudflare Edge 网关**: 依托 Cloudflare Workers 与 Workers KV，借助 Web Crypto API 实现全球边缘亚毫秒级授权验证。
- **直观可视的人性化管理后台**: Google 表格本身即是你的数据库，无需开发额外面板即可实时查看、修改、禁用或发放许可证。
- **硬件绑定锁 (HWID)**: 首次激活时自动将授权密钥锁定至目标机器的唯一硬件特征标识。
- **密码学 HMAC-SHA256 防篡改**: 防止客户端与服务端之间的网络通信遭受中间人（MITM）嗅探或逆向篡改伪造。
- **滑动窗口 Nonce 防重放攻击**: 具备 5 分钟时间漂移容差窗口，全面拦截请求重放攻击。
- **即时远程吊销与设备黑名单**: 可通过 Web 控制台或 Google 表格直接吊销授权或将违规硬件 HWID 永久加入黑名单。
- **自动化备份与灾难恢复**: 支持基于 SHA-256 数据校验和与 AES-256-GCM 加密的时间点快照导出与一键还原。
- **实时生命周期 Webhook**: 配备工作队列的事件分发调度器，向租户与全局端点发送带 HMAC 签名的事件通知。
- **加盐 SHA-256 安全认证**: 密码在持久化存储前均经过高强度密码学加盐与哈希处理。
- **弹性本地缓存与离线宽限期**: 内存级许可证与 KV 文档缓存，从容抵御 Google API 速率限制（HTTP 429）与瞬时网络波动。
- **内嵌式 Web 管理控制台**: 单一独立可执行文件（`sheet-license-broker.exe`），内置深邃祖母绿风格的专业管理面板。

---

## 🏛️ 系统架构

```mermaid
flowchart TD
    Client["桌面应用 / CLI / Web 应用"] -->|HTTPS REST + HMAC-SHA256| Guard["防篡改安全守卫 & Nonce 缓存"]
    Guard --> Limiter["速率限制器 & IP 信誉网关"]
    Limiter --> Broker["sheet-license-broker (Go 网关)"]
    Broker -->|//go:embed| WebUI["内嵌管理控制台 (端口 9082)"]
    Broker -->|抓取| Prom["Prometheus 监控 (/metrics)"]
    Broker -->|加密磁盘日志| Spool["本地磁盘 Spool (AES-256-GCM)"]
    Broker -->|SIEM 导出| SIEM["审计导出流水线 (AES-256-GCM)"]
    Broker -->|告警| Alerts["安全 Webhook (Discord & Slack)"]
    Broker -->|Raft RPC & CRDT 同步| Peers["集群对等节点网格 (反熵同步)"]
    Broker -->|内存 TTL 缓存| Cache["本地缓存 (配额保护 & 离线降级)"]
    Broker -->|主用角色| Primary["主用 GAS Web 应用 (Code.gs)"]
    Broker -.->|自动故障切换| Standby["备用 GAS Web 应用 (Code.gs)"]
    Primary --> Sheets1["主用 Google 表格数据库"]
    Standby -.-> Sheets2["备用 Google 表格数据库"]

    subgraph Google Sheets 数据库
        Sheets1 --> Tab1["工作表: Users (加盐哈希认证)"]
        Sheets1 --> Tab2["工作表: Licenses (HWID 锁定与到期时间)"]
        Sheets1 --> Tab3["工作表: Blacklist (吊销与封禁 HWID)"]
        Sheets1 --> Tab4["工作表: Audit_Logs (安全审计跟踪与封禁记录)"]
        Sheets1 --> Tab5["工作表: Attestations (TPM Quote 测量值与声明)"]
        Sheets1 --> Tab6["工作表: KV_Database (NoSQL 存储)"]
        Sheets1 --> Tab7["工作表: ConsensusNodes (节点发现与心跳)"]
    end
```

---

## 🚀 快速上手

### 1. 运行本地网关与控制台

确保工作站已安装 Go 1.22+：

```bash
# 克隆仓库
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# 以独立模式构建并运行单二进制文件
go run .
```

在浏览器中打开 **`http://localhost:9082`** 即可访问实时管理控制台。

### 2. 连接线上 Google 表格 (代理模式)

将 Broker 桥接至已部署的 Google Apps Script Web 应用：

```bash
# 设置 Apps Script Web 应用 URL
export GAS_WEBAPP_URL="https://script.google.com/macros/s/.../exec"
export CACHE_TTL_SECONDS="600" # 可选: 10 分钟缓存 TTL

# 启动网关
./sheet-license-broker.exe
```

服务器将自动识别远程 URL，代理转发传入请求，并在本地缓存查询结果；当遇到网络中断时，将透明降级至本地缓存数据。

---

## 📋 Google 表格设置与 Clasp 部署流程

### 方案 A: Clasp CLI 零点击自动化部署

如果您使用 `@google/clasp` CLI：

```bash
# 1. 登录您的 Google 账号
npx @google/clasp login

# 2. 使用自动化部署辅助脚本进行部署
node scripts/deploy_clasp.mjs --script-id <YOUR_APPS_SCRIPT_ID>
```

有关创建和配置 Clasp 项目的完整说明，请参阅 [`gas/README.md`](file:///gas/README.md)。

### 方案 B: 3 分钟手动配置

1. 打开 [Google 表格](https://sheets.new) 并新建一个空白电子表格。
2. 在顶部菜单栏中，依次点击 **扩展程序 > Apps 脚本**。
3. 将默认代码替换为 [`gas/Code.gs`](file:///gas/Code.gs) 的全部内容。
4. 点击 **部署 > 新建部署**：
   - 类型：**Web 应用**
   - 执行身份：`我 (您的邮箱)`
   - 谁可以访问：`任何人`
5. 点击 **部署** 并复制生成的 **Web 应用 URL** (`https://script.google.com/macros/s/.../exec`)。

首次收到请求时，Google 表格将自动创建三个专用工作表：
- **`Users`**: `user_id`, `username`, `password_hash`, `salt`, `role`, `created_at`
- **`Licenses`**: `license_key`, `bound_hwid`, `max_devices`, `status`, `expires_at`, `created_at`
- **`KV_Database`**: `collection`, `doc_id`, `payload`, `updated_at`

---

## 📡 REST API 接口规范

### 健康检查与诊断

#### 获取服务健康状态与代理状态
```http
GET /api/health
```

#### Ping 后端网关
```http
GET /api/proxy/ping
```

---

### 身份认证

#### 用户注册
```http
POST /api/users/register
Content-Type: application/json

{
  "username": "developer",
  "password": "SecurePassword123!",
  "role": "admin"
}
```

#### 用户认证 / 登录
```http
POST /api/users/login
Content-Type: application/json

{
  "username": "developer",
  "password": "SecurePassword123!"
}
```

---

### 许可证管理

#### 签发授权密钥
```http
POST /api/licenses
Content-Type: application/json

{
  "days": 30,
  "max_devices": 1
}
```
**响应：**
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

#### 验证并绑定硬件 HWID
```http
POST /api/licenses/validate
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid": "WIN-B829-94AA-0123"
}
```
**响应：**
```json
{
  "valid": true,
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid_bound": "WIN-B829-94AA-0123",
  "expires_at": "2026-11-12T12:00:00Z",
  "source": "remote_gas"
}
```

*注意: 若许可证处于激活且未绑定状态，它将锁定至提交的 `hwid`。后续来自相同硬件的请求将验证成功；不匹配的硬件请求将被拒绝。响应中还会标明结果是由 `cache`、`remote_gas` 还是 `offline_cache` 提供。*

---

### 防篡改与安全防护

#### HMAC-SHA256 请求签名
当 `HMAC_ENFORCE=true`（或配置了 `HMAC_SECRET`）时，客户端使用标准请求头防止请求遭受中间人嗅探：
- `X-Signature`: 针对 `METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(BODY)` 计算得到的十六进制编码 HMAC-SHA256 签名。
- `X-Timestamp`: 当前 Unix 时间戳（秒）（强制执行 5 分钟滑动时钟漂移窗口）。
- `X-Nonce`: 每次请求唯一的密码学随机字符串（防御重放攻击）。

#### 吊销授权密钥
```http
POST /api/licenses/revoke
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "reason": "Payment refunded"
}
```

#### 封禁设备硬件 ID (HWID)
```http
POST /api/security/blacklist
Content-Type: application/json

{
  "type": "device",
  "target": "WIN-B829-94AA-0123",
  "reason": "Fraudulent key sharing"
}
```

#### 获取黑名单与吊销记录列表
```http
GET /api/security/blacklist
```

---

### NoSQL 键值数据库

#### 存储文档
```http
POST /api/docs
Content-Type: application/json

{
  "collection": "user_settings",
  "doc_id": "usr_9918",
  "payload": "{\"dark_mode\":true,\"telemetry\":false}"
}
```

#### 获取全部文档
```http
GET /api/docs
```

---

### 多租户命名空间

#### 注册租户
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

#### 签发租户命名空间许可证
```http
POST /api/licenses
Content-Type: application/json
X-Tenant-ID: tenant-gamehub

{
  "days": 60,
  "max_devices": 2
}
```
*生成符合 `GHUB-LIC-XXXX-YYYY` 格式的格式化密钥。*

---

### 自动化备份与灾难恢复

#### 导出加密备份 (AES-256-GCM + SHA-256 完整性校验)
```http
POST /api/backup/export
Content-Type: application/json

{
  "secret_key": "your-backup-master-passphrase"
}
```

#### 从快照还原
```http
POST /api/backup/restore
Content-Type: application/json

{
  "secret_key": "your-backup-master-passphrase",
  "encrypted_payload": "<hex-encoded-ciphertext>"
}
```

---

### 动态功能标志与基于用量的分级计量

#### 获取标准功能目录与订阅层级
```http
GET /api/features
```
**响应：**
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

#### 检查许可证功能权限
```http
POST /api/features/check
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "feature": "analytics"
}
```
**响应：**
```json
{
  "license_key": "KEY-7F2A-9C4B-E108",
  "feature": "analytics",
  "tier": "pro",
  "allowed": true
}
```

#### 记录用量并强制执行层级配额
```http
POST /api/usage/record
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "metric": "api_calls",
  "units": 1
}
```
**响应：**
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

#### 查询用量统计数据
```http
GET /api/usage/stats?license_key=KEY-7F2A-9C4B-E108
```
**响应：**
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

### 硬件证明与反篡改遥测

#### 请求 TPM / Enclave 挑战随机数
```http
POST /api/attestation/challenge
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid": "WIN-B829-94AA-0123"
}
```
**响应：**
```json
{
  "status": "success",
  "challenge_id": "9a4f2b1c8e3d",
  "nonce": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "expires_at": "2026-10-14T12:05:00Z"
}
```

#### 验证 TPM 2.0 PCR Quote 测量值
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

#### 发送反调试与完整性遥测数据
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

---

### 🛡️ 企业级速率限制与 SIEM 审计导出

#### 速率限制器与 IP 信誉遥测
```http
GET /api/security/ratelimit/status
GET /api/security/reputation
```

#### 施加 / 查询临时限制
```http
# 查询活动临时封禁记录
GET /api/security/bans

# 施加临时限制
POST /api/security/bans
Content-Type: application/json

{
  "key": "198.51.100.24",
  "reason": "Repeated failed validation attempts",
  "duration_minutes": 15
}

# 解除临时限制
POST /api/security/bans/unban
Content-Type: application/json

{
  "key": "198.51.100.24"
}
```

#### 导出加密审计包 (对接 SIEM / SOC 分析)
```http
POST /api/security/audit/export
Content-Type: application/json

{
  "secret_key": "enterprise-compliance-secret",
  "limit": 500
}
```

#### 验证并解密审计包
```http
POST /api/security/audit/verify
Content-Type: application/json

{
  "secret_key": "enterprise-compliance-secret",
  "bundle": { ... }
}
```

---

### 🌐 分布式共识与多地域 Quorum 同步

#### 集群状态与节点拓扑
```http
GET /api/consensus/status
GET /api/consensus/peers
```

响应：
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

#### 将对等节点加入集群
```http
POST /api/consensus/peers/join
Content-Type: application/json

{
  "node_id": "node-2",
  "address": "http://192.168.1.50:9082"
}
```

#### 触发反熵状态同步
```http
POST /api/consensus/sync/trigger
```

---

### ⚡ 实时 WebSocket 流式传输与遥测推送

#### 双向 WebSocket 遥测数据流
将持久化 WebSocket 客户端连接至 `/api/stream/ws`，以进行实时遥测数据流式传输与亚秒级 Kill-Switch 推送：

```http
GET /api/stream/ws?license_key=SLB-XXXX-XXXX&hwid=HWID-1234 HTTP/1.1
Host: localhost:9082
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

#### 查询已连接流式客户端与遥测数据
```http
# 列出活跃流式传输会话
GET /api/stream/clients

# 查询流式传输指标与最近事件审计日志
GET /api/stream/telemetry
```

#### 执行即时远程紧急阻断 (Kill-Switch)
```http
POST /api/stream/kill
Content-Type: application/json

{
  "target": "SLB-XXXX-XXXX",
  "reason": "Suspected device cloning or fraud",
  "immediate": true
}
```
*注意: 目标 (Target) 可以是指定的许可证密钥 (License Key)、设备 HWID、客户端 ID，或传入 `"ALL"` 执行紧急全网广播阻断。信号将以亚秒级延迟即时推送到匹配的客户端 Socket。*

---

### 🕵️ 零知识证明 (ZKP) 匿名验证

#### 获取 NIST P-256 公共参数与生成元
```http
GET /api/zkp/params
```

#### 签发匿名盲凭证
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

#### 验证零知识陈述证明 (Sigma 协议)
```http
POST /api/zkp/verify
Content-Type: application/json

{
  "credential": { ... },
  "required_tier": "enterprise"
}
```

#### 查询已消耗 Nullifier 状态
```http
GET /api/zkp/nullifiers/check?nullifier=7f2a9c4b...
```

---

### 🔐 企业级单点登录 (SSO) 与 SCIM 2.0 目录配置

#### SAML 2.0 服务提供商元数据
下载适用于 Okta、Azure AD 或 PingFederate 的标准 SP 元数据 XML：
```http
GET /api/sso/saml/metadata?entity_id=urn:sheet-license-broker:sp
```

#### SAML 2.0 断言消费服务 (ACS)
处理传入的 SAML 断言并签发经认证的会话令牌：
```http
POST /api/sso/saml/acs
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PHNhbWxwOlJlc3BvbnNlIHhtbG5z...
```

#### OpenID Connect (OIDC) 回调
验证来自 Google Workspace、Auth0 或 Keycloak 的 ID 令牌和声明：
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

#### 身份提供商 (IdP) 管理
```http
# 注册新的 SAML 或 OIDC IdP
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

# 列出已注册的 IdP
GET /api/sso/idp
```

#### SCIM 2.0 目录配置 (RFC 7644)
将企业用户生命周期配置直接与 Okta、Microsoft Entra ID (Azure AD) 或 OneLogin 无缝集成：

```http
# 服务提供商配置
GET /scim/v2/ServiceProviderConfig

# 列出目录用户 (分页)
GET /scim/v2/Users?startIndex=1&count=50

# 配置用户 (自动分配许可证席位)
POST /scim/v2/Users
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "alice@corp.com",
  "emails": [{ "value": "alice@corp.com", "primary": true }],
  "roles": [{ "value": "operator" }],
  "active": true
}

# 注销用户 (即时吊销分配的许可证席位并推送 Kill-Switch)
DELETE /scim/v2/Users/usr-okta-8821
```

#### 临时 RBAC 会话令牌
```http
# 签发临时令牌
POST /api/sso/token/mint
Content-Type: application/json

{
  "user_id": "usr_9918",
  "email": "alice@corp.com",
  "role": "admin",
  "scopes": ["license:read", "license:write", "sso:manage"]
}

# 内省令牌并强制执行 Scope 权限
POST /api/sso/token/introspect
Content-Type: application/json

{
  "token": "sso_tok_7f2a9c4b...",
  "required_scope": "license:write"
}
```

---

### ⚛️ 后量子密码学与 ML-DSA 混合签名

#### 获取 NIST FIPS 204 格参数与活动密钥信息
```http
GET /api/pqc/params
```
**响应：**
```json
{
  "status": "success",
  "lattice": { "dimension": 256, "modulus": 8380417, "d": 13 },
  "primary_algorithm": "ML-DSA-65",
  "active_key_id": "pqc-key-9b0d-e626",
  "grace_window_days": 7
}
```

#### 列出公钥验证密钥
```http
GET /api/pqc/keys
```

#### 签发混合抗量子许可证签名
```http
POST /api/pqc/sign
Content-Type: application/json

{
  "license_key": "LIC-PRO-2026-99",
  "hwid": "HWID-9B0D-E626-C8D9-6D4B",
  "payload": "entitlement-v1-pro-tier"
}
```
**响应：**
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

#### 验证经典与格密码双重签名
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
**响应：**
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

#### 带宽限期的原子密钥轮换
```http
POST /api/pqc/rotate
Content-Type: application/json

{
  "algorithm": "ML-DSA-65",
  "grace_days": 7,
  "reason": "Routine cryptographic key rollover"
}
```

#### 紧急泄露密钥吊销
```http
POST /api/pqc/revoke
Content-Type: application/json

{
  "key_id": "pqc-key-old-compromised",
  "reason": "Private key leakage detected"
}
```

---

### 🛡️ 行为异常检测与自适应风险评分

`sheet-license-broker` 内置企业级行为异常检测引擎，能够跨客户端应用追踪统计心跳漂移、不可能的地理位移并计算动态风险评分。

#### 自适应治理策略
- **评分 0 – 49 (正常 Nominal)**: 正常运行，不受限制访问。正常的持续活动会随时间平滑衰减累积的风险分值。
- **评分 50 – 84 (可疑 Suspicious)**: 需要升级挑战。强制要求在 5 分钟内完成一次性密码学二次证明挑战（`POST /api/anomaly/challenge/issue` 与 `/verify`）。
- **评分 85 – 100 (高风险 / 已失陷 High Risk / Compromised)**: 立即执行零信任隔离。验证接口（`POST /api/licenses/verify`）将自动拒绝并返回 HTTP 403 Forbidden，同时向安全 Webhook 广播警报。

#### 记录客户端遥测观测值
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
**响应：**
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

#### 查询自适应风险评分
```http
GET /api/anomaly/score?license_key=SLB-PRO-2026-99
```

#### 签发与验证二次证明挑战
```http
# 签发挑战令牌
POST /api/anomaly/challenge/issue
Content-Type: application/json

{
  "license_key": "SLB-PRO-2026-99",
  "hwid": "HWID-9B0D-E626-C8D9-6D4B"
}

# 验证挑战令牌
POST /api/anomaly/challenge/verify
Content-Type: application/json

{
  "challenge_token": "ch_7f2a9c4b..."
}
```

#### 导出安全事件拓扑图 (SIEM 标准数据源)
导出符合 RFC 规范的拓扑事件节点与边关系，完美适配 Splunk、Datadog、Elastic 与 Microsoft Sentinel：
```http
GET /api/anomaly/graph?min_score=50&limit=50
```
**响应：**
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

#### 引擎遥测运行状态
```http
GET /api/anomaly/status
```

---

## ⚡ Cloudflare Edge 网关

如需在全球分布式节点实现亚毫秒级边缘许可证验证，可部署位于 `edge/cloudflare/` 下的 Cloudflare Worker：

```bash
cd edge/cloudflare
wrangler deploy
```

- **10ms 以内 POP 节点验证**: 直接从 Cloudflare Workers KV 缓存中秒级校验有效许可证。
- **硬件级 Web Crypto**: 在请求抵达源站之前，在边缘完成 HMAC-SHA256 签名校验与防重放拦截。
- **自动源站回退**: 未命中缓存的查询、密钥绑定与吊销操作将透明代理转发至源站服务器。

---

## 💻 多语言客户端 SDK

`sheet-license-broker` 在 `sdk/` 目录下提供了生产就绪的各语言客户端 SDK，支持自动硬件 ID (HWID) 设备绑定与 HMAC-SHA256 密码学请求签名。

### 🐍 Python 客户端 (`sdk/python/sheet_license_client.py`)

零外部依赖（仅使用标准库 `urllib` 与 `hashlib`）：

```python
from sheet_license_client import SheetLicenseClient, get_machine_hwid

client = SheetLicenseClient(base_url="http://localhost:9082", secret_key="your-hmac-secret")

# 1. 验证许可证密钥（自动附加本地机器 HWID）
res = client.verify_license("SLB-XXXX-XXXX-XXXX")
if res.get("valid"):
    print("License verified. Tier:", res.get("tier"))

    # 2. 检查动态功能标志权限
    if client.is_feature_enabled("SLB-XXXX-XXXX-XXXX", "analytics"):
        print("Analytics module enabled!")

    # 3. 记录用量以计入层级配额
    client.record_usage("SLB-XXXX-XXXX-XXXX", "api_calls", 1)

    # 4. 企业级 SSO 与 SCIM 目录令牌校验
    sso_status = client.get_sso_status()
    token_info = client.introspect_session_token("sso_tok_...", required_scope="license:write")

    # 5. 行为异常遥测与风险评分
    client.record_anomaly_telemetry("SLB-XXXX-XXXX-XXXX", latitude=37.5665, longitude=126.9780)
    risk = client.get_anomaly_risk_score(license_key="SLB-XXXX-XXXX-XXXX")
else:
    print("Denied:", res.get("message"))
```

### ⚡ C# / .NET & Unity (`sdk/csharp/SheetLicenseClient.cs`)

单文件辅助库，兼容 Unity Mono/IL2CPP、WPF 与 .NET 桌面端应用：

```csharp
using SheetLicenseBroker;

var client = new SheetLicenseClient("http://localhost:9082", "your-hmac-secret");

// 验证许可证并检查层级权益
var result = await client.VerifyLicenseAsync("SLB-XXXX-XXXX-XXXX");
if (result.Valid) {
    Console.WriteLine($"Access granted! Tier: {result.Tier}, Expiry: {result.ExpirationDate}");

    // 动态功能门控
    if (await client.IsFeatureEnabledAsync("SLB-XXXX-XXXX-XXXX", "analytics")) {
        Console.WriteLine("Analytics initialized.");
    }

    // 记录用量
    await client.RecordUsageAsync("SLB-XXXX-XXXX-XXXX", "api_calls", 1);

    // 企业级 SSO 与 SCIM 目录令牌检查
    var ssoStatus = await client.GetSSOStatusAsync();
    var tokenInfo = await client.IntrospectSessionTokenAsync("sso_tok_...", "license:write");

    // 行为异常遥测与风险评分
    await client.RecordAnomalyTelemetryAsync("SLB-XXXX-XXXX-XXXX", 37.5665, 126.9780);
    var risk = await client.GetAnomalyRiskScoreAsync("SLB-XXXX-XXXX-XXXX");
}
```

### 🟩 TypeScript & Node.js (`@sheet-license/client`)

零依赖原生 ESM 包，适用于 Node.js 后端与 Electron 应用：

```typescript
import { SheetLicenseClient } from '@sheet-license/client';

const client = new SheetLicenseClient({
  baseUrl: 'http://localhost:9082',
  secretKey: 'your-hmac-secret',
});

const result = await client.verifyLicense('SLB-XXXX-XXXX-XXXX');
if (result.valid) {
  console.log('License active. Tier:', result.tier);

  // 动态功能门控
  const hasAnalytics = await client.isFeatureEnabled('SLB-XXXX-XXXX-XXXX', 'analytics');
  if (hasAnalytics) {
    console.log('Analytics feature enabled for client');
  }

  // 记录用量指标
  await client.recordUsage('SLB-XXXX-XXXX-XXXX', 'api_calls', 1);

  // 企业级 SSO 与 SCIM 目录令牌检查
  const ssoStatus = await client.getSSOStatus();
  const tokenInfo = await client.introspectSessionToken('sso_tok_...', 'license:write');

  // 行为异常遥测与风险评分
  await client.recordAnomalyTelemetry('SLB-XXXX-XXXX-XXXX', { latitude: 37.5665, longitude: 126.9780 });
  const risk = await client.getAnomalyRiskScore('SLB-XXXX-XXXX-XXXX');
}
```

### 🔷 Go 客户端 (`sdk/go/client.go`)

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

		// 动态功能门控
		allowed, _ := client.IsFeatureEnabled(context.Background(), "SLB-XXXX-XXXX-XXXX", "analytics")
		if allowed {
			fmt.Println("Analytics feature enabled.")
		}

		// 记录用量消费
		_ = client.RecordUsage(context.Background(), "SLB-XXXX-XXXX-XXXX", "api_calls", 1)

		// 企业级 SSO 与 SCIM 目录令牌检查
		ssoStatus, _ := client.GetSSOStatus(context.Background())
		tokenInfo, _ := client.IntrospectSessionToken(context.Background(), "sso_tok_...", "license:write")
		_ = ssoStatus
		_ = tokenInfo

		// 行为异常遥测与风险评分
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

---

## 🛠️ 测试与编译

运行自动化测试套件：

```bash
# 执行所有包的单元测试
go test -v ./...

# 编译独立的生产环境二进制文件
go build -ldflags="-s -w" -o sheet-license-broker.exe .
```

---

## 📄 开源许可证

本项目基于 [MIT 许可证](../../LICENSE) 开源。
