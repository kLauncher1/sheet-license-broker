<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <b>🇮🇳 हिन्दी</b>
</p>

# Sheet-License-Broker

<p align="center">
  <strong>Google Sheets और Google Apps Script द्वारा संचालित सर्वरलेस प्रमाणीकरण, लाइसेंस पात्रता और NoSQL डेटाबेस गेटवे</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/version-v1.5.0-emerald.svg" alt="Version: v1.5.0">
  <img src="https://img.shields.io/badge/anomaly-Z--Score%20%26%20SIEM%20Topology-F59E0B.svg" alt="Behavioral Anomaly & SIEM Graph">
  <img src="https://img.shields.io/badge/pqc-NIST%20FIPS%20204%20ML--DSA-7C3AED.svg" alt="Post-Quantum Cryptography">
  <img src="https://img.shields.io/badge/sso-SAML%202.0%20%26%20OIDC-blueviolet.svg" alt="SAML & OIDC SSO">
  <img src="https://img.shields.io/badge/scim-RFC%207643%20%2F%207644%20SCIM%202.0-10B981.svg" alt="SCIM 2.0 Directory Provisioning">
  <img src="https://img.shields.io/badge/zkp-pedersen%20%26%20sigma%20proofs-10B981.svg" alt="Zero-Knowledge Proofs">
  <img src="https://img.shields.io/badge/stream-websocket%20telemetry%20%26%20kill--switch-10B981.svg" alt="WebSocket Streaming & Kill-Switch">
  <img src="https://img.shields.io/badge/consensus-raft%20quorum%20%26%20CRDT-blue.svg" alt="Distributed Consensus">
  <img src="https://img.shields.io/badge/security-rate%20limits%20%26%20SIEM%20audit-blueviolet.svg" alt="Security & Rate Limiting">
  <img src="https://img.shields.io/badge/attestation-TPM%202.0%20%26%20Enclave-0284C7.svg" alt="Hardware Attestation">
  <img src="https://img.shields.io/badge/tiers-dynamic%20flags-8B5CF6.svg" alt="Feature Flags & Tier Metering">
  <img src="https://img.shields.io/badge/go-%3E%3D1.22-00ADD8.svg" alt="Go Version">
  <img src="https://img.shields.io/badge/high--availability-active--standby-059669.svg" alt="High Availability">
  <img src="https://img.shields.io/badge/metrics-prometheus-E6522C.svg" alt="Prometheus Metrics">
  <img src="https://img.shields.io/badge/cloudflare-edge%20worker-F38020.svg" alt="Cloudflare Workers">
  <img src="https://img.shields.io/badge/google--apps--script-deployed-34A853.svg" alt="Google Apps Script">
  <img src="https://img.shields.io/badge/hosting-0%24%2Fmo-10B981.svg" alt="Hosting Cost">
</p>

</div>

---

## 💡 संक्षिप्त परिचय

**`sheet-license-broker`** किसी भी Google स्प्रेडशीट को डेस्कटॉप ऍप्लिकेशन्स, CLI उपयोगिताओं और इंडी SaaS टूल्स के लिए प्रमाणीकृत, उत्पादन-तैयार (production-ready) सर्वरलेस बैकएंड में परिवर्तित करता है।

उपयोगकर्ता लॉगिन और सॉफ़्टवेयर लाइसेंस कुंजियों को संभालने के लिए महंगे क्लाउड डेटाबेस इंस्टेंस के भुगतान करने या Docker कंटेनरों को प्रबंधित करने के बजाय, `sheet-license-broker` एक **Google Apps Script (GAS)** क्लाउड इंजन को एक **उच्च-गति Go ब्रिज, पोस्ट-क्वांटम ML-DSA हस्ताक्षर श्रृंखलाओं, वितरित Raft कोरम सर्वसम्मति, CRDT LWW-Element-Set सिंक्रनाइज़ेशन, Cloudflare Edge Gateway, क्रिप्टोग्राफ़िक हार्डवेयर सत्यापन (TPM 2.0 और Enclaves), बहु-किरायेदार (multi-tenant) नेमस्पेसिंग, डुअल-शीट एक्टिव-स्टैंडबाय उच्च उपलब्धता, डायनामिक फीचर फ़्लैग्स और उपयोगिता मीटरिंग, एन्क्रिप्टेड डिस्क स्पूलिंग, Prometheus मेट्रिक्स, क्रिप्टोग्राफ़िक HMAC एंटी-टैम्पर सत्यापन, लचीले ऑफ़लाइन कैशिंग और एक एम्बेडेड वेब UI** के साथ जोड़ता है।

### बैकएंड के रूप में Google Sheets ही क्यों?
- **शून्य लागत ($0/माह)**: Google Drive और Apps Script के निःशुल्क कोटा (प्रति दिन 20,000 अनुरोधों तक) का लाभ उठाता है।
- **पोस्ट-क्वांटम क्रिप्टोग्राफी और ML-DSA हस्ताक्षर श्रृंखला (NIST FIPS 204)**: ड्यूल क्लासिकल ECDSA / लैटिस हाइब्रिड हस्ताक्षर श्रृंखलाओं (`Hybrid-P256-MLDSA65`), शून्य-डाउनटाइम कुंजी रोटेशन ग्रेस विंडो और तत्काल आपातकालीन निरस्तीकरण किल-स्विच प्रसारण के साथ क्वांटम-प्रतिरोधी मॉड्यूल-लैटिस डिजिटल हस्ताक्षर सत्यापन (ML-DSA-44 / ML-DSA-65)।
- **व्यवहार विसंगति का पता लगाना और अनुकूली जोखिम स्कोरिंग**: सांख्यिकीय स्लाइडिंग-विंडो Z-Score हार्टबीट ड्रिफ्ट ट्रैकिंग (±15% जिटर सहनशीलता), हैवर्सिन वेग असंभव यात्रा का पता लगाना (>950 किमी/घंटा या समवर्ती /24 सबनेट्स), प्रगतिशील नाममात्र क्षय के साथ अनुकूली जोखिम स्कोर गणना, जोखिम स्कोर ≥ 50 पर स्वचालित पुनः-प्रमाणीकरण चुनौती वृद्धि, जोखिम स्कोर ≥ 85 पर शून्य-विश्वास स्वचालित संगरोध (quarantine), और एंटरप्राइज SIEM अंतर्ग्रहण के लिए मानकीकृत सुरक्षा घटना टोपोलॉजी ग्राफ़ निर्यातक (`siem-topology-v1`)।
- **एंटरप्राइज़ सिंगल साइन-ऑन (SSO) और SCIM 2.0 डायरेक्टरी प्रोविज़निंग**: SAML 2.0 और OIDC पहचान संघ (federation), RFC 7643/7644 डायरेक्टरी सिंक्रनाइज़ेशन, स्वचालित लाइसेंस सीट आवंटन, और तत्काल डीप्रोविज़निंग निरस्तीकरण।
- **शून्य-ज्ञान प्रमाण (ZKP) अनाम सत्यापन**: NIST P-256 पर पेडरसन प्रतिबद्धताएं, निर्धारक हैश-टू-कर्व स्वतंत्र जनरेटर, गैर-संवादात्मक सिग्मा प्रस्तुति प्रमाण (फ़िएट-शमीर रूपांतरित), और क्लाइंट हार्डवेयर गोपनीयता की रक्षा करने वाली प्रयुक्त न्यूलीफायर रिप्ले रक्षा रजिस्ट्रियां।
- **वितरित Raft कोरम सर्वसम्मति और CRDT मेश**: वितरित ब्रोकर नोड्स में एंटी-एन्ट्रॉपी सिंक के लिए लाइटवेट लीडर चुनाव, बहुमत लॉग कोरम, संघर्ष-मुक्त LWW-Element-Set स्थिति प्रतिकृति, और SHA-256 मर्कल ट्री स्थिति डाइजेस्ट।
- **एंटरप्राइज़ दर-सीमित (Rate-Limiting) और प्रगतिशील बैकऑफ़**: प्रगतिशील दंड विलंब और मानक `X-RateLimit-*` हेडर के साथ प्रति IP और HWID थ्रेड-सुरक्षित स्लाइडिंग-विंडो थ्रॉटलिंग।
- **स्लाइडिंग-विंडो IP/HWID प्रतिष्ठा कैश**: बार-बार सुरक्षा उल्लंघनों पर स्वचालित अस्थायी प्रतिबंध और उच्च-प्राथमिकता वाले घटना वेबहुक अलर्ट।
- **SIEM के लिए एन्क्रिप्टेड ऑडिट टोकन निर्यात**: Splunk, Datadog और AWS CloudWatch अंतर्ग्रहण के लिए HMAC हस्ताक्षरों के साथ सील किए गए अनुपालन योग्य AES-256-GCM एन्क्रिप्टेड ऑडिट बंडल।
- **क्रिप्टोग्राफ़िक हार्डवेयर सत्यापन और एन्क्लेव बाइंडिंग**: क्लोन हमलों को रोकने के लिए TPM 2.0 PCR उद्धरण सत्यापन और Apple Secure Enclave / Windows Hello हार्डवेयर कुंजी सत्यापन।
- **क्लाइंट एंटी-डीबगिंग और मेमोरी-टैम्पर टेलीमेट्री**: डीबगर अटैचमेंट या कोड सेक्शन संशोधनों को प्रदर्शित करने वाले उपकरणों को तत्काल किल-स्विच ऑटो-बैनिंग के साथ निरंतर अखंडता स्कोरिंग।
- **डायनामिक फीचर फ़्लैग्स और उपयोग-आधारित टियर मीटरिंग**: रनटाइम फीचर गेटिंग (`client.isFeatureEnabled("analytics")`) और सीधे Google Sheets में संग्रहीत परमाणु उपभोग कोटा ट्रैकिंग के साथ Free, Pro और Enterprise सदस्यता टियर।
- **डुअल-शीट एक्टिव-स्टैंडबाय प्रतिकृति**: टकराव-मुक्त द्विदिशीय सुलह के साथ प्राथमिक और स्टैंडबाय शीट के बीच स्वचालित विफलता (failover)।
- **एन्क्रिप्टेड लोकल डिस्क स्पूल**: नेटवर्क रुकावटों के दौरान शून्य डेटा हानि की गारंटी देने वाली AES-256-GCM एन्क्रिप्टेड जर्नल कतार (`spool.bin`)।
- **एंटरप्राइज़ Prometheus टेलीमेट्री (`/metrics`)**: Prometheus प्रारूप में काउंटरों, गेजों और लेटेंसी को उजागर करने वाला अंतर्निहित स्क्रेपर एंडपॉइंट।
- **घटना अलर्ट वेबहुक**: Discord और Slack चैनलों पर प्रेषित तत्काल समृद्ध सुरक्षा घटना सूचनाएं।
- **मल्टी-टेनेंट नेमस्पेसिंग**: कस्टम उपसर्गों (उदा. `ACME-LIC-XXXX-YYYY`) और स्वतंत्र नीतियों के साथ अलग-अलग उत्पादों और किरायेदारों को अलग करें।
- **Cloudflare Edge Gateway**: Cloudflare Workers और Workers KV के साथ Web Crypto API के माध्यम से सब-मिलीसेकंड एज लाइसेंस सत्यापन।
- **मानव-पठनीय एडमिन पैनल**: आपकी Google Sheet ही आपका डेटाबेस है। सीधे रीयल-टाइम में लाइसेंस देखें, संपादित करें, प्रतिबंधित करें या स्वीकृत करें।
- **हार्डवेयर-लॉक्ड सुरक्षा (HWID)**: पहले बूट पर लाइसेंस कुंजियों को विशिष्ट मशीन हार्डवेयर आईडी से लॉक करता है।
- **क्रिप्टोग्राफ़िक HMAC-SHA256 एंटी-टैम्पर**: MITM निरीक्षण और रिवर्स-इंजीनियर्ड पेलोड स्पूफिंग के खिलाफ आने वाले क्लाइंट ट्रैफ़िक की सुरक्षा करता है।
- **स्लाइडिंग-विंडो नॉन्स रिप्ले न्यूनीकरण**: 5-मिनट के समय-ड्रिफ्ट सहनशीलता विंडो के साथ अनुरोध रिप्ले हमलों को रोकता है।
- **तत्काल रिमोट निरस्तीकरण और डिवाइस ब्लैकलिस्टिंग**: वेब कंसोल या Google Sheets टैब से सीधे लाइसेंस रद्द करें या संदिग्ध हार्डवेयर आईडी को ब्लॉक करें।
- **स्वचालित बैकअप और आपदा पुनर्प्राप्ति**: SHA-256 डेटा चेकसम और AES-256-GCM एन्क्रिप्शन के साथ सुरक्षित पॉइंट-इन-टाइम स्थिति निर्यात और पुनर्स्थापना।
- **रीयल-टाइम लाइफसाइकिल वेबहुक**: किरायेदार और वैश्विक एंडपॉइंट्स के लिए वर्कर कतारों और HMAC-हस्ताक्षरित वेबहुक डिलीवरी के साथ इवेंट डिस्पैचर।
- **साल्टेड SHA-256 प्रमाणीकरण**: डेटाबेस में संग्रहीत होने से पहले पासवर्ड को क्रिप्टोग्राफ़िक रूप से साल्ट और हैश किया जाता है।
- **लचीला स्थानीय कैशिंग और ऑफ़लाइन ग्रेस**: मेमोरी-कैश्ड लाइसेंस और KV दस्तावेज़ Google API दर सीमाओं (HTTP 429) और नेटवर्क व्यवधानों से बचाते हैं।
- **एम्बेडेड वेब डैशबोर्ड**: एमराल्ड-डार्क प्रबंधन कंसोल के साथ स्व-निहित एकल बाइनरी (`sheet-license-broker.exe`)।

---

## 🏛️ आर्किटेक्चर

```mermaid
flowchart TD
    Client["डेस्कटॉप ऐप / CLI / वेबऐप"] -->|HTTPS REST + HMAC-SHA256| Guard["एंटी-टैम्पर सिक्योरिटी गार्ड और नॉन्स कैश"]
    Guard --> Limiter["दर सीमक और IP प्रतिष्ठा गेट"]
    Limiter --> Broker["sheet-license-broker (Go गेटवे)"]
    Broker -->|//go:embed| WebUI["एम्बेडेड एडमिन कंसोल (पोर्ट 9082)"]
    Broker -->|Scrape| Prom["Prometheus मॉनिटरिंग (/metrics)"]
    Broker -->|Encrypted Disk Journal| Spool["स्थानीय डिस्क स्पूल (AES-256-GCM)"]
    Broker -->|SIEM Export| SIEM["ऑडिट निर्यात पाइपलाइन (AES-256-GCM)"]
    Broker -->|Alerts| Alerts["सुरक्षा वेबहुक (Discord और Slack)"]
    Broker -->|Raft RPC & CRDT Sync| Peers["क्लस्टर पीयर मेश (एंटी-एन्ट्रॉपी)"]
    Broker -->|In-Memory TTL Cache| Cache["स्थानीय कैश (कोटा और ऑफ़लाइन फ़ालबैक)"]
    Broker -->|Active Role| Primary["प्राथमिक GAS वेब ऐप (Code.gs)"]
    Broker -.->|Automatic Failover| Standby["स्टैंडबाय GAS वेब ऐप (Code.gs)"]
    Primary --> Sheets1["प्राथमिक Google Sheet DB"]
    Standby -.-> Sheets2["स्टैंडबाय Google Sheet DB"]

    subgraph Google Sheets डेटाबेस
        Sheets1 --> Tab1["टैब: Users (साल्टेड हैश प्रमाणीकरण)"]
        Sheets1 --> Tab2["टैब: Licenses (HWID लॉक और समाप्ति)"]
        Sheets1 --> Tab3["टैब: Blacklist (निरस्तीकरण और प्रतिबंधित HWIDs)"]
        Sheets1 --> Tab4["टैब: Audit_Logs (सुरक्षा ऑडिट ट्रेल और प्रतिबंध)"]
        Sheets1 --> Tab5["टैब: Attestations (TPM उद्धरण और दावे)"]
        Sheets1 --> Tab6["टैब: KV_Database (NoSQL स्टोर)"]
        Sheets1 --> Tab7["टैब: ConsensusNodes (पीयर डिस्कवरी और हार्टबीट्स)"]
    end
```

---

## 🚀 त्वरित आरंभ

### 1. स्थानीय गेटवे और कंसोल प्रारंभ करें

सुनिश्चित करें कि आपके वर्कस्टेशन पर Go 1.22+ स्थापित है:

```bash
# रिपॉजिटरी क्लोन करें
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# स्टैंडअलोन मोड में एकल बाइनरी का निर्माण और संचालन करें
go run .
```

लाइव एडमिनिस्ट्रेशन कंसोल तक पहुंचने के लिए अपने ब्राउज़र में **`http://localhost:9082`** खोलें।

### 2. लाइव Google Sheets से कनेक्ट करें (प्रॉक्सी मोड)

ब्रोकर को आपके परिनियोजित Google Apps Script Web App से कनेक्ट करने के लिए:

```bash
# अपने Apps Script Web App का URL सेट करें
export GAS_WEBAPP_URL="https://script.google.com/macros/s/.../exec"
export CACHE_TTL_SECONDS="600" # वैकल्पिक: 10 मिनट कैश TTL

# गेटवे लॉन्च करें
./sheet-license-broker.exe
```

सर्वर स्वचालित रूप से रिमोट URL का पता लगाता है, आने वाले प्रश्नों को अग्रेषित करता है, परिणामों को स्थानीय रूप से कैश करता है, और नेटवर्क रुकावटों के दौरान पारदर्शी रूप से कैश्ड डेटा पर फ़ालबैक करता है।

---

## 📋 Google Sheets सेटअप और Clasp परिनियोजन

### विकल्प A: Clasp CLI द्वारा स्वचालित परिनियोजन

यदि आप `@google/clasp` CLI का उपयोग करते हैं:

```bash
# 1. अपने Google खाते में लॉगिन करें
npx @google/clasp login

# 2. स्वचालित सहायक स्क्रिप्ट का उपयोग करके परिनियोजित करें
node scripts/deploy_clasp.mjs --script-id <YOUR_APPS_SCRIPT_ID>
```

Clasp प्रोजेक्ट बनाने और कॉन्फ़िगर करने के संपूर्ण निर्देशों के लिए [`gas/README.md`](../../gas/README.md) देखें।

### विकल्प B: मैनुअल सेटअप (3 मिनट)

1. [Google Sheets](https://sheets.new) खोलें और एक नया रिक्त स्प्रेडशीट बनाएं।
2. शीर्ष मेनू में, **Extensions > Apps Script** पर नेविगेट करें।
3. डिफ़ॉल्ट कोड को [`gas/Code.gs`](../../gas/Code.gs) की सामग्री से बदलें।
4. **Deploy > New deployment** पर क्लिक करें:
   - Type: **Web app**
   - Execute as: `Me (your email)`
   - Who has access: `Anyone`
5. **Deploy** पर क्लिक करें और अपना **Web app URL** (`https://script.google.com/macros/s/.../exec`) कॉपी करें।

आपकी Google Sheet पहले अनुरोध पर स्वचालित रूप से तीन समर्पित टैब उत्पन्न करेगी:
- **`Users`**: `user_id`, `username`, `password_hash`, `salt`, `role`, `created_at`
- **`Licenses`**: `license_key`, `bound_hwid`, `max_devices`, `status`, `expires_at`, `created_at`
- **`KV_Database`**: `collection`, `doc_id`, `payload`, `updated_at`

---

## 📡 REST API विनिर्देश

### Health & Diagnostics

#### Get Service Health & Proxy Status
```http
GET /api/health
```

#### Ping Backend
```http
GET /api/proxy/ping
```

---

### Authentication

#### Register User
```http
POST /api/users/register
Content-Type: application/json

{
  "username": "developer",
  "password": "SecurePassword123!",
  "role": "admin"
}
```

#### Authenticate / Login
```http
POST /api/users/login
Content-Type: application/json

{
  "username": "developer",
  "password": "SecurePassword123!"
}
```

---

### License Management

#### Issue License Key
```http
POST /api/licenses
Content-Type: application/json

{
  "days": 30,
  "max_devices": 1
}
```
**Response:**
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

#### Validate & Bind HWID
```http
POST /api/licenses/validate
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid": "WIN-B829-94AA-0123"
}
```
**Response:**
```json
{
  "valid": true,
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid_bound": "WIN-B829-94AA-0123",
  "expires_at": "2026-11-12T12:00:00Z",
  "source": "remote_gas"
}
```

*नोट: यदि लाइसेंस सक्रिय और अनबाउंड है, तो यह सबमिट किए गए `hwid` से लॉक हो जाता है। मेल खाने वाले हार्डवेयर से बाद के कॉल सफल होते हैं; बेमेल हार्डवेयर से कॉल अस्वीकार कर दिए जाते हैं। प्रतिक्रियाएं यह भी इंगित करती हैं कि परिणाम `cache`, `remote_gas`, या `offline_cache` से प्रस्तुत किया गया था या नहीं।*

---

### Anti-Tamper & Security

#### HMAC-SHA256 Request Signing
जब `HMAC_ENFORCE=true` हो (या जब `HMAC_SECRET` कॉन्फ़िगर किया गया हो), तो क्लाइंट मानक हेडर का उपयोग करके MITM इंटरसेप्शन से अनुरोधों की सुरक्षा करते हैं:
- `X-Signature`: `METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(BODY)` पर गणना किया गया हेक्स-एन्कोडेड HMAC-SHA256 हस्ताक्षर।
- `X-Timestamp`: सेकंड में वर्तमान यूनिक्स टाइमस्टैम्प (5-मिनट के क्लॉक ड्रिफ्ट विंडो को लागू करता है)।
- `X-Nonce`: प्रति अनुरोध अद्वितीय क्रिप्टोग्राफ़िक नॉन्स स्ट्रिंग (रिप्ले हमलों को रोकता है)।

#### Revoke License Key
```http
POST /api/licenses/revoke
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "reason": "Payment refunded"
}
```

#### Blacklist Device Hardware ID (HWID)
```http
POST /api/security/blacklist
Content-Type: application/json

{
  "type": "device",
  "target": "WIN-B829-94AA-0123",
  "reason": "Fraudulent key sharing"
}
```

#### List Blacklist & Revocation Entries
```http
GET /api/security/blacklist
```

---

### NoSQL Key-Value Store

#### Store Document
```http
POST /api/docs
Content-Type: application/json

{
  "collection": "user_settings",
  "doc_id": "usr_9918",
  "payload": "{\"dark_mode\":true,\"telemetry\":false}"
}
```

#### Fetch All Documents
```http
GET /api/docs
```

---

### Multi-Tenant Namespaces

#### Register Tenant
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

#### Issue Tenant-Namespaced License
```http
POST /api/licenses
Content-Type: application/json
X-Tenant-ID: tenant-gamehub

{
  "days": 60,
  "max_devices": 2
}
```
*`GHUB-LIC-XXXX-YYYY` के अनुरूप स्वरूपित कुंजियाँ उत्पन्न करता है।*

---

### Automated Backup & Disaster Recovery

#### Export Encrypted Backup (AES-256-GCM + SHA-256 Integrity)
```http
POST /api/backup/export
Content-Type: application/json

{
  "secret_key": "your-backup-master-passphrase"
}
```

#### Restore From Snapshot
```http
POST /api/backup/restore
Content-Type: application/json

{
  "secret_key": "your-backup-master-passphrase",
  "encrypted_payload": "<hex-encoded-ciphertext>"
}
```

---

### Dynamic Feature Flags & Usage-Based Tier Metering

#### List Standard Feature Catalogue & Tiers
```http
GET /api/features
```
**Response:**
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

#### Check License Feature Entitlement
```http
POST /api/features/check
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "feature": "analytics"
}
```
**Response:**
```json
{
  "license_key": "KEY-7F2A-9C4B-E108",
  "feature": "analytics",
  "tier": "pro",
  "allowed": true
}
```

#### Record Usage & Enforce Tier Quotas
```http
POST /api/usage/record
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "metric": "api_calls",
  "units": 1
}
```
**Response:**
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

#### Query Usage Statistics
```http
GET /api/usage/stats?license_key=KEY-7F2A-9C4B-E108
```
**Response:**
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

### Hardware Attestation & Anti-Tamper Telemetry

#### Request TPM / Enclave Challenge Nonce
```http
POST /api/attestation/challenge
Content-Type: application/json

{
  "license_key": "KEY-7F2A-9C4B-E108",
  "hwid": "WIN-B829-94AA-0123"
}
```
**Response:**
```json
{
  "status": "success",
  "challenge_id": "9a4f2b1c8e3d",
  "nonce": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "expires_at": "2026-10-14T12:05:00Z"
}
```

#### Verify TPM 2.0 PCR Quote
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

#### Transmit Anti-Debugging & Integrity Telemetry
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

### 🛡️ Enterprise Rate Limiting & SIEM Audit Export

#### Rate Limiter & IP Reputation Telemetry
```http
GET /api/security/ratelimit/status
GET /api/security/reputation
```

#### Impose / List Temporary Restrictions
```http
# List active temporary bans
GET /api/security/bans

# Impose temporary restriction
POST /api/security/bans
Content-Type: application/json

{
  "key": "198.51.100.24",
  "reason": "Repeated failed validation attempts",
  "duration_minutes": 15
}

# Lift temporary restriction
POST /api/security/bans/unban
Content-Type: application/json

{
  "key": "198.51.100.24"
}
```

#### Export Encrypted Audit Bundle (for SIEM / SOC Ingestion)
```http
POST /api/security/audit/export
Content-Type: application/json

{
  "secret_key": "enterprise-compliance-secret",
  "limit": 500
}
```

#### Verify & Decrypt Audit Bundle
```http
POST /api/security/audit/verify
Content-Type: application/json

{
  "secret_key": "enterprise-compliance-secret",
  "bundle": { ... }
}
```

---

### 🌐 Distributed Consensus & Multi-Region Quorum Sync

#### Cluster Status & Peer Topology
```http
GET /api/consensus/status
GET /api/consensus/peers
```

Response:
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

#### Join Cluster Peer
```http
POST /api/consensus/peers/join
Content-Type: application/json

{
  "node_id": "node-2",
  "address": "http://192.168.1.50:9082"
}
```

#### Trigger Anti-Entropy State Synchronization
```http
POST /api/consensus/sync/trigger
```

---

### ⚡ Real-Time WebSocket Streaming & Telemetry Push

#### Bidirectional WebSocket Telemetry Stream
रीयल-टाइम टेलीमेट्री स्ट्रीमिंग और सब-सेकंड किल-स्विच पुश के लिए `/api/stream/ws` से स्थायी WebSocket क्लाइंट कनेक्ट करें:

```http
GET /api/stream/ws?license_key=SLB-XXXX-XXXX&hwid=HWID-1234 HTTP/1.1
Host: localhost:9082
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

#### Query Connected Streaming Clients & Telemetry
```http
# List active streaming sessions
GET /api/stream/clients

# Query streaming metrics and recent event audit log
GET /api/stream/telemetry
```

#### Execute Instantaneous Remote Kill-Switch
```http
POST /api/stream/kill
Content-Type: application/json

{
  "target": "SLB-XXXX-XXXX",
  "reason": "Suspected device cloning or fraud",
  "immediate": true
}
```
*नोट: लक्ष्य एक विशिष्ट लाइसेंस कुंजी, डिवाइस HWID, क्लाइंट ID, या आपातकालीन प्रसारण किल-स्विच निष्पादन के लिए `"ALL"` हो सकता है। सिग्नल सब-सेकंड डिलीवरी के साथ मेल खाने वाले क्लाइंट सॉकेट पर पुश किए जाते हैं।*

---

### 🕵️ Zero-Knowledge Proof (ZKP) Anonymous Verification

#### Fetch NIST P-256 Public Parameters & Generators
```http
GET /api/zkp/params
```

#### Issue Anonymous Blinded Credential
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

#### Verify Zero-Knowledge Presentation Proof (Sigma Protocol)
```http
POST /api/zkp/verify
Content-Type: application/json

{
  "credential": { ... },
  "required_tier": "enterprise"
}
```

#### Inspect Spent Nullifier Status
```http
GET /api/zkp/nullifiers/check?nullifier=7f2a9c4b...
```

---

### 🔐 Enterprise Single Sign-On (SSO) & SCIM 2.0 Directory Provisioning

#### SAML 2.0 Service Provider Metadata
Okta, Azure AD, या PingFederate के लिए मानक SP मेटाडेटा XML डाउनलोड करें:
```http
GET /api/sso/saml/metadata?entity_id=urn:sheet-license-broker:sp
```

#### SAML 2.0 Assertion Consumer Service (ACS)
इनबाउंड SAML असर्शन को प्रोसेस करें और प्रमाणित सत्र टोकन जारी करें:
```http
POST /api/sso/saml/acs
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PHNhbWxwOlJlc3BvbnNlIHhtbG5z...
```

#### OpenID Connect (OIDC) Callback
Google Workspace, Auth0, या Keycloak से ID टोकन और दावों को सत्यापित करें:
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

#### Identity Provider (IdP) Management
```http
# Register new SAML or OIDC IdP
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

# List registered IdPs
GET /api/sso/idp
```

#### SCIM 2.0 Directory Provisioning (RFC 7644)
कॉर्पोरेट उपयोगकर्ता जीवनचक्र प्रोविज़निंग को सीधे Okta, Microsoft Entra ID (Azure AD), या OneLogin के साथ एकीकृत करें:

```http
# Service Provider Configuration
GET /scim/v2/ServiceProviderConfig

# List directory users (paginated)
GET /scim/v2/Users?startIndex=1&count=50

# Provision user (automatically allocates license seat)
POST /scim/v2/Users
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "alice@corp.com",
  "emails": [{ "value": "alice@corp.com", "primary": true }],
  "roles": [{ "value": "operator" }],
  "active": true
}

# Deprovision user (instantly revokes allocated license seat and pushes kill-switch)
DELETE /scim/v2/Users/usr-okta-8821
```

#### Ephemeral RBAC Session Tokens
```http
# Mint ephemeral token
POST /api/sso/token/mint
Content-Type: application/json

{
  "user_id": "usr_9918",
  "email": "alice@corp.com",
  "role": "admin",
  "scopes": ["license:read", "license:write", "sso:manage"]
}

# Introspect token and enforce scope permissions
POST /api/sso/token/introspect
Content-Type: application/json

{
  "token": "sso_tok_7f2a9c4b...",
  "required_scope": "license:write"
}
```

---

### ⚛️ Post-Quantum Cryptography & ML-DSA Hybrid Signatures

#### Fetch NIST FIPS 204 Lattice Parameters & Active Key Info
```http
GET /api/pqc/params
```
**Response:**
```json
{
  "status": "success",
  "lattice": { "dimension": 256, "modulus": 8380417, "d": 13 },
  "primary_algorithm": "ML-DSA-65",
  "active_key_id": "pqc-key-9b0d-e626",
  "grace_window_days": 7
}
```

#### List Public Verification Keys
```http
GET /api/pqc/keys
```

#### Issue Hybrid Quantum-Resistant License Signature
```http
POST /api/pqc/sign
Content-Type: application/json

{
  "license_key": "LIC-PRO-2026-99",
  "hwid": "HWID-9B0D-E626-C8D9-6D4B",
  "payload": "entitlement-v1-pro-tier"
}
```
**Response:**
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

#### Verify Dual Classical & Lattice Signatures
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
**Response:**
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

#### Atomic Key Rotation with Grace Period
```http
POST /api/pqc/rotate
Content-Type: application/json

{
  "algorithm": "ML-DSA-65",
  "grace_days": 7,
  "reason": "Routine cryptographic key rollover"
}
```

#### Emergency Compromise Key Revocation
```http
POST /api/pqc/revoke
Content-Type: application/json

{
  "key_id": "pqc-key-old-compromised",
  "reason": "Private key leakage detected"
}
```

---

### 🛡️ Behavioral Anomaly Detection & Adaptive Risk Scoring

`sheet-license-broker` में एक एंटरप्राइज़-ग्रेड व्यवहार विसंगति इंजन शामिल है जो क्लाइंट अनुप्रयोगों में सांख्यिकीय हार्टबीट ड्रिफ्ट, असंभव भौगोलिक यात्रा और गतिशील जोखिम स्कोरिंग को ट्रैक करता है।

#### Adaptive Governance Policy
- **Score 0 – 49 (Nominal)**: सामान्य संचालन, अप्रतिबंधित पहुंच। सामान्य गतिविधि समय के साथ संचित जोखिम बिंदुओं को उत्तरोत्तर क्षय (decay) करती है।
- **Score 50 – 84 (Suspicious)**: चुनौती वृद्धि की आवश्यकता है। 5-मिनट के एकल-उपयोग क्रिप्टोग्राफ़िक पुनः-सत्यापन चुनौती (`POST /api/anomaly/challenge/issue` और `/verify`) को लागू करता है।
- **Score 85 – 100 (High Risk / Compromised)**: तत्काल शून्य-विश्वास संगरोध (zero-trust quarantine)। सत्यापन कॉल (`POST /api/licenses/verify`) स्वचालित रूप से HTTP 403 Forbidden के साथ अस्वीकार कर दिए जाते हैं, और अलर्ट सुरक्षा वेबहुक पर प्रसारित किए जाते हैं।

#### Record Client Telemetry Observation
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
**Response:**
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

#### Query Adaptive Risk Score
```http
GET /api/anomaly/score?license_key=SLB-PRO-2026-99
```

#### Issue & Verify Re-Attestation Challenge
```http
# Issue challenge token
POST /api/anomaly/challenge/issue
Content-Type: application/json

{
  "license_key": "SLB-PRO-2026-99",
  "hwid": "HWID-9B0D-E626-C8D9-6D4B"
}

# Verify challenge token
POST /api/anomaly/challenge/verify
Content-Type: application/json

{
  "challenge_token": "ch_7f2a9c4b..."
}
```

#### Export Security Incident Graph (SIEM Standard Feed)
Splunk, Datadog, Elastic, और Microsoft Sentinel के लिए स्वरूपित RFC-अनुपालन टोपोलॉजिकल घटना नोड्स और किनारों का निर्यात करें:
```http
GET /api/anomaly/graph?min_score=50&limit=50
```
**Response:**
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

#### Engine Telemetry Status
```http
GET /api/anomaly/status
```

---

## ⚡ Cloudflare Edge Gateway

विश्व स्तर पर वितरित, सब-मिलीसेकंड एज लाइसेंस सत्यापन के लिए, `edge/cloudflare/` में स्थित Cloudflare Worker को परिनियोजित करें:

```bash
cd edge/cloudflare
wrangler deploy
```

- **Sub-10ms POP Verification**: Cloudflare Workers KV कैश से सीधे वैध लाइसेंस की पुष्टि करता है।
- **Hardware Web Crypto**: ओरिजिन तक पहुंचने से पहले एज HMAC-SHA256 हस्ताक्षर और रिप्ले रोकथाम।
- **Automated Origin Fallback**: अनकैश्ड प्रश्न, कुंजी बाइंड और निरस्तीकरण पारदर्शी रूप से ओरिजिन सर्वर पर प्रॉक्सी होते हैं।

---

## 💻 Multi-Language Client SDKs

`sheet-license-broker` में `sdk/` के अंतर्गत उत्पादन-तैयार क्लाइंट SDK शामिल हैं जो स्वचालित हार्डवेयर आईडी (HWID) डिवाइस बाइंडिंग और क्रिप्टोग्राफ़िक HMAC-SHA256 अनुरोध हस्ताक्षर का समर्थन करते हैं।

### 🐍 Python Client (`sdk/python/sheet_license_client.py`)

शून्य बाहरी निर्भरताएं (मानक लाइब्रेरी `urllib` और `hashlib` का उपयोग करता है):

```python
from sheet_license_client import SheetLicenseClient, get_machine_hwid

client = SheetLicenseClient(base_url="http://localhost:9082", secret_key="your-hmac-secret")

# 1. Verify license key (automatically attaches local machine HWID)
res = client.verify_license("SLB-XXXX-XXXX-XXXX")
if res.get("valid"):
    print("License verified. Tier:", res.get("tier"))

    # 2. Check dynamic feature flag entitlement
    if client.is_feature_enabled("SLB-XXXX-XXXX-XXXX", "analytics"):
        print("Analytics module enabled!")

    # 3. Record consumption towards tier quotas
    client.record_usage("SLB-XXXX-XXXX-XXXX", "api_calls", 1)

    # 4. Enterprise SSO & SCIM directory token check
    sso_status = client.get_sso_status()
    token_info = client.introspect_session_token("sso_tok_...", required_scope="license:write")

    # 5. Behavioral anomaly telemetry & risk scoring
    client.record_anomaly_telemetry("SLB-XXXX-XXXX-XXXX", latitude=37.5665, longitude=126.9780)
    risk = client.get_anomaly_risk_score(license_key="SLB-XXXX-XXXX-XXXX")
else:
    print("Denied:", res.get("message"))
```

### ⚡ C# / .NET & Unity (`sdk/csharp/SheetLicenseClient.cs`)

Unity Mono/IL2CPP, WPF, और .NET Desktop के साथ संगत एकल-फ़ाइल सहायक:

```csharp
using SheetLicenseBroker;

var client = new SheetLicenseClient("http://localhost:9082", "your-hmac-secret");

// Verify license and check tier entitlement
var result = await client.VerifyLicenseAsync("SLB-XXXX-XXXX-XXXX");
if (result.Valid) {
    Console.WriteLine($"Access granted! Tier: {result.Tier}, Expiry: {result.ExpirationDate}");

    // Dynamic feature gating
    if (await client.IsFeatureEnabledAsync("SLB-XXXX-XXXX-XXXX", "analytics")) {
        Console.WriteLine("Analytics initialized.");
    }

    // Record usage
    await client.RecordUsageAsync("SLB-XXXX-XXXX-XXXX", "api_calls", 1);

    // Enterprise SSO & SCIM directory token check
    var ssoStatus = await client.GetSSOStatusAsync();
    var tokenInfo = await client.IntrospectSessionTokenAsync("sso_tok_...", "license:write");

    // Behavioral anomaly telemetry & risk scoring
    await client.RecordAnomalyTelemetryAsync("SLB-XXXX-XXXX-XXXX", 37.5665, 126.9780);
    var risk = await client.GetAnomalyRiskScoreAsync("SLB-XXXX-XXXX-XXXX");
}
```

### 🟩 TypeScript & Node.js (`@sheet-license/client`)

Node.js बैकएंड और Electron ऐप्स के लिए शून्य-निर्भरता वाला नेटिव ESM पैकेज:

```typescript
import { SheetLicenseClient } from '@sheet-license/client';

const client = new SheetLicenseClient({
  baseUrl: 'http://localhost:9082',
  secretKey: 'your-hmac-secret',
});

const result = await client.verifyLicense('SLB-XXXX-XXXX-XXXX');
if (result.valid) {
  console.log('License active. Tier:', result.tier);

  // Dynamic feature gating
  const hasAnalytics = await client.isFeatureEnabled('SLB-XXXX-XXXX-XXXX', 'analytics');
  if (hasAnalytics) {
    console.log('Analytics feature enabled for client');
  }

  // Record usage metrics
  await client.recordUsage('SLB-XXXX-XXXX-XXXX', 'api_calls', 1);

  // Enterprise SSO & SCIM directory token check
  const ssoStatus = await client.getSSOStatus();
  const tokenInfo = await client.introspectSessionToken('sso_tok_...', 'license:write');

  // Behavioral anomaly telemetry & risk scoring
  await client.recordAnomalyTelemetry('SLB-XXXX-XXXX-XXXX', { latitude: 37.5665, longitude: 126.9780 });
  const risk = await client.getAnomalyRiskScore('SLB-XXXX-XXXX-XXXX');
}
```

### 🔷 Go Client (`sdk/go/client.go`)

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

		// Dynamic feature gating
		allowed, _ := client.IsFeatureEnabled(context.Background(), "SLB-XXXX-XXXX-XXXX", "analytics")
		if allowed {
			fmt.Println("Analytics feature enabled.")
		}

		// Record usage consumption
		_ = client.RecordUsage(context.Background(), "SLB-XXXX-XXXX-XXXX", "api_calls", 1)

		// Enterprise SSO & SCIM directory token check
		ssoStatus, _ := client.GetSSOStatus(context.Background())
		tokenInfo, _ := client.IntrospectSessionToken(context.Background(), "sso_tok_...", "license:write")
		_ = ssoStatus
		_ = tokenInfo

		// Behavioral anomaly telemetry & risk scoring
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

## 🛠️ Verification & Build

स्वचालित परीक्षण सूट चलाएं:

```bash
# Execute unit tests across all packages
go test -v ./...

# Compile standalone production binary
go build -ldflags="-s -w" -o sheet-license-broker.exe .
```

---

## 📄 License

Licensed under the [MIT License](../../LICENSE).
