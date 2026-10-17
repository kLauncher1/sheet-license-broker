<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <b>🇮🇳 हिन्दी</b>
</p>

# Sheet-License-Broker

<p align="center">
  <strong>Google Sheets और Google Apps Script द्वारा संचालित सर्वरलेस प्रमाणीकरण, सॉफ़्टवेयर लाइसेंसिंग और NoSQL डेटाबेस गेटवे</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/लाइसेंस-MIT-blue.svg" alt="लाइसेंस: MIT">
  <img src="https://img.shields.io/badge/संस्करण-v1.5.0-emerald.svg" alt="संस्करण: v1.5.0">
  <img src="https://img.shields.io/badge/विसंगति%20पहचान-Z--Score%20%26%20SIEM%20Topology-F59E0B.svg" alt="व्यवहार विसंगति और SIEM टोपोलॉजी">
  <img src="https://img.shields.io/badge/पोस्ट--क्वांटम-NIST%20FIPS%20204%20ML--DSA-7C3AED.svg" alt="पोस्ट-क्वांटम क्रिप्टोग्राफी">
  <img src="https://img.shields.io/badge/एसएसओ-SAML%202.0%20%26%20OIDC-blueviolet.svg" alt="SAML और OIDC SSO">
  <img src="https://img.shields.io/badge/डायरेक्टरी%20प्रावधान-RFC%207643%20%2F%207644%20SCIM%202.0-10B981.svg" alt="SCIM 2.0">
  <img src="https://img.shields.io/badge/जीरो--नॉलेज%20प्रमाण-pedersen%20%26%20sigma%20proofs-10B981.svg" alt="शून्य-ज्ञान प्रमाण">
  <img src="https://img.shields.io/badge/स्ट्रीमिंग-websocket%20telemetry%20%26%20kill--switch-10B981.svg" alt="WebSocket स्ट्रीमिंग और किल-स्विच">
  <img src="https://img.shields.io/badge/आम%20सहमति-raft%20quorum%20%26%20CRDT-blue.svg" alt="वितरित सर्वसम्मति">
  <img src="https://img.shields.io/badge/सुरक्षा-rate%20limits%20%26%20SIEM%20audit-blueviolet.svg" alt="सुरक्षा और दर सीमा">
  <img src="https://img.shields.io/badge/हार्डवेयर%20प्रमाणन-TPM%202.0%20%26%20Enclave-0284C7.svg" alt="हार्डवेयर सत्यापन">
  <img src="https://img.shields.io/badge/टियर%20मीटरिंग-dynamic%20flags-8B5CF6.svg" alt="डायनामिक फीचर्स">
  <img src="https://img.shields.io/badge/Go%20संस्करण-%3E%3D1.22-00ADD8.svg" alt="Go संस्करण">
  <img src="https://img.shields.io/badge/उच्च%20उपलब्धता-active--standby-059669.svg" alt="उच्च उपलब्धता">
  <img src="https://img.shields.io/badge/मेट्रिक्स-prometheus-E6522C.svg" alt="Prometheus मेट्रिक्स">
  <img src="https://img.shields.io/badge/cloudflare-edge%20worker-F38020.svg" alt="Cloudflare Workers">
  <img src="https://img.shields.io/badge/google--apps--script-तैनात-34A853.svg" alt="Google Apps Script">
  <img src="https://img.shields.io/badge/होस्टिंग%20लागत-0%24%2Fमाह-10B981.svg" alt="होस्टिंग लागत: $0/माह">
</p>

</div>

---

## 💡 संक्षिप्त परिचय (Overview)

**`sheet-license-broker`** किसी भी साधारण Google स्प्रेडशीट को डेस्कटॉप एप्लिकेशन, सीएलआई टूल्स (CLI) और स्वतंत्र सास (SaaS) उत्पादों के लिए उच्च-प्रदर्शन, सुरक्षित और उत्पादन-तैयार सर्वरलेस बैकएंड में बदल देता है।

अब आपको केवल यूज़र लॉगिन और लाइसेंस कुंजियों को सत्यापित करने के लिए महंगे क्लाउड डेटाबेस का मासिक शुल्क चुकाने या जटिल डॉकर कंटेनर चलाने की आवश्यकता नहीं है। `sheet-license-broker` Google के **Apps Script (GAS)** क्लाउड इंजन को उच्च-गति **Go ब्रिज, पोस्ट-क्वांटम ML-DSA सिग्नेचर चेन (NIST FIPS 204), वितरित Raft कोरम सहमति, संघर्ष-मुक्त CRDT LWW-Element-Set सिंक्रनाइज़ेशन, Cloudflare Edge Gateway, क्रिप्टोग्राफ़िक हार्डवेयर सत्यापन (TPM 2.0 और एन्क्लेव), मल्टी-टेनेंट अलगाव, दोहरी शीट सक्रिय-स्टैंडबाय उच्च उपलब्धता (HA), डायनामिक फीचर फ्लैग्स, एन्क्रिप्टेड डिस्क स्पूल, Prometheus मेट्रिक्स, HMAC छेड़छाड़-रोधी सुरक्षा, लचीला ऑफ़लाइन कैश और अंतर्निहित वेब कंसोल** के साथ एकीकृत करता है।

### बैकएंड के रूप में Google Sheets ही क्यों?
- **शून्य होस्टिंग लागत ($0/माह)**: Google Drive और Apps Script के निःशुल्क कोटा (प्रतिदिन 20,000 अनुरोध तक) का पूर्ण उपयोग।
- **पोस्ट-क्वांटम क्रिप्टोग्राफी और ML-DSA सिग्नेचर चेन (NIST FIPS 204)**: क्वांटम कंप्यूटर प्रतिरोधी लैटिस-आधारित डिजिटल हस्ताक्षर (ML-DSA-44 / ML-DSA-65), हाइब्रिड ECDSA / लैटिस चेन (`Hybrid-P256-MLDSA65`), बिना किसी डाउनटाइम के कुंजी रोटेशन और आपातकालीन लाइसेंस निरस्तीकरण प्रसारण।
- **व्यवहार विसंगति पहचान और अनुकूली जोखिम स्कोरिंग**: रोलिंग विंडो Z-Score हार्टबीट ड्रिफ्ट ट्रैकिंग (&plusmn;15% जिटर छूट), हावरसाइन सूत्र द्वारा असंभव भौगोलिक यात्रा का पता लगाना (&gt;950 किमी/घंटा या समवर्ती /24 सबनेट गतिविधि), स्वतः जोखिम अंक क्षय, जोखिम स्कोर &ge; 50 होने पर क्रिप्टोग्राफ़िक चुनौती जारी करना, जोखिम स्कोर &ge; 85 पर स्वचालित शून्य-विश्वास क्वारंटाइन और SIEM-संगत घटना टोपोलॉजी ग्राफ (`siem-topology-v1`) तैयार करना।
- **एंटरप्राइज सिंगल साइन-ऑन (SSO) और SCIM 2.0 डायरेक्टरी प्रोविजनिंग**: SAML 2.0 और OIDC पहचान संघ, RFC 7643/7644 मानकों के अनुसार कर्मचारियों का स्वतः लाइसेंस आवंटन और नौकरी छोड़ने पर तत्काल किल-स्विच निष्कासन।
- **शून्य-ज्ञान प्रमाण (ZKP) अनाम सत्यापन**: NIST P-256 वक्र पर पेडरसन कमिटमेंट, गैर-संवादात्मक सिग्मा प्रमाण (फिएट-शमीर रूपांतरण) और क्लाइंट की हार्डवेयर गोपनीयता की रक्षा के लिए खर्च किए गए नलिफायर रिप्ले रोकथाम रजिस्टर।
- **वितरित Raft कोरम और CRDT जाल**: हल्का नेता चुनाव, बहुमत लॉग सर्वसम्मति, बिना किसी टकराव के स्थिति प्रतिकृति और नोड्स के बीच एंटी-एन्ट्रॉपी डेटा सिंक के लिए SHA-256 मर्कल ट्री सारांश।
- **उन्नत दर सीमा और क्रमिक विलंब**: आईपी और हार्डवेयर आईडी (HWID) के लिए थ्रेड-सुरक्षित स्लाइडिंग विंडो नियंत्रण और मानक `X-RateLimit-*` प्रतिक्रिया हेडर।
- **प्रतिष्ठा कैश और स्वतः अस्थायी प्रतिबंध**: बार-बार सुरक्षा नियमों का उल्लंघन करने वालों पर स्वतः प्रतिबंध और सुरक्षा वेबहुक को तत्काल चेतावनी प्रेषण।
- **SIEM के लिए एन्क्रिप्टेड ऑडिट बंडल**: Splunk, Datadog और AWS CloudWatch के लिए उपयुक्त AES-256-GCM और HMAC से सुरक्षित अनुपालन ऑडिट पैकेज।
- **हार्डवेयर सत्यापन और क्लोन सुरक्षा**: सॉफ्टवेयर क्लोनिंग को रोकने के लिए TPM 2.0 PCR Quote और Apple Secure Enclave / Windows Hello चिप्स का हार्डवेयर स्तर पर सत्यापन।
- **डायनामिक फीचर फ्लैग और टियर मीटरिंग**: Free, Pro, Enterprise प्लान के आधार पर रनटाइम अधिकार जांच (`client.isFeatureEnabled("analytics")`) और Google Sheets में सुरक्षित खपत कोटा ट्रैकिंग।
- **सक्रिय-स्टैंडबाय स्वचालित विफलता समाधान (Failover)**: प्राथमिक और बैकअप शीट के बीच स्वतः स्विचिंग और कनेक्टिविटी बहाल होने पर निर्बाध द्विदिश डेटा सुलह।
- **एन्क्रिप्टेड लोकल डिस्क स्पूल**: नेटवर्क कटने पर भी शून्य डेटा नुकसान सुनिश्चित करने वाला AES-256-GCM एन्क्रिप्टेड जर्नल क्यू (`spool.bin`)।
- **अंतर्निहित वेब कंसोल**: एकल स्टैंडअलोन बाइनरी (`sheet-license-broker.exe`) में एम्बेडेड गहरा हरा डार्क मोड प्रबंधन पैनल।

---

## 🏛️ आर्किटेक्चर (Architecture)

```mermaid
flowchart TD
    Client["डेस्कटॉप ऐप / सीएलआई / वेब ऐप"] -->|HTTPS REST + HMAC-SHA256| Guard["छेड़छाड़-रोधी गार्ड और Nonce कैश"]
    Guard --> Limiter["दर सीमक और आईपी प्रतिष्ठा गेट"]
    Limiter --> Broker["sheet-license-broker (Go गेटवे)"]
    Broker -->|//go:embed| WebUI["अंतर्निहित व्यवस्थापक कंसोल (पोर्ट 9082)"]
    Broker -->|स्क्रैप| Prom["Prometheus मॉनिटरिंग (/metrics)"]
    Broker -->|एन्क्रिप्टेड डिस्क जर्नल| Spool["स्थानीय डिस्क स्पूल (AES-256-GCM)"]
    Broker -->|SIEM निर्यात| SIEM["ऑडिट पाइपलाइन (AES-256-GCM)"]
    Broker -->|अलर्ट| Alerts["सुरक्षा वेबहुक (Discord और Slack)"]
    Broker -->|Raft RPC और CRDT सिंक| Peers["क्लस्टर पीयर मेश (Anti-Entropy)"]
    Broker -->|मेमोरी TTL कैश| Cache["स्थानीय कैश (कोटा और ऑफलाइन फॉलबैक)"]
    Broker -->|सक्रिय भूमिका| Primary["प्राथमिक GAS वेब ऐप (Code.gs)"]
    Broker -.->|स्वतः फेवरओवर| Standby["स्टैंडबाय GAS वेब ऐप (Code.gs)"]
    Primary --> Sheets1["प्राथमिक Google Sheets डेटाबेस"]
    Standby -.-> Sheets2["स्टैंडबाय Google Sheets डेटाबेस"]

    subgraph Google Sheets डेटाबेस
        Sheets1 --> Tab1["टैब: Users (सॉल्टेड हैश प्रमाणीकरण)"]
        Sheets1 --> Tab2["टैब: Licenses (HWID बाइंड और समाप्ति)"]
        Sheets1 --> Tab3["टैब: Blacklist (रद्द और प्रतिबंधित HWID)"]
        Sheets1 --> Tab4["टैब: Audit_Logs (सुरक्षा ऑडिट और प्रतिबंध)"]
        Sheets1 --> Tab5["टैब: Attestations (TPM Quote और दावे)"]
        Sheets1 --> Tab6["टैब: KV_Database (NoSQL डेटा स्टोर)"]
        Sheets1 --> Tab7["टैब: ConsensusNodes (पीयर खोज और हार्टबीट)"]
    end
```

---

## 🚀 त्वरित आरंभ (Quick Start)

### 1. स्थानीय गेटवे और कंसोल प्रारंभ करें

सुनिश्चित करें कि आपके कंप्यूटर पर Go 1.22+ स्थापित है:

```bash
# रिपॉजिटरी को क्लोन करें
git clone https://github.com/kLauncher1/sheet-license-broker.git
cd sheet-license-broker

# स्टैंडअलोन मोड में चलाएं
go run .
```

ब्राउज़र में **`http://localhost:9082`** पर जाकर लाइव वेब कंसोल देखें।

### 2. लाइव Google Sheets से कनेक्ट करें (प्रॉक्सी मोड)

अपने Google Apps Script वेब ऐप से गेटवे को जोड़ने के लिए पर्यावरण चर सेट करें:

```bash
# Apps Script वेब ऐप का URL सेट करें
export GAS_WEBAPP_URL="https://script.google.com/macros/s/.../exec"
export CACHE_TTL_SECONDS="600" # वैकल्पिक: 10 मिनट कैश TTL

# गेटवे लॉन्च करें
./sheet-license-broker.exe
```

सर्वर स्वचालित रूप से दूरस्थ URL का पता लगा लेगा, अनुरोधों को आगे भेजेगा, प्रतिक्रियाओं को स्थानीय स्तर पर कैश करेगा और नेटवर्क बाधाओं के दौरान ऑफ़लाइन कैश से काम करता रहेगा।

---

## 📋 Google Sheets सेटअप और Clasp परिनियोजन

### विकल्प A: Clasp CLI द्वारा स्वचालित परिनियोजन

यदि आपके पास `@google/clasp` टूल है:

```bash
# 1. अपने Google खाते में लॉगिन करें
npx @google/clasp login

# 2. स्वचालित हेल्पर स्क्रिप्ट चलाएं
node scripts/deploy_clasp.mjs --script-id <YOUR_APPS_SCRIPT_ID>
```

### विकल्प B: 3 मिनट का मैनुअल सेटअप

1. [Google Sheets](https://sheets.new) पर जाएं और एक खाली स्प्रेडशीट बनाएं।
2. शीर्ष मेनू में **एक्सटेंशन > Apps Script** पर क्लिक करें।
3. डिफ़ॉल्ट कोड को मिटाएं और [`gas/Code.gs`](../../gas/Code.gs) की पूरी सामग्री चिपकाएं।
4. **Deploy > New deployment** पर क्लिक करें:
   - प्रकार: **Web app**
   - निष्पादित करें: **Me (आपका ईमेल)**
   - किसके पास पहुंच है: **Anyone**
5. **Deploy** पर क्लिक करें और उत्पन्न **Web app URL** (`https://script.google.com/macros/s/.../exec`) को कॉपी करें।

पहला अनुरोध प्राप्त होने पर शीट अपने आप आवश्यक टैब (`Users`, `Licenses`, `KV_Database`) बना लेगी।

---

## 📡 REST API विनिर्देश सारांश

| अनुभाग | विधि और एंडपॉइंट | विवरण |
| :--- | :--- | :--- |
| **निदान** | `GET /api/health` | सेवा स्वास्थ्य और टेलीमेट्री की पूरी स्थिति जांचें |
| **निदान** | `GET /api/proxy/ping` | Google Apps Script बैकएंड के साथ राउंड-ट्रिप लेटेंसी जांचें |
| **प्रमाणीकरण** | `POST /api/users/register` | उपयोगकर्ता खाता पंजीकृत करें (सॉल्टेड पासवर्ड हैश) |
| **प्रमाणीकरण** | `POST /api/users/login` | उपयोगकर्ता लॉगिन क्रेडेंशियल सत्यापित करें |
| **लाइसेंस** | `POST /api/licenses` | नई लाइसेंस कुंजी जारी करें (वैधता दिन और डिवाइस सीमा) |
| **लाइसेंस** | `POST /api/licenses/validate` | लाइसेंस जांचें और पहले अनुरोधकर्ता के HWID से लॉक करें |
| **लाइसेंस** | `POST /api/licenses/revoke` | किसी लाइसेंस कुंजी को तुरंत रद्द करें |
| **सुरक्षा** | `POST /api/security/blacklist` | दुर्भावनापूर्ण डिवाइस HWID या लाइसेंस को ब्लैकलिस्ट करें |
| **सुरक्षा** | `GET /api/security/blacklist` | सक्रिय ब्लैकलिस्ट प्रविष्टियां देखें |
| **NoSQL** | `POST /api/docs` | संग्रह और दस्तावेज़ आईडी के आधार पर JSON डेटा सहेजें |
| **NoSQL** | `GET /api/docs` | सभी सहेजे गए दस्तावेज़ प्राप्त करें |
| **मल्टी-टेनेंट** | `POST /api/tenants/register` | विशिष्ट कुंजी उपसर्ग और वेबहुक के साथ किरायेदार पंजीकृत करें |
| **बैकअप** | `POST /api/backup/export` | AES-256-GCM एन्क्रिप्टेड स्थिति स्नैपशॉट निर्यात करें |
| **बैकअप** | `POST /api/backup/restore` | एन्क्रिप्टेड स्नैपशॉट से संपूर्ण डेटा पुनर्स्थापित करें |
| **सुविधाएं** | `GET /api/features` | वैश्विक फीचर कैटलॉग और प्लान कोटा देखें |
| **सुविधाएं** | `POST /api/features/check` | जांचें कि लाइसेंस के पास किसी विशेष सुविधा का अधिकार है या नहीं |
| **उपयोग ट्रैकिंग**| `POST /api/usage/record` | API कॉल जैसी खपत मेट्रिक्स रिकॉर्ड करें और घटाएं |
| **हार्डवेयर प्रमाण**| `POST /api/attestation/challenge` | TPM 2.0 के लिए एकल-उपयोग Nonce चुनौती जारी करें |
| **हार्डवेयर प्रमाण**| `POST /api/attestation/verify` | TPM 2.0 PCR कोटेशन और क्रिप्टोग्राफिक हस्ताक्षर सत्यापित करें |
| **दर नियंत्रण** | `GET /api/security/ratelimit/status`| आईपी और HWID स्लाइडिंग विंडो थ्रॉटलिंग मेट्रिक्स |
| **सहमति** | `GET /api/consensus/status` | Raft कोरम और CRDT क्लस्टर सिंक्रनाइज़ेशन स्थिति |
| **लाइव स्ट्रीम** | `GET /api/stream/ws` | त्वरित आपातकालीन ब्लॉक के लिए द्विदिश WebSocket कनेक्शन |
| **ZKP** | `POST /api/zkp/verify` | बिना विवरण उजागर किए अनाम सिग्मा प्रमाण सत्यापित करें |
| **SSO / SCIM** | `GET /api/sso/saml/metadata` | Okta/Azure के लिए मानक SP XML मेटाडेटा डाउनलोड करें |
| **SSO / SCIM** | `POST /scim/v2/Users` | SCIM 2.0 डायरेक्टरी से कर्मचारी जोड़ें और सीट आवंटित करें |
| **पोस्ट-क्वांटम** | `POST /api/pqc/sign` | हाइब्रिड क्वांटम-सुरक्षित ML-DSA लैटिस हस्ताक्षर उत्पन्न करें |
| **विसंगति** | `POST /api/anomaly/record` | व्यवहार टेलीमेट्री दर्ज करें और जोखिम स्कोर अपडेट करें |
| **SIEM ग्राफ** | `GET /api/anomaly/graph` | सुरक्षा घटना सहसंबंध टोपोलॉजी ग्राफ तैयार करें |

---

## 💻 बहु-भाषा क्लाइंट SDK

### 🐍 Python क्लाइंट (`sdk/python/sheet_license_client.py`)
बिना किसी बाहरी निर्भरता के, केवल मानक लाइब्रेरी पर आधारित:

```python
from sheet_license_client import SheetLicenseClient

client = SheetLicenseClient(base_url="http://localhost:9082", secret_key="your-hmac-secret")

# 1. लाइसेंस सत्यापित करें (लोकल मशीन HWID अपने आप जुड़ जाता है)
res = client.verify_license("SLB-XXXX-XXXX-XXXX")
if res.get("valid"):
    print("लाइसेंस सत्यापित हुआ। टियर:", res.get("tier"))

    # 2. गतिशील सुविधा अनुमति की जांच करें
    if client.is_feature_enabled("SLB-XXXX-XXXX-XXXX", "analytics"):
        print("एनालिटिक्स मॉड्यूल सक्रिय है!")

    # 3. उपयोग खपत दर्ज करें
    client.record_usage("SLB-XXXX-XXXX-XXXX", "api_calls", 1)
```

### ⚡ C# / .NET और Unity (`sdk/csharp/SheetLicenseClient.cs`)
Unity Mono/IL2CPP, WPF और .NET डेस्कटॉप ऐप्स के अनुकूल:

```csharp
using SheetLicenseBroker;

var client = new SheetLicenseClient("http://localhost:9082", "your-hmac-secret");
var result = await client.VerifyLicenseAsync("SLB-XXXX-XXXX-XXXX");
if (result.Valid) {
    Console.WriteLine($"पहुंच स्वीकृत! टियर: {result.Tier}, समाप्ति: {result.ExpirationDate}");
}
```

### 🟩 TypeScript और Node.js (`@sheet-license/client`)
Node.js सर्वर और Electron डेस्कटॉप ऐप्स के लिए:

```typescript
import { SheetLicenseClient } from '@sheet-license/client';

const client = new SheetLicenseClient({
  baseUrl: 'http://localhost:9082',
  secretKey: 'your-hmac-secret',
});

const result = await client.verifyLicense('SLB-XXXX-XXXX-XXXX');
if (result.valid) {
  console.log('लाइसेंस वैध है। टियर:', result.tier);
}
```

### 🔷 Go क्लाइंट (`sdk/go/client.go`)

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
		fmt.Printf("लाइसेंस वैध है (टियर: %s)। प्रोग्राम प्रारंभ हो रहा है...\n", res.Tier)
	}
}
```

---

## 🛠️ परीक्षण और निर्माण (Build)

```bash
# संपूर्ण रिपॉजिटरी में यूनिट परीक्षण चलाएं
go test -v ./...

# उत्पादन के लिए अनुकूलित एकल बाइनरी संकलित करें
go build -ldflags="-s -w" -o sheet-license-broker.exe .
```

---

## 📄 लाइसेंस (License)

यह परियोजना [MIT लाइसेंस](../../LICENSE) के अंतर्गत उपलब्ध है।
