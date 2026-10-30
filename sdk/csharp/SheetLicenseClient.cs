using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SheetLicenseBroker
{
    /// <summary>
    /// Exception thrown when broker operations fail.
    /// </summary>
    public class BrokerException : Exception
    {
        public int StatusCode { get; }
        public string ResponseBody { get; }

        public BrokerException(string message, int statusCode = 0, string responseBody = "")
            : base(message)
        {
            StatusCode = statusCode;
            ResponseBody = responseBody;
        }
    }

    /// <summary>
    /// License validation result payload.
    /// </summary>
    public class LicenseVerificationResult
    {
        public bool Valid { get; set; }
        public string Message { get; set; }
        public string Error { get; set; }
        public string Key { get; set; }
        public string ExpirationDate { get; set; }
        public string Tier { get; set; }
        public string Source { get; set; }
        public string RawJson { get; set; }
    }

    /// <summary>
    /// Single-file client library for Unity, WPF, and .NET desktop applications
    /// communicating with Sheet-License-Broker with HMAC-SHA256 anti-tamper security.
    /// </summary>
    public class SheetLicenseClient
    {
        private readonly string _baseUrl;
        private readonly byte[] _secretKey;
        private readonly string _tenantId;
        private readonly int _timeoutMs;

        public string TenantId => _tenantId;

        public SheetLicenseClient(string baseUrl = "http://127.0.0.1:9082", string secretKey = null, string tenantId = null, int timeoutSeconds = 10)
        {
            _baseUrl = (baseUrl ?? "http://127.0.0.1:9082").TrimEnd('/');
            _secretKey = string.IsNullOrEmpty(secretKey) ? null : Encoding.UTF8.GetBytes(secretKey);
            _tenantId = string.IsNullOrWhiteSpace(tenantId) ? null : tenantId.Trim();
            _timeoutMs = timeoutSeconds * 1000;
        }

        /// <summary>
        /// Generates a stable, unique Hardware ID for the machine.
        /// Extracts hardware cryptographic GUID or falls back to machine fingerprints.
        /// </summary>
        public static string GetMachineHwid()
        {
            StringBuilder sb = new StringBuilder();

            try
            {
                // Windows Registry MachineGuid query
                using (var rk = Microsoft.Win32.RegistryKey.OpenBaseKey(
                    Microsoft.Win32.RegistryHive.LocalMachine,
                    Microsoft.Win32.RegistryView.Registry64))
                {
                    using (var subKey = rk.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                    {
                        var guid = subKey?.GetValue("MachineGuid")?.ToString();
                        if (!string.IsNullOrEmpty(guid))
                        {
                            sb.Append(guid);
                        }
                    }
                }
            }
            catch
            {
                // Non-Windows or restricted registry access fallback
            }

            if (sb.Length == 0)
            {
                sb.Append(Environment.MachineName);
                sb.Append("|");
                sb.Append(Environment.UserName);
                sb.Append("|");
                sb.Append(Environment.ProcessorCount);
            }

            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
                string hex = BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
                return string.Format("HWID-{0}-{1}-{2}-{3}",
                    hex.Substring(0, 4),
                    hex.Substring(4, 4),
                    hex.Substring(8, 4),
                    hex.Substring(12, 4));
            }
        }

        private static string ComputeSha256Hex(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(data ?? new byte[0]);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        private string ComputeHmacHex(string canonical)
        {
            if (_secretKey == null || _secretKey.Length == 0) return null;
            using (HMACSHA256 hmac = new HMACSHA256(_secretKey))
            {
                byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical));
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        private HttpWebRequest CreateRequest(string method, string path, byte[] bodyBytes)
        {
            string url = _baseUrl + path;
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = method.ToUpperInvariant();
            req.Timeout = _timeoutMs;
            req.Accept = "application/json";
            req.UserAgent = "SheetLicenseClient-CSharp/0.5.0";

            if (!string.IsNullOrEmpty(_tenantId))
            {
                req.Headers["X-Tenant-ID"] = _tenantId;
            }

            if (bodyBytes != null && bodyBytes.Length > 0)
            {
                req.ContentType = "application/json; charset=utf-8";
            }

            if (_secretKey != null)
            {
                long ts = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
                string nonce = Guid.NewGuid().ToString("N");
                string bodyHash = ComputeSha256Hex(bodyBytes);
                string canonical = string.Format("{0}\n{1}\n{2}\n{3}\n{4}",
                    req.Method, path, ts, nonce, bodyHash);

                string sig = ComputeHmacHex(canonical);
                req.Headers["X-Signature"] = sig;
                req.Headers["X-Timestamp"] = ts.ToString();
                req.Headers["X-Nonce"] = nonce;
            }

            return req;
        }

        private async Task<string> SendRequestAsync(string method, string path, string jsonPayload = null)
        {
            byte[] bodyBytes = string.IsNullOrEmpty(jsonPayload) ? new byte[0] : Encoding.UTF8.GetBytes(jsonPayload);
            HttpWebRequest req = CreateRequest(method, path, bodyBytes);

            try
            {
                if (bodyBytes.Length > 0 && method != "GET")
                {
                    using (Stream reqStream = await req.GetRequestStreamAsync().ConfigureAwait(false))
                    {
                        await reqStream.WriteAsync(bodyBytes, 0, bodyBytes.Length).ConfigureAwait(false);
                    }
                }

                using (WebResponse resp = await req.GetResponseAsync().ConfigureAwait(false))
                using (Stream respStream = resp.GetResponseStream())
                using (StreamReader reader = new StreamReader(respStream, Encoding.UTF8))
                {
                    return await reader.ReadToEndAsync().ConfigureAwait(false);
                }
            }
            catch (WebException wex)
            {
                int code = 0;
                string errBody = wex.Message;
                if (wex.Response is HttpWebResponse httpResp)
                {
                    code = (int)httpResp.StatusCode;
                    using (Stream errStream = httpResp.GetResponseStream())
                    using (StreamReader reader = new StreamReader(errStream, Encoding.UTF8))
                    {
                        errBody = reader.ReadToEnd();
                    }
                }
                throw new BrokerException(string.Format("Broker request failed ({0}): {1}", code, errBody), code, errBody);
            }
        }

        /// <summary>
        /// Validates a license key for the machine hardware ID.
        /// </summary>
        public async Task<LicenseVerificationResult> VerifyLicenseAsync(string licenseKey, string hwid = null)
        {
            string machineHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string payload = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\"}}",
                EscapeJson(licenseKey), EscapeJson(machineHwid));

            try
            {
                string json = await SendRequestAsync("POST", "/api/licenses/validate", payload).ConfigureAwait(false);
                return new LicenseVerificationResult
                {
                    Valid = json.Contains("\"valid\":true") || json.Contains("\"valid\": true"),
                    Message = ExtractJsonField(json, "message"),
                    Key = licenseKey,
                    Source = ExtractJsonField(json, "source"),
                    RawJson = json
                };
            }
            catch (BrokerException bex)
            {
                return new LicenseVerificationResult
                {
                    Valid = false,
                    Error = ExtractJsonField(bex.ResponseBody, "error") ?? bex.Message,
                    Message = ExtractJsonField(bex.ResponseBody, "message"),
                    Key = licenseKey,
                    Source = ExtractJsonField(bex.ResponseBody, "source"),
                    RawJson = bex.ResponseBody
                };
            }
        }

        /// <summary>
        /// Synchronous license verification helper for Unity or single-threaded game loops.
        /// </summary>
        public LicenseVerificationResult VerifyLicense(string licenseKey, string hwid = null)
        {
            return Task.Run(() => VerifyLicenseAsync(licenseKey, hwid)).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Creates a new license key with the specified duration in days.
        /// </summary>
        public async Task<string> CreateLicenseAsync(int days = 30, int maxDevices = 1)
        {
            string payload = string.Format("{{\"days\":{0},\"max_devices\":{1}}}", days, maxDevices);
            return await SendRequestAsync("POST", "/api/licenses", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Instantly revokes an existing license key.
        /// </summary>
        public async Task<string> RevokeLicenseAsync(string licenseKey, string reason = "")
        {
            string payload = string.Format("{{\"license_key\":\"{0}\",\"reason\":\"{1}\"}}",
                EscapeJson(licenseKey), EscapeJson(reason));
            return await SendRequestAsync("POST", "/api/licenses/revoke", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Authenticates user credentials.
        /// </summary>
        public async Task<string> LoginUserAsync(string username, string password)
        {
            string payload = string.Format("{{\"username\":\"{0}\",\"password\":\"{1}\"}}",
                EscapeJson(username), EscapeJson(password));
            return await SendRequestAsync("POST", "/api/users/login", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries broker health status.
        /// </summary>
        public async Task<string> GetHealthAsync()
        {
            return await SendRequestAsync("GET", "/health").ConfigureAwait(false);
        }

        /// <summary>
        /// Checks whether a specific feature flag is permitted for a license key.
        /// </summary>
        public async Task<bool> IsFeatureEnabledAsync(string licenseKey, string feature)
        {
            string payload = string.Format("{{\"license_key\":\"{0}\",\"feature\":\"{1}\"}}",
                EscapeJson(licenseKey), EscapeJson(feature));
            string raw = await SendRequestAsync("POST", "/api/features/check", payload).ConfigureAwait(false);
            return raw.IndexOf("\"enabled\":true", StringComparison.OrdinalIgnoreCase) != -1;
        }

        public bool IsFeatureEnabled(string licenseKey, string feature)
        {
            return Task.Run(() => IsFeatureEnabledAsync(licenseKey, feature)).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Reports resource consumption units for a license key with quota bounds checking.
        /// </summary>
        public async Task<string> RecordUsageAsync(string licenseKey, string metric, long units = 1, long limit = 0, string period = "")
        {
            string payload = string.Format("{{\"license_key\":\"{0}\",\"metric\":\"{1}\",\"units\":{2},\"limit\":{3}{4}}}",
                EscapeJson(licenseKey),
                EscapeJson(metric),
                units,
                limit,
                string.IsNullOrEmpty(period) ? "" : string.Format(",\"period\":\"{0}\"", EscapeJson(period)));
            return await SendRequestAsync("POST", "/api/usage/record", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Retrieves consumption records for all metered resources of a license key.
        /// </summary>
        public async Task<string> GetUsageAsync(string licenseKey)
        {
            return await SendRequestAsync("GET", "/api/usage/stats?license_key=" + Uri.EscapeDataString(licenseKey.Trim())).ConfigureAwait(false);
        }

        /// <summary>
        /// Obtains a single-use random nonce challenge for TPM / enclave binding.
        /// </summary>
        public async Task<string> RequestAttestationChallengeAsync(string licenseKey, string hwid = null)
        {
            string targetHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string payload = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\"}}",
                EscapeJson(licenseKey), EscapeJson(targetHwid));
            return await SendRequestAsync("POST", "/api/attestation/challenge", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Submits a signed TPM 2.0 PCR quote to attest hardware platform integrity.
        /// </summary>
        public async Task<string> VerifyTPMAttestationAsync(string licenseKey, string challengeId, string tpmQuoteJson, string hwid = null)
        {
            string targetHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string quote = string.IsNullOrWhiteSpace(tpmQuoteJson) ? "{}" : tpmQuoteJson.Trim();
            string payload = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\",\"challenge_id\":\"{2}\",\"attestation_type\":\"tpm2\",\"tpm_quote\":{3}}}",
                EscapeJson(licenseKey), EscapeJson(targetHwid), EscapeJson(challengeId), quote);
            return await SendRequestAsync("POST", "/api/attestation/verify", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Transmits anti-debugging and memory integrity telemetry to the broker.
        /// </summary>
        public async Task<string> ReportTelemetryAsync(string licenseKey, bool debuggerPresent, bool memoryIntegrity, string hwid = null)
        {
            string targetHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string payload = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\",\"report\":{{\"debugger_present\":{2},\"memory_integrity\":{3}}}}}",
                EscapeJson(licenseKey), EscapeJson(targetHwid),
                debuggerPresent ? "true" : "false",
                memoryIntegrity ? "true" : "false");
            return await SendRequestAsync("POST", "/api/attestation/telemetry", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Requests an encrypted audit bundle for enterprise compliance auditing pipelines.
        /// </summary>
        public async Task<string> ExportAuditTokenAsync(string secretKey = null, int limit = 500)
        {
            string payload = string.Format("{{\"secret_key\":\"{0}\",\"limit\":{1}}}",
                EscapeJson(secretKey ?? ""), limit);
            return await SendRequestAsync("POST", "/api/security/audit/export", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries the broker's distributed Raft role, quorum health, and cluster topology.
        /// </summary>
        public async Task<string> GetClusterStatusAsync() =>
            await SendRequestAsync("GET", "/api/consensus/status", null).ConfigureAwait(false);

        /// <summary>
        /// Queries active WebSocket telemetry client sessions.
        /// </summary>
        public async Task<string> GetStreamClientsAsync() =>
            await SendRequestAsync("GET", "/api/stream/clients", null).ConfigureAwait(false);

        /// <summary>
        /// Dispatches an instantaneous remote kill-switch directive to targeted clients.
        /// </summary>
        public async Task<string> SendKillSwitchAsync(string target, string reason = "Administrative remote termination directive", bool immediate = true)
        {
            string payload = string.Format("{{\"target\":\"{0}\",\"reason\":\"{1}\",\"immediate\":{2}}}",
                EscapeJson(target), EscapeJson(reason), immediate ? "true" : "false");
            return await SendRequestAsync("POST", "/api/stream/kill", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries aggregate streaming telemetry and active client metrics.
        /// </summary>
        public async Task<string> GetStreamTelemetryAsync() =>
            await SendRequestAsync("GET", "/api/stream/telemetry", null).ConfigureAwait(false);

        /// <summary>
        /// Fetches public elliptic curve parameters and issuer public key.
        /// </summary>
        public async Task<string> GetZKPParamsAsync() =>
            await SendRequestAsync("GET", "/api/zkp/params", null).ConfigureAwait(false);

        /// <summary>
        /// Issues an issuer-signed anonymous entitlement credential for an authenticated license.
        /// </summary>
        public async Task<string> IssueAnonymousCredentialAsync(string licenseKey, string hwid = null, string tier = "pro", int validDays = 30, string scope = "production")
        {
            string targetHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string payload = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\",\"tier\":\"{2}\",\"valid_days\":{3},\"scope\":\"{4}\",\"tenant_id\":\"{5}\"}}",
                EscapeJson(licenseKey), EscapeJson(targetHwid), EscapeJson(tier), validDays, EscapeJson(scope), EscapeJson(TenantId ?? "default"));
            return await SendRequestAsync("POST", "/api/zkp/credential/issue", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Submits a zero-knowledge presentation proof for privacy-preserving entitlement access.
        /// </summary>
        public async Task<string> VerifyZKPProofAsync(string proofJson, string requiredTier = "free", long epoch = 0)
        {
            if (epoch <= 0) epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 3600;
            string payload = string.Format("{{\"proof\":{0},\"required_tier\":\"{1}\",\"epoch\":{2}}}",
                proofJson, EscapeJson(requiredTier), epoch);
            return await SendRequestAsync("POST", "/api/zkp/verify", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries overall telemetry on zero-knowledge verifications.
        /// </summary>
        public async Task<string> GetZKPStatusAsync() =>
            await SendRequestAsync("GET", "/api/zkp/status", null).ConfigureAwait(false);

        /// <summary>
        /// Queries telemetry on SSO identity providers and SCIM directory status.
        /// </summary>
        public async Task<string> GetSSOStatusAsync() =>
            await SendRequestAsync("GET", "/api/sso/status", null).ConfigureAwait(false);

        /// <summary>
        /// Validates an ephemeral session token and checks permissions.
        /// </summary>
        public async Task<string> IntrospectSessionTokenAsync(string token, string requiredScope = null)
        {
            string payload = string.Format("{{\"token\":\"{0}\",\"required_scope\":\"{1}\"}}",
                EscapeJson(token), EscapeJson(requiredScope ?? ""));
            return await SendRequestAsync("POST", "/api/sso/token/introspect", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries SCIM 2.0 directory users list with pagination.
        /// </summary>
        public async Task<string> ListSCIMUsersAsync(int startIndex = 1, int count = 50)
        {
            string path = string.Format("/scim/v2/Users?startIndex={0}&count={1}", startIndex, count);
            return await SendRequestAsync("GET", path, null).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries post-quantum cryptography parameters and active key info.
        /// </summary>
        public async Task<string> GetPQCParamsAsync() =>
            await SendRequestAsync("GET", "/api/pqc/params", null).ConfigureAwait(false);

        /// <summary>
        /// Retrieves active public keys for client-side lattice signature verification.
        /// </summary>
        public async Task<string> GetPQCPublicKeysAsync() =>
            await SendRequestAsync("GET", "/api/pqc/keys", null).ConfigureAwait(false);

        /// <summary>
        /// Issues a quantum-resistant hybrid signature over a payload for an entitled license.
        /// </summary>
        public async Task<string> SignPQCLicenseAsync(string licenseKey, string payload, string hwid = null)
        {
            string targetHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string body = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\",\"payload\":\"{2}\"}}",
                EscapeJson(licenseKey), EscapeJson(targetHwid), EscapeJson(payload));
            return await SendRequestAsync("POST", "/api/pqc/sign", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Verifies dual classical and post-quantum lattice signatures.
        /// </summary>
        public async Task<string> VerifyPQCSignatureAsync(string payload, string signatureJson)
        {
            string body = string.Format("{{\"payload\":\"{0}\",\"signature\":{1}}}",
                EscapeJson(payload), string.IsNullOrWhiteSpace(signatureJson) ? "{}" : signatureJson.Trim());
            return await SendRequestAsync("POST", "/api/pqc/verify", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Requests an administrative PQC key rotation with active grace period.
        /// </summary>
        public async Task<string> RotatePQCKeyAsync(string algorithm = null, int graceDays = 7, string reason = "Routine rotation")
        {
            string body = string.Format("{{\"algorithm\":\"{0}\",\"grace_days\":{1},\"reason\":\"{2}\"}}",
                EscapeJson(algorithm ?? "ML-DSA-65"), graceDays, EscapeJson(reason));
            return await SendRequestAsync("POST", "/api/pqc/rotate", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Revokes a compromised PQC key by ID.
        /// </summary>
        public async Task<string> RevokePQCKeyAsync(string keyId, string reason = "Administrative revocation")
        {
            string body = string.Format("{{\"key_id\":\"{0}\",\"reason\":\"{1}\"}}",
                EscapeJson(keyId), EscapeJson(reason));
            return await SendRequestAsync("POST", "/api/pqc/revoke", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries operational telemetry for the PQC subsystem.
        /// </summary>
        public async Task<string> GetPQCStatusAsync() =>
            await SendRequestAsync("GET", "/api/pqc/status", null).ConfigureAwait(false);

        /// <summary>
        /// Submits client telemetry or heartbeat to the behavioral anomaly engine.
        /// </summary>
        public async Task<string> RecordAnomalyObservationAsync(string licenseKey, string ip = "", string action = "heartbeat")
        {
            string hwid = GetMachineHwid();
            string body = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\",\"ip\":\"{2}\",\"action\":\"{3}\"}}",
                EscapeJson(licenseKey), EscapeJson(hwid), EscapeJson(ip), EscapeJson(action));
            return await SendRequestAsync("POST", "/api/anomaly/record", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries current adaptive risk score and factors for an entity.
        /// </summary>
        public async Task<string> GetAnomalyRiskScoreAsync(string licenseKey = "", string hwid = "")
        {
            string machineHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string url = string.Format("/api/anomaly/score?license_key={0}&hwid={1}",
                Uri.EscapeDataString(licenseKey ?? ""), Uri.EscapeDataString(machineHwid ?? ""));
            return await SendRequestAsync("GET", url, null).ConfigureAwait(false);
        }

        /// <summary>
        /// Requests an escalation challenge token for an entity.
        /// </summary>
        public async Task<string> IssueAnomalyChallengeAsync(string licenseKey = "", string hwid = "")
        {
            string machineHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string body = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\"}}",
                EscapeJson(licenseKey ?? ""), EscapeJson(machineHwid ?? ""));
            return await SendRequestAsync("POST", "/api/anomaly/challenge/issue", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Submits a challenge token response to clear escalation penalties.
        /// </summary>
        public async Task<string> VerifyAnomalyChallengeAsync(string challengeToken)
        {
            string body = string.Format("{{\"challenge_token\":\"{0}\"}}", EscapeJson(challengeToken ?? ""));
            return await SendRequestAsync("POST", "/api/anomaly/challenge/verify", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Exports real-time topological incident graph for enterprise SIEM ingestion.
        /// </summary>
        public async Task<string> ExportIncidentGraphAsync(int minScore = 0, int limit = 50)
        {
            string url = string.Format("/api/anomaly/graph?min_score={0}&limit={1}", minScore, limit);
            return await SendRequestAsync("GET", url, null).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries behavioral anomaly operational telemetry metrics.
        /// </summary>
        public async Task<string> GetAnomalyStatusAsync() =>
            await SendRequestAsync("GET", "/api/anomaly/status", null).ConfigureAwait(false);

        /// <summary>
        /// Requests a cryptographically random 32-byte single-use attestation challenge nonce.
        /// </summary>
        public async Task<string> RequestEnclaveChallengeAsync() =>
            await SendRequestAsync("POST", "/api/enclave/challenge", "{}").ConfigureAwait(false);

        /// <summary>
        /// Submits an Intel SGX or AMD SEV-SNP attestation quote for policy verification.
        /// </summary>
        public async Task<string> AttestEnclaveQuoteAsync(string platform, string quoteHex, string nonce, string policyId = null)
        {
            string body = string.IsNullOrEmpty(policyId)
                ? string.Format("{{\"platform\":\"{0}\",\"quote\":\"{1}\",\"nonce\":\"{2}\"}}",
                    EscapeJson(platform), EscapeJson(quoteHex), EscapeJson(nonce))
                : string.Format("{{\"platform\":\"{0}\",\"quote\":\"{1}\",\"nonce\":\"{2}\",\"policy_id\":\"{3}\"}}",
                    EscapeJson(platform), EscapeJson(quoteHex), EscapeJson(nonce), EscapeJson(policyId));
            return await SendRequestAsync("POST", "/api/enclave/attest", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Validates an enclave quote and establishes an ephemeral ECDH encrypted tunnel session.
        /// </summary>
        public async Task<string> EstablishEnclaveTunnelAsync(string platform, string quoteHex, string nonce, string clientPublicKey, string policyId = null)
        {
            string body = string.IsNullOrEmpty(policyId)
                ? string.Format("{{\"platform\":\"{0}\",\"quote\":\"{1}\",\"nonce\":\"{2}\",\"client_public_key\":\"{3}\"}}",
                    EscapeJson(platform), EscapeJson(quoteHex), EscapeJson(nonce), EscapeJson(clientPublicKey))
                : string.Format("{{\"platform\":\"{0}\",\"quote\":\"{1}\",\"nonce\":\"{2}\",\"client_public_key\":\"{3}\",\"policy_id\":\"{4}\"}}",
                    EscapeJson(platform), EscapeJson(quoteHex), EscapeJson(nonce), EscapeJson(clientPublicKey), EscapeJson(policyId));
            return await SendRequestAsync("POST", "/api/enclave/tunnel/handshake", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Submits an encrypted license query inside the zero-plaintext confidential computing enclave tunnel.
        /// </summary>
        public async Task<string> EvaluateEnclaveLicenseAsync(string sessionId, long sequence, string nonceHex, string payloadHex)
        {
            string body = string.Format("{{\"session_id\":\"{0}\",\"sequence\":{1},\"nonce\":\"{2}\",\"payload\":\"{3}\"}}",
                EscapeJson(sessionId), sequence, EscapeJson(nonceHex), EscapeJson(payloadHex));
            return await SendRequestAsync("POST", "/api/enclave/tunnel/evaluate", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries confidential computing operational telemetry and registered policies.
        /// </summary>
        public async Task<string> GetEnclaveStatusAsync() =>
            await SendRequestAsync("GET", "/api/enclave/status", null).ConfigureAwait(false);

        /// <summary>
        /// Computes optimal nearest Edge Point of Presence (POP) based on client geo coordinates and latency weighting.
        /// </summary>
        public async Task<string> GetAnycastRouteAsync(double lat, double lon, string clientIp = "", string preferredRegion = "")
        {
            string url = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "/api/anycast/route?lat={0}&lon={1}&ip={2}&region={3}",
                lat, lon, Uri.EscapeDataString(clientIp ?? ""), Uri.EscapeDataString(preferredRegion ?? ""));
            return await SendRequestAsync("GET", url, null).ConfigureAwait(false);
        }

        /// <summary>
        /// Ingests dynamic active telemetry probes to refine global edge routing decisions.
        /// </summary>
        public async Task<string> ReportAnycastProbeAsync(string targetPopId, double rttMs, double jitterMs = 0, double packetLoss = 0, string sourceIp = "")
        {
            string body = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "{{\"target_pop_id\":\"{0}\",\"rtt_ms\":{1},\"jitter_ms\":{2},\"packet_loss\":{3},\"source_ip\":\"{4}\"}}",
                EscapeJson(targetPopId ?? ""), rttMs, jitterMs, packetLoss, EscapeJson(sourceIp ?? ""));
            return await SendRequestAsync("POST", "/api/anycast/probe", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries global POP point of presence health, latency metrics, and partition states.
        /// </summary>
        public async Task<string> GetAnycastStatusAsync() =>
            await SendRequestAsync("GET", "/api/anycast/status", null).ConfigureAwait(false);

        /// <summary>
        /// Retrieves telemetry metrics for sub-millisecond in-memory L1 cache hits, misses, and revalidations.
        /// </summary>
        public async Task<string> GetEdgeCacheStatsAsync() =>
            await SendRequestAsync("GET", "/api/anycast/cache/stats", null).ConfigureAwait(false);

        /// <summary>
        /// Validates license key with sub-millisecond edge cache lookups and network partition tolerance.
        /// </summary>
        public async Task<string> FastVerifyLicenseAsync(string licenseKey, string hwid = "", string preferredPop = "")
        {
            string machineHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string body = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\",\"preferred_pop\":\"{2}\"}}",
                EscapeJson(licenseKey ?? ""), EscapeJson(machineHwid ?? ""), EscapeJson(preferredPop ?? ""));
            return await SendRequestAsync("POST", "/api/anycast/verify", body).ConfigureAwait(false);
        }

        /// <summary>
        /// Retrieves diagnostic telemetry from the automated marketplace webhooks bridge.
        /// </summary>
        public async Task<string> GetMarketplaceStatusAsync() =>
            await SendRequestAsync("GET", "/api/marketplace/status", null).ConfigureAwait(false);

        public string GetMarketplaceStatus() =>
            GetMarketplaceStatusAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Sends a synthetic purchase or cancellation webhook to test automated provisioning and revocation.
        /// </summary>
        public async Task<string> SimulateMarketplaceWebhookAsync(string customerEmail, string provider = "stripe", string action = "provision", string tier = "pro", int seats = 1, int daysValid = 30)
        {
            string body = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "{{\"customer_email\":\"{0}\",\"provider\":\"{1}\",\"action\":\"{2}\",\"tier\":\"{3}\",\"seats\":{4},\"days_valid\":{5}}}",
                EscapeJson(customerEmail ?? ""), EscapeJson(provider ?? "stripe"), EscapeJson(action ?? "provision"),
                EscapeJson(tier ?? "pro"), seats, daysValid);
            return await SendRequestAsync("POST", "/api/marketplace/simulate", body).ConfigureAwait(false);
        }

        public string SimulateMarketplaceWebhook(string customerEmail, string provider = "stripe", string action = "provision", string tier = "pro", int seats = 1, int daysValid = 30) =>
            SimulateMarketplaceWebhookAsync(customerEmail, provider, action, tier, seats, daysValid).GetAwaiter().GetResult();

        /// <summary>
        /// Retrieves the transaction audit ledger of processed marketplace webhook events.
        /// </summary>
        public async Task<string> ListMarketplaceTransactionsAsync(string provider = null, string customerEmail = null, string status = null, int limit = 0)
        {
            var queryParams = new System.Collections.Generic.List<string>();
            if (!string.IsNullOrEmpty(provider)) queryParams.Add("provider=" + Uri.EscapeDataString(provider));
            if (!string.IsNullOrEmpty(customerEmail)) queryParams.Add("customer_email=" + Uri.EscapeDataString(customerEmail));
            if (!string.IsNullOrEmpty(status)) queryParams.Add("status=" + Uri.EscapeDataString(status));
            if (limit > 0) queryParams.Add("limit=" + limit);

            string path = "/api/marketplace/transactions";
            if (queryParams.Count > 0) path += "?" + string.Join("&", queryParams);
            return await SendRequestAsync("GET", path, null).ConfigureAwait(false);
        }

        public string ListMarketplaceTransactions(string provider = null, string customerEmail = null, string status = null, int limit = 0) =>
            ListMarketplaceTransactionsAsync(provider, customerEmail, status, limit).GetAwaiter().GetResult();

        /// <summary>
        /// Queries operational telemetry for the air-gapped license vault.
        /// </summary>
        public async Task<string> GetAirgapStatusAsync() =>
            await SendRequestAsync("GET", "/api/airgap/status", null).ConfigureAwait(false);

        public string GetAirgapStatus() =>
            GetAirgapStatusAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Issues a cryptographically signed offline dongle token.
        /// </summary>
        public async Task<string> IssueAirgapDongleTokenAsync(string licenseKey, string hwid = null, string tier = "enterprise", int daysValid = 30, int maxDevices = 1)
        {
            string machineHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string body = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "{{\"license_key\":\"{0}\",\"hwid\":\"{1}\",\"tier\":\"{2}\",\"days_valid\":{3},\"max_devices\":{4}}}",
                EscapeJson(licenseKey ?? ""), EscapeJson(machineHwid ?? ""), EscapeJson(tier ?? "enterprise"), daysValid, maxDevices);
            return await SendRequestAsync("POST", "/api/airgap/token/issue", body).ConfigureAwait(false);
        }

        public string IssueAirgapDongleToken(string licenseKey, string hwid = null, string tier = "enterprise", int daysValid = 30, int maxDevices = 1) =>
            IssueAirgapDongleTokenAsync(licenseKey, hwid, tier, daysValid, maxDevices).GetAwaiter().GetResult();

        /// <summary>
        /// Verifies an offline dongle token against master keys and monotonic clocks.
        /// </summary>
        public async Task<string> VerifyAirgapDongleTokenAsync(string token, string hwid = null, long timestamp = 0)
        {
            string machineHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            if (timestamp <= 0) timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string body = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "{{\"token\":\"{0}\",\"hwid\":\"{1}\",\"timestamp\":{2}}}",
                EscapeJson(token ?? ""), EscapeJson(machineHwid ?? ""), timestamp);
            return await SendRequestAsync("POST", "/api/airgap/token/verify", body).ConfigureAwait(false);
        }

        public string VerifyAirgapDongleToken(string token, string hwid = null, long timestamp = 0) =>
            VerifyAirgapDongleTokenAsync(token, hwid, timestamp).GetAwaiter().GetResult();

        /// <summary>
        /// Requests an offline machine activation challenge with QR payload.
        /// </summary>
        public async Task<string> RequestAirgapActivationAsync(string licenseKey, string hwid = null)
        {
            string machineHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string body = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\"}}",
                EscapeJson(licenseKey ?? ""), EscapeJson(machineHwid ?? ""));
            return await SendRequestAsync("POST", "/api/airgap/activate/request", body).ConfigureAwait(false);
        }

        public string RequestAirgapActivation(string licenseKey, string hwid = null) =>
            RequestAirgapActivationAsync(licenseKey, hwid).GetAwaiter().GetResult();

        /// <summary>
        /// Fulfills an offline activation from a scanned QR payload.
        /// </summary>
        public async Task<string> FulfillAirgapActivationAsync(string qrPayload)
        {
            string body = string.Format("{{\"qr_payload\":\"{0}\"}}", EscapeJson(qrPayload ?? ""));
            return await SendRequestAsync("POST", "/api/airgap/activate/fulfill", body).ConfigureAwait(false);
        }

        public string FulfillAirgapActivation(string qrPayload) =>
            FulfillAirgapActivationAsync(qrPayload).GetAwaiter().GetResult();

        /// <summary>
        /// Queries monotonic high-water mark and rollback tamper state.
        /// </summary>
        public async Task<string> GetAirgapRollbackStateAsync(string hwid = null)
        {
            string machineHwid = string.IsNullOrEmpty(hwid) ? GetMachineHwid() : hwid;
            string path = "/api/airgap/rollback/state?hwid=" + Uri.EscapeDataString(machineHwid);
            return await SendRequestAsync("GET", path, null).ConfigureAwait(false);
        }

        public string GetAirgapRollbackState(string hwid = null) =>
            GetAirgapRollbackStateAsync(hwid).GetAwaiter().GetResult();

        /// <summary>
        /// Unlocks a tripped airgap vault using an administrative recovery token.
        /// </summary>
        public async Task<string> UnlockAirgapRollbackAsync(string vaultId, string hwid, string nonce, long timestamp, string adminSignature)
        {
            string body = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "{{\"vault_id\":\"{0}\",\"hwid\":\"{1}\",\"nonce\":\"{2}\",\"timestamp\":{3},\"admin_signature\":\"{4}\"}}",
                EscapeJson(vaultId ?? ""), EscapeJson(hwid ?? ""), EscapeJson(nonce ?? ""), timestamp, EscapeJson(adminSignature ?? ""));
            return await SendRequestAsync("POST", "/api/airgap/rollback/unlock", body).ConfigureAwait(false);
        }

        public string UnlockAirgapRollback(string vaultId, string hwid, string nonce, long timestamp, string adminSignature) =>
            UnlockAirgapRollbackAsync(vaultId, hwid, nonce, timestamp, adminSignature).GetAwaiter().GetResult();

        /// <summary>
        /// Retrieves operational status for the Zero-Trust mesh and internal Certificate Authority.
        /// </summary>
        public async Task<string> GetZeroTrustStatusAsync() =>
            await SendRequestAsync("GET", "/api/zerotrust/status", null).ConfigureAwait(false);

        public string GetZeroTrustStatus() =>
            GetZeroTrustStatusAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Lists all enrolled Zero-Trust mesh peer nodes.
        /// </summary>
        public async Task<string> ListZeroTrustPeersAsync() =>
            await SendRequestAsync("GET", "/api/zerotrust/peers", null).ConfigureAwait(false);

        public string ListZeroTrustPeers() =>
            ListZeroTrustPeersAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Enrolls a new peer node and issues an mTLS certificate signed by the internal CA.
        /// </summary>
        public async Task<string> EnrollZeroTrustPeerAsync(string nodeId, string role = "cluster_peer", int validityDays = 90)
        {
            string body = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "{{\"node_id\":\"{0}\",\"role\":\"{1}\",\"validity_days\":{2}}}",
                EscapeJson(nodeId ?? ""), EscapeJson(role ?? "cluster_peer"), validityDays);
            return await SendRequestAsync("POST", "/api/zerotrust/peers/enroll", body).ConfigureAwait(false);
        }

        public string EnrollZeroTrustPeer(string nodeId, string role = "cluster_peer", int validityDays = 90) =>
            EnrollZeroTrustPeerAsync(nodeId, role, validityDays).GetAwaiter().GetResult();

        /// <summary>
        /// Revokes a peer node certificate and marks its status as REVOKED in the internal CRL.
        /// </summary>
        public async Task<string> RevokeZeroTrustPeerAsync(string nodeId, string reason = "Administrative revocation")
        {
            string body = string.Format("{{\"node_id\":\"{0}\",\"reason\":\"{1}\"}}",
                EscapeJson(nodeId ?? ""), EscapeJson(reason ?? ""));
            return await SendRequestAsync("POST", "/api/zerotrust/peers/revoke", body).ConfigureAwait(false);
        }

        public string RevokeZeroTrustPeer(string nodeId, string reason = "Administrative revocation") =>
            RevokeZeroTrustPeerAsync(nodeId, reason).GetAwaiter().GetResult();

        /// <summary>
        /// Rotates the internal Root CA while maintaining dual-trust continuity.
        /// </summary>
        public async Task<string> RotateZeroTrustCAAsync(int validityDays = 365)
        {
            string body = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "{{\"validity_days\":{0}}}", validityDays);
            return await SendRequestAsync("POST", "/api/zerotrust/ca/rotate", body).ConfigureAwait(false);
        }

        public string RotateZeroTrustCA(int validityDays = 365) =>
            RotateZeroTrustCAAsync(validityDays).GetAwaiter().GetResult();

        /// <summary>
        /// Queries hardware-backed key slot capabilities and operation counters.
        /// </summary>
        public async Task<string> GetZeroTrustHSMStatusAsync() =>
            await SendRequestAsync("GET", "/api/zerotrust/hsm/status", null).ConfigureAwait(false);

        public string GetZeroTrustHSMStatus() =>
            GetZeroTrustHSMStatusAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Cryptographically verifies whether a given peer identity is actively authorized.
        /// </summary>
        public async Task<string> VerifyZeroTrustPeerAsync(string nodeId, string serialNumber)
        {
            string body = string.Format("{{\"node_id\":\"{0}\",\"serial_number\":\"{1}\"}}",
                EscapeJson(nodeId ?? ""), EscapeJson(serialNumber ?? ""));
            return await SendRequestAsync("POST", "/api/zerotrust/verify", body).ConfigureAwait(false);
        }

        public string VerifyZeroTrustPeer(string nodeId, string serialNumber) =>
            VerifyZeroTrustPeerAsync(nodeId, serialNumber).GetAwaiter().GetResult();

        /// <summary>
        /// Retrieves operational status for the autonomous healing and quota rebalancing subsystem.
        /// </summary>
        public async Task<string> GetHealingStatusAsync() =>
            await SendRequestAsync("GET", "/api/healing/status", null).ConfigureAwait(false);

        public string GetHealingStatus() =>
            GetHealingStatusAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Consumes capacity from the real-time auto-scaling token bucket rate limiter.
        /// </summary>
        public async Task<string> ConsumeHealingBucketAsync(double tokens = 1.0)
        {
            string body = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "{{\"tokens\":{0}}}", tokens);
            return await SendRequestAsync("POST", "/api/healing/bucket/consume", body).ConfigureAwait(false);
        }

        public string ConsumeHealingBucket(double tokens = 1.0) =>
            ConsumeHealingBucketAsync(tokens).GetAwaiter().GetResult();

        /// <summary>
        /// Issues a cryptographically signed healing ticket allowing a client to resume an interrupted session.
        /// </summary>
        public async Task<string> IssueHealingTicketAsync(string clientId, string hwid, string tenantId = "default", string sessionId = "", long lastAckSeq = 0, long ttlSeconds = 180)
        {
            string body = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "{{\"session_id\":\"{0}\",\"client_id\":\"{1}\",\"hwid\":\"{2}\",\"tenant_id\":\"{3}\",\"last_ack_seq\":{4},\"ttl_seconds\":{5}}}",
                EscapeJson(sessionId ?? ""), EscapeJson(clientId ?? ""), EscapeJson(hwid ?? ""), EscapeJson(tenantId ?? "default"), lastAckSeq, ttlSeconds);
            return await SendRequestAsync("POST", "/api/healing/tunnel/ticket", body).ConfigureAwait(false);
        }

        public string IssueHealingTicket(string clientId, string hwid, string tenantId = "default", string sessionId = "", long lastAckSeq = 0, long ttlSeconds = 180) =>
            IssueHealingTicketAsync(clientId, hwid, tenantId, sessionId, lastAckSeq, ttlSeconds).GetAwaiter().GetResult();

        /// <summary>
        /// Resumes an interrupted client connection tunnel with a signed healing ticket.
        /// </summary>
        public async Task<string> ResumeHealingTunnelAsync(string ticketJson) =>
            await SendRequestAsync("POST", "/api/healing/tunnel/resume", ticketJson).ConfigureAwait(false);

        public string ResumeHealingTunnel(string ticketJson) =>
            ResumeHealingTunnelAsync(ticketJson).GetAwaiter().GetResult();

        /// <summary>
        /// Requests a dynamic quota borrowing lease between tenant pools.
        /// </summary>
        public async Task<string> BorrowHealingQuotaAsync(string borrowerTenant, string lenderTenant, long amount, long durationMinutes = 15)
        {
            string body = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "{{\"borrower_tenant\":\"{0}\",\"lender_tenant\":\"{1}\",\"amount\":{2},\"duration_minutes\":{3}}}",
                EscapeJson(borrowerTenant ?? ""), EscapeJson(lenderTenant ?? ""), amount, durationMinutes);
            return await SendRequestAsync("POST", "/api/healing/quota/borrow", body).ConfigureAwait(false);
        }

        public string BorrowHealingQuota(string borrowerTenant, string lenderTenant, long amount, long durationMinutes = 15) =>
            BorrowHealingQuotaAsync(borrowerTenant, lenderTenant, amount, durationMinutes).GetAwaiter().GetResult();

        /// <summary>
        /// Voluntarily returns a borrowed quota allocation.
        /// </summary>
        public async Task<string> ReturnHealingQuotaAsync(string leaseId)
        {
            string body = string.Format("{{\"lease_id\":\"{0}\"}}", EscapeJson(leaseId ?? ""));
            return await SendRequestAsync("POST", "/api/healing/quota/return", body).ConfigureAwait(false);
        }

        public string ReturnHealingQuota(string leaseId) =>
            ReturnHealingQuotaAsync(leaseId).GetAwaiter().GetResult();

        /// <summary>
        /// Triggers an automated distributed quota rebalancing evaluation.
        /// </summary>
        public async Task<string> RebalanceHealingQuotasAsync() =>
            await SendRequestAsync("POST", "/api/healing/quota/rebalance", "{}").ConfigureAwait(false);

        public string RebalanceHealingQuotas() =>
            RebalanceHealingQuotasAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Queries real-time telemetry, FIPS 140-3 certification level, and operational status of the HSM vault.
        /// </summary>
        public async Task<string> GetHSMStatusAsync() =>
            await SendRequestAsync("GET", "/api/hsm/status", null).ConfigureAwait(false);

        public string GetHSMStatus() =>
            GetHSMStatusAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Lists all provisioned PKCS#11 hardware slots and token descriptors.
        /// </summary>
        public async Task<string> ListHSMSlotsAsync() =>
            await SendRequestAsync("GET", "/api/hsm/slots", null).ConfigureAwait(false);

        public string ListHSMSlots() =>
            ListHSMSlotsAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Authenticates an ephemeral session against a hardware slot token using constant-time PIN evaluation.
        /// </summary>
        public async Task<string> HSMLoginAsync(int slotId, string pin, string userType = "USER")
        {
            string body = string.Format("{{\"slot_id\":{0},\"pin\":\"{1}\",\"user_type\":\"{2}\"}}",
                slotId, EscapeJson(pin ?? ""), EscapeJson(userType ?? "USER"));
            return await SendRequestAsync("POST", "/api/hsm/login", body).ConfigureAwait(false);
        }

        public string HSMLogin(int slotId, string pin, string userType = "USER") =>
            HSMLoginAsync(slotId, pin, userType).GetAwaiter().GetResult();

        /// <summary>
        /// Revokes an active authenticated session on the specified slot.
        /// </summary>
        public async Task<string> HSMLogoutAsync(int slotId = 0)
        {
            string body = string.Format("{{\"slot_id\":{0}}}", slotId);
            return await SendRequestAsync("POST", "/api/hsm/logout", body).ConfigureAwait(false);
        }

        public string HSMLogout(int slotId = 0) =>
            HSMLogoutAsync(slotId).GetAwaiter().GetResult();

        /// <summary>
        /// Derives a dedicated envelope key inside the hardware cryptoki boundary using HKDF-SHA256.
        /// </summary>
        public async Task<string> DeriveHSMKeyAsync(int slotId, string purpose, string context, string saltHex = "", int keyLengthBits = 256)
        {
            string body = string.Format("{{\"slot_id\":{0},\"purpose\":\"{1}\",\"context\":\"{2}\",\"salt_hex\":\"{3}\",\"key_length_bits\":{4}}}",
                slotId, EscapeJson(purpose ?? ""), EscapeJson(context ?? ""), EscapeJson(saltHex ?? ""), keyLengthBits);
            return await SendRequestAsync("POST", "/api/hsm/derive", body).ConfigureAwait(false);
        }

        public string DeriveHSMKey(int slotId, string purpose, string context, string saltHex = "", int keyLengthBits = 256) =>
            DeriveHSMKeyAsync(slotId, purpose, context, saltHex, keyLengthBits).GetAwaiter().GetResult();

        /// <summary>
        /// Performs authenticated AES-256-GCM envelope encryption under an HSM-derived key.
        /// </summary>
        public async Task<string> EncryptHSMEnvelopeAsync(int slotId, string plaintext, string associatedData = "", string purpose = "audit_token_encryption")
        {
            string body = string.Format("{{\"slot_id\":{0},\"plaintext\":\"{1}\",\"associated_data\":\"{2}\",\"purpose\":\"{3}\"}}",
                slotId, EscapeJson(plaintext ?? ""), EscapeJson(associatedData ?? ""), EscapeJson(purpose ?? ""));
            return await SendRequestAsync("POST", "/api/hsm/encrypt", body).ConfigureAwait(false);
        }

        public string EncryptHSMEnvelope(int slotId, string plaintext, string associatedData = "", string purpose = "audit_token_encryption") =>
            EncryptHSMEnvelopeAsync(slotId, plaintext, associatedData, purpose).GetAwaiter().GetResult();

        /// <summary>
        /// Performs authenticated AES-256-GCM envelope decryption and verification under an HSM-derived key.
        /// </summary>
        public async Task<string> DecryptHSMEnvelopeAsync(int slotId, string ciphertextHex, string nonceHex, string associatedData = "", string purpose = "audit_token_encryption")
        {
            string body = string.Format("{{\"slot_id\":{0},\"ciphertext_hex\":\"{1}\",\"nonce_hex\":\"{2}\",\"associated_data\":\"{3}\",\"purpose\":\"{4}\"}}",
                slotId, EscapeJson(ciphertextHex ?? ""), EscapeJson(nonceHex ?? ""), EscapeJson(associatedData ?? ""), EscapeJson(purpose ?? ""));
            return await SendRequestAsync("POST", "/api/hsm/decrypt", body).ConfigureAwait(false);
        }

        public string DecryptHSMEnvelope(int slotId, string ciphertextHex, string nonceHex, string associatedData = "", string purpose = "audit_token_encryption") =>
            DecryptHSMEnvelopeAsync(slotId, ciphertextHex, nonceHex, associatedData, purpose).GetAwaiter().GetResult();

        /// <summary>
        /// Triggers on-demand FIPS 140-3 Known Answer Tests (KAT) for all approved cryptographic primitives.
        /// </summary>
        public async Task<string> RunHSMSelfTestAsync() =>
            await SendRequestAsync("POST", "/api/hsm/fips/selftest", "{}").ConfigureAwait(false);

        public string RunHSMSelfTest() =>
            RunHSMSelfTestAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Retrieves the formal FIPS 140-3 Level 4 compliance audit report and certification evidence.
        /// </summary>
        public async Task<string> GetHSMFIPSReportAsync() =>
            await SendRequestAsync("GET", "/api/hsm/fips/report", null).ConfigureAwait(false);

        public string GetHSMFIPSReport() =>
            GetHSMFIPSReportAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Simulates an environmental or physical tamper sensor trip, latching hardware zeroization.
        /// </summary>
        public async Task<string> SimulateHSMTamperAsync(string sensorId = "DEFAULT_BREACH")
        {
            string body = string.Format("{{\"sensor_id\":\"{0}\"}}", EscapeJson(sensorId ?? ""));
            return await SendRequestAsync("POST", "/api/hsm/tamper/simulate", body).ConfigureAwait(false);
        }

        public string SimulateHSMTamper(string sensorId = "DEFAULT_BREACH") =>
            SimulateHSMTamperAsync(sensorId).GetAwaiter().GetResult();

        /// <summary>
        /// Performs immediate administrative zeroization across all hardware slots and key registers.
        /// </summary>
        public async Task<string> ZeroizeHSMAsync() =>
            await SendRequestAsync("POST", "/api/hsm/zeroize", "{}").ConfigureAwait(false);

        public string ZeroizeHSM() =>
            ZeroizeHSMAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Queries real-time operational status and telemetry for the ML-KEM lattice subsystem.
        /// </summary>
        public async Task<string> GetMLKEMStatusAsync() =>
            await SendRequestAsync("GET", "/api/pqc/kem/status", null).ConfigureAwait(false);

        public string GetMLKEMStatus() =>
            GetMLKEMStatusAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Lists all registered public encapsulation keys.
        /// </summary>
        public async Task<string> ListMLKEMKeysAsync() =>
            await SendRequestAsync("GET", "/api/pqc/kem/keys", null).ConfigureAwait(false);

        public string ListMLKEMKeys() =>
            ListMLKEMKeysAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Generates and registers a new lattice keypair (ML-KEM-768 or ML-KEM-1024).
        /// </summary>
        public async Task<string> GenerateMLKEMKeyAsync(string algorithm = "ML-KEM-768")
        {
            string body = string.Format("{{\"algorithm\":\"{0}\"}}", EscapeJson(algorithm ?? "ML-KEM-768"));
            return await SendRequestAsync("POST", "/api/pqc/kem/keys/generate", body).ConfigureAwait(false);
        }

        public string GenerateMLKEMKey(string algorithm = "ML-KEM-768") =>
            GenerateMLKEMKeyAsync(algorithm).GetAwaiter().GetResult();

        /// <summary>
        /// Encapsulates a shared secret against the specified (or default) public key.
        /// </summary>
        public async Task<string> EncapsulateMLKEMAsync(string keyId = "")
        {
            string body = string.Format("{{\"key_id\":\"{0}\"}}", EscapeJson(keyId ?? ""));
            return await SendRequestAsync("POST", "/api/pqc/kem/encapsulate", body).ConfigureAwait(false);
        }

        public string EncapsulateMLKEM(string keyId = "") =>
            EncapsulateMLKEMAsync(keyId).GetAwaiter().GetResult();

        /// <summary>
        /// Decapsulates a ciphertext using the server-side private key.
        /// </summary>
        public async Task<string> DecapsulateMLKEMAsync(string keyId, string ciphertextHex)
        {
            string body = string.Format("{{\"key_id\":\"{0}\",\"ciphertext_hex\":\"{1}\"}}",
                EscapeJson(keyId ?? ""), EscapeJson(ciphertextHex ?? ""));
            return await SendRequestAsync("POST", "/api/pqc/kem/decapsulate", body).ConfigureAwait(false);
        }

        public string DecapsulateMLKEM(string keyId, string ciphertextHex) =>
            DecapsulateMLKEMAsync(keyId, ciphertextHex).GetAwaiter().GetResult();

        /// <summary>
        /// Executes a post-quantum hybrid key exchange handshake (ECDH P-256 + ML-KEM).
        /// </summary>
        public async Task<string> HybridKEMHandshakeAsync(string clientEcdhPubHex, string clientMlkemKeyId = "", string requestedMode = "hybrid", string algorithm = "ML-KEM-768", string clientNonce = "")
        {
            string body = string.Format("{{\"client_ecdh_pub_hex\":\"{0}\",\"client_mlkem_key_id\":\"{1}\",\"requested_mode\":\"{2}\",\"algorithm\":\"{3}\",\"client_nonce\":\"{4}\"}}",
                EscapeJson(clientEcdhPubHex ?? ""), EscapeJson(clientMlkemKeyId ?? ""), EscapeJson(requestedMode ?? "hybrid"), EscapeJson(algorithm ?? "ML-KEM-768"), EscapeJson(clientNonce ?? ""));
            return await SendRequestAsync("POST", "/api/pqc/kem/handshake", body).ConfigureAwait(false);
        }

        public string HybridKEMHandshake(string clientEcdhPubHex, string clientMlkemKeyId = "", string requestedMode = "hybrid", string algorithm = "ML-KEM-768", string clientNonce = "") =>
            HybridKEMHandshakeAsync(clientEcdhPubHex, clientMlkemKeyId, requestedMode, algorithm, clientNonce).GetAwaiter().GetResult();

        /// <summary>
        /// Verifies an active ephemeral hybrid session.
        /// </summary>
        public async Task<string> VerifyHybridKEMSessionAsync(string sessionId)
        {
            string url = "/api/pqc/kem/sessions/verify?session_id=" + Uri.EscapeDataString(sessionId ?? "");
            return await SendRequestAsync("GET", url, null).ConfigureAwait(false);
        }

        public string VerifyHybridKEMSession(string sessionId) =>
            VerifyHybridKEMSessionAsync(sessionId).GetAwaiter().GetResult();

        private static string EscapeJson(string str)
        {
            if (string.IsNullOrEmpty(str)) return "";
            return str.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "");
        }

        private static string ExtractJsonField(string json, string fieldName)
        {
            if (string.IsNullOrEmpty(json)) return null;
            string pattern = "\"" + fieldName + "\":\"";
            int idx = json.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx == -1) return null;
            int start = idx + pattern.Length;
            int end = json.IndexOf("\"", start, StringComparison.Ordinal);
            if (end == -1) return null;
            return json.Substring(start, end - start);
        }
    }
}
