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
            string targetHwid = string.IsNullOrEmpty(hwid) ? HWID : hwid;
            string payload = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\"}}",
                EscapeJson(licenseKey), EscapeJson(targetHwid));
            return await SendRequestAsync("POST", "/api/attestation/challenge", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Submits a signed TPM 2.0 PCR quote to attest hardware platform integrity.
        /// </summary>
        public async Task<string> VerifyTPMAttestationAsync(string licenseKey, string challengeId, string tpmQuoteJson, string hwid = null)
        {
            string targetHwid = string.IsNullOrEmpty(hwid) ? HWID : hwid;
            string payload = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\",\"challenge_id\":\"{2}\",\"attestation_type\":\"tpm2\",\"tpm_quote\":{3}}}",
                EscapeJson(licenseKey), EscapeJson(targetHwid), EscapeJson(challengeId), tpmQuoteJson);
            return await SendRequestAsync("POST", "/api/attestation/verify", payload).ConfigureAwait(false);
        }

        /// <summary>
        /// Transmits anti-debugging and memory integrity telemetry to the broker.
        /// </summary>
        public async Task<string> ReportTelemetryAsync(string licenseKey, bool debuggerPresent, bool memoryIntegrity, string hwid = null)
        {
            string targetHwid = string.IsNullOrEmpty(hwid) ? HWID : hwid;
            string payload = string.Format("{{\"license_key\":\"{0}\",\"hwid\":\"{1}\",\"report\":{{\"debugger_present\":{2},\"memory_integrity\":{3}}}}}",
                EscapeJson(licenseKey), EscapeJson(targetHwid),
                debuggerPresent ? "true" : "false",
                memoryIntegrity ? "true" : "false");
            return await SendRequestAsync("POST", "/api/attestation/telemetry", payload).ConfigureAwait(false);
        }

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
