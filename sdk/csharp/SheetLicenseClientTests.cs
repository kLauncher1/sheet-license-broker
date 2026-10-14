using System;
using System.Net;
using System.Text;
using System.Threading;
using SheetLicenseBroker;

namespace SheetLicenseBrokerTests
{
    class Program
    {
        static int Main(string[] args)
        {
            Console.WriteLine("=== Testing SheetLicenseClient (C#) ===");

            // 1. Test HWID Format
            string hwid = SheetLicenseClient.GetMachineHwid();
            Console.WriteLine("Generated Machine HWID: " + hwid);
            if (!hwid.StartsWith("HWID-"))
            {
                Console.Error.WriteLine("FAIL: HWID does not start with HWID- prefix");
                return 1;
            }
            string[] parts = hwid.Split('-');
            if (parts.Length != 5)
            {
                Console.Error.WriteLine("FAIL: HWID parts count mismatch, expected 5, got " + parts.Length);
                return 1;
            }
            Console.WriteLine("PASS: HWID format validation");

            // 2. Test Local HTTP Mock Server
            int port = 9188;
            string prefix = "http://127.0.0.1:" + port + "/";
            HttpListener listener = new HttpListener();
            listener.Prefixes.Add(prefix);
            listener.Start();

            Thread serverThread = new Thread(() =>
            {
                while (listener.IsListening)
                {
                    try
                    {
                        var ctx = listener.GetContext();
                        byte[] respBytes;
                        string reqBody = "";
                        if (ctx.Request.HasEntityBody)
                        {
                            using (var reader = new System.IO.StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding))
                            {
                                reqBody = reader.ReadToEnd();
                            }
                        }

                        if (ctx.Request.Url.AbsolutePath == "/api/licenses/validate")
                        {
                            // Check headers
                            string sig = ctx.Request.Headers["X-Signature"];
                            string ts = ctx.Request.Headers["X-Timestamp"];
                            string nonce = ctx.Request.Headers["X-Nonce"];

                            if (string.IsNullOrEmpty(sig) || string.IsNullOrEmpty(ts) || string.IsNullOrEmpty(nonce))
                            {
                                ctx.Response.StatusCode = 401;
                                respBytes = Encoding.UTF8.GetBytes("{\"error\":\"missing_headers\"}");
                            }
                            else if (reqBody.Contains("EXPIRED-KEY"))
                            {
                                ctx.Response.StatusCode = 401;
                                respBytes = Encoding.UTF8.GetBytes("{\"valid\":false,\"error\":\"License expired\"}");
                            }
                            else
                            {
                                ctx.Response.StatusCode = 200;
                                respBytes = Encoding.UTF8.GetBytes("{\"valid\":true,\"message\":\"License active and valid\",\"source\":\"memory\"}");
                            }
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/health")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"healthy\",\"version\":\"0.9.0\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/features/check")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"enabled\":true,\"tier\":\"pro\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/usage/record")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"exceeded\":false,\"record\":{\"count\":10}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/usage/stats")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"records\":[{\"metric\":\"api_calls\",\"count\":10}]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/attestation/challenge")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"challenge_id\":\"ch-cs-123\",\"nonce\":\"test-nonce-1234\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/attestation/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"record\":{\"trust_level\":\"attested_hardware\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/attestation/telemetry")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"tamper_score\":0,\"tampered\":false}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/security/audit/export")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"bundle\":{\"bundle_id\":\"bundle-cs-123\",\"record_count\":5}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/tenant/echo")
                        {
                            string tenant = ctx.Request.Headers["X-Tenant-ID"] ?? "";
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"tenant\":\"" + tenant + "\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/consensus/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"node_id\":\"node-cs-test\",\"role\":\"leader\",\"has_quorum\":true}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/stream/clients")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"count\":1,\"clients\":[{\"id\":\"cl-cs-1\",\"license_key\":\"LIC-STREAM-CS\"}]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/stream/kill")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"target\":\"LIC-STREAM-CS\",\"signaled_clients\":1}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/stream/telemetry")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"telemetry\":{\"active_connections\":1,\"total_heartbeats\":99}}");
                        }
                        else
                        {
                            ctx.Response.StatusCode = 404;
                            respBytes = Encoding.UTF8.GetBytes("{\"error\":\"not_found\"}");
                        }

                        ctx.Response.ContentType = "application/json";
                        ctx.Response.ContentLength64 = respBytes.Length;
                        ctx.Response.OutputStream.Write(respBytes, 0, respBytes.Length);
                        ctx.Response.Close();
                    }
                    catch
                    {
                        break;
                    }
                }
            });
            serverThread.IsBackground = true;
            serverThread.Start();

            try
            {
                var client = new SheetLicenseClient("http://127.0.0.1:" + port, "test-secret-key", "tenant-alpha");

                // 2. Test Verification with HMAC
                var result = client.VerifyLicense("SLB-TEST-12345");
                if (!result.Valid)
                {
                    Console.Error.WriteLine("FAIL: Expected valid license response, got invalid: " + result.Error);
                    return 1;
                }
                if (result.Message != "License active and valid")
                {
                    Console.Error.WriteLine("FAIL: Unexpected message: " + result.Message);
                    return 1;
                }
                Console.WriteLine("PASS: License validation with HMAC signature headers");

                // 3. Test Invalid License handling
                var invalidResult = client.VerifyLicense("EXPIRED-KEY");
                if (invalidResult.Valid)
                {
                    Console.Error.WriteLine("FAIL: Expected expired license to return Valid=false");
                    return 1;
                }
                if (!invalidResult.Error.Contains("expired"))
                {
                    Console.Error.WriteLine("FAIL: Expected expired error message, got: " + invalidResult.Error);
                    return 1;
                }
                Console.WriteLine("PASS: Expired license rejection and error parsing");

                // 4. Test Health endpoint
                string health = client.GetHealthAsync().GetAwaiter().GetResult();
                if (!health.Contains("healthy"))
                {
                    Console.Error.WriteLine("FAIL: Health response does not contain healthy: " + health);
                    return 1;
                }
                Console.WriteLine("PASS: Health check query");

                // 5. Test Feature check
                bool hasAnalytics = client.IsFeatureEnabled("SLB-TEST-12345", "analytics");
                if (!hasAnalytics)
                {
                    Console.Error.WriteLine("FAIL: Expected analytics feature to be enabled");
                    return 1;
                }
                Console.WriteLine("PASS: Feature entitlement check");

                // 6. Test Usage recording
                string usageRaw = client.RecordUsageAsync("SLB-TEST-12345", "api_calls", 10, 100).GetAwaiter().GetResult();
                if (!usageRaw.Contains("\"status\":\"success\""))
                {
                    Console.Error.WriteLine("FAIL: Usage recording failed: " + usageRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Usage consumption recording");

                // 7. Test Usage stats query
                string usageStats = client.GetUsageAsync("SLB-TEST-12345").GetAwaiter().GetResult();
                if (!usageStats.Contains("\"records\""))
                {
                    Console.Error.WriteLine("FAIL: Usage stats query failed: " + usageStats);
                    return 1;
                }
                Console.WriteLine("PASS: Usage statistics query");

                // 8. Test Attestation challenge
                string challengeRaw = client.RequestAttestationChallengeAsync("SLB-TEST-12345").GetAwaiter().GetResult();
                if (!challengeRaw.Contains("ch-cs-123"))
                {
                    Console.Error.WriteLine("FAIL: Attestation challenge failed: " + challengeRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Attestation challenge request");

                // 9. Test TPM attestation verification
                string verifyRaw = client.VerifyTPMAttestationAsync("SLB-TEST-12345", "ch-cs-123", "{\"pcr0\":\"abc\"}").GetAwaiter().GetResult();
                if (!verifyRaw.Contains("attested_hardware"))
                {
                    Console.Error.WriteLine("FAIL: TPM attestation verify failed: " + verifyRaw);
                    return 1;
                }
                Console.WriteLine("PASS: TPM attestation verification");

                // 10. Test Telemetry reporting
                string telemetryRaw = client.ReportTelemetryAsync("SLB-TEST-12345", false, true).GetAwaiter().GetResult();
                if (!telemetryRaw.Contains("\"status\":\"success\""))
                {
                    Console.Error.WriteLine("FAIL: Telemetry reporting failed: " + telemetryRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Telemetry reporting");

                // 11. Test Audit token export
                string auditRaw = client.ExportAuditTokenAsync("test-audit-key", 100).GetAwaiter().GetResult();
                if (!auditRaw.Contains("bundle-cs-123"))
                {
                    Console.Error.WriteLine("FAIL: Audit token export failed: " + auditRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Audit token export");

                // 12. Test Tenant ID property
                if (client.TenantId != "tenant-alpha")
                {
                    Console.Error.WriteLine("FAIL: Expected tenantId tenant-alpha, got: " + client.TenantId);
                    return 1;
                }
                Console.WriteLine("PASS: Multi-tenant configuration and headers");

                // 13. Test Cluster status query
                string clusterRaw = client.GetClusterStatusAsync().GetAwaiter().GetResult();
                if (!clusterRaw.Contains("node-cs-test") || !clusterRaw.Contains("leader"))
                {
                    Console.Error.WriteLine("FAIL: Cluster status query failed: " + clusterRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Cluster status query");

                // 14. Test Stream clients, kill switch, and telemetry
                string streamClientsRaw = client.GetStreamClientsAsync().GetAwaiter().GetResult();
                if (!streamClientsRaw.Contains("LIC-STREAM-CS"))
                {
                    Console.Error.WriteLine("FAIL: Stream clients query failed: " + streamClientsRaw);
                    return 1;
                }
                string killRaw = client.SendKillSwitchAsync("LIC-STREAM-CS", "Hardware violation", true).GetAwaiter().GetResult();
                if (!killRaw.Contains("success"))
                {
                    Console.Error.WriteLine("FAIL: Stream kill switch failed: " + killRaw);
                    return 1;
                }
                string telemRaw = client.GetStreamTelemetryAsync().GetAwaiter().GetResult();
                if (!telemRaw.Contains("active_connections"))
                {
                    Console.Error.WriteLine("FAIL: Stream telemetry failed: " + telemRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Stream clients, kill switch, and telemetry");

                Console.WriteLine("=== All 14 C# Client Tests Passed Successfully! ===");
                return 0;
            }
            finally
            {
                listener.Stop();
                listener.Close();
            }
        }
    }
}
