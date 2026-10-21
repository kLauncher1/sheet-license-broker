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
                        else if (ctx.Request.Url.AbsolutePath == "/api/zkp/params")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"curve\":\"P-256\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/zkp/credential/issue")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"credential\":{\"id\":\"cred-cs-123\",\"tier\":2},\"blinding_factor\":\"1234abcd\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/zkp/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"valid\":true,\"details\":{\"valid\":true,\"claimed_tier\":2,\"tier_name\":\"pro\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/zkp/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"zkp\":{\"total_credentials_issued\":5,\"total_proofs_verified\":10}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/sso/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"total_idps\":2,\"active_directory_users\":25,\"allocated_license_seats\":25}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/sso/token/introspect")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"active\":true,\"authorized\":true,\"claims\":{\"user_id\":\"usr-cs-1\",\"email\":\"cs-user@corp.com\",\"role\":\"operator\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath.StartsWith("/scim/v2/Users"))
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:ListResponse\"],\"totalResults\":1,\"Resources\":[{\"userName\":\"cs-user@corp.com\",\"active\":true}]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/params")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"lattice\":{\"dimension\":256,\"modulus\":8380417,\"d\":13},\"primary_algorithm\":\"ML-DSA-65\",\"active_key_id\":\"pqc-key-cs-1\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/keys")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"count\":1,\"keys\":[{\"key_id\":\"pqc-key-cs-1\",\"algorithm\":\"ML-DSA-65\",\"public_key_hex\":\"aabbcc\",\"status\":\"active\"}]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/sign")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"signature\":{\"algorithm\":\"Hybrid-P256-MLDSA65\",\"key_id\":\"pqc-key-cs-1\",\"classical_sig_b64\":\"sig_classic\",\"pqc_sig_hex\":\"sig_pqc\",\"payload_hash_hex\":\"payload_hash\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"result\":{\"valid\":true,\"algorithm\":\"Hybrid-P256-MLDSA65\",\"classical_valid\":true,\"pqc_valid\":true}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/rotate")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"active_key\":{\"key_id\":\"pqc-key-cs-2\",\"algorithm\":\"ML-DSA-65\",\"status\":\"active\"},\"grace_period_days\":7}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/revoke")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"revoked_key_id\":\"pqc-key-cs-1\",\"reason\":\"Administrative revocation\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"pqc\":{\"primary_algorithm\":\"ML-DSA-65\",\"active_keys\":1,\"total_signatures\":12,\"total_verifications\":10,\"rotation_count\":1}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/anomaly/record")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"recorded\",\"risk_score\":{\"entity_id\":\"LIC-CS-01\",\"score\":0,\"level\":\"low\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath.StartsWith("/api/anomaly/score"))
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"entity_id\":\"LIC-CS-01\",\"score\":20,\"level\":\"low\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/anomaly/challenge/issue")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"challenge_issued\",\"challenge_token\":\"cs-token-123\",\"risk_score\":{\"score\":50,\"challenge_escalation\":true}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/anomaly/challenge/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"challenge_cleared\",\"valid\":true,\"risk_score\":{\"score\":10,\"challenge_escalation\":false}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath.StartsWith("/api/anomaly/graph"))
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"format\":\"siem-topology-v1\",\"total_nodes\":5,\"total_edges\":4}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/anomaly/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"total_observations\":200,\"active_monitored_entities\":20,\"anomalies_detected\":4}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/enclave/challenge")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"challenge\":\"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff\",\"expires_in\":300}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/enclave/attest")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"valid\":true,\"attestation\":{\"valid\":true,\"platform\":\"intel_sgx\",\"mr_enclave\":\"aabbccddeeff\",\"mr_signer\":\"112233445566\",\"svn\":1,\"debug\":false}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/enclave/tunnel/handshake")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"established\":true,\"session_id\":\"enclave-sess-cs-01\",\"broker_public_key\":\"abcdef0123456789abcdef0123456789\",\"expires_at\":\"2030-01-01T00:00:00Z\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/enclave/tunnel/evaluate")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"session_id\":\"enclave-sess-cs-01\",\"sequence\":1,\"nonce\":\"0102030405060708090a0b0c\",\"payload\":\"cafebabedeadbeef\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/enclave/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"telemetry\":{\"verified_quotes\":5,\"active_tunnels\":2,\"total_evaluations\":12,\"failed_attestations\":0},\"policies\":[]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath.StartsWith("/api/anycast/route"))
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"selected_pop\":{\"id\":\"iad\",\"name\":\"Ashburn IAD\",\"region\":\"us-east\",\"status\":\"healthy\"},\"estimated_latency_ms\":8.5,\"signed_routing_token\":\"cs-anycast-token-123\",\"timestamp\":\"2026-10-18T12:00:00Z\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/anycast/probe")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"recorded\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/anycast/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"pop_count\":6,\"edge_routing_enabled\":true,\"is_partitioned\":false}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/anycast/cache/stats")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"hits\":42,\"misses\":3,\"lookup_latency_us\":88.2,\"hit_ratio\":0.933}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/anycast/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"valid\":true,\"license_key\":\"LIC-CS-ANYCAST\",\"hwid_bound\":\"HWID-CS-01\",\"tier\":\"enterprise\",\"message\":\"Fast verify L1 cache hit\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/marketplace/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"enabled\":true,\"supported_providers\":[\"stripe\",\"lemonsqueezy\",\"paddle\"],\"total_provisioned\":7,\"stripe_configured\":true}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/marketplace/simulate")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"transaction\":{\"id\":\"tx_cs_1\",\"event_id\":\"sim_cs_1\",\"provider\":\"stripe\",\"action\":\"provision\",\"customer_email\":\"cs_buyer@test.com\",\"license_key\":\"KEY-CS-MKT-01\",\"tier\":\"enterprise\",\"seats\":2,\"status\":\"PROVISIONED\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/marketplace/transactions")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("[{\"id\":\"tx_cs_1\",\"event_id\":\"sim_cs_1\",\"provider\":\"stripe\",\"action\":\"provision\",\"customer_email\":\"cs_buyer@test.com\",\"license_key\":\"KEY-CS-MKT-01\",\"tier\":\"enterprise\",\"seats\":2,\"status\":\"PROVISIONED\"}]");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/airgap/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"vault_active\":true,\"master_public_key\":\"pub_key_cs_hex\",\"total_issued_tokens\":15,\"total_verified_tokens\":40,\"total_activations\":8,\"rollback_tripped_count\":0}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/airgap/token/issue")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"token\":{\"token_id\":\"DONGLE-CS-001\",\"license_key\":\"LIC-AIRGAP-CS-1\",\"tier\":\"enterprise\",\"counter\":3},\"dongle_token\":\"compact_cs_token_base64\",\"qr_payload\":\"AIRGAP:B45:1234:CSQRPAYLOAD\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/airgap/token/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"valid\":true,\"token\":{\"token_id\":\"DONGLE-CS-001\",\"license_key\":\"LIC-AIRGAP-CS-1\",\"tier\":\"enterprise\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/airgap/activate/request")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"activation\":{\"request_id\":\"ACT-CS-001\",\"license_key\":\"LIC-AIRGAP-CS-ACT\",\"qr_payload\":\"AIRGAP:B45:5678:ACTCSQR\",\"status\":\"ACTIVATED\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/airgap/activate/fulfill")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"token\":{\"token_id\":\"DONGLE-FULFILLED-CS\",\"license_key\":\"LIC-AIRGAP-CS-ACT\",\"tier\":\"enterprise-airgap\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/airgap/rollback/state")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"state\":{\"vault_id\":\"VAULT-CS-01\",\"hwid\":\"HWID-CS-01\",\"monotonic_counter\":110,\"tampered\":false}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/airgap/rollback/unlock")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"state\":{\"vault_id\":\"VAULT-CS-01\",\"hwid\":\"HWID-CS-01\",\"monotonic_counter\":111,\"tampered\":false}}");
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

                // 15. Test Zero-Knowledge Proofs (ZKP)
                string zkpParamsRaw = client.GetZKPParamsAsync().GetAwaiter().GetResult();
                if (!zkpParamsRaw.Contains("P-256"))
                {
                    Console.Error.WriteLine("FAIL: ZKP params failed: " + zkpParamsRaw);
                    return 1;
                }
                string zkpCredRaw = client.IssueAnonymousCredentialAsync("LIC-ZKP-CS", null, "pro", 30, "production").GetAwaiter().GetResult();
                if (!zkpCredRaw.Contains("cred-cs-123"))
                {
                    Console.Error.WriteLine("FAIL: ZKP credential issue failed: " + zkpCredRaw);
                    return 1;
                }
                string zkpVerifyRaw = client.VerifyZKPProofAsync("{\"ax\":\"1\"}", "pro", 100).GetAwaiter().GetResult();
                if (!zkpVerifyRaw.Contains("\"valid\":true"))
                {
                    Console.Error.WriteLine("FAIL: ZKP proof verify failed: " + zkpVerifyRaw);
                    return 1;
                }
                string zkpStatusRaw = client.GetZKPStatusAsync().GetAwaiter().GetResult();
                if (!zkpStatusRaw.Contains("total_proofs_verified"))
                {
                    Console.Error.WriteLine("FAIL: ZKP status failed: " + zkpStatusRaw);
                    return 1;
                }
                Console.WriteLine("PASS: ZKP params, credential issue, proof verify, and telemetry");

                // 16. Test SSO & SCIM directory
                string ssoStatusRaw = client.GetSSOStatusAsync().GetAwaiter().GetResult();
                if (!ssoStatusRaw.Contains("active_directory_users"))
                {
                    Console.Error.WriteLine("FAIL: SSO status query failed: " + ssoStatusRaw);
                    return 1;
                }
                string introRaw = client.IntrospectSessionTokenAsync("sso.test.token", "license:read").GetAwaiter().GetResult();
                if (!introRaw.Contains("\"active\":true") || !introRaw.Contains("cs-user@corp.com"))
                {
                    Console.Error.WriteLine("FAIL: Token introspection failed: " + introRaw);
                    return 1;
                }
                string scimRaw = client.ListSCIMUsersAsync(1, 10).GetAwaiter().GetResult();
                if (!scimRaw.Contains("cs-user@corp.com"))
                {
                    Console.Error.WriteLine("FAIL: SCIM list users failed: " + scimRaw);
                    return 1;
                }
                Console.WriteLine("PASS: SSO status, token introspection, and SCIM directory");

                // 17. Test Post-Quantum Cryptography (PQC) & ML-DSA signatures
                string pqcParamsRaw = client.GetPQCParamsAsync().GetAwaiter().GetResult();
                if (!pqcParamsRaw.Contains("ML-DSA-65") || !pqcParamsRaw.Contains("8380417"))
                {
                    Console.Error.WriteLine("FAIL: PQC params failed: " + pqcParamsRaw);
                    return 1;
                }
                string pqcKeysRaw = client.GetPQCPublicKeysAsync().GetAwaiter().GetResult();
                if (!pqcKeysRaw.Contains("pqc-key-cs-1"))
                {
                    Console.Error.WriteLine("FAIL: PQC public keys failed: " + pqcKeysRaw);
                    return 1;
                }
                string pqcSignRaw = client.SignPQCLicenseAsync("VALID-KEY-123", "payload-cs-data").GetAwaiter().GetResult();
                if (!pqcSignRaw.Contains("Hybrid-P256-MLDSA65") || !pqcSignRaw.Contains("pqc-key-cs-1"))
                {
                    Console.Error.WriteLine("FAIL: PQC sign failed: " + pqcSignRaw);
                    return 1;
                }
                string pqcVerifyRaw = client.VerifyPQCSignatureAsync("payload-cs-data", "{\"algorithm\":\"Hybrid-P256-MLDSA65\"}").GetAwaiter().GetResult();
                if (!pqcVerifyRaw.Contains("\"valid\":true") || !pqcVerifyRaw.Contains("\"pqc_valid\":true"))
                {
                    Console.Error.WriteLine("FAIL: PQC verify failed: " + pqcVerifyRaw);
                    return 1;
                }
                string pqcRotateRaw = client.RotatePQCKeyAsync("ML-DSA-65", 7, "Routine rotation").GetAwaiter().GetResult();
                if (!pqcRotateRaw.Contains("pqc-key-cs-2"))
                {
                    Console.Error.WriteLine("FAIL: PQC rotate failed: " + pqcRotateRaw);
                    return 1;
                }
                string pqcRevokeRaw = client.RevokePQCKeyAsync("pqc-key-cs-1", "Security deprecation").GetAwaiter().GetResult();
                if (!pqcRevokeRaw.Contains("pqc-key-cs-1"))
                {
                    Console.Error.WriteLine("FAIL: PQC revoke failed: " + pqcRevokeRaw);
                    return 1;
                }
                string pqcStatusRaw = client.GetPQCStatusAsync().GetAwaiter().GetResult();
                if (!pqcStatusRaw.Contains("ML-DSA-65") || !pqcStatusRaw.Contains("total_signatures"))
                {
                    Console.Error.WriteLine("FAIL: PQC status failed: " + pqcStatusRaw);
                    return 1;
                }
                Console.WriteLine("PASS: PQC params, keys, sign, verify, rotate, revoke, and status");

                // Test 18: Behavioral Anomaly Detection & Adaptive Risk Scoring
                string anomRecRaw = client.RecordAnomalyObservationAsync("LIC-CS-01", "198.51.100.1").GetAwaiter().GetResult();
                if (!anomRecRaw.Contains("recorded"))
                {
                    Console.Error.WriteLine("FAIL: Anomaly observation failed: " + anomRecRaw);
                    return 1;
                }
                string anomScoreRaw = client.GetAnomalyRiskScoreAsync("LIC-CS-01").GetAwaiter().GetResult();
                if (!anomScoreRaw.Contains("score") || !anomScoreRaw.Contains("LIC-CS-01"))
                {
                    Console.Error.WriteLine("FAIL: Anomaly score failed: " + anomScoreRaw);
                    return 1;
                }
                string anomChRaw = client.IssueAnomalyChallengeAsync("LIC-CS-01").GetAwaiter().GetResult();
                if (!anomChRaw.Contains("cs-token-123"))
                {
                    Console.Error.WriteLine("FAIL: Anomaly challenge issue failed: " + anomChRaw);
                    return 1;
                }
                string anomVerRaw = client.VerifyAnomalyChallengeAsync("cs-token-123").GetAwaiter().GetResult();
                if (!anomVerRaw.Contains("\"valid\":true"))
                {
                    Console.Error.WriteLine("FAIL: Anomaly challenge verify failed: " + anomVerRaw);
                    return 1;
                }
                string anomGraphRaw = client.ExportIncidentGraphAsync(0, 10).GetAwaiter().GetResult();
                if (!anomGraphRaw.Contains("siem-topology-v1"))
                {
                    Console.Error.WriteLine("FAIL: Anomaly graph failed: " + anomGraphRaw);
                    return 1;
                }
                string anomStatusRaw = client.GetAnomalyStatusAsync().GetAwaiter().GetResult();
                if (!anomStatusRaw.Contains("total_observations"))
                {
                    Console.Error.WriteLine("FAIL: Anomaly status failed: " + anomStatusRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Anomaly observation, risk score, challenge, graph, and status");

                // Test 19: Confidential Enclave Attestation & Zero-Plaintext Tunnels
                string encChRaw = client.RequestEnclaveChallengeAsync().GetAwaiter().GetResult();
                if (!encChRaw.Contains("11223344556677889900aabbccddeeff"))
                {
                    Console.Error.WriteLine("FAIL: Enclave challenge failed: " + encChRaw);
                    return 1;
                }
                string encAttestRaw = client.AttestEnclaveQuoteAsync("intel_sgx", "aabbccddeeff", "11223344556677889900aabbccddeeff").GetAwaiter().GetResult();
                if (!encAttestRaw.Contains("\"valid\":true") || !encAttestRaw.Contains("intel_sgx"))
                {
                    Console.Error.WriteLine("FAIL: Enclave attest failed: " + encAttestRaw);
                    return 1;
                }
                string encTunnelRaw = client.EstablishEnclaveTunnelAsync("intel_sgx", "aabbccddeeff", "11223344556677889900aabbccddeeff", "cs_pub_key_hex").GetAwaiter().GetResult();
                if (!encTunnelRaw.Contains("\"established\":true") || !encTunnelRaw.Contains("enclave-sess-cs-01"))
                {
                    Console.Error.WriteLine("FAIL: Enclave tunnel handshake failed: " + encTunnelRaw);
                    return 1;
                }
                string encEvalRaw = client.EvaluateEnclaveLicenseAsync("enclave-sess-cs-01", 1, "0102030405060708090a0b0c", "cafebabedeadbeef").GetAwaiter().GetResult();
                if (!encEvalRaw.Contains("enclave-sess-cs-01") || !encEvalRaw.Contains("cafebabedeadbeef"))
                {
                    Console.Error.WriteLine("FAIL: Enclave evaluate failed: " + encEvalRaw);
                    return 1;
                }
                string encStatusRaw = client.GetEnclaveStatusAsync().GetAwaiter().GetResult();
                if (!encStatusRaw.Contains("verified_quotes") || !encStatusRaw.Contains("active_tunnels"))
                {
                    Console.Error.WriteLine("FAIL: Enclave status failed: " + encStatusRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Enclave challenge, quote attestation, encrypted tunnel, evaluation, and status");

                // Test 20: Geo-Distributed Anycast Edge Routing and Sub-Millisecond L1 Cache
                string routeRaw = client.GetAnycastRouteAsync(38.9072, -77.0369, "198.51.100.1", "us-east").GetAwaiter().GetResult();
                if (!routeRaw.Contains("iad") || !routeRaw.Contains("cs-anycast-token-123"))
                {
                    Console.Error.WriteLine("FAIL: Anycast route failed: " + routeRaw);
                    return 1;
                }
                string probeRaw = client.ReportAnycastProbeAsync("iad", 8.5, 0.5, 0.0, "198.51.100.1").GetAwaiter().GetResult();
                if (!probeRaw.Contains("recorded"))
                {
                    Console.Error.WriteLine("FAIL: Anycast probe report failed: " + probeRaw);
                    return 1;
                }
                string anycastStatusRaw = client.GetAnycastStatusAsync().GetAwaiter().GetResult();
                if (!anycastStatusRaw.Contains("pop_count") || !anycastStatusRaw.Contains("edge_routing_enabled"))
                {
                    Console.Error.WriteLine("FAIL: Anycast status failed: " + anycastStatusRaw);
                    return 1;
                }
                string cacheStatsRaw = client.GetEdgeCacheStatsAsync().GetAwaiter().GetResult();
                if (!cacheStatsRaw.Contains("lookup_latency_us") || !cacheStatsRaw.Contains("hits"))
                {
                    Console.Error.WriteLine("FAIL: Edge cache stats failed: " + cacheStatsRaw);
                    return 1;
                }
                string fastVerifyRaw = client.FastVerifyLicenseAsync("LIC-CS-ANYCAST").GetAwaiter().GetResult();
                if (!fastVerifyRaw.Contains("\"valid\":true") || !fastVerifyRaw.Contains("LIC-CS-ANYCAST"))
                {
                    Console.Error.WriteLine("FAIL: Fast verify license failed: " + fastVerifyRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Anycast route, probe, status, edge cache stats, and fast verify");

                // 21. Marketplace status, simulate, and transactions
                string mktStatusRaw = client.GetMarketplaceStatusAsync().GetAwaiter().GetResult();
                if (!mktStatusRaw.Contains("\"enabled\":true") || !mktStatusRaw.Contains("total_provisioned"))
                {
                    Console.Error.WriteLine("FAIL: Marketplace status failed: " + mktStatusRaw);
                    return 1;
                }
                string simRaw = client.SimulateMarketplaceWebhookAsync("cs_buyer@test.com", "stripe", "provision", "enterprise", 2).GetAwaiter().GetResult();
                if (!simRaw.Contains("KEY-CS-MKT-01") || !simRaw.Contains("PROVISIONED"))
                {
                    Console.Error.WriteLine("FAIL: Marketplace simulate failed: " + simRaw);
                    return 1;
                }
                string txListRaw = client.ListMarketplaceTransactionsAsync().GetAwaiter().GetResult();
                if (!txListRaw.Contains("cs_buyer@test.com") || !txListRaw.Contains("KEY-CS-MKT-01"))
                {
                    Console.Error.WriteLine("FAIL: Marketplace transactions failed: " + txListRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Marketplace status, simulate webhook, and transactions");

                // 22. Airgap status, dongle issue/verify, activation request/fulfill, rollback state, and unlock
                string airgapStatusRaw = client.GetAirgapStatusAsync().GetAwaiter().GetResult();
                if (!airgapStatusRaw.Contains("\"vault_active\":true") || !airgapStatusRaw.Contains("pub_key_cs_hex"))
                {
                    Console.Error.WriteLine("FAIL: Airgap status failed: " + airgapStatusRaw);
                    return 1;
                }
                string dongleIssueRaw = client.IssueAirgapDongleTokenAsync("LIC-AIRGAP-CS-1").GetAwaiter().GetResult();
                if (!dongleIssueRaw.Contains("DONGLE-CS-001") || !dongleIssueRaw.Contains("compact_cs_token_base64"))
                {
                    Console.Error.WriteLine("FAIL: Dongle issue failed: " + dongleIssueRaw);
                    return 1;
                }
                string dongleVerifyRaw = client.VerifyAirgapDongleTokenAsync("compact_cs_token_base64").GetAwaiter().GetResult();
                if (!dongleVerifyRaw.Contains("\"valid\":true") || !dongleVerifyRaw.Contains("LIC-AIRGAP-CS-1"))
                {
                    Console.Error.WriteLine("FAIL: Dongle verify failed: " + dongleVerifyRaw);
                    return 1;
                }
                string actReqRaw = client.RequestAirgapActivationAsync("LIC-AIRGAP-CS-ACT").GetAwaiter().GetResult();
                if (!actReqRaw.Contains("ACT-CS-001") || !actReqRaw.Contains("ACTCSQR"))
                {
                    Console.Error.WriteLine("FAIL: Airgap activate request failed: " + actReqRaw);
                    return 1;
                }
                string actFulfillRaw = client.FulfillAirgapActivationAsync("AIRGAP:B45:5678:ACTCSQR").GetAwaiter().GetResult();
                if (!actFulfillRaw.Contains("DONGLE-FULFILLED-CS") || !actFulfillRaw.Contains("LIC-AIRGAP-CS-ACT"))
                {
                    Console.Error.WriteLine("FAIL: Airgap activate fulfill failed: " + actFulfillRaw);
                    return 1;
                }
                string rollbackStateRaw = client.GetAirgapRollbackStateAsync("HWID-CS-01").GetAwaiter().GetResult();
                if (!rollbackStateRaw.Contains("monotonic_counter") || !rollbackStateRaw.Contains("110"))
                {
                    Console.Error.WriteLine("FAIL: Airgap rollback state failed: " + rollbackStateRaw);
                    return 1;
                }
                string rollbackUnlockRaw = client.UnlockAirgapRollbackAsync("VAULT-CS-01", "HWID-CS-01", "nonce-1", 12345678, "admin_sig").GetAwaiter().GetResult();
                if (!rollbackUnlockRaw.Contains("111"))
                {
                    Console.Error.WriteLine("FAIL: Airgap rollback unlock failed: " + rollbackUnlockRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Airgap status, dongle issue/verify, activation request/fulfill, and rollback state/unlock");

                Console.WriteLine("=== All 22 C# Client Tests Passed Successfully! ===");
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
