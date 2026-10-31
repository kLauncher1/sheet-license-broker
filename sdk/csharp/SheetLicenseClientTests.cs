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
                        else if (ctx.Request.Url.AbsolutePath == "/api/enclave/tdx/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"valid\":true,\"attestation\":{\"valid\":true,\"platform\":\"intel_tdx\",\"measurement\":\"mrtd_cs_hex\",\"rtmr0\":\"rtmr0_cs_hex\",\"svn\":2,\"debug\":false}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/enclave/token/issue")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"token\":{\"token_id\":\"tok_cs_123\",\"platform\":\"intel_tdx\",\"measurement\":\"mrtd_cs_hex\",\"svn\":2,\"signature\":\"sig_cs_123\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/enclave/token/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"valid\":true,\"result\":{\"valid\":true,\"platform\":\"intel_tdx\",\"svn\":2,\"measurement\":\"mrtd_cs_hex\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/enclave/isolated/decrypt")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"result\":{\"success\":true,\"license_key_masked\":\"SLB-****-****-CS01\",\"tier\":\"enterprise\",\"hardware_isolated\":true,\"memory_zeroized\":true,\"evaluation_digest\":\"sha256_cs_digest\"}}");
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
                        else if (ctx.Request.Url.AbsolutePath == "/api/zerotrust/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"ca_initialized\":true,\"ca_root_fingerprint\":\"zt_ca_cs_hex\",\"mtls_enforced\":true,\"active_peers_count\":2,\"hsm_enabled\":true,\"hsm_slots_count\":3}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/zerotrust/peers")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"peers\":[{\"node_id\":\"node-cs-01\",\"role\":\"cluster_peer\",\"serial_number\":\"cs_serial_01\",\"status\":\"ACTIVE\"}]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/zerotrust/peers/enroll")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"enrollment\":{\"node_id\":\"node-cs-01\",\"role\":\"cluster_peer\",\"serial_number\":\"cs_serial_01\",\"fingerprint_sha256\":\"cs_fp_01\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/zerotrust/peers/revoke")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"node_id\":\"node-cs-01\",\"revoked\":true,\"reason\":\"C# decomm\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/zerotrust/ca/rotate")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"message\":\"Rotated\",\"root_fingerprint\":\"rotated_cs_fp_hex\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/zerotrust/hsm/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"hsm_enabled\":true,\"slots_count\":3,\"slots\":[{\"slot_id\":0,\"label\":\"Root CA Master Key Slot\",\"operations_count\":10}]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/zerotrust/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"valid\":true,\"reason\":\"valid\",\"node_id\":\"node-cs-01\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/healing/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"bucket\":{\"capacity\":100.0,\"mode\":\"normal\"},\"active_tunnels\":2,\"active_leases\":[]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/healing/bucket/consume")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"allowed\":true,\"stats\":{\"current_tokens\":98.0,\"capacity\":100.0}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/healing/tunnel/ticket")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"session_id\":\"sess-cs-heal\",\"client_id\":\"client-cs-01\",\"signature\":\"cs_sig_heal\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/healing/tunnel/resume")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"resumed\",\"session\":{\"state\":\"resumed\"},\"missed_events\":[],\"missed_count\":0}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/healing/quota/borrow")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"lease\":{\"lease_id\":\"lease-cs-01\",\"amount\":400}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/healing/quota/return")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"returned\",\"lease_id\":\"lease-cs-01\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/healing/quota/rebalance")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"rebalanced\",\"events\":[]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/hsm/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"initialized\":true,\"hardware_available\":true,\"fips_level\":\"FIPS_140_3_LEVEL_4\",\"slots_total\":3,\"active_sessions\":1,\"tamper_detected\":false,\"locked_out\":false,\"master_key_present\":true,\"operations_count\":60,\"uptime_seconds\":800}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/hsm/slots")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"slots\":[{\"slot_id\":0,\"description\":\"Hardware Cryptoki Slot 0\",\"token_present\":true,\"hardware_slot\":true}]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/hsm/login")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"authenticated\":true,\"slot_id\":0,\"user_type\":\"USER\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/hsm/logout")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"logged_out\":true,\"slot_id\":0}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/hsm/derive")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"slot_id\":0,\"purpose\":\"audit_token_encryption\",\"fingerprint\":\"HSM-KEY-CS-FPR-01\",\"key_length_bits\":256,\"algorithm\":\"AES_256_GCM_HKDF_SHA256\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/hsm/encrypt")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"slot_id\":1,\"ciphertext_hex\":\"cs_cipher_hex_123\",\"nonce_hex\":\"cs_nonce_hex_123\",\"key_fingerprint\":\"HSM-KEY-CS-FPR-01\",\"algorithm\":\"AES_256_GCM_FIPS_140_3\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/hsm/decrypt")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"slot_id\":1,\"plaintext\":\"CONFIDENTIAL-CS-DATA\",\"authenticated\":true}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/hsm/fips/selftest")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"self_tests\":[{\"test_name\":\"KAT-SHA-256\",\"passed\":true}],\"count\":1}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/hsm/fips/report")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"certification_level\":\"FIPS_140_3_LEVEL_4\",\"hardware_model\":\"FIPS-140-3-L4-VAULT\",\"serial_number\":\"HSM4-ROOT-9842\",\"tamper_state\":\"SECURE_NORMAL\",\"kat_passed\":true}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/hsm/tamper/simulate")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"tamper_latched\":true,\"sensor_id\":\"DEFAULT_BREACH\",\"zeroized\":true}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/hsm/zeroize")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"zeroized\":true}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/kem/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"initialized\":true,\"active_keys_count\":2,\"default_algorithm\":\"ML-KEM-768\",\"quantum_enforced\":false,\"active_sessions_count\":1}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/kem/keys")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"keys\":[{\"key_id\":\"mlkem-768-cs-01\",\"algorithm\":\"ML-KEM-768\",\"fingerprint\":\"fp-cs-768\"}]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/kem/keys/generate")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"key_id\":\"mlkem-1024-cs-02\",\"algorithm\":\"ML-KEM-1024\",\"fingerprint\":\"fp-cs-1024\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/kem/encapsulate")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"key_id\":\"mlkem-768-cs-01\",\"algorithm\":\"ML-KEM-768\",\"ciphertext_hex\":\"cs_cipher_hex_777\",\"shared_secret_hex\":\"cs_ss_hex_888\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/kem/decapsulate")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"key_id\":\"mlkem-768-cs-01\",\"shared_secret_hex\":\"cs_ss_hex_888\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/kem/handshake")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"session_id\":\"sess-cs-pqc-01\",\"server_ecdh_pub_hex\":\"04aabbcc\",\"ciphertext_hex\":\"cs_cipher_hex_777\",\"auth_tag_hex\":\"cs_auth_tag\",\"agreed_mode\":\"hybrid\",\"algorithm\":\"ML-KEM-768\",\"quantum_resistant\":true}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/pqc/kem/sessions/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"valid\":true,\"session_id\":\"sess-cs-pqc-01\",\"agreed_mode\":\"hybrid\",\"algorithm\":\"ML-KEM-768\",\"quantum_resistant\":true}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/transparency/status")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"log_id\":\"slb-transparency-cs-mock\",\"tree_size\":20,\"root_hash_hex\":\"aabbcc112233\",\"active_witnesses\":3,\"total_entries\":20,\"compliance_rfc\":\"RFC 6962\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/transparency/append")
                        {
                            ctx.Response.StatusCode = 201;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"success\",\"entry\":{\"index\":20,\"action\":\"license_created\",\"leaf_hash_hex\":\"leaf_hex_cs\"},\"sth\":{\"tree_size\":21,\"root_hash_hex\":\"new_root_hex_cs\"}}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/transparency/sth")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"tree_size\":20,\"root_hash_hex\":\"aabbcc112233\",\"log_id\":\"slb-transparency-cs-mock\",\"witness_signatures\":[{\"witness_id\":\"witness-enclave-sgx\",\"tree_size\":20,\"status\":\"verified\"}]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/transparency/entries")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"start\":0,\"count\":2,\"entries\":[{\"index\":0,\"action\":\"license_issued\"},{\"index\":1,\"action\":\"license_revoked\"}]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/transparency/inclusion-proof")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"leaf_index\":5,\"tree_size\":20,\"leaf_hash_hex\":\"leaf_hex_cs\",\"root_hash_hex\":\"aabbcc112233\",\"audit_path_hex\":[\"p0\",\"p1\"]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/transparency/inclusion-proof/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"verified\":true,\"leaf_index\":5,\"tree_size\":20}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/transparency/consistency-proof")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"first_size\":10,\"second_size\":20,\"first_root_hex\":\"root10\",\"second_root_hex\":\"aabbcc112233\",\"proof_hex\":[\"cp0\"]}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/transparency/consistency-proof/verify")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"verified\":true,\"first_size\":10,\"second_size\":20}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/transparency/witness/cosign")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"witness_id\":\"witness-enclave-sgx\",\"tree_size\":20,\"status\":\"verified\"}");
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/api/transparency/witnesses")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"witnesses\":[\"witness-enclave-sgx\",\"witness-node-iad\",\"witness-edge-fra\"],\"count\":3}");
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

                string ztStatusRaw = client.GetZeroTrustStatusAsync().GetAwaiter().GetResult();
                if (!ztStatusRaw.Contains("\"ca_initialized\":true") || !ztStatusRaw.Contains("zt_ca_cs_hex"))
                {
                    Console.Error.WriteLine("FAIL: ZeroTrust status failed: " + ztStatusRaw);
                    return 1;
                }
                string ztPeersRaw = client.ListZeroTrustPeersAsync().GetAwaiter().GetResult();
                if (!ztPeersRaw.Contains("node-cs-01"))
                {
                    Console.Error.WriteLine("FAIL: ZeroTrust peers list failed: " + ztPeersRaw);
                    return 1;
                }
                string ztEnrollRaw = client.EnrollZeroTrustPeerAsync("node-cs-01").GetAwaiter().GetResult();
                if (!ztEnrollRaw.Contains("cs_serial_01"))
                {
                    Console.Error.WriteLine("FAIL: ZeroTrust enroll failed: " + ztEnrollRaw);
                    return 1;
                }
                string ztVerifyRaw = client.VerifyZeroTrustPeerAsync("node-cs-01", "cs_serial_01").GetAwaiter().GetResult();
                if (!ztVerifyRaw.Contains("\"valid\":true"))
                {
                    Console.Error.WriteLine("FAIL: ZeroTrust verify failed: " + ztVerifyRaw);
                    return 1;
                }
                string ztRevokeRaw = client.RevokeZeroTrustPeerAsync("node-cs-01", "C# decomm").GetAwaiter().GetResult();
                if (!ztRevokeRaw.Contains("\"revoked\":true"))
                {
                    Console.Error.WriteLine("FAIL: ZeroTrust revoke failed: " + ztRevokeRaw);
                    return 1;
                }
                string ztRotateRaw = client.RotateZeroTrustCAAsync(180).GetAwaiter().GetResult();
                if (!ztRotateRaw.Contains("rotated_cs_fp_hex"))
                {
                    Console.Error.WriteLine("FAIL: ZeroTrust rotate failed: " + ztRotateRaw);
                    return 1;
                }
                string ztHsmRaw = client.GetZeroTrustHSMStatusAsync().GetAwaiter().GetResult();
                if (!ztHsmRaw.Contains("Root CA Master Key Slot"))
                {
                    Console.Error.WriteLine("FAIL: ZeroTrust HSM status failed: " + ztHsmRaw);
                    return 1;
                }
                Console.WriteLine("PASS: ZeroTrust status, peers, enroll/verify/revoke, CA rotate, and HSM slot query");

                // 24. Healing status, consume, issue/resume ticket, borrow/return quota, and rebalance
                string healStatusRaw = client.GetHealingStatusAsync().GetAwaiter().GetResult();
                if (!healStatusRaw.Contains("100") || !healStatusRaw.Contains("active_tunnels"))
                {
                    Console.Error.WriteLine("FAIL: Healing status query failed: " + healStatusRaw);
                    return 1;
                }
                string healConsumeRaw = client.ConsumeHealingBucketAsync(2.0).GetAwaiter().GetResult();
                if (!healConsumeRaw.Contains("\"allowed\":true"))
                {
                    Console.Error.WriteLine("FAIL: Healing bucket consume failed: " + healConsumeRaw);
                    return 1;
                }
                string healTicketRaw = client.IssueHealingTicketAsync("client-cs-01", "HWID-CS-01").GetAwaiter().GetResult();
                if (!healTicketRaw.Contains("cs_sig_heal"))
                {
                    Console.Error.WriteLine("FAIL: Healing ticket issue failed: " + healTicketRaw);
                    return 1;
                }
                string healResumeRaw = client.ResumeHealingTunnelAsync(healTicketRaw).GetAwaiter().GetResult();
                if (!healResumeRaw.Contains("resumed"))
                {
                    Console.Error.WriteLine("FAIL: Healing tunnel resume failed: " + healResumeRaw);
                    return 1;
                }
                string healBorrowRaw = client.BorrowHealingQuotaAsync("tenant-b", "tenant-l", 400).GetAwaiter().GetResult();
                if (!healBorrowRaw.Contains("lease-cs-01"))
                {
                    Console.Error.WriteLine("FAIL: Healing quota borrow failed: " + healBorrowRaw);
                    return 1;
                }
                string healReturnRaw = client.ReturnHealingQuotaAsync("lease-cs-01").GetAwaiter().GetResult();
                if (!healReturnRaw.Contains("returned"))
                {
                    Console.Error.WriteLine("FAIL: Healing quota return failed: " + healReturnRaw);
                    return 1;
                }
                string healRebalRaw = client.RebalanceHealingQuotasAsync().GetAwaiter().GetResult();
                if (!healRebalRaw.Contains("rebalanced"))
                {
                    Console.Error.WriteLine("FAIL: Healing quota rebalance failed: " + healRebalRaw);
                    return 1;
                }
                Console.WriteLine("PASS: Healing status, consume, ticket, tunnel resume, quota borrow/return, and rebalance");

                // 25. HSM status, slots, login/logout, derive key, envelope encrypt/decrypt, FIPS test/report, tamper, and zeroize
                string hsmStatusRaw = client.GetHSMStatusAsync().GetAwaiter().GetResult();
                if (!hsmStatusRaw.Contains("FIPS_140_3_LEVEL_4"))
                {
                    Console.Error.WriteLine("FAIL: HSM status query failed: " + hsmStatusRaw);
                    return 1;
                }
                string hsmSlotsRaw = client.ListHSMSlotsAsync().GetAwaiter().GetResult();
                if (!hsmSlotsRaw.Contains("Hardware Cryptoki Slot 0"))
                {
                    Console.Error.WriteLine("FAIL: HSM slots list failed: " + hsmSlotsRaw);
                    return 1;
                }
                string hsmLoginRaw = client.HSMLoginAsync(0, "FIPS-ROOT-PIN-9842", "USER").GetAwaiter().GetResult();
                if (!hsmLoginRaw.Contains("\"authenticated\":true"))
                {
                    Console.Error.WriteLine("FAIL: HSM login failed: " + hsmLoginRaw);
                    return 1;
                }
                string hsmLogoutRaw = client.HSMLogoutAsync(0).GetAwaiter().GetResult();
                if (!hsmLogoutRaw.Contains("\"logged_out\":true"))
                {
                    Console.Error.WriteLine("FAIL: HSM logout failed: " + hsmLogoutRaw);
                    return 1;
                }
                string hsmDeriveRaw = client.DeriveHSMKeyAsync(0, "audit_token_encryption", "CS-CTX").GetAwaiter().GetResult();
                if (!hsmDeriveRaw.Contains("HSM-KEY-CS-FPR-01"))
                {
                    Console.Error.WriteLine("FAIL: HSM derive failed: " + hsmDeriveRaw);
                    return 1;
                }
                string hsmEncRaw = client.EncryptHSMEnvelopeAsync(1, "CONFIDENTIAL-CS-DATA", "AAD-CS").GetAwaiter().GetResult();
                if (!hsmEncRaw.Contains("cs_cipher_hex_123"))
                {
                    Console.Error.WriteLine("FAIL: HSM encrypt failed: " + hsmEncRaw);
                    return 1;
                }
                string hsmDecRaw = client.DecryptHSMEnvelopeAsync(1, "cs_cipher_hex_123", "cs_nonce_hex_123", "AAD-CS").GetAwaiter().GetResult();
                if (!hsmDecRaw.Contains("CONFIDENTIAL-CS-DATA"))
                {
                    Console.Error.WriteLine("FAIL: HSM decrypt failed: " + hsmDecRaw);
                    return 1;
                }
                string hsmTestRaw = client.RunHSMSelfTestAsync().GetAwaiter().GetResult();
                if (!hsmTestRaw.Contains("KAT-SHA-256"))
                {
                    Console.Error.WriteLine("FAIL: HSM self-test failed: " + hsmTestRaw);
                    return 1;
                }
                string hsmReportRaw = client.GetHSMFIPSReportAsync().GetAwaiter().GetResult();
                if (!hsmReportRaw.Contains("FIPS_140_3_LEVEL_4") || !hsmReportRaw.Contains("kat_passed"))
                {
                    Console.Error.WriteLine("FAIL: HSM FIPS report failed: " + hsmReportRaw);
                    return 1;
                }
                string hsmTamperRaw = client.SimulateHSMTamperAsync("DEFAULT_BREACH").GetAwaiter().GetResult();
                if (!hsmTamperRaw.Contains("\"tamper_latched\":true"))
                {
                    Console.Error.WriteLine("FAIL: HSM tamper failed: " + hsmTamperRaw);
                    return 1;
                }
                string hsmZeroizeRaw = client.ZeroizeHSMAsync().GetAwaiter().GetResult();
                if (!hsmZeroizeRaw.Contains("\"zeroized\":true"))
                {
                    Console.Error.WriteLine("FAIL: HSM zeroize failed: " + hsmZeroizeRaw);
                    return 1;
                }
                Console.WriteLine("PASS: HSM status, slots, login/logout, derive key, envelope encrypt/decrypt, FIPS test/report, tamper, and zeroize");

                // 26. Test ML-KEM Post-Quantum Key Exchange and Hybrid Sessions
                string kemStatusRaw = client.GetMLKEMStatusAsync().GetAwaiter().GetResult();
                if (!kemStatusRaw.Contains("\"initialized\":true") || !kemStatusRaw.Contains("ML-KEM-768"))
                {
                    Console.Error.WriteLine("FAIL: ML-KEM status failed: " + kemStatusRaw);
                    return 1;
                }
                string kemKeysRaw = client.ListMLKEMKeysAsync().GetAwaiter().GetResult();
                if (!kemKeysRaw.Contains("mlkem-768-cs-01"))
                {
                    Console.Error.WriteLine("FAIL: ML-KEM keys failed: " + kemKeysRaw);
                    return 1;
                }
                string kemGenRaw = client.GenerateMLKEMKeyAsync("ML-KEM-1024").GetAwaiter().GetResult();
                if (!kemGenRaw.Contains("mlkem-1024-cs-02") || !kemGenRaw.Contains("ML-KEM-1024"))
                {
                    Console.Error.WriteLine("FAIL: ML-KEM generate failed: " + kemGenRaw);
                    return 1;
                }
                string kemEncapRaw = client.EncapsulateMLKEMAsync("mlkem-768-cs-01").GetAwaiter().GetResult();
                if (!kemEncapRaw.Contains("cs_cipher_hex_777") || !kemEncapRaw.Contains("cs_ss_hex_888"))
                {
                    Console.Error.WriteLine("FAIL: ML-KEM encapsulate failed: " + kemEncapRaw);
                    return 1;
                }
                string kemDecapRaw = client.DecapsulateMLKEMAsync("mlkem-768-cs-01", "cs_cipher_hex_777").GetAwaiter().GetResult();
                if (!kemDecapRaw.Contains("cs_ss_hex_888"))
                {
                    Console.Error.WriteLine("FAIL: ML-KEM decapsulate failed: " + kemDecapRaw);
                    return 1;
                }
                string kemHSRaw = client.HybridKEMHandshakeAsync("04112233", "mlkem-768-cs-01", "hybrid", "ML-KEM-768", "cs-nonce").GetAwaiter().GetResult();
                if (!kemHSRaw.Contains("sess-cs-pqc-01") || !kemHSRaw.Contains("\"quantum_resistant\":true"))
                {
                    Console.Error.WriteLine("FAIL: ML-KEM handshake failed: " + kemHSRaw);
                    return 1;
                }
                string kemVerifyRaw = client.VerifyHybridKEMSessionAsync("sess-cs-pqc-01").GetAwaiter().GetResult();
                if (!kemVerifyRaw.Contains("\"valid\":true") || !kemVerifyRaw.Contains("sess-cs-pqc-01"))
                {
                    Console.Error.WriteLine("FAIL: ML-KEM verify session failed: " + kemVerifyRaw);
                    return 1;
                }
                Console.WriteLine("PASS: ML-KEM status, keys, generate key, encapsulate/decapsulate, hybrid handshake, and verify session");

                // 27. Test SEV-SNP & Intel TDX Remote Attestation, Attestation Tokens, and Isolated Decryption
                string tdxVerifyRaw = client.VerifyTDXQuoteAsync("deadbeef_tdx_cs", "nonce_cs_123", "default-tdx").GetAwaiter().GetResult();
                if (!tdxVerifyRaw.Contains("\"valid\":true") || !tdxVerifyRaw.Contains("intel_tdx") || !tdxVerifyRaw.Contains("mrtd_cs_hex"))
                {
                    Console.Error.WriteLine("FAIL: TDX verify quote failed: " + tdxVerifyRaw);
                    return 1;
                }
                string tokIssueRaw = client.IssueAttestationTokenAsync("intel_tdx", "mrtd_cs_hex", "rtmr0_cs_hex", 2, false, "nonce_cs_123", "pub_cs_hex", 1800).GetAwaiter().GetResult();
                if (!tokIssueRaw.Contains("tok_cs_123") || !tokIssueRaw.Contains("intel_tdx"))
                {
                    Console.Error.WriteLine("FAIL: Issue attestation token failed: " + tokIssueRaw);
                    return 1;
                }
                string tokVerifyRaw = client.VerifyAttestationTokenAsync("tok_cs_123", 1, false).GetAwaiter().GetResult();
                if (!tokVerifyRaw.Contains("\"valid\":true") || !tokVerifyRaw.Contains("intel_tdx"))
                {
                    Console.Error.WriteLine("FAIL: Verify attestation token failed: " + tokVerifyRaw);
                    return 1;
                }
                string isoDecRaw = client.ExecuteIsolatedDecryptionAsync("intel_tdx", "tok_cs_123", "enc_payload_cs", "0102030405060708090a0b0c", "key_32_bytes_cs_hex_123456789012").GetAwaiter().GetResult();
                if (!isoDecRaw.Contains("\"success\":true") || !isoDecRaw.Contains("SLB-****-****-CS01") || !isoDecRaw.Contains("\"hardware_isolated\":true"))
                {
                    Console.Error.WriteLine("FAIL: Isolated decryption failed: " + isoDecRaw);
                    return 1;
                }
                Console.WriteLine("PASS: SEV-SNP & TDX remote attestation, attestation tokens, and isolated memory decryption");

                // 28. Test Verifiable Merkle Transparency Logs, RFC 6962 Proofs, and Witness Co-Signatures
                string trStatusRaw = client.GetTransparencyStatusAsync().GetAwaiter().GetResult();
                if (!trStatusRaw.Contains("slb-transparency-cs-mock") || !trStatusRaw.Contains("RFC 6962"))
                {
                    Console.Error.WriteLine("FAIL: Transparency status failed: " + trStatusRaw);
                    return 1;
                }
                string trAppendRaw = client.AppendTransparencyEntryAsync("license_created", "tenant-alpha", "{\"seat\":10}").GetAwaiter().GetResult();
                if (!trAppendRaw.Contains("\"status\":\"success\"") || !trAppendRaw.Contains("leaf_hex_cs"))
                {
                    Console.Error.WriteLine("FAIL: Transparency append failed: " + trAppendRaw);
                    return 1;
                }
                string trSTHRaw = client.GetTransparencySTHAsync().GetAwaiter().GetResult();
                if (!trSTHRaw.Contains("aabbcc112233") || !trSTHRaw.Contains("witness-enclave-sgx"))
                {
                    Console.Error.WriteLine("FAIL: Transparency STH failed: " + trSTHRaw);
                    return 1;
                }
                string trEntriesRaw = client.GetTransparencyEntriesAsync(0, 2).GetAwaiter().GetResult();
                if (!trEntriesRaw.Contains("\"count\":2") || !trEntriesRaw.Contains("license_issued"))
                {
                    Console.Error.WriteLine("FAIL: Transparency entries failed: " + trEntriesRaw);
                    return 1;
                }
                string trIncProofRaw = client.GetTransparencyInclusionProofAsync(5, 20).GetAwaiter().GetResult();
                if (!trIncProofRaw.Contains("leaf_hex_cs") || !trIncProofRaw.Contains("audit_path_hex"))
                {
                    Console.Error.WriteLine("FAIL: Transparency inclusion proof failed: " + trIncProofRaw);
                    return 1;
                }
                string trIncVerifyRaw = client.VerifyTransparencyInclusionProofAsync(trIncProofRaw).GetAwaiter().GetResult();
                if (!trIncVerifyRaw.Contains("\"verified\":true"))
                {
                    Console.Error.WriteLine("FAIL: Verify transparency inclusion proof failed: " + trIncVerifyRaw);
                    return 1;
                }
                string trConsProofRaw = client.GetTransparencyConsistencyProofAsync(10, 20).GetAwaiter().GetResult();
                if (!trConsProofRaw.Contains("root10") || !trConsProofRaw.Contains("proof_hex"))
                {
                    Console.Error.WriteLine("FAIL: Transparency consistency proof failed: " + trConsProofRaw);
                    return 1;
                }
                string trConsVerifyRaw = client.VerifyTransparencyConsistencyProofAsync(trConsProofRaw).GetAwaiter().GetResult();
                if (!trConsVerifyRaw.Contains("\"verified\":true"))
                {
                    Console.Error.WriteLine("FAIL: Verify transparency consistency proof failed: " + trConsVerifyRaw);
                    return 1;
                }
                string trCosignRaw = client.CosignTransparencySTHAsync("witness-enclave-sgx").GetAwaiter().GetResult();
                if (!trCosignRaw.Contains("witness-enclave-sgx") || !trCosignRaw.Contains("verified"))
                {
                    Console.Error.WriteLine("FAIL: Transparency cosign failed: " + trCosignRaw);
                    return 1;
                }
                string trWitnessesRaw = client.ListTransparencyWitnessesAsync().GetAwaiter().GetResult();
                if (!trWitnessesRaw.Contains("witness-enclave-sgx") || !trWitnessesRaw.Contains("\"count\":3"))
                {
                    Console.Error.WriteLine("FAIL: Transparency witnesses failed: " + trWitnessesRaw);
                    return 1;
                }
                Console.WriteLine("PASS: RFC 6962 transparency status, STH, inclusion/consistency proofs, and witness co-signatures");

                Console.WriteLine("=== All 28 C# Client Tests Passed Successfully! ===");
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
