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
                            else
                            {
                                ctx.Response.StatusCode = 200;
                                respBytes = Encoding.UTF8.GetBytes("{\"valid\":true,\"message\":\"License active and valid\",\"source\":\"memory\"}");
                            }
                        }
                        else if (ctx.Request.Url.AbsolutePath == "/health")
                        {
                            ctx.Response.StatusCode = 200;
                            respBytes = Encoding.UTF8.GetBytes("{\"status\":\"healthy\",\"version\":\"0.4.0\"}");
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
                var client = new SheetLicenseClient("http://127.0.0.1:" + port, "test-secret-key");

                // Test Verification with HMAC
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

                // Test Health endpoint
                string health = client.GetHealthAsync().GetAwaiter().GetResult();
                if (!health.Contains("healthy"))
                {
                    Console.Error.WriteLine("FAIL: Health response does not contain healthy: " + health);
                    return 1;
                }
                Console.WriteLine("PASS: Health check query");

                Console.WriteLine("=== All C# Client Tests Passed Successfully! ===");
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
