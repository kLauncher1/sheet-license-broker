using System;
using System.IO;
using System.Threading.Tasks;
using SheetLicenseBroker;

namespace DesktopLicenseProtectionSample
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            Console.WriteLine("==================================================");
            Console.WriteLine("  Sheet-License-Broker C# / Unity Protection Sample");
            Console.WriteLine("==================================================");

            string brokerUrl = Environment.GetEnvironmentVariable("BROKER_URL") ?? "http://127.0.0.1:9082";
            string secretKey = Environment.GetEnvironmentVariable("BROKER_SECRET") ?? "";
            string licenseKey = Environment.GetEnvironmentVariable("APP_LICENSE_KEY") ?? "SLB-SAMPLE-KEY-99999";

            var client = new SheetLicenseClient(brokerUrl, string.IsNullOrEmpty(secretKey) ? null : secretKey);
            string hwid = SheetLicenseClient.GetMachineHwid();

            Console.WriteLine("[*] Resolved Machine HWID: " + hwid);
            Console.WriteLine("[*] Validating License: " + licenseKey);

            // 1. Verify license via asynchronous API (or client.VerifyLicense for synchronous Unity game loops)
            var result = await client.VerifyLicenseAsync(licenseKey, hwid);

            if (result.Valid)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] License Validated! Access Granted.");
                Console.ResetColor();
                Console.WriteLine("    Message: " + result.Message);
                Console.WriteLine("    Source: " + result.Source);

                // Run protected application logic
                RunProtectedFeatures();
                return 0;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[-] License check status: " + (result.Error ?? result.Message));
                Console.ResetColor();
                Console.WriteLine("[*] In production, prompt the user for license activation or fallback to trial mode.");
                return 0;
            }
        }

        static void RunProtectedFeatures()
        {
            Console.WriteLine("[*] Loading premium modules, 3D scenes, or sensitive analytics...");
            Console.WriteLine("[+] Application engine running.");
        }
    }
}
