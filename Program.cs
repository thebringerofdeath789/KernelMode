using System;

namespace KernelMode
{
    internal static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            // Perform a compatibility check to ensure the program is running on a 64-bit OS.
            // Many features, such as kernel structure offsets and assembly signatures, are x64-specific.
            if (!Environment.Is64BitOperatingSystem)
            {
                Console.WriteLine("[-] This program is designed to run on 64-bit versions of Windows only.");
                Console.WriteLine("Press any key to exit.");
                Console.ReadKey();
                return;
            }

            PoCMenu.Run();
        }
    }
}
