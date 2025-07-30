using System;

namespace KernelMode
{
	internal class Program
	{
		static void Main(string[] args)
		{
			Console.Title = "KernelMode PoC";
			Console.WriteLine("[+] Initializing KernelMode PoC...");

			try
			{
				PoCMenu.Run();
			}
			catch (Exception ex)
			{
				Console.WriteLine("[!] Unhandled exception: " + ex.Message);
				Console.WriteLine(ex.StackTrace);
			}

			Console.WriteLine("[*] Press any key to exit...");
			Console.ReadKey();
		}
	}
}
