// File: Providers/IProvider.cs
// Project: KernelMode

using System;

namespace KernelMode.Providers
{
	public interface IProvider : IDisposable
	{
		bool IsInitialized { get; }

		bool Initialize();

		bool ReadMemory(ulong address, byte[] buffer, int size);

		bool WriteMemory(ulong address, byte[] buffer, int size);

		bool MapShellcode(byte[] shellcode, ulong param);
	}
}
