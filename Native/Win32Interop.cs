// File: Native/Win32Interop.cs
// Project: KernelMode

using System;

namespace KernelMode.Native
{
	public static class Win32Interop
	{
		public const uint GENERIC_READ = 0x80000000;
		public const uint GENERIC_WRITE = 0x40000000;
		public const uint OPEN_EXISTING = 3;
		public const uint FILE_SHARE_READ = 0x00000001;
		public const uint FILE_SHARE_WRITE = 0x00000002;

		public const int ERROR_INSUFFICIENT_BUFFER = 122;

		public static void PrintError(string context)
		{
			int errorCode = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
			Console.WriteLine($"[-] {context} failed with error code: {errorCode} (0x{errorCode:X})");
		}
	}
}
