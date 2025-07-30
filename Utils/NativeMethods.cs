// File: Utils/NativeMethods.cs
// Project: KernelMode

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace KernelMode.Utils
{
	public static class NativeMethods
	{
		public const uint GENERIC_READ = 0x80000000;
		public const uint GENERIC_WRITE = 0x40000000;
		public const uint OPEN_EXISTING = 3;

		public const uint FILE_DEVICE_UNKNOWN = 0x00000022;
		public const uint METHOD_BUFFERED = 0x00000000;
		public const uint FILE_ANY_ACCESS = 0x00000000;
		public const uint FILE_SPECIAL_ACCESS = FILE_ANY_ACCESS;

		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		public static extern SafeFileHandle CreateFile(
			string lpFileName,
			uint dwDesiredAccess,
			uint dwShareMode,
			IntPtr lpSecurityAttributes,
			uint dwCreationDisposition,
			uint dwFlagsAndAttributes,
			IntPtr hTemplateFile);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool DeviceIoControl(
			SafeFileHandle hDevice,
			uint dwIoControlCode,
			IntPtr lpInBuffer,
			int nInBufferSize,
			IntPtr lpOutBuffer,
			int nOutBufferSize,
			out int lpBytesReturned,
			IntPtr lpOverlapped);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool DeviceIoControl(
			SafeFileHandle hDevice,
			uint dwIoControlCode,
			[In] byte[] lpInBuffer,
			int nInBufferSize,
			[Out] byte[] lpOutBuffer,
			int nOutBufferSize,
			ref int lpBytesReturned,
			IntPtr lpOverlapped);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool CloseHandle(IntPtr hObject);

		[DllImport("kernel32.dll")]
		public static extern IntPtr GetCurrentProcess();

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool ReadProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			[Out] byte[] lpBuffer,
			int dwSize,
			out int lpNumberOfBytesRead);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool WriteProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			[In] byte[] lpBuffer,
			int dwSize,
			out int lpNumberOfBytesWritten);
	}
}
