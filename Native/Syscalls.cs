// File: Native/Syscalls.cs
// Project: KernelMode

using System;
using System.Runtime.InteropServices;

namespace KernelMode.Native
{
	public static class Syscalls
	{
		[DllImport("ntdll.dll")]
		public static extern uint NtQuerySystemInformation(
			int SystemInformationClass,
			IntPtr SystemInformation,
			int SystemInformationLength,
			out int ReturnLength);

		[DllImport("ntdll.dll", SetLastError = true)]
		public static extern int NtOpenProcess(
			out IntPtr processHandle,
			uint desiredAccess,
			ref OBJECT_ATTRIBUTES objectAttributes,
			ref CLIENT_ID clientId);

		[StructLayout(LayoutKind.Sequential)]
		public struct CLIENT_ID
		{
			public IntPtr UniqueProcess;
			public IntPtr UniqueThread;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct OBJECT_ATTRIBUTES
		{
			public int Length;
			public IntPtr RootDirectory;
			public IntPtr ObjectName;
			public uint Attributes;
			public IntPtr SecurityDescriptor;
			public IntPtr SecurityQualityOfService;
		}

		public static void DebugInfo()
		{
			Console.WriteLine("[*] Syscall wrapper loaded.");
		}
	}
}
