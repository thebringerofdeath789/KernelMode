// File: Privilege/PrivilegeViewer.cs
// Project: KernelMode

using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace KernelMode.Privilege
{
	public static class PrivilegeViewer
	{
		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern bool GetTokenInformation(
			IntPtr tokenHandle,
			int tokenInformationClass,
			IntPtr tokenInformation,
			int tokenInformationLength,
			out int returnLength);

		[DllImport("kernel32.dll")]
		private static extern IntPtr GetCurrentProcess();

		private const int TokenElevation = 20;
		private const uint TOKEN_QUERY = 0x0008;

		public static void ShowPrivileges()
		{
			Console.WriteLine($"[*] Current user: {WindowsIdentity.GetCurrent().Name}");

			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out IntPtr tokenHandle))
			{
				Console.WriteLine("[-] Failed to open process token.");
				return;
			}

			int tokenInfoLength = Marshal.SizeOf(typeof(uint));
			IntPtr elevationPtr = Marshal.AllocHGlobal(tokenInfoLength);

			if (GetTokenInformation(tokenHandle, TokenElevation, elevationPtr, tokenInfoLength, out _))
			{
				int isElevated = Marshal.ReadInt32(elevationPtr);
				Console.WriteLine($"[+] Token is {(isElevated != 0 ? "elevated (SYSTEM or Admin)" : "not elevated (Standard user)")}");
			}
			else
			{
				Console.WriteLine("[-] Failed to get token elevation info.");
			}

			Marshal.FreeHGlobal(elevationPtr);
		}
	}
}
