// File: Utils/DriverInstaller.cs
// Project: KernelMode

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32;

namespace KernelMode.Utils
{
	public static class DriverInstaller
	{
		private const int SERVICE_KERNEL_DRIVER = 0x00000001;
		private const int SERVICE_DEMAND_START = 0x00000003;
		private const int SERVICE_ERROR_NORMAL = 0x00000001;
		private const uint SERVICE_ALL_ACCESS = 0xF01FF;

		[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		private static extern IntPtr OpenSCManager(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

		[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		private static extern IntPtr CreateService(
			IntPtr hSCManager,
			string lpServiceName,
			string lpDisplayName,
			uint dwDesiredAccess,
			uint dwServiceType,
			uint dwStartType,
			uint dwErrorControl,
			string lpBinaryPathName,
			string lpLoadOrderGroup,
			IntPtr lpdwTagId,
			string lpDependencies,
			string lpServiceStartName,
			string lpPassword);

		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern bool CloseServiceHandle(IntPtr hSCObject);

		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string lpServiceArgVectors);

		public static bool InstallAndStart(string serviceName, string driverPath)
		{
			Console.WriteLine($"[*] Installing driver {serviceName} from: {driverPath}");

			IntPtr scm = OpenSCManager(null, null, SERVICE_ALL_ACCESS);
			if (scm == IntPtr.Zero)
			{
				Console.WriteLine("[-] Failed to open SCM.");
				return false;
			}

			IntPtr service = CreateService(
				scm,
				serviceName,
				serviceName,
				SERVICE_ALL_ACCESS,
				SERVICE_KERNEL_DRIVER,
				SERVICE_DEMAND_START,
				SERVICE_ERROR_NORMAL,
				driverPath,
				null, IntPtr.Zero, null, null, null);

			if (service == IntPtr.Zero)
			{
				Console.WriteLine("[-] CreateService failed.");
				CloseServiceHandle(scm);
				return false;
			}

			bool started = StartService(service, 0, null);
			CloseServiceHandle(service);
			CloseServiceHandle(scm);

			Console.WriteLine(started ? "[+] Driver started." : "[-] Failed to start driver.");
			return started;
		}
	}
}
