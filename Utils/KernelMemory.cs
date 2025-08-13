// File: Utils/KernelMemory.cs
// Project: KernelMode

using KernelMode.Providers;
using System;
//using KernelMode.EDR;

namespace KernelMode.Utils
{
	public static class KernelMemory
	{
		private static IProvider _provider;
		public static IProvider GetProvider()
		{
			return _provider;
		}

		public static void SetProvider(IProvider provider)
		{
			_provider = provider ?? throw new ArgumentNullException(nameof(provider));
		}

		public static bool IsReady => _provider != null;

		public static bool Read(ulong address, byte[] buffer, int size)
		{
			if (!IsReady || buffer == null || size <= 0)
				return false;

			return _provider.ReadMemory(address, buffer, size);
		}

		public static bool Write(ulong address, byte[] data, int size)
		{
			if (!IsReady || data == null || size <= 0)
				return false;

			return _provider.WriteMemory(address, data, size);
		}

		public static ulong ReadQword(ulong address)
		{
			byte[] buffer = new byte[8];
			return Read(address, buffer, 8) ? BitConverter.ToUInt64(buffer, 0) : 0;
		}

		public static uint ReadDword(ulong address)
		{
			byte[] buffer = new byte[4];
			return Read(address, buffer, 4) ? BitConverter.ToUInt32(buffer, 0) : 0;
		}

		public static ushort ReadWord(ulong address)
		{
			byte[] buffer = new byte[2];
			return Read(address, buffer, 2) ? BitConverter.ToUInt16(buffer, 0) : (ushort)0;
		}

		public static byte ReadByte(ulong address)
		{
			byte[] buffer = new byte[1];
			return Read(address, buffer, 1) ? buffer[0] : (byte)0;
		}

		public static bool WriteQword(ulong address, ulong value)
		{
			return Write(address, BitConverter.GetBytes(value), 8);
		}

		public static bool WriteDword(ulong address, uint value)
		{
			return Write(address, BitConverter.GetBytes(value), 4);
		}

		public static bool WriteWord(ulong address, ushort value)
		{
			return Write(address, BitConverter.GetBytes(value), 2);
		}

		public static bool WriteByte(ulong address, byte value)
		{
			return Write(address, new byte[] { value }, 1);
		}
	}
}
