// File: Utils/OffsetResolver.cs
// Project: KernelMode

using System;
using System.Collections.Generic;

namespace KernelMode.Utils
{
	public static class OffsetResolver
	{
		public struct WindowsBuildOffsets
		{
			public int TokenOffset;
			public ulong EtwEventWrite;
			public ulong AmsiScanBuffer;
		}

		private static readonly Dictionary<int, WindowsBuildOffsets> OffsetMap = new Dictionary<int, WindowsBuildOffsets>()
		{
			{ 19041, new WindowsBuildOffsets { TokenOffset = 0x4b8, EtwEventWrite = 0xFFFFF80200012345, AmsiScanBuffer = 0x7FFB30001234 } }, // Win10 2004+
            { 19042, new WindowsBuildOffsets { TokenOffset = 0x4b8, EtwEventWrite = 0xFFFFF80200012345, AmsiScanBuffer = 0x7FFB30001234 } },
			{ 19043, new WindowsBuildOffsets { TokenOffset = 0x4b8, EtwEventWrite = 0xFFFFF80200012345, AmsiScanBuffer = 0x7FFB30001234 } },
			{ 19044, new WindowsBuildOffsets { TokenOffset = 0x4b8, EtwEventWrite = 0xFFFFF80200012345, AmsiScanBuffer = 0x7FFB30001234 } },
			{ 19045, new WindowsBuildOffsets { TokenOffset = 0x4c0, EtwEventWrite = 0xFFFFF80200013333, AmsiScanBuffer = 0x7FFB30009999 } }, // 22H2
            { 22000, new WindowsBuildOffsets { TokenOffset = 0x4e0, EtwEventWrite = 0xFFFFF80200015555, AmsiScanBuffer = 0x7FFB30101111 } }, // Win11 21H2
            { 22621, new WindowsBuildOffsets { TokenOffset = 0x4e8, EtwEventWrite = 0xFFFFF80200017777, AmsiScanBuffer = 0x7FFB30102222 } }, // Win11 22H2
            { 22631, new WindowsBuildOffsets { TokenOffset = 0x4f0, EtwEventWrite = 0xFFFFF80200019999, AmsiScanBuffer = 0x7FFB30103333 } }  // Win11 23H2+
        };
		private static readonly Dictionary<string, ulong> OffsetTable = new Dictionary<string, ulong>()
		{
			{ "ActiveProcessLinks", 0x2f0 }, // Example offset, update as needed
            { "Token", 0x360 }               // Example offset, update as needed
        };

		public static ulong Resolve(string name)
		{
			if (OffsetTable.ContainsKey(name))
				return OffsetTable[name];
			throw new NotSupportedException($"Offset '{name}' not found.");
		}
		public static int GetTokenOffset()
		{
			int build = Environment.OSVersion.Version.Build;

			if (OffsetMap.TryGetValue(build, out var off))
			{
				Console.WriteLine($"[*] Using known Token offset: 0x{off.TokenOffset:X} for build {build}");
				return off.TokenOffset;
			}

			Console.WriteLine("[-] Unknown build, unable to resolve Token offset.");
			return -1;
		}

		public static ulong GetEtwEventWriteAddress()
		{
			int build = Environment.OSVersion.Version.Build;

			if (OffsetMap.TryGetValue(build, out var off) && off.EtwEventWrite != 0)
			{
				Console.WriteLine($"[*] Using known EtwEventWrite: 0x{off.EtwEventWrite:X}");
				return off.EtwEventWrite;
			}

			Console.WriteLine("[-] Failed to resolve EtwEventWrite.");
			return 0;
		}

		public static ulong GetAmsiScanBufferAddress()
		{
			int build = Environment.OSVersion.Version.Build;

			if (OffsetMap.TryGetValue(build, out var off) && off.AmsiScanBuffer != 0)
			{
				Console.WriteLine($"[*] Using known AmsiScanBuffer: 0x{off.AmsiScanBuffer:X}");
				return off.AmsiScanBuffer;
			}

			Console.WriteLine("[-] Failed to resolve AmsiScanBuffer.");
			return 0;
		}
	}
}
