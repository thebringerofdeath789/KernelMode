// File: Shellcode/ScV1.cs
// Project: KernelMode

using System;

namespace KernelMode.Shellcode
{
	public static class ScV1
	{
		public static byte[] Get(ulong param = 0)
		{
			// Original KDU V1 shellcode: calls mapped DriverEntry without loader cleanup
			// This version will patch in the target image base or param if needed

			byte[] shellcode = new byte[]
			{
				0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28
                0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,       // mov rcx, <image_base or param>
                0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,       // mov rax, <DriverEntry>
                0xFF, 0xD0,                               // call rax
                0x48, 0x83, 0xC4, 0x28,                   // add rsp, 0x28
                0xC3                                      // ret
            };

			// runtime patch: insert rcx (param) at offset 6
			BitConverter.GetBytes(param).CopyTo(shellcode, 6);
			// DriverEntry patch must be inserted externally before execution
			return shellcode;
		}
	}
}
