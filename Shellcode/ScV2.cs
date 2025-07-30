// File: Shellcode/ScV2.cs
// Project: KernelMode

using System;

namespace KernelMode.Shellcode
{
	public static class ScV2
	{
		public static byte[] Get(ulong param = 0)
		{
			// V2: supports zeroing the loader memory post-map (cleaner shellcode execution)
			// Based on KDUMapShellcodeV2.asm, parameter passed in RCX

			byte[] shellcode = new byte[]
			{
				0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28
                0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,       // mov rcx, <param>
                0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,       // mov rax, <DriverEntry>
                0xFF, 0xD0,                               // call rax
                0x48, 0x31, 0xC9,                         // xor rcx, rcx
                0x48, 0x89, 0x0D, 0, 0, 0, 0,             // mov [rip+X], rcx (zero self)
                0x48, 0x83, 0xC4, 0x28,                   // add rsp, 0x28
                0xC3                                      // ret
            };

			// Patch param into rcx (offset 6)
			BitConverter.GetBytes(param).CopyTo(shellcode, 6);
			// DriverEntry patch must be externally inserted
			// Optional RIP-relative zeroing offset must also be patched in at offset 27

			return shellcode;
		}
	}
}
