// File: Shellcode/ScV3.cs
// Project: KernelMode

using System;

namespace KernelMode.Shellcode
{
	public static class ScV3
	{
		public static byte[] Get(ulong param = 0)
		{
			// V3 shellcode: calls DriverEntry and returns its NTSTATUS

			byte[] shellcode = new byte[]
			{
				0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28
                0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,       // mov rcx, <param>
                0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,       // mov rax, <DriverEntry>
                0xFF, 0xD0,                               // call rax
                0x48, 0x83, 0xC4, 0x28,                   // add rsp, 0x28
                0xC3                                      // ret (RAX = DriverEntry return)
            };

			BitConverter.GetBytes(param).CopyTo(shellcode, 6);
			// DriverEntry address must be patched externally at offset 16

			return shellcode;
		}
	}
}
