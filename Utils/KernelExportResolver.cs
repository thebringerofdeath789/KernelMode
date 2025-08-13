/* Utils/KernelExportResolver.cs */
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace KernelMode.Utils
{
    public class KernelExportResolver
    {
        private readonly byte[] _ntoskrnl;
        private readonly ulong _ntoskrnlBase;
        private readonly Dictionary<string, ulong> _exportCache = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);

        public KernelExportResolver(byte[] ntoskrnlImage, ulong ntoskrnlBase)
        {
            _ntoskrnl = ntoskrnlImage;
            _ntoskrnlBase = ntoskrnlBase;
            ParseExports();
        }

        public ulong Resolve(string exportName)
        {
            if (_exportCache.TryGetValue(exportName, out ulong address))
            {
                return address;
            }
            Console.WriteLine($"[!] Export not resolved: {exportName}");
            return 0;
        }

        private void ParseExports()
        {
            int peHeaderOffset = BitConverter.ToInt32(_ntoskrnl, 0x3C);
            int exportDirRva = BitConverter.ToInt32(_ntoskrnl, peHeaderOffset + 0x88);
            int exportDirOffset = RvaToOffset(exportDirRva);

            if (exportDirOffset == 0) return;

            int namesRva = BitConverter.ToInt32(_ntoskrnl, exportDirOffset + 0x20);
            int ordinalsRva = BitConverter.ToInt32(_ntoskrnl, exportDirOffset + 0x24);
            int functionsRva = BitConverter.ToInt32(_ntoskrnl, exportDirOffset + 0x1C);
            int numberOfNames = BitConverter.ToInt32(_ntoskrnl, exportDirOffset + 0x18);

            int namesOffset = RvaToOffset(namesRva);
            int ordinalsOffset = RvaToOffset(ordinalsRva);
            int functionsOffset = RvaToOffset(functionsRva);

            for (int i = 0; i < numberOfNames; i++)
            {
                int nameRva = BitConverter.ToInt32(_ntoskrnl, namesOffset + i * 4);
                int nameOffset = RvaToOffset(nameRva);
                string name = ReadNullTerminatedString(nameOffset);

                ushort ordinal = BitConverter.ToUInt16(_ntoskrnl, ordinalsOffset + i * 2);
                int functionRva = BitConverter.ToInt32(_ntoskrnl, functionsOffset + ordinal * 4);

                _exportCache[name] = _ntoskrnlBase + (ulong)functionRva;
            }
        }

        private int RvaToOffset(int rva)
        {
            int peHeaderOffset = BitConverter.ToInt32(_ntoskrnl, 0x3C);
            short numberOfSections = BitConverter.ToInt16(_ntoskrnl, peHeaderOffset + 6);
            int sizeOfOptionalHeader = BitConverter.ToInt16(_ntoskrnl, peHeaderOffset + 20);
            int sectionTableOffset = peHeaderOffset + 24 + sizeOfOptionalHeader;

            for (int i = 0; i < numberOfSections; i++)
            {
                int sectionOffset = sectionTableOffset + (i * 40);
                int virtAddr = BitConverter.ToInt32(_ntoskrnl, sectionOffset + 12);
                int virtSize = BitConverter.ToInt32(_ntoskrnl, sectionOffset + 8);
                int rawPtr = BitConverter.ToInt32(_ntoskrnl, sectionOffset + 20);

                if (rva >= virtAddr && rva < virtAddr + virtSize)
                {
                    return rawPtr + (rva - virtAddr);
                }
            }
            return 0;
        }

        private string ReadNullTerminatedString(int offset)
        {
            int end = Array.IndexOf(_ntoskrnl, (byte)0, offset);
            if (end == -1) end = _ntoskrnl.Length;
            return Encoding.ASCII.GetString(_ntoskrnl, offset, end - offset);
        }
    }
}
