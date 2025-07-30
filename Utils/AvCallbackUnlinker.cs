//using KernelMode.Interfaces;
using KernelMode.Providers;

namespace KernelMode.EDR
{
	public static class AVCallbackUnlinker
	{
		public static void Execute(IProvider provider)
		{
			// Logic to unlink registered ObjectCallbacks or MiniFilter callbacks
			// Will be filled out per-driver later (DBUtil, GDRV, etc.)
		}
	}
}
