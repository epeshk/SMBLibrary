using System;
using System.Threading;
using System.Threading.Tasks;

namespace Utilities
{
	public static class WaitHandleHelper
	{
		public static Task ToTask(this WaitHandle waitHandle, TimeSpan timeOut)
		{
			var tcs = new TaskCompletionSource<object>();

			// Registering callback to wait till WaitHandle changes its state

			ThreadPool.RegisterWaitForSingleObject(
				waitObject: waitHandle,
				callBack:(o, timeout) => { tcs.SetResult(null); }, 
				state: null, 
				timeout: timeOut, 
				executeOnlyOnce: true);

			return tcs.Task;
		}
	}
}