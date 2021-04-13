using System;
using System.Buffers;
using SMBLibrary;

namespace Utilities
{
	public class SimpleMemoryOwner : IMemoryOwner<byte>
	{
		private byte[] _arr;
		private readonly bool _ret;

		public SimpleMemoryOwner(byte[] arr, bool ret = false)
		{
			_arr = arr;
			_ret = ret;
		}
			
		public void Dispose()
		{
			if(_ret) ExactArrayPool.Return(_arr);
			_arr = null;
		}

		public Memory<byte> Memory => _arr;
	}
}