using System;
 using System.Collections.Generic;
 using System.Threading;
 using MemoryPools.Collections.Specialized;

 namespace SMBLibrary
{
	public class ExactArrayPool
	{
		public static byte[] Rent(int length) =>
			ExactArrayPool<byte>.Rent(length);

		public static void Return(byte[] buf1, byte[] buf2)
		{
			Return(buf1);
			Return(buf2);
		}

		public static void Return(byte[] buf1, byte[] buf2, byte[] buf3)
		{
			Return(buf1);
			Return(buf2);
			Return(buf3);
		}
		
		public static void Return(byte[] buf) => ExactArrayPool<byte>.Return(buf);
	}

	public class ExactArrayPool<T>
	{
		public static int HugeArraysLeaks;
		public static int HugeArraysAllocated;
		public static long SizeMissTotalLength;
		public static Dictionary<int, int> Misses = new Dictionary<int, int>(100); 
		
		// 0..400
		private static PoolingQueue<T[]>[] pools;

		static ExactArrayPool()
		{
			pools = new PoolingQueue<T[]>[512];
		}

		public static T[] Rent(int length)
		{
			lock (pools)
			{
				if (length >= pools.Length)
				{
					Interlocked.Increment(ref HugeArraysLeaks);
					Interlocked.Increment(ref HugeArraysAllocated);
					
					if (!Misses.ContainsKey(length)) Misses[length] = 1;
					else Misses[length]++;
					
					Interlocked.Add(ref SizeMissTotalLength, length);
					
					return new T[length];
				}

				if (length == 0) return Array.Empty<T>();

				if (pools[length] == null) pools[length] = new PoolingQueueRef<T[]>();
				if (pools[length].TryDequeue(out var item))
				{
					return item;
				}

				return new T[length];
			}
		}

		public static void Return(T[] buf)
		{
			lock (pools)
			{
				if (buf.Length == 0) return;
				if (buf.Length < pools.Length && pools[buf.Length] != null)
				{
					pools[buf.Length].Enqueue(buf);
				}
				else
				{
					Interlocked.Decrement(ref HugeArraysLeaks);
				}
			}
		}
	}
}