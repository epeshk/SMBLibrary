using System;

namespace SMBLibrary
{
	internal static class StaticRandom
	{
		static StaticRandom()
		{
			Instance = new Random();
		}
		
		public static Random Instance { get; }
	}
}