using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;

namespace MemoryPools.Collections
{
	public static class EmptyIfNulls
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static bool IsEmptyOrNull(this string input)
		{
			return string.IsNullOrEmpty(input);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static string EmptyIfNull(this string input)
		{
			return input ?? string.Empty;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static T[] EmptyIfNull<T>(this T[] input)
		{
			return input ?? Array.Empty<T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static List<T> EmptyIfNull<T>(this List<T> input)
		{
			return input ?? ListInstancesHolder<T>.Instance;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IList<T> EmptyIfNull<T>(this IList<T> input)
		{
			return input ?? ListInstancesHolder<T>.Instance;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IReadOnlyList<T> EmptyIfNull<T>(this IReadOnlyList<T> input)
		{
			return input ?? ListInstancesHolder<T>.Instance;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IReadOnlyCollection<T> EmptyIfNull<T>(this IReadOnlyCollection<T> input)
		{
			return input ?? ListInstancesHolder<T>.Instance;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static ICollection<T> EmptyIfNull<T>(this ICollection<T> input)
		{
			return input ?? ListInstancesHolder<T>.Instance;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IEnumerable<T> EmptyIfNull<T>(this IEnumerable<T> input)
		{
			return input ?? Enumerable.Empty<T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Dictionary<TK, TV> EmptyIfNull<TK, TV>(this Dictionary<TK, TV> input)
		{
			return input ?? DictionaryInstancesHolder<TK, TV>.Instance;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IDictionary<TK, TV> EmptyIfNull<TK, TV>(this IDictionary<TK, TV> input)
		{
			return input ?? DictionaryInstancesHolder<TK, TV>.Instance;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IReadOnlyDictionary<TK, TV> EmptyIfNull<TK, TV>(this IReadOnlyDictionary<TK, TV> input)
		{
			return input ?? DictionaryInstancesHolder<TK, TV>.Instance;
		}

		#region Pre-compiled method for instance getting

		private static class ListInstancesHolder<T>
		{
			private static List<T> _instance;

			public static List<T> Instance
			{
				[PrePrepareMethod] get { return _instance ??= new List<T>(0); }
			}
		}

		private static class DictionaryInstancesHolder<TK, TV>
		{
			private static Dictionary<TK, TV> _instance;

			public static Dictionary<TK, TV> Instance
			{
				[PrePrepareMethod] get { return _instance ??= new Dictionary<TK, TV>(0); }
			}
		}

		#endregion
	}
}