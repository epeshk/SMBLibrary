using System.Collections.Generic;

namespace MemoryPools.Collections
{
	public static class CollectionFrom
	{
		/// <summary>
		///     Returns enumerator, which yields given element
		/// </summary>
		public static IEnumerable<T> Yield<T>(this T instance)
		{
			yield return instance;
		}

		/// <summary>
		///     Returns enumerator, which yields given elements
		/// </summary>
		public static IEnumerable<T> Yield<T>(this (T, T) instance)
		{
			yield return instance.Item1;
			yield return instance.Item2;
		}

		/// <summary>
		///     Returns enumerator, which yields given elements
		/// </summary>
		public static IEnumerable<T> Yield<T>(this (T, T, T) instance)
		{
			yield return instance.Item1;
			yield return instance.Item2;
			yield return instance.Item3;
		}

		/// <summary>
		///     Returns enumerator, which yields given elements
		/// </summary>
		public static IEnumerable<T> Yield<T>(this (T, T, T, T) instance)
		{
			yield return instance.Item1;
			yield return instance.Item2;
			yield return instance.Item3;
			yield return instance.Item4;
		}

		/// <summary>
		///     Returns enumerator, which yields given elements
		/// </summary>
		public static IEnumerable<T> Yield<T>(this (T, T, T, T, T) instance)
		{
			yield return instance.Item1;
			yield return instance.Item2;
			yield return instance.Item3;
			yield return instance.Item4;
			yield return instance.Item5;
		}

		/// <summary>
		///     Converts ValueTuple to key-value single-entry dictionary
		/// </summary>
		public static IDictionary<TK, TV> ToDictionary<TK, TV>(this (TK, TV) instance)
		{
			return new Dictionary<TK, TV>(1) {[instance.Item1] = instance.Item2};
		}
	}
}