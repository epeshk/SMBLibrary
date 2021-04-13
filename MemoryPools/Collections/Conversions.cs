using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

namespace MemoryPools.Collections
{
	public static class Conversions
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IDictionary<TK, TV> ToDictionary<TK, TV>(this IEnumerable<KeyValuePair<TK, TV>> self)
		{
			return self.ToDictionary(pair => pair.Key, pair => pair.Value);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IDictionary<TK, TV> ToDictionarySafe<TK, TV>(this IEnumerable<KeyValuePair<TK, TV>> self)
		{
			return self.EmptyIfNull().ToDictionary(pair => pair.Key, pair => pair.Value);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IDictionary<TK, TV> ToDictionary<TK, TV>(this IEnumerable<(TK, TV)> self)
		{
			return self.ToDictionary(pair => pair.Item1, pair => pair.Item2);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IDictionary<TK, TV> ToDictionarySafe<TK, TV>(this IEnumerable<(TK, TV)> self)
		{
			return self.EmptyIfNull().ToDictionary(pair => pair.Item1, pair => pair.Item2);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IDictionary<TK, TV> Swap<TV, TK>(this IDictionary<TV, TK> self)
		{
			return self.ToDictionary(p => p.Value, p => p.Key);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IDictionary<TK, TV> SwapSafe<TV, TK>(this IDictionary<TV, TK> self)
		{
			return self.EmptyIfNull().ToDictionary(p => p.Value, p => p.Key);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static TV GetValueOrDefault<TK, TV>(this IReadOnlyDictionary<TK, TV> self, TK key, TV defValue = default)
		{
			return self.TryGetValue(key, out var res) ? res : defValue;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static TV GetValueOrDefaultSafe<TK, TV>(this IReadOnlyDictionary<TK, TV> self, TK key, TV defValue = default)
		{
			return self == null ? defValue : GetValueOrDefault(self, key, defValue);
		}
	}
}