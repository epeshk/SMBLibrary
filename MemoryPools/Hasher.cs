using System;
using System.Collections;

namespace MemoryPools
{
	/// <summary>
	///     Universal hasher for GetHashCode() implementations
	///     <example>
	///         public override int GetHashCode() => new Hasher
	///         {
	///             CreatedDateTime,
	///             LastModifiedDateTime,
	///             Length,
	///             Path,
	///             Name,
	///         };
	///     </example>
	/// </summary>
	public struct Hasher : IEnumerable
	{
		/// <summary>
		///     Gets the accumulated hash value
		/// </summary>
		public int? Hash { get; private set; }

		/// <summary>
		///     Add value of not Nullable{} type to the hash
		/// </summary>
		public void Add<T>(T value)
		{
			var hash = typeof(T).IsValueType
				? value.GetHashCode() // value is never null
				: value?.GetHashCode(); // only reference types get here

			AddImpl(hash);
		}

		/// <summary>
		///     Add value of Nullable{} type to the hash
		/// </summary>
		public void Add<T>(T? value)
			where T : struct
		{
			AddImpl(value?.GetHashCode()); // Nullable<> get here
		}

		private void AddImpl(int? value)
		{
			Hash = Combine(Hash, value);
		}

		/// <inheritdoc />
		public override int GetHashCode()
		{
			return Hash ?? 17;
		}

		/// <summary>
		///     Cast to int
		/// </summary>
		public static implicit operator int(Hasher h)
		{
			return h.GetHashCode();
		}

		/// <summary>
		///     IEnumerable implementation to satisfy compiler
		/// </summary>
		IEnumerator IEnumerable.GetEnumerator()
		{
			throw new NotImplementedException();
		}

		/// <summary>
		///     Combine two hash codes
		/// </summary>
		public static int Combine(int? left, int? right)
		{
			unchecked
			{
				return 37 * (left ?? 17) + (right ?? 0);
			}
		}

		/// <summary>
		///     Combine with another hash code
		/// </summary>
		public Hasher Combine(int? value)
		{
			return new Hasher {Hash = Combine(Hash, value)};
		}
	}
}