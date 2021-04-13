using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using MemoryPools.Memory.Pooling;

namespace MemoryPools.Text
{
	/// <summary>
	///     Allows to do non-allocating strings building:
	///     <example>
	///         var stringBuilder = new ValueStringBuilder(stackalloc char[MAX_STRING_LENGTH /* 256 for ex */]);
	///         stringBuilder.Append("Incorrect file name: ");
	///         stringBuilder.Append(file.Name);
	///         stringBuilder.Append(". Please, check path.");
	///         _logger.Info(stringBuilder);
	///     </example>
	/// </summary>
	public ref struct ValueStringBuilder
	{
		private IMemoryOwner<char> _arrayToReturnToPool;
		private Span<char> _chars;
		private int _pos;

		public ValueStringBuilder(Span<char> initialBuffer)
		{
			_arrayToReturnToPool = null;
			_chars = initialBuffer;
			_pos = 0;
		}

		public int Length
		{
			get => _pos;
			set
			{
				var delta = value - _pos;
				if (delta > 0)
					Append('\0', delta);
				else
					_pos = value;
			}
		}

		public Span<char> AsSpanNoClear()
		{
			return _arrayToReturnToPool == null
				? _chars
				: _arrayToReturnToPool.Memory.Span;
		}

		public override string ToString()
		{
			var s = _chars.Slice(0, _pos).ToString();
			Dispose();
			return s;
		}

		public bool TryCopyTo(Span<char> destination, out int charsWritten)
		{
			if (_chars.Slice(0, _pos).TryCopyTo(destination))
			{
				charsWritten = _pos;
				Dispose();
				return true;
			}

			charsWritten = 0;
			Dispose();
			return false;
		}

		public void Insert(int index, char value, int count)
		{
			if (_pos > _chars.Length - count) Grow(count);

			var remaining = _pos - index;
			_chars.Slice(index, remaining).CopyTo(_chars.Slice(index + count));
			_chars.Slice(index, count).Fill(value);
			_pos += count;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Append(char c)
		{
			var pos = _pos;
			if (pos < _chars.Length)
			{
				_chars[pos] = c;
				_pos = pos + 1;
			}
			else
			{
				GrowAndAppend(c);
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Append(string s)
		{
			var pos = _pos;
			if (s.Length == 1 && pos < _chars.Length
			) // very common case, e.g. appending strings from NumberFormatInfo like separators, percent symbols, etc.
			{
				_chars[pos] = s[0];
				_pos = pos + 1;
			}
			else
			{
				AppendSlow(s);
			}
		}

		private void AppendSlow(string s)
		{
			var pos = _pos;
			if (pos > _chars.Length - s.Length) Grow(s.Length);

			s.AsSpan().CopyTo(_chars.Slice(pos));
			_pos += s.Length;
		}

		public void Append(char c, int count)
		{
			if (_pos > _chars.Length - count) Grow(count);

			var dst = _chars.Slice(_pos, count);
			for (var i = 0; i < dst.Length; i++) dst[i] = c;
			_pos += count;
		}

		public unsafe void Append(char* value, int length)
		{
			var pos = _pos;
			if (pos > _chars.Length - length) Grow(length);

			var dst = _chars.Slice(_pos, length);
			for (var i = 0; i < dst.Length; i++) dst[i] = *value++;
			_pos += length;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Span<char> AppendSpan(int length)
		{
			var origPos = _pos;
			if (origPos > _chars.Length - length) Grow(length);

			_pos = origPos + length;
			return _chars.Slice(origPos, length);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		private void GrowAndAppend(char c)
		{
			Grow(1);
			Append(c);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		private void Grow(int requiredAdditionalCapacity)
		{
			Debug.Assert(requiredAdditionalCapacity > _chars.Length - _pos);

			var poolArray =
				BucketsBasedCrossThreadsMemoryPool<char>.Shared.Rent(Math.Max(_pos + requiredAdditionalCapacity,
					_chars.Length * 2));

			_chars.CopyTo(poolArray.Memory.Span);

			var toReturn = _arrayToReturnToPool;
			_arrayToReturnToPool = poolArray;
			_chars = _arrayToReturnToPool.Memory.Span;

			if (toReturn != null) toReturn.Dispose();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Dispose()
		{
			var toReturn = _arrayToReturnToPool;
			this = default; // for safety, to avoid using pooled array if this instance is erroneously appended to again
			if (toReturn != null) toReturn.Dispose();
		}
	}
}