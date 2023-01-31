using System;

namespace SMBLibrary.Client
{
	public class NtResult<T>
	{
		private readonly T _content;
		private readonly bool _hasContent;
		public NTStatus Status { get; }

		public T Content => _hasContent
			? _content
			: throw new InvalidOperationException($"{this.GetType().Name} has no content. Status: {Status}");
        
		public NtResult(NTStatus status) => Status = status;

		public NtResult(T content) : this(NTStatus.STATUS_SUCCESS, content) { }
		public NtResult(NTStatus status, T content) : this(status)
		{
			_content = content;
			_hasContent = true;
		}

		public static implicit operator NtResult<T>(NTStatus status) => new(status);
		public static implicit operator NtResult<T>(T result) => new(result);
	}

	public struct NtResult
	{
		public static NtResult<T> Create<T>(NTStatus status)
		{
			return new NtResult<T>(status);
		}

		public static NtResult<T> Create<T>(NTStatus status, T result)
		{
			return new NtResult<T>(status, result);
		}
		public static NtResult<T> Create<T>(T result)
		{
			return new NtResult<T>(result);
		}
	}
}