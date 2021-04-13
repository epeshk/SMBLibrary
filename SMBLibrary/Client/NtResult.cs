namespace SMBLibrary.Client
{
	public struct NtResult<T>
	{
		public NTStatus Status;
		public T Result;

		public void Deconstruct(out NTStatus status, out T result)
		{
			result = Result;
			status = Status;
		}
	}

	public struct NtResult
	{
		public static NtResult<T> Create<T>(NTStatus status)
		{
			return new NtResult<T> {Status = status};
		}

		public static NtResult<T> Create<T>(NTStatus status, T result)
		{
			return new NtResult<T>
			{
				Status = status, Result = result
			};
		}
	}
}