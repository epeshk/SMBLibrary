using System;

namespace SMBLibrary.Client;

public class NTResult<T>
{
    private readonly T _content;
    private readonly bool _hasContent;
    public NTStatus Status { get; }

    public T Content => _hasContent
        ? _content
        : throw new InvalidOperationException($"{this.GetType().Name} has no content. Status: {Status}");
        
    public NTResult(NTStatus status) => Status = status;

    public NTResult(T content) : this(NTStatus.STATUS_SUCCESS, content) { }
    public NTResult(NTStatus status, T content) : this(status)
    {
        _content = content;
        _hasContent = true;
    }

    public static implicit operator NTResult<T>(NTStatus status) => new(status);
    public static implicit operator NTResult<T>(T result) => new(result);
}