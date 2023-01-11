using System;
using System.Buffers;
using System.Runtime.InteropServices;

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

internal class ArrayMemoryOwner : IMemoryOwner<byte>
{
    private readonly ArrayPool<byte> pool;
    private readonly Action<string> errorLogger;

    public ArrayMemoryOwner(byte[] array, int offset, int length, ArrayPool<byte> pool, Action<string> errorLogger)
    {
        this.pool = pool;
        this.errorLogger = errorLogger;
        Memory = array.AsMemory(offset, length);
    }

    public Memory<byte> Memory { get; }

    private void ReleaseUnmanagedResources()
    {
        if (MemoryMarshal.TryGetArray<byte>(Memory, out var segment))
            pool.Return(segment.Array!);
    }

    public void Dispose()
    {
        ReleaseUnmanagedResources();
        GC.SuppressFinalize(this);
    }

    ~ArrayMemoryOwner()
    {
        // ReSharper disable All
        try { errorLogger?.Invoke("SMBClient - Pooled array leak!"); }
        catch { }
        
        try { ReleaseUnmanagedResources(); }
        catch { }
    }
}