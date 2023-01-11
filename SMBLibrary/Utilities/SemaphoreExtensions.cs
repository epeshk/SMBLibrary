using System;
using System.Threading;
using System.Threading.Tasks;

namespace Utilities;

internal struct SemaphoreReleaser : IDisposable
{
  private readonly SemaphoreSlim semaphore;

  public SemaphoreReleaser(SemaphoreSlim semaphore)
  {
    this.semaphore = semaphore;
  }

  public void Dispose()
  {
    semaphore?.Release();
  }
}

internal static class SemaphoreExtensions
{
  public static async Task<SemaphoreReleaser> AcquireAsync(this SemaphoreSlim semaphore, CancellationToken token)
  {
    await semaphore.WaitAsync(token);
    return new SemaphoreReleaser(semaphore);
  }
}