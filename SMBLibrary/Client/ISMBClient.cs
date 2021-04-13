using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace SMBLibrary.Client
{
    public interface ISmbClient : IAsyncDisposable
    {
        ValueTask<bool> ConnectAsync(IPAddress serverAddress, SMBTransportType transport);

        ValueTask DisconnectAsync();

        ValueTask<NTStatus> LoginAsync(string domainName, string userName, string password);

        ValueTask<NTStatus> LoginAsync(string domainName, string userName, string password, AuthenticationMethod authenticationMethod);

        ValueTask<NTStatus> LogoffAsync();

        ValueTask<NtResult<IEnumerable<string>>> ListSharesAsync();

        ValueTask<NtResult<ISMBFileStore>> TreeConnectAsync(string shareName);

        uint MaxReadSize { get; }

        uint MaxWriteSize { get; }
    }
}
