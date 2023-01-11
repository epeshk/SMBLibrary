/* Copyright (C) 2017-2022 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using SMBLibrary.NetBios;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Client
{
    public class SMB2Client : ISMBClient
    {
        private static readonly Lazy<ArrayPool<byte>> defaultPool = new(ArrayPool<byte>.Create); 

        private static int clientIdSource;
        private readonly int clientId;
        
        private readonly Action<string> traceLog;
        internal readonly Action<string> errorLog;
        private readonly TimeSpan timeout;
        private readonly ArrayPool<byte> pool;

        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        public static readonly uint ClientMaxTransactSize = 1048576;
        public static readonly uint ClientMaxReadSize = 1048576;
        public static readonly uint ClientMaxWriteSize = 1048576;
        private static readonly ushort DesiredCredits = 16;

        private string m_serverName;
        private SMBTransportType m_transport;
        private bool m_isConnected;
        private bool m_isLoggedIn;
        private Socket m_clientSocket;

        private readonly ConcurrentDictionary<ulong, TaskCompletionSource<SMB2Response>> m_incomingQueue = new();
        private readonly SemaphoreSlim asyncLock = new(1, 1);
        private readonly CancellationTokenSource m_globalCancellation = new();
        private readonly CancellationToken m_globalCancellationToken;
        private TaskCompletionSource<SessionPacket> m_sessionResponsePacket;

        private uint m_messageID = 0;
        private SMB2Dialect m_dialect;
        private bool m_signingRequired;
        private SMBSigningKey m_signingKey;
        private bool m_encryptSessionData;
        private SMBEncryptor m_encryptionKey;
        private byte[] m_decryptionKey;
        private uint m_maxTransactSize;
        private uint m_maxReadSize;
        private uint m_maxWriteSize;
        private ulong m_sessionID;
        private byte[] m_securityBlob;
        private byte[] m_sessionKey;
        private ushort m_availableCredits = 1;

        private ITrailerDecryptor decryptor = new TrailerDecryptor();
        
        public bool EncryptionRequired { get; set; }
        public bool SigningRequired { get; set; }

        public SMB2Client(
            TimeSpan defaultTimeout,
            Action<string> errorLog,
            Action<string> traceLog = null,
            ArrayPool<byte> pool = null)
        {
            this.traceLog = traceLog;
            this.errorLog = errorLog;
            this.timeout = defaultTimeout;
            this.pool = pool ?? defaultPool.Value;
            m_globalCancellationToken = m_globalCancellation.Token;
            clientId = Interlocked.Increment(ref clientIdSource) - 1;
        }

        /// <param name="serverName">
        /// When a Windows Server host is using Failover Cluster and Cluster Shared Volumes, each of those CSV file shares is associated
        /// with a specific host name associated with the cluster and is not accessible using the node IP address or node host name.
        /// </param>
        public Task<bool> Connect(string serverName, SMBTransportType transport)
        {
            m_serverName = serverName;
            IPAddress[] hostAddresses = Dns.GetHostAddresses(serverName);
            if (hostAddresses.Length == 0)
            {
                throw new Exception(String.Format("Cannot resolve host name {0} to an IP address", serverName));
            }
            IPAddress serverAddress = hostAddresses[0];
            return Connect(serverAddress, transport);
        }

        public Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport)
        {
            int port = (transport == SMBTransportType.DirectTCPTransport ? DirectTCPPort : NetBiosOverTCPPort);
            return Connect(serverAddress, transport, port);
        }

        private async Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport, int port)
        {
            if (m_serverName == null)
            {
                m_serverName = serverAddress.ToString();
            }

            m_transport = transport;
            if (!m_isConnected)
            {
                if (!ConnectSocket(serverAddress, port))
                {
                    return false;
                }

                if (transport == SMBTransportType.NetBiosOverTCP)
                {
                    SessionRequestPacket sessionRequest = new SessionRequestPacket();
                    sessionRequest.CalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServiceService);
                    sessionRequest.CallingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService);
                    m_sessionResponsePacket = new TaskCompletionSource<SessionPacket>(TaskCreationOptions.RunContinuationsAsynchronously);
                    await TrySendPacketAsync(m_clientSocket, sessionRequest);

                    SessionPacket sessionResponsePacket = await m_sessionResponsePacket.Task;
                    if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                    {
                        m_clientSocket.Disconnect(false);
                        if (!ConnectSocket(serverAddress, port))
                        {
                            return false;
                        }

                        NameServiceClient nameServiceClient = new NameServiceClient(serverAddress);
                        string serverName = nameServiceClient.GetServerName();
                        if (serverName == null)
                        {
                            return false;
                        }

                        sessionRequest.CalledName = serverName;
                        m_sessionResponsePacket = new TaskCompletionSource<SessionPacket>(TaskCreationOptions.RunContinuationsAsynchronously);
                        await TrySendPacketAsync(m_clientSocket, sessionRequest);

                        sessionResponsePacket = await m_sessionResponsePacket.Task;
                        if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                        {
                            return false;
                        }
                    }
                }

                bool supportsDialect = await NegotiateDialect();
                if (!supportsDialect)
                {
                    m_clientSocket.Close();
                }
                else
                {
                    m_isConnected = true;
                }
            }
            return m_isConnected;
        }

        private bool ConnectSocket(IPAddress serverAddress, int port)
        {
            m_clientSocket = new Socket(serverAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            m_clientSocket.NoDelay = true;

            try
            {
                m_clientSocket.Connect(serverAddress, port);
            }
            catch (SocketException)
            {
                return false;
            }

            ConnectionState state = new ConnectionState(m_clientSocket, pool, decryptor);
            NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
            m_clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, OnClientSocketReceive, state);
            return true;
        }

        public void Disconnect()
        {
            if (m_isConnected)
            {
                m_clientSocket.Disconnect(false);
                m_isConnected = false;
            }
        }

        private async Task<bool> NegotiateDialect()
        {
            NegotiateRequest request = new NegotiateRequest();
            request.SecurityMode = SigningRequired ? SecurityMode.SigningRequired : SecurityMode.SigningEnabled;
            request.Capabilities = Capabilities.Encryption;
            request.ClientGuid = Guid.NewGuid();
            request.ClientStartTime = DateTime.Now;
            request.Dialects.Add(SMB2Dialect.SMB202);
            request.Dialects.Add(SMB2Dialect.SMB210);
            request.Dialects.Add(SMB2Dialect.SMB300);

            NegotiateResponse response = await TrySendCommand<NegotiateResponse>(request);
            if (response != null && response.Header.Status == NTStatus.STATUS_SUCCESS)
            {
                m_dialect = response.DialectRevision;
                m_signingRequired = (response.SecurityMode & SecurityMode.SigningRequired) > 0 || SigningRequired;
                m_maxTransactSize = Math.Min(response.MaxTransactSize, ClientMaxTransactSize);
                m_maxReadSize = Math.Min(response.MaxReadSize, ClientMaxReadSize);
                m_maxWriteSize = Math.Min(response.MaxWriteSize, ClientMaxWriteSize);
                m_securityBlob = response.SecurityBuffer;
                return true;
            }
            return false;
        }

        public Task<NTStatus> Login(string domainName, string userName, string password)
        {
            return Login(domainName, userName, password, AuthenticationMethod.NTLMv2);
        }

        public async Task<NTStatus> Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod)
        {
            if (!m_isConnected)
            {
                throw new InvalidOperationException("A connection must be successfully established before attempting login");
            }

            byte[] negotiateMessage = NTLMAuthenticationHelper.GetNegotiateMessage(m_securityBlob, domainName, authenticationMethod);
            if (negotiateMessage == null)
            {
                return NTStatus.SEC_E_INVALID_TOKEN;
            }

            SessionSetupRequest request = new SessionSetupRequest();
            request.SecurityMode = SecurityMode.SigningEnabled;
            request.SecurityBuffer = negotiateMessage;
            SMB2Response response = await TrySendCommand<SMB2Response>(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED && response is SessionSetupResponse)
                {
                    string spn = string.Format("cifs/{0}", m_serverName);
                    byte[] authenticateMessage = NTLMAuthenticationHelper.GetAuthenticateMessage(((SessionSetupResponse)response).SecurityBuffer, domainName, userName, password, spn, authenticationMethod, out m_sessionKey);
                    if (authenticateMessage == null)
                    {
                        return NTStatus.SEC_E_INVALID_TOKEN;
                    }

                    m_sessionID = response.Header.SessionID;
                    request = new SessionSetupRequest();
                    request.SecurityMode = SecurityMode.SigningEnabled;
                    request.SecurityBuffer = authenticateMessage;
                    response = await TrySendCommand<SMB2Response>(request);
                    if (response != null)
                    {
                        m_isLoggedIn = (response.Header.Status == NTStatus.STATUS_SUCCESS);
                        if (m_isLoggedIn)
                        {
                            m_signingKey = new SMBSigningKey(SMB2Cryptography.GenerateSigningKey(m_sessionKey, m_dialect, null));
                            if (m_dialect == SMB2Dialect.SMB300)
                            {
                                m_encryptSessionData = (((SessionSetupResponse)response).SessionFlags & SessionFlags.EncryptData) > 0 || EncryptionRequired;
                                m_encryptionKey = new SMBEncryptor(SMB2Cryptography.GenerateClientEncryptionKey(m_sessionKey, SMB2Dialect.SMB300, null));
                                m_decryptionKey = SMB2Cryptography.GenerateClientDecryptionKey(m_sessionKey, SMB2Dialect.SMB300, null);
                                decryptor.SetDecryptionKey(m_decryptionKey);
                            }
                            else if (EncryptionRequired)
                            {
                                throw new InvalidOperationException("Encryption is not supported.");
                            }
                        }
                        return response.Header.Status;
                    }
                }
                else
                {
                    return response.Header.Status;
                }
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTStatus> Logoff()
        {
            if (!m_isConnected)
            {
                throw new InvalidOperationException("A login session must be successfully established before attempting logoff");
            }

            LogoffRequest request = new LogoffRequest();

            SMB2Response response = await TrySendCommand<SMB2Response>(request);
            if (response != null)
            {
                m_isLoggedIn = (response.Header.Status != NTStatus.STATUS_SUCCESS);
                return response.Header.Status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }
        
        public async Task<NTResult<List<string>>> ListShares()
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before retrieving share list");
            }

            var namedPipeShare = await TreeConnect("IPC$");
            if (namedPipeShare.Status != NTStatus.STATUS_SUCCESS)
            {
                return namedPipeShare.Status;
            }

            var shares = await ServerServiceHelper.ListShares(namedPipeShare.Content, m_serverName, SMBLibrary.Services.ShareType.DiskDrive);
            await namedPipeShare.Content.Disconnect();
            return shares;
        }

        public async Task<NTResult<ISMBFileStore>> TreeConnect(string shareName)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before connecting to a share");
            }

            string sharePath = String.Format(@"\\{0}\{1}", m_serverName, shareName);
            TreeConnectRequest request = new TreeConnectRequest();
            request.Path = sharePath;
            SMB2Response response = await TrySendCommand<SMB2Response>(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is TreeConnectResponse connectResponse)
                {
                    bool encryptShareData = (connectResponse.ShareFlags & ShareFlags.EncryptData) > 0;
                    return new SMB2FileStore(this, connectResponse.Header.TreeID, m_encryptSessionData || encryptShareData);
                }

                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        private void OnClientSocketReceive(IAsyncResult ar)
        {
            ConnectionState state = (ConnectionState)ar.AsyncState;
            Socket clientSocket = state.ClientSocket;

            if (!clientSocket.Connected)
            {
                return;
            }

            int numberOfBytesReceived = 0;
            try
            {
                numberOfBytesReceived = clientSocket.EndReceive(ar);
            }
            catch (ArgumentException) // The IAsyncResult object was not returned from the corresponding synchronous method on this class.
            {
                errorLog?.Invoke($"{clientId} - [ReceiveCallback] EndReceive ArgumentException");
                return;
            }
            catch (ObjectDisposedException)
            {
                errorLog?.Invoke($"{clientId} - [ReceiveCallback] EndReceive ObjectDisposedException");
                m_globalCancellation.Cancel();
                return;
            }
            catch (SocketException ex)
            {
                errorLog?.Invoke($"{clientId} - [ReceiveCallback] EndReceive SocketException: " + ex.Message);
                m_globalCancellation.Cancel();
                return;
            }

            if (numberOfBytesReceived == 0)
            {
                m_globalCancellation.Cancel();
                m_isConnected = false;
            }
            else
            {
                NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
                buffer.SetNumberOfBytesReceived(numberOfBytesReceived);
                traceLog?.Invoke($"{clientId} - received {numberOfBytesReceived} bytes");
                ProcessConnectionBuffer(state);

                try
                {
                    clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), state);
                }
                catch (ObjectDisposedException)
                {
                    m_isConnected = false;
                    errorLog?.Invoke("[ReceiveCallback] BeginReceive ObjectDisposedException");
                }
                catch (SocketException ex)
                {
                    m_isConnected = false;
                    errorLog?.Invoke("[ReceiveCallback] BeginReceive SocketException: " + ex.Message);
                    m_globalCancellation.Cancel();
                }
            }
        }

        private void ProcessConnectionBuffer(ConnectionState state)
        {
            NBTConnectionReceiveBuffer receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacket packet = null;
                try
                {
                    packet = receiveBuffer.DequeuePacket();
                }
                catch (Exception e)
                {
                    errorLog?.Invoke(e.ToString());
                    state.ClientSocket.Close();
                    break;
                }

                if (packet != null)
                {
                    ProcessPacket(packet, state);
                }
            }
        }

        private void ProcessPacket(SessionPacket packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                var messageBytes = packet.Trailer[0].Array;

                SMB2Response command;
                try
                {
                    var dataBuffer = packet.Trailer.Length > 1 ? packet.Trailer[1].Array : null;
                    command = SMB2Response.ReadResponse(messageBytes, 0, dataBuffer, pool);
                    traceLog?.Invoke($"{clientId} - received command of type {command.CommandName} ({command.GetType().Name}) with messageId: {command.Header.MessageID}, sessionId: {command.Header.SessionID}");
                }
                catch (Exception ex)
                {
                    errorLog?.Invoke($"{clientId} - Invalid SMB2 response: " + ex.Message);
                    state.ClientSocket.Close();
                    m_isConnected = false;
                    m_globalCancellation.Cancel();
                    return;
                }

                m_availableCredits += command.Header.Credits;

                if (m_transport == SMBTransportType.DirectTCPTransport && command is NegotiateResponse)
                {
                    NegotiateResponse negotiateResponse = (NegotiateResponse)command;
                    if ((negotiateResponse.Capabilities & Capabilities.LargeMTU) > 0)
                    {
                        // [MS-SMB2] 3.2.5.1 Receiving Any Message - If the message size received exceeds Connection.MaxTransactSize, the client MUST disconnect the connection.
                        // Note: Windows clients do not enforce the MaxTransactSize value, we add 256 bytes.
                        int maxPacketSize = SessionPacket.HeaderLength + (int)Math.Min(negotiateResponse.MaxTransactSize, ClientMaxTransactSize) + 256;
                        if (maxPacketSize > state.ReceiveBuffer.Buffer.Length)
                        {
                            state.ReceiveBuffer.IncreaseBufferSize(maxPacketSize);
                        }
                    }
                }

                // [MS-SMB2] 3.2.5.1.2 - If the MessageId is 0xFFFFFFFFFFFFFFFF, this is not a reply to a previous request,
                // and the client MUST NOT attempt to locate the request, but instead process it as follows:
                // If the command field in the SMB2 header is SMB2 OPLOCK_BREAK, it MUST be processed as specified in 3.2.5.19.
                // Otherwise, the response MUST be discarded as invalid.
                if (command.Header.MessageID != 0xFFFFFFFFFFFFFFFF || command.Header.Command == SMB2CommandName.OplockBreak)
                {
                    if (command.Header.IsAsync && command.Header.Status == NTStatus.STATUS_PENDING)
                        return;
                    var key = command.Header.MessageID;
                    if (!m_incomingQueue.TryRemove(key, out var completion))
                    {
                        errorLog?.Invoke($"{clientId} - Not found matching request for messageId: {key}");
                        return;
                    }
                    
                    traceLog?.Invoke($"{clientId} - completing request with messageId: {key}");
                    completion.SetResult(command);
                }
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                m_sessionResponsePacket.TrySetResult(packet);
            }
            else if (packet is SessionKeepAlivePacket && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                // [RFC 1001] NetBIOS session keep alives do not require a response from the NetBIOS peer
            }
            else
            {
                errorLog?.Invoke("Inappropriate NetBIOS session packet");
                m_globalCancellation.Cancel();
                state.ClientSocket.Close();
            }
        }

        private async Task<TResponse> TrySendCommand<TResponse>(SMB2Request request) where TResponse : SMB2Response
        {
            var responseCommand = await TrySendCommand(request, m_encryptSessionData);
            return responseCommand as TResponse;
        }

        internal async Task<TResponse> TrySendCommand<TResponse>(SMB2Request request, bool encryptData) where TResponse : SMB2Response
        {
            var responseCommand = await TrySendCommand(request, encryptData);
            return responseCommand as TResponse;
        }

        private async Task<SMB2Response> TrySendCommand(SMB2Request request, bool encryptData)
        {
            var responseTask = await SendAsync(request, encryptData);

            try
            {
                var response = await responseTask.WaitAsync(timeout, m_globalCancellationToken);
                traceLog?.Invoke($"{clientId} - received response for messageId: {response.Header.MessageID}");
                return response;
            }
            catch (OperationCanceledException e) when (e.CancellationToken == m_globalCancellationToken)
            {
                throw new IOException($"{nameof(SMB2Client)} was disconnected.");
            }
        }

        private async Task<Task<SMB2Response>> SendAsync(SMB2Request request, bool encryptData)
        {
            using var releaser = await asyncLock.AcquireAsync(m_globalCancellationToken);

            if (m_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTCP)
            {
                request.Header.CreditCharge = 0;
                request.Header.Credits = 1;
                m_availableCredits -= 1;
            }
            else
            {
                if (request.Header.CreditCharge == 0)
                {
                    request.Header.CreditCharge = 1;
                }

                if (m_availableCredits < request.Header.CreditCharge)
                {
                    throw new Exception("Not enough credits");
                }

                m_availableCredits -= request.Header.CreditCharge;

                if (m_availableCredits < DesiredCredits)
                {
                    request.Header.Credits += (ushort)(DesiredCredits - m_availableCredits);
                }
            }

            request.Header.MessageID = m_messageID;
            request.Header.SessionID = m_sessionID;
            // [MS-SMB2] If the client encrypts the message [..] then the client MUST set the Signature field of the SMB2 header to zero
            if (m_signingRequired && !encryptData)
            {
                request.Header.IsSigned = (m_sessionID != 0 &&
                                           ((request.CommandName == SMB2CommandName.TreeConnect || request.Header.TreeID != 0) ||
                                            (m_dialect == SMB2Dialect.SMB300 && request.CommandName == SMB2CommandName.Logoff)));
                if (request.Header.IsSigned)
                {
                    request.Header.Signature = new byte[16]; // Request could be reused
                    byte[] signature = SMB2Cryptography.CalculateSignature(m_signingKey, m_dialect, request.GetBytes());
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    request.Header.Signature = ByteReader.ReadBytes(signature, 0, 16);
                }
            }

            var completion = new TaskCompletionSource<SMB2Response>(TaskCreationOptions.RunContinuationsAsynchronously);
            var key = request.Header.MessageID;
            if (!m_incomingQueue.TryAdd(key, completion))
            {
                var errorMessage =
                    $"{clientId} - Duplicate key. MessageID: {request.Header.MessageID}, SessionID: {request.Header.SessionID}";
                errorLog?.Invoke(errorMessage);
                throw new InvalidOperationException(errorMessage);
            }

            traceLog?.Invoke(
                $"{clientId} - Sending message of type {request.GetType().Name} with messageId: {request.Header.MessageID}, sessionId: {request.Header.SessionID} to {m_clientSocket.RemoteEndPoint}");

            await TrySendCommand(m_clientSocket, request, encryptData ? m_encryptionKey : null);

            if (m_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTCP)
            {
                m_messageID++;
            }
            else
            {
                m_messageID += request.Header.CreditCharge;
            }

            return completion.Task;
        }

        public uint MaxTransactSize
        {
            get
            {
                return m_maxTransactSize;
            }
        }

        public uint MaxReadSize
        {
            get
            {
                return m_maxReadSize;
            }
        }

        public uint MaxWriteSize
        {
            get
            {
                return m_maxWriteSize;
            }
        }

        public bool IsConnected
        {
            get
            {
                return m_isConnected;
            }
        }

        private async Task TrySendCommand(Socket socket, SMB2Request request, SMBEncryptor encryptor)
        {
            SessionMessagePacket packet = new SessionMessagePacket();
            byte[] pooledArray = null;
            var requestBytes = request.GetBytes();

            if (encryptor != null)
            {
                if (requestBytes.Length == 1)
                    packet.Trailer = encryptor.TransformMessage(requestBytes[0], request.Header.SessionID);
                else
                {
                    pooledArray = pool.Rent(requestBytes.Sum(x => x.Count));
                    int offset = 0;
                    foreach (var segment in requestBytes)
                    {
                        segment.AsSpan().CopyTo(pooledArray.AsSpan(offset));
                        offset += segment.Count;
                    }
                    packet.Trailer = encryptor.TransformMessage(new ArraySegment<byte>(pooledArray, 0, offset), request.Header.SessionID);
                }
            }
            else
            {
                packet.Trailer = requestBytes;
            }

            try
            {
                await TrySendPacketAsync(socket, packet);
            }
            finally
            {
                if (pooledArray != null)
                    pool.Return(pooledArray);
            }
        }

        private static Task TrySendPacketAsync(Socket socket, SessionPacket packet)
        {
            var packetBytes = packet.GetBytes();
            return socket.SendAsync(packetBytes, SocketFlags.None);
        }
    }
}
