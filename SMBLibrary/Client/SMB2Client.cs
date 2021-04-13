/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using MemoryPools.Memory;
using SMBLibrary.NetBios;
using SMBLibrary.SMB2;
using Utilities;
using ShareType = SMBLibrary.Services.ShareType;

#pragma warning disable 1998

namespace SMBLibrary.Client
{
    public class Smb2Client : ISmbClient
    {
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        public static readonly uint ClientMaxTransactSize = 1048576;
        public static readonly uint ClientMaxReadSize = 1048576;
        public static readonly uint ClientMaxWriteSize = 1048576;
        private static readonly ushort DesiredCredits = 16; 

        private SMBTransportType _transport;
        private bool _isConnected;
        private bool _isLoggedIn;
        private Socket _clientSocket;

        private volatile SMB2Command m_incoming_first = null;
        private List<SMB2Command> m_incomingQueue = new List<SMB2Command>();
        private AutoResetEvent m_incomingQueueEventHandle = new AutoResetEvent(false);

        private SessionPacketBase _sessionResponsePacket;
        private AutoResetEvent _sessionResponseEventHandle = new AutoResetEvent(false);

        private uint _messageId;
        private SMB2Dialect _dialect;
        private bool _signingRequired;
        private uint _maxTransactSize;
        private uint _maxReadSize;
        private uint _maxWriteSize;
        private ulong _sessionId;
        private IMemoryOwner<byte> _securityBlob;
        private byte[] _sessionKey;
        private ushort _availableCredits = 1;

        private ConnectionState _connectionState;

        Action<Task<int>, object> _onClientSocketChainedReceiveCached;

        public Smb2Client()
        {
            _onClientSocketChainedReceiveCached = OnClientSocketChainedReceive;
        }

        public async ValueTask<bool> ConnectAsync(IPAddress serverAddress, SMBTransportType transport)
        {
            _transport = transport;
            if (!_isConnected)
            {
                int port;
                if (transport == SMBTransportType.NetBiosOverTCP)
                {
                    port = NetBiosOverTCPPort;
                }
                else
                {
                    port = DirectTCPPort;
                }

                if (!ConnectSocket(serverAddress, port))
                {
                    return false;
                }

                if (transport == SMBTransportType.NetBiosOverTCP)
                {
                    var sessionRequest = ObjectsPool<SessionRequestPacket>.Get().Init();
                    sessionRequest.CalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServiceService);
                    sessionRequest.CallingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService);
                    TrySendPacket(_clientSocket, sessionRequest);

                    var sessionResponsePacket = WaitForSessionResponsePacket();
                    if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                    {
                        _clientSocket.Disconnect(false);
                        if (!ConnectSocket(serverAddress, port))
                        {
                            return false;
                        }

                        var nameServiceClient = new NameServiceClient(serverAddress);
                        var serverName = nameServiceClient.GetServerName();
                        if (serverName == null)
                        {
                            return false;
                        }

                        sessionRequest.CalledName = serverName;
                        TrySendPacket(_clientSocket, sessionRequest);

                        sessionResponsePacket = WaitForSessionResponsePacket();
                        if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                        {
                            return false;
                        }
                    }
                }

                var supportsDialect = NegotiateDialect();
                if (!supportsDialect)
                {
                    _clientSocket.Close();
                }
                else
                {
                    _isConnected = true;
                }
            }
            return _isConnected;
        }
        
        private bool ConnectSocket(IPAddress serverAddress, int port)
        {
            _clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            
            try
            {
                _clientSocket.Connect(serverAddress, port);
            }
            catch (SocketException)
            {
                return false;
            }

            _connectionState = new ConnectionState();
            var buffer = _connectionState.ReceiveBuffer;
            try
            {
                _clientSocket
                    .ReceiveAsync(buffer.Buffer.Slice(buffer.WriteOffset, buffer.AvailableLength), SocketFlags.None)
                    .AsTask()
                    .ContinueWith(_onClientSocketChainedReceiveCached, TaskContinuationOptions.LongRunning);
            }
            catch (ArgumentException) // The IAsyncResult object was not returned from the corresponding synchronous method on this class.
            {
                return false;
            }
            catch (ObjectDisposedException)
            {
                Log("[ReceiveCallback] EndReceive ObjectDisposedException");
                return false;
            }
            catch (SocketException ex) when (ex.ErrorCode == (int) SocketError.ConnectionReset)
            {
                ;
            }
            catch (SocketException ex) 
            {
                Log("[ReceiveCallback] EndReceive SocketException: " + ex.Message);
                return false;
            }
            return true;
        }

        private void OnClientSocketChainedReceive(Task<int> task, object objState)
        {
            var wellDone = false;
            var bytesReceived = 0;

            try
            {
                bytesReceived = task.Result;

                while (bytesReceived > 0)
                {
                    wellDone = false;

                    if (!_clientSocket.Connected)
                    {
                        return;
                    }

                    var numberOfBytesReceived = bytesReceived;

                    var buffer = _connectionState.ReceiveBuffer;
                    buffer.SetNumberOfBytesReceived(numberOfBytesReceived);
                    ProcessConnectionBuffer(_connectionState);

                    bytesReceived = _clientSocket.Receive(buffer.Buffer.Slice(buffer.WriteOffset, buffer.AvailableLength).Span, SocketFlags.None);

                    wellDone = true;
                }

                _isConnected = false;
            }
            catch (ObjectDisposedException)
            {
                Log("[ReceiveCallback] EndReceive ObjectDisposedException");
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)   // by remote 
            {
                // Log("[ReceiveCallback] EndReceive known error: " + ex.Message);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted || 
                                             ex.SocketErrorCode == SocketError.OperationAborted)       // by us 
            {
                ; // Log("[ReceiveCallback] EndReceive known error: " + ex.Message);
            }
            catch (SocketException ex) 
            {
                Log("[ReceiveCallback] EndReceive SocketException: " + ex.Message + $" ({ex.SocketErrorCode})");
            }
            catch (Exception ee)
            {
                Log("[ReceiveCallback] EndReceive unexpected: " + ee.Message);
            }
            finally
            {
                if (!wellDone)
                {
                    _connectionState.Dispose();
                    _connectionState = null;
                }
            }
        }

        public async ValueTask DisconnectAsync()
        {
            if (_clientSocket?.Connected == true)
            {
                _clientSocket.Disconnect(false);
                _clientSocket.Close();
                _isConnected = false;
                _clientSocket = null;
            }
        }

        private bool NegotiateDialect()
        {
            var request = ObjectsPool<NegotiateRequest>.Get().Init();
            
            request.SecurityMode = SecurityMode.SigningEnabled;
            request.ClientGuid = Guid.NewGuid();
            request.ClientStartTime = DateTime.Now;
            request.Dialects.Add(SMB2Dialect.SMB202);
            request.Dialects.Add(SMB2Dialect.SMB210);

            TrySendCommand(request);
            // request.Dispose();
            
            var response = WaitForCommand(SMB2CommandName.Negotiate) as NegotiateResponse;
            if (response != null && response.Header.Status == NTStatus.STATUS_SUCCESS)
            {
                _dialect = response.DialectRevision;
                _signingRequired = (response.SecurityMode & SecurityMode.SigningRequired) > 0;
                _maxTransactSize = Math.Min(response.MaxTransactSize, ClientMaxTransactSize);
                _maxReadSize = Math.Min(response.MaxReadSize, ClientMaxReadSize);
                _maxWriteSize = Math.Min(response.MaxWriteSize, ClientMaxWriteSize);
                _securityBlob = response.SecurityBuffer.AddOwner();

                response.Dispose();
                return true;
            }
            response?.Dispose();
            return false;
        }

        public ValueTask<NTStatus> LoginAsync(string domainName, string userName, string password) => 
            LoginAsync(domainName, userName, password, AuthenticationMethod.NTLMv2);

        public async ValueTask<NTStatus> LoginAsync(string domainName, string userName, string password, AuthenticationMethod authenticationMethod)
        {
            if (!_isConnected)
            {
                throw new InvalidOperationException("A connection must be successfully established before attempting login");
            }

            var negotiateMessage = NTLMAuthenticationHelper.GetNegotiateMessage(_securityBlob.Memory.Span, domainName, authenticationMethod);
            if (negotiateMessage == null)
            {
                return NTStatus.SEC_E_INVALID_TOKEN;
            }

            var request = ObjectsPool<SessionSetupRequest>.Get().Init();
            SMB2Command response = null;
            try
            {
                request.SecurityMode = SecurityMode.SigningEnabled;
                request.SecurityBuffer = negotiateMessage;
                TrySendCommand(request);
                request = null;

                response = WaitForCommand(SMB2CommandName.SessionSetup);
                if (response != null)
                {
                    if (response.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED &&
                        response is SessionSetupResponse)
                    {
                        var authenticateMessage = NTLMAuthenticationHelper.GetAuthenticateMessage(
                            ((SessionSetupResponse) response).SecurityBuffer.Memory.Span, domainName, userName, password,
                            authenticationMethod, out _sessionKey);
                        if (authenticateMessage == null)
                        {
                            return NTStatus.SEC_E_INVALID_TOKEN;
                        }

                        _sessionId = response.Header.SessionId;
                        response.Dispose();

                        request = ObjectsPool<SessionSetupRequest>.Get().Init();
                        request.SecurityMode = SecurityMode.SigningEnabled;
                        request.SecurityBuffer = authenticateMessage;
                        TrySendCommand(request);
                        request = null;

                        response = WaitForCommand(SMB2CommandName.SessionSetup);
                        if (response != null)
                        {
                            _isLoggedIn = (response.Header.Status == NTStatus.STATUS_SUCCESS);

                            var status = response.Header.Status;
                            return status;
                        }
                    }
                    else
                    {
                        var status = response.Header.Status;
                        return status;
                    }
                }
            }
            finally
            {
                request?.Dispose();
                response?.Dispose();
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async ValueTask<NTStatus> LogoffAsync()
        {
            if (!_isConnected)
            {
                throw new InvalidOperationException("A login session must be successfully established before attempting logoff");
            }

            var request = ObjectsPool<LogoffRequest>.Get().Init();
            TrySendCommand(request);
            // request.Dispose();

            var response = WaitForCommand(SMB2CommandName.Logoff);
            if (response != null)
            {
                _isLoggedIn = (response.Header.Status != NTStatus.STATUS_SUCCESS);

                var status = response.Header.Status;
                response.Dispose();
                return status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public async ValueTask<NtResult<IEnumerable<string>>> ListSharesAsync()
        {
            if (!_isConnected || !_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before retrieving share list");
            }

            var (status, namedPipeShare) = await TreeConnectAsync("IPC$");
            if (namedPipeShare == null)
            {
                return NtResult.Create<IEnumerable<string>>(status);
            }

            var shares = ServerServiceHelper.ListShares(namedPipeShare, ShareType.DiskDrive, out status);
            namedPipeShare.Disconnect();

            return new NtResult<IEnumerable<string>> {Result = shares, Status = status};
        }

        public async ValueTask<NtResult<ISMBFileStore>> TreeConnectAsync(string shareName)
        {
            if (!_isConnected || !_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before connecting to a share");
            }

            NTStatus status;
            var serverIPAddress = ((IPEndPoint)_clientSocket.RemoteEndPoint).Address;
            var sharePath = String.Format(@"\\{0}\{1}", serverIPAddress, shareName);
            var request = ObjectsPool<TreeConnectRequest>.Get().Init();
            request.Path = sharePath;
            
            await TrySendCommandAsync(request);
            request.Dispose();

            using (var response = WaitForCommand(SMB2CommandName.TreeConnect))
            {
                if (response != null)
                {
                    status = response.Header.Status;
                    if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is TreeConnectResponse)
                    {
                        return NtResult.Create(status, (ISMBFileStore) new Smb2FileStore(this, response.Header.TreeId));
                    }
                }
                else
                {
                    status = NTStatus.STATUS_INVALID_SMB;
                }
            }

            return NtResult.Create<ISMBFileStore>(status, null);
        }

        private void ProcessConnectionBuffer(ConnectionState state)
        {
            var receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacketBase packet;
                try
                {
                    packet = receiveBuffer.DequeuePacket();
                }
                catch (Exception)
                {
                    _clientSocket.Close();
                    break;
                }

                if (packet != null)
                {
                    ProcessPacket(packet, state);
                }
            }
        }

        protected virtual void ProcessPacket(SessionPacketBase packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                SMB2Command command;
                try
                {
                    command = SMB2Command.ReadResponse(packet.Trailer.Memory.Span, 0);
                }
                catch (Exception ex)
                {
                    Log($"Invalid SMB2 response: {ex.Message}\n{ex.StackTrace}");
                    _clientSocket.Close();
                    _isConnected = false;
                    return;
                }

                _availableCredits += command.Header.Credits;

                if (_transport == SMBTransportType.DirectTCPTransport && command is NegotiateResponse)
                {
                    var negotiateResponse = (NegotiateResponse)command;
                    if ((negotiateResponse.Capabilities & Capabilities.LargeMTU) > 0)
                    {
                        // [MS-SMB2] 3.2.5.1 Receiving Any Message - If the message size received exceeds Connection.MaxTransactSize, the client MUST disconnect the connection.
                        // Note: Windows clients do not enforce the MaxTransactSize value, we add 256 bytes.
                        var maxPacketSize = SessionPacketBase.HeaderLength + (int)Math.Min(negotiateResponse.MaxTransactSize, ClientMaxTransactSize) + 256;
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
                if (command.Header.MessageId != 0xFFFFFFFFFFFFFFFF || command.Header.Command == SMB2CommandName.OplockBreak)
                {
                    if (Interlocked.CompareExchange(ref m_incoming_first, command, default) != default)
                    {
                        lock (m_incomingQueue)
                        {
                            m_incomingQueue.Add(command);
                        }
                    }

                    m_incomingQueueEventHandle.Set();
                }
                else
                {
                    command.Dispose();
                }
                
                packet.Dispose();
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) && _transport == SMBTransportType.NetBiosOverTCP)
            {
                _sessionResponsePacket?.Dispose();
                _sessionResponsePacket = packet;
                _sessionResponseEventHandle.Set();
            }
            else if (packet is SessionKeepAlivePacket && _transport == SMBTransportType.NetBiosOverTCP)
            {
                // [RFC 1001] NetBIOS session keep alives do not require a response from the NetBIOS peer
                packet.Dispose();
            }
            else
            {
                Log("Inappropriate NetBIOS session packet");
                _clientSocket.Close();
                packet.Dispose();
            }
        }

        internal SMB2Command WaitForCommand(SMB2CommandName commandName)
        {
            const int timeOut = 5000;
            var stopwatch = ObjectsPool<Stopwatch>.Get();
            stopwatch.Restart();

            var message = WaitForCommand(commandName, stopwatch, timeOut);
            
            ObjectsPool<Stopwatch>.Return(stopwatch);
            
            return message;
        }

        internal virtual SMB2Command WaitForCommand(SMB2CommandName commandName, Stopwatch stopwatch, int timeOut)
        {
            while (stopwatch.ElapsedMilliseconds < timeOut)
            {
                var top = m_incoming_first;
                if (top?.CommandName == commandName)
                {
                    m_incoming_first = null;
                    return top;
                }

                if (m_incomingQueue.Count != 0)
                {
                    lock (m_incomingQueue)
                    {
                        for (var index = 0; index < m_incomingQueue.Count; index++)
                        {
                            var command = m_incomingQueue[index];
                            if (command.CommandName == commandName)
                            {
                                m_incomingQueue.RemoveAt(index);
                                return command;
                            }
                        }
                    }
                }
                
                m_incomingQueueEventHandle.WaitOne(100);
            }

            return null;
        }

        internal SessionPacketBase WaitForSessionResponsePacket()
        {
            const int TimeOut = 5000;
            var stopwatch = ObjectsPool<Stopwatch>.Get();
            stopwatch.Restart();
            
            while (stopwatch.ElapsedMilliseconds < TimeOut)
            {
                var result = Interlocked.Exchange(ref _sessionResponsePacket, null);
                if (result != null)
                {
                    ObjectsPool<Stopwatch>.Return(stopwatch);
                    return result;
                }
                
                _sessionResponseEventHandle.WaitOne(500);
            }
            ObjectsPool<Stopwatch>.Return(stopwatch);
            return null;
        }

        private void Log(string message)
        {
            Console.WriteLine(message);
        }

        internal void TrySendCommand(SMB2Command request)
        {
            if (_dialect == SMB2Dialect.SMB202 || _transport == SMBTransportType.NetBiosOverTCP)
            {
                request.Header.CreditCharge = 0;
                request.Header.Credits = 1;
                _availableCredits -= 1;
            }
            else
            {
                if (request.Header.CreditCharge == 0)
                {
                    request.Header.CreditCharge = 1;
                }

                if (_availableCredits < request.Header.CreditCharge)
                {
                    throw new Exception("Not enough credits");
                }

                _availableCredits -= request.Header.CreditCharge;

                if (_availableCredits < DesiredCredits)
                {
                    request.Header.Credits += (ushort)(DesiredCredits - _availableCredits);
                }
            }

            request.Header.MessageId = _messageId;
            request.Header.SessionId = _sessionId;
            if (_signingRequired)
            {
                request.Header.IsSigned = (_sessionId != 0 && (request.CommandName == SMB2CommandName.TreeConnect || request.Header.TreeId != 0));
                if (request.Header.IsSigned)
                {
                    Span<byte> hash = stackalloc byte[16];
                    // request.Header.Signature = Arrays.Rent(16); // Request could be reused
                    var buffer = request.GetBytes();
                    using var hasher = new HMACSHA256(_sessionKey);
                    hasher.TryComputeHash(buffer.Memory.Span, hash, out _);
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    ByteReader.ReadBytes(request.Header.Signature.Memory.Span, hash, 0, 16);
                    buffer.Dispose();
                }
            }

            var creditCharge = request.Header.CreditCharge;
            
            TrySendCommand(_clientSocket, request);
            
            if (_dialect == SMB2Dialect.SMB202 || _transport == SMBTransportType.NetBiosOverTCP)
            {
                _messageId++;
            }
            else
            {
                _messageId += creditCharge;
            }
        }
        
        internal ValueTask TrySendCommandAsync(SMB2Command request)
        {
            if (_dialect == SMB2Dialect.SMB202 || _transport == SMBTransportType.NetBiosOverTCP)
            {
                request.Header.CreditCharge = 0;
                request.Header.Credits = 1;
                _availableCredits -= 1;
            }
            else
            {
                if (request.Header.CreditCharge == 0)
                {
                    request.Header.CreditCharge = 1;
                }

                if (_availableCredits < request.Header.CreditCharge)
                {
                    throw new Exception("Not enough credits");
                }

                _availableCredits -= request.Header.CreditCharge;

                if (_availableCredits < DesiredCredits)
                {
                    request.Header.Credits += (ushort)(DesiredCredits - _availableCredits);
                }
            }

            request.Header.MessageId = _messageId;
            request.Header.SessionId = _sessionId;
            if (_signingRequired)
            {
                request.Header.IsSigned = (_sessionId != 0 && (request.CommandName == SMB2CommandName.TreeConnect || request.Header.TreeId != 0));
                if (request.Header.IsSigned)
                {
                    Span<byte> hash = stackalloc byte[16];
                    //request.Header.Signature = Arrays.Rent(16); // Request could be reused
                    var buffer = request.GetBytes();
                    using var hasher = new HMACSHA256(_sessionKey);
                    hasher.TryComputeHash(buffer.Memory.Span, hash, out _);
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    ByteReader.ReadBytes(request.Header.Signature.Memory.Span, hash, 0, 16);
                    buffer.Dispose();
                }
            }

            var creditCharge = request.Header.CreditCharge;
            
            TrySendCommand(_clientSocket, request);
            
            if (_dialect == SMB2Dialect.SMB202 || _transport == SMBTransportType.NetBiosOverTCP)
            {
                _messageId++;
            }
            else
            {
                _messageId += creditCharge;
            }
            return new ValueTask();
        }

        public uint MaxTransactSize => _maxTransactSize;

        public uint MaxReadSize => _maxReadSize;

        public uint MaxWriteSize => _maxWriteSize;

        public void TrySendCommand(Socket socket, SMB2Command request)
        {
            var packet = ObjectsPool<SessionMessagePacket>.Get().Init();
            packet.Trailer = request.GetBytes();
            TrySendPacket(socket, packet);
            request.Dispose();
        }
        
        public virtual void TrySendPacket(Socket socket, SessionPacketBase packet)
        {
            IMemoryOwner<byte> packetBytes = null;
            try
            {
                packetBytes = packet.GetBytes();
                socket.Send(packetBytes.Memory.Span);
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
            finally
            {
                packetBytes?.Dispose();
                packet.Dispose();
            }
        }

        public ValueTask DisposeAsync() => DisconnectAsync();
    }
}
