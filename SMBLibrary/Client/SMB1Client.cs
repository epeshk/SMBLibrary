/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MemoryPools.Memory;
using SMBLibrary.Authentication.NTLM;
using SMBLibrary.NetBios;
using SMBLibrary.Services;
using SMBLibrary.SMB1;
using Utilities;

#pragma warning disable 1998

namespace SMBLibrary.Client
{
    public class SMB1Client : ISmbClient
    {
        private const string NTLanManagerDialect = "NT LM 0.12";
        
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        private static readonly ushort ClientMaxBufferSize = 65535; // Valid range: 512 - 65535
        private static readonly ushort ClientMaxMpxCount = 1;

        private SMBTransportType _transport;
        private bool _isConnected;
        private bool _isLoggedIn;
        private Socket _clientSocket;
        private bool _forceExtendedSecurity;
        private bool _unicode;
        private bool _largeFiles;
        private bool _infoLevelPassthrough;
        private bool _largeRead;
        private bool _largeWrite;
        private uint _serverMaxBufferSize;
        private ushort _maxMpxCount;

        private object m_incomingQueueLock = new object();
        private List<SMB1Message> m_incomingQueue = new List<SMB1Message>();
        private EventWaitHandle m_incomingQueueEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private SessionPacketBase _sessionResponsePacket;
        private EventWaitHandle m_sessionResponseEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);
        Action<Task<int>, object> _onClientSocketChainedReceiveCached;
        private ConnectionState _connectionState;
        
        private ushort _userId;
        private byte[] _serverChallenge;
        private byte[] _securityBlob;

        public SMB1Client()
        {
            _onClientSocketChainedReceiveCached = OnClientSocketChainedReceive;
        }

        // done
        public ValueTask<bool> ConnectAsync(IPAddress serverAddress, SMBTransportType transport)
        {
            return ConnectAsync(serverAddress, transport, true);
        }

        // done
        public async ValueTask<bool> ConnectAsync(IPAddress serverAddress, SMBTransportType transport, bool forceExtendedSecurity)
        {
            _transport = transport;
            if (!_isConnected)
            {
                _forceExtendedSecurity = forceExtendedSecurity;
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
                    var sessionRequest = new SessionRequestPacket();
                    sessionRequest.CalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServiceService);
                    sessionRequest.CallingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService);
                    TrySendPacket(sessionRequest);

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
                        TrySendPacket(sessionRequest);

                        sessionResponsePacket = WaitForSessionResponsePacket();
                        if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                        {
                            return false;
                        }
                    }
                }

                var supportsDialect = NegotiateDialect(_forceExtendedSecurity);
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

        // done
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
            
            _clientSocket
                .ReceiveAsync(buffer.Buffer.Slice(buffer.WriteOffset, buffer.AvailableLength), SocketFlags.None)
                .AsTask()
                .ContinueWith(_onClientSocketChainedReceiveCached, TaskContinuationOptions.LongRunning);
            
            return true;
        }

        public async ValueTask DisconnectAsync()
        {
            if (_clientSocket?.Connected == true)
            {
                _isConnected = false;
                _clientSocket.Disconnect(false);
                _clientSocket.Close();
                _clientSocket = null;
            }
        }

        private bool NegotiateDialect(bool forceExtendedSecurity)
        {
            var request = new NegotiateRequest();
            request.Dialects.Add(NTLanManagerDialect);
            TrySendMessage(request);
            
            var reply = WaitForCommand(CommandName.SMB_COM_NEGOTIATE);
            if (reply == null)
            {
                return false;
            }

            if (reply.Commands[0] is NegotiateResponse && !forceExtendedSecurity)
            {
                var response = (NegotiateResponse)reply.Commands[0];
                _unicode = ((response.Capabilities & Capabilities.Unicode) > 0);
                _largeFiles = ((response.Capabilities & Capabilities.LargeFiles) > 0);
                var ntSMB = ((response.Capabilities & Capabilities.NTSMB) > 0);
                var rpc = ((response.Capabilities & Capabilities.RpcRemoteApi) > 0);
                var ntStatusCode = ((response.Capabilities & Capabilities.NTStatusCode) > 0);
                _infoLevelPassthrough = ((response.Capabilities & Capabilities.InfoLevelPassthrough) > 0);
                _largeRead = ((response.Capabilities & Capabilities.LargeRead) > 0);
                _largeWrite = ((response.Capabilities & Capabilities.LargeWrite) > 0);
                _serverMaxBufferSize = response.MaxBufferSize;
                _maxMpxCount = Math.Min(response.MaxMpxCount, ClientMaxMpxCount);
                _serverChallenge = response.Challenge;
                
                reply.Dispose();
                return ntSMB && rpc && ntStatusCode;
            }

            if (reply.Commands[0] is NegotiateResponseExtended)
            {
                var response = (NegotiateResponseExtended)reply.Commands[0];
                _unicode = ((response.Capabilities & Capabilities.Unicode) > 0);
                _largeFiles = ((response.Capabilities & Capabilities.LargeFiles) > 0);
                var ntSMB = ((response.Capabilities & Capabilities.NTSMB) > 0);
                var rpc = ((response.Capabilities & Capabilities.RpcRemoteApi) > 0);
                var ntStatusCode = ((response.Capabilities & Capabilities.NTStatusCode) > 0);
                _infoLevelPassthrough = ((response.Capabilities & Capabilities.InfoLevelPassthrough) > 0);
                _largeRead = ((response.Capabilities & Capabilities.LargeRead) > 0);
                _largeWrite = ((response.Capabilities & Capabilities.LargeWrite) > 0);
                _serverMaxBufferSize = response.MaxBufferSize;
                _maxMpxCount = Math.Min(response.MaxMpxCount, ClientMaxMpxCount);
                _securityBlob = response.SecurityBlob;
                
                reply.Dispose();
                return ntSMB && rpc && ntStatusCode;
            }

            return false;
        }

        public ValueTask<NTStatus> LoginAsync(string domainName, string userName, string password)
        {
            return LoginAsync(domainName, userName, password, AuthenticationMethod.NTLMv2);
        }

        public async ValueTask<NTStatus> LoginAsync(string domainName, string userName, string password, AuthenticationMethod authenticationMethod)
        {
            if (!_isConnected)
            {
                throw new InvalidOperationException("A connection must be successfully established before attempting login");
            }

            var clientCapabilities = Capabilities.NTSMB | Capabilities.RpcRemoteApi | Capabilities.NTStatusCode | Capabilities.NTFind;
            if (_unicode)
            {
                clientCapabilities |= Capabilities.Unicode;
            }
            if (_largeFiles)
            {
                clientCapabilities |= Capabilities.LargeFiles;
            }
            if (_largeRead)
            {
                clientCapabilities |= Capabilities.LargeRead;
            }

            if (_serverChallenge != null)
            {
                var request = new SessionSetupAndXRequest();
                request.MaxBufferSize = ClientMaxBufferSize;
                request.MaxMpxCount = _maxMpxCount;
                request.Capabilities = clientCapabilities;
                request.AccountName = userName;
                request.PrimaryDomain = domainName;
                var clientChallenge = new byte[8];
                StaticRandom.Instance.NextBytes(clientChallenge);
                if (authenticationMethod == AuthenticationMethod.NTLMv1)
                {
                    request.OEMPassword = NTLMCryptography.ComputeLMv1Response(_serverChallenge, password);
                    request.UnicodePassword = NTLMCryptography.ComputeNTLMv1Response(_serverChallenge, password);
                }
                else if (authenticationMethod == AuthenticationMethod.NTLMv1ExtendedSessionSecurity)
                {
                    // [MS-CIFS] CIFS does not support Extended Session Security because there is no mechanism in CIFS to negotiate Extended Session Security
                    throw new ArgumentException("SMB Extended Security must be negotiated in order for NTLMv1 Extended Session Security to be used");
                }
                else // NTLMv2
                {
                    // Note: NTLMv2 over non-extended security session setup is not supported under Windows Vista and later which will return STATUS_INVALID_PARAMETER.
                    // https://msdn.microsoft.com/en-us/library/ee441701.aspx
                    // https://msdn.microsoft.com/en-us/library/cc236700.aspx
                    request.OEMPassword = NTLMCryptography.ComputeLMv2Response(_serverChallenge, clientChallenge, password, userName, domainName);
                    var clientChallengeStructure = new NTLMv2ClientChallenge(DateTime.UtcNow, clientChallenge, AVPairUtils.GetAVPairSequence(domainName, Environment.MachineName));
                    var temp = clientChallengeStructure.GetBytesPadded();
                    var proofStr = NTLMCryptography.ComputeNTLMv2Proof(_serverChallenge, temp, password, userName, domainName);
                    request.UnicodePassword = ByteUtils.Concatenate_Rental(proofStr, temp);
                }
                
                TrySendMessage(request);

                var reply = WaitForCommand(CommandName.SMB_COM_SESSION_SETUP_ANDX);
                if (reply != null)
                {
                    _isLoggedIn = (reply.Header.Status == NTStatus.STATUS_SUCCESS);
                    return reply.Header.Status;
                }
                return NTStatus.STATUS_INVALID_SMB;
            }
            else // m_securityBlob != null
            {
                var negotiateMessage = NTLMAuthenticationHelper.GetNegotiateMessage(_securityBlob, domainName, authenticationMethod);
                if (negotiateMessage == null)
                {
                    return NTStatus.SEC_E_INVALID_TOKEN;
                }

                var request = (SessionSetupAndXRequestExtended) ObjectsPool<SessionSetupAndXRequestExtended>.Get().Init();
                request.MaxBufferSize = ClientMaxBufferSize;
                request.MaxMpxCount = _maxMpxCount;
                request.Capabilities = clientCapabilities;
                request.SecurityBlob = negotiateMessage;
                TrySendMessage(request);
                
                var reply = WaitForCommand(CommandName.SMB_COM_SESSION_SETUP_ANDX);
                if (reply != null)
                {
                    if (reply.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED && reply.Commands[0] is SessionSetupAndXResponseExtended)
                    {
                        var response = (SessionSetupAndXResponseExtended)reply.Commands[0];
                        var authenticateMessage = NTLMAuthenticationHelper.GetAuthenticateMessage(response.SecurityBlob.Memory.Span, domainName, userName, password, authenticationMethod, out _);
                        if (authenticateMessage == null)
                        {
                            reply.Dispose();
                            return NTStatus.SEC_E_INVALID_TOKEN;
                        }

                        _userId = reply.Header.UID;
                        request = (SessionSetupAndXRequestExtended) ObjectsPool<SessionSetupAndXRequestExtended>.Get().Init();
                        request.MaxBufferSize = ClientMaxBufferSize;
                        request.MaxMpxCount = _maxMpxCount;
                        request.Capabilities = clientCapabilities;
                        request.SecurityBlob = authenticateMessage;
                        TrySendMessage(request);

                        reply.Dispose();
                        reply = WaitForCommand(CommandName.SMB_COM_SESSION_SETUP_ANDX);
                        if (reply != null)
                        {
                            _isLoggedIn = (reply.Header.Status == NTStatus.STATUS_SUCCESS);
                            reply.Dispose();
                            return reply.Header.Status;
                        }
                    }
                    else
                    {
                        var status = reply.Header.Status;
                        reply.Dispose();
                        return status;
                    }
                }
                return NTStatus.STATUS_INVALID_SMB;
            }
        }

        public async ValueTask<NTStatus> LogoffAsync()
        {
            if (!_isConnected)
            {
                throw new InvalidOperationException("A login session must be successfully established before attempting logoff");
            }

            var request = new LogoffAndXRequest();
            TrySendMessage(request);

            var reply = WaitForCommand(CommandName.SMB_COM_LOGOFF_ANDX);
            if (reply != null)
            {
                _isLoggedIn = (reply.Header.Status != NTStatus.STATUS_SUCCESS);
                return reply.Header.Status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public async ValueTask<NtResult<IEnumerable<string>>> ListSharesAsync()
        {
            if (!_isConnected || !_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before retrieving share list");
            }

            var namedPipeShare = TreeConnect("IPC$", ServiceName.NamedPipe, out var status);
            if (namedPipeShare == null)
            {
                return NtResult.Create<IEnumerable<string>>(status, null);
            }

            var shares = ServerServiceHelper.ListShares(namedPipeShare, ShareType.DiskDrive, out status);
            namedPipeShare.Disconnect();
            return NtResult.Create<IEnumerable<string>>(status, shares);
        }

        public async ValueTask<NtResult<ISMBFileStore>> TreeConnectAsync(string shareName)
        {
            var task= TreeConnect(shareName, ServiceName.AnyType, out var status);
            return NtResult.Create<ISMBFileStore>(status, task);
        }

        public ISMBFileStore TreeConnect(string shareName, ServiceName serviceName, out NTStatus status)
        {
            if (!_isConnected || !_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before connecting to a share");
            }

            var request = (TreeConnectAndXRequest) ObjectsPool<TreeConnectAndXRequest>.Get().Init();
            request.Path = shareName;
            request.Service = serviceName;
            TrySendMessage(request);
            var reply = WaitForCommand(CommandName.SMB_COM_TREE_CONNECT_ANDX);
            if (reply != null)
            {
                status = reply.Header.Status;
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is TreeConnectAndXResponse)
                {
                    var response = (TreeConnectAndXResponse)reply.Commands[0];
                    reply.Dispose();
                    return new SMB1FileStore(this, reply.Header.TID);
                }
            }
            else
            {
                status = NTStatus.STATUS_INVALID_SMB;
            }
            return null;
        }

        // done
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
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                Log("[ReceiveCallback] EndReceive Disconnected by remote peer");
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

        // done
        private void ProcessConnectionBuffer(ConnectionState state)
        {
            var receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacketBase packet = null;
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

        // done
        protected virtual void ProcessPacket(SessionPacketBase packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                SMB1Message message;
                try
                {
                    message = SMB1Message.GetSMB1Message(packet.Trailer.Memory.Span);
                }
                catch (Exception ex)
                {
                    Log("Invalid SMB1 message: " + ex.Message);
                    _clientSocket.Close();
                    _isConnected = false;
                    return;
                }

                // [MS-CIFS] 3.2.5.1 - If the MID value is the reserved value 0xFFFF, the message can be an OpLock break
                // sent by the server. Otherwise, if the PID and MID values of the received message are not found in the
                // Client.Connection.PIDMIDList, the message MUST be discarded.
                if ((message.Header.MID == 0xFFFF && message.Header.Command == CommandName.SMB_COM_LOCKING_ANDX) ||
                    (message.Header.PID == 0 && message.Header.MID == 0))
                {
                    lock (m_incomingQueueLock)
                    {
                        m_incomingQueue.Add(message);
                        m_incomingQueueEventHandle.Set();
                    }
                }
                else
                {
                    message.Dispose();
                }
                
                packet.Dispose();
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) && _transport == SMBTransportType.NetBiosOverTCP)
            {
                _sessionResponsePacket = packet;
                m_sessionResponseEventHandle.Set();
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

        internal SMB1Message WaitForCommand(CommandName commandName)
        {
            const int TimeOut = 5000;
            var stopwatch = ObjectsPool<Stopwatch>.Get();
            stopwatch.Restart();

            SMB1Message message = WaitForCommand(commandName, stopwatch, TimeOut);
            return message;
        }

        internal virtual SMB1Message WaitForCommand(CommandName commandName, Stopwatch stopwatch, int timeOut)
        {
            while (stopwatch.ElapsedMilliseconds < timeOut)
            {
                lock (m_incomingQueueLock)
                {
                    for (var index = 0; index < m_incomingQueue.Count; index++)
                    {
                        var message = m_incomingQueue[index];

                        if (message.Commands[0].CommandName == commandName)
                        {
                            m_incomingQueue.RemoveAt(index);
                            return message;
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
            var stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < TimeOut)
            {
                if (_sessionResponsePacket != null)
                {
                    var result = _sessionResponsePacket;
                    _sessionResponsePacket = null;
                    return result;
                }

                m_sessionResponseEventHandle.WaitOne(100);
            }

            return null;
        }

        private void Log(string message)
        {
            Debug.Print(message);
        }

        internal void TrySendMessage(SMB1Command request)
        {
            TrySendMessage(request, 0);
        }

        internal void TrySendMessage(SMB1Command request, ushort treeID)
        {
            var message = ObjectsPool<SMB1Message>.Get().Init();
            message.Header.UnicodeFlag = _unicode;
            message.Header.ExtendedSecurityFlag = _forceExtendedSecurity;
            message.Header.Flags2 |= HeaderFlags2.LongNamesAllowed | HeaderFlags2.LongNameUsed | HeaderFlags2.NTStatusCode;
            message.Header.UID = _userId;
            message.Header.TID = treeID;
            message.Commands.Add(request);
            TrySendMessage(message);
        }

        public bool Unicode => _unicode;

        public bool LargeFiles => _largeFiles;

        public bool InfoLevelPassthrough => _infoLevelPassthrough;

        public bool LargeRead => _largeRead;

        public bool LargeWrite => _largeWrite;

        public uint ServerMaxBufferSize => _serverMaxBufferSize;

        public int MaxMpxCount => _maxMpxCount;

        public uint MaxReadSize => (uint)ClientMaxBufferSize - (SMB1Header.Length + 3 + ReadAndXResponse.ParametersLength);

        public uint MaxWriteSize
        {
            get
            {
                var result = ServerMaxBufferSize - (SMB1Header.Length + 3 + WriteAndXRequest.ParametersFixedLength + 4);
                if (_unicode)
                {
                    result--;
                }
                return result;
            }
        }

        public void TrySendMessage(SMB1Message message)
        {
            var packet = new SessionMessagePacket();
            packet.Trailer = message.GetBytes();
            TrySendPacket(packet);
            packet.Dispose();
            message.Dispose();
        }

        protected virtual void TrySendPacket(SessionPacketBase packet)
        {
            try
            {
                var packetBytes = packet.GetBytes();
                _clientSocket.Send(packetBytes.Memory.Span);
                packetBytes.Dispose();
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }

        public ValueTask DisposeAsync() => DisconnectAsync();
    }
}
