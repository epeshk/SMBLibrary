/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using MemoryPools.Memory;
using SMBLibrary.NetBios;
using SMBLibrary.Server.SMB2;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Server
{
    public partial class SMBServer
    {
        private void ProcessSMB2RequestChain(List<SMB2Command> requestChain, ref ConnectionState state)
        {
            var responseChain = new List<SMB2Command>();
            FileID? fileID = null;
            NTStatus? fileIDStatus = null;
            for (var index = 0; index < requestChain.Count; index++)
            {
                var request = requestChain[index];
                SMB2Command response;
                if (request.Header.IsRelatedOperations && RequestContainsFileID(request))
                {
                    if (fileIDStatus != null && fileIDStatus != NTStatus.STATUS_SUCCESS &&
                        fileIDStatus != NTStatus.STATUS_BUFFER_OVERFLOW)
                    {
                        // [MS-SMB2] When the current request requires a FileId and the previous request either contains
                        // or generates a FileId, if the previous request fails with an error, the server SHOULD fail the
                        // current request with the same error code returned by the previous request.
                        state.LogToServer(Severity.Verbose,
                            "Compunded related request {0} failed because FileId generation failed.",
                            request.CommandName);
                        response = ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, fileIDStatus.Value);
                    }
                    else if (fileID != null)
                    {
                        SetRequestFileID(request, fileID);
                        response = ProcessSMB2Command(request, ref state);
                    }
                    else
                    {
                        // [MS-SMB2] When the current request requires a FileId, and if the previous request neither contains
                        // nor generates a FileId, the server MUST fail the compounded request with STATUS_INVALID_PARAMETER.
                        state.LogToServer(Severity.Verbose,
                            "Compunded related request {0} failed, the previous request neither contains nor generates a FileId.",
                            request.CommandName);
                        response = ObjectsPool<ErrorResponse>.Get()
                            .Init(request.CommandName, NTStatus.STATUS_INVALID_PARAMETER);
                    }
                }
                else
                {
                    fileID = GetRequestFileID(request);
                    response = ProcessSMB2Command(request, ref state);
                }

                if (response != null)
                {
                    UpdateSMB2Header(response, request, state);
                    responseChain.Add(response);
                    if (GeneratesFileID(response))
                    {
                        fileID = GetResponseFileID(response);
                        fileIDStatus = response.Header.Status;
                    }
                    else if (RequestContainsFileID(request))
                    {
                        fileIDStatus = response.Header.Status;
                    }
                }
            }

            if (responseChain.Count > 0)
            {
                EnqueueResponseChain(state, responseChain);
            }
        }

        /// <summary>
        /// May return null
        /// </summary>
        private SMB2Command ProcessSMB2Command(SMB2Command command, ref ConnectionState state)
        {
            if (state.Dialect == SMBDialect.NotSet)
            {
                if (command is NegotiateRequest)
                {
                    var request = (NegotiateRequest)command;
                    var response = NegotiateHelper.GetNegotiateResponse(request, m_securityProvider, state, m_transport, m_serverGuid, m_serverStartTime);
                    if (state.Dialect != SMBDialect.NotSet)
                    {
                        state = new SMB2ConnectionState(state);
                        m_connectionManager.AddConnection(state);
                    }
                    return response;
                }

                // [MS-SMB2] If the request being received is not an SMB2 NEGOTIATE Request [..]
                // and Connection.NegotiateDialect is 0xFFFF or 0x02FF, the server MUST
                // disconnect the connection.
                state.LogToServer(Severity.Debug, "Invalid Connection State for command {0}", command.CommandName.ToString());
                state.ClientSocket.Close();
                return null;
            }

            if (command is NegotiateRequest)
            {
                // [MS-SMB2] If Connection.NegotiateDialect is 0x0202, 0x0210, 0x0300, 0x0302, or 0x0311,
                // the server MUST disconnect the connection.
                state.LogToServer(Severity.Debug, "Rejecting NegotiateRequest. NegotiateDialect is already set");
                state.ClientSocket.Close();
                return null;
            }

            return ProcessSMB2Command(command, (SMB2ConnectionState)state);
        }

        private SMB2Command ProcessSMB2Command(SMB2Command command, SMB2ConnectionState state)
        {
            if (command is SessionSetupRequest)
            {
                return SessionSetupHelper.GetSessionSetupResponse((SessionSetupRequest)command, m_securityProvider, state);
            }

            if (command is EchoRequest)
            {
                return new EchoResponse();
            }

            var session = state.GetSession(command.Header.SessionId);
            if (session == null)
            {
                return ObjectsPool<ErrorResponse>.Get().Init(command.CommandName, NTStatus.STATUS_USER_SESSION_DELETED);
            }

            if (command is TreeConnectRequest)
            {
                return TreeConnectHelper.GetTreeConnectResponse((TreeConnectRequest)command, state, m_services, m_shares);
            }

            if (command is LogoffRequest)
            {
                state.LogToServer(Severity.Information, "Logoff: User '{0}' logged off. (SessionID: {1})", session.UserName, command.Header.SessionId);
                m_securityProvider.DeleteSecurityContext(ref session.SecurityContext.AuthenticationContext);
                state.RemoveSession(command.Header.SessionId);
                return new LogoffResponse();
            }

            if (command.Header.IsAsync)
            {
                // TreeID will not be present in an ASYNC header
                if (command is CancelRequest)
                {
                    return CancelHelper.GetCancelResponse((CancelRequest)command, state);
                }
            }
            else
            {
                var share = session.GetConnectedTree(command.Header.TreeId);
                if (share == null)
                {
                    state.LogToServer(Severity.Verbose, "{0} failed. Invalid TreeID (SessionID: {1}, TreeID: {2}).", command.CommandName, command.Header.SessionId, command.Header.TreeId);
                    return ObjectsPool<ErrorResponse>.Get().Init(command.CommandName, NTStatus.STATUS_NETWORK_NAME_DELETED);
                }

                if (command is TreeDisconnectRequest)
                {
                    return TreeConnectHelper.GetTreeDisconnectResponse((TreeDisconnectRequest)command, share, state);
                }

                if (command is CreateRequest)
                {
                    return CreateHelper.GetCreateResponse((CreateRequest)command, share, state);
                }

                if (command is QueryInfoRequest)
                {
                    return QueryInfoHelper.GetQueryInfoResponse((QueryInfoRequest)command, share, state);
                }

                if (command is SetInfoRequest)
                {
                    return SetInfoHelper.GetSetInfoResponse((SetInfoRequest)command, share, state);
                }

                if (command is QueryDirectoryRequest)
                {
                    return QueryDirectoryHelper.GetQueryDirectoryResponse((QueryDirectoryRequest)command, share, state);
                }

                if (command is ReadRequest)
                {
                    return ReadWriteResponseHelper.GetReadResponse((ReadRequest)command, share, state);
                }

                if (command is WriteRequest)
                {
                    return ReadWriteResponseHelper.GetWriteResponse((WriteRequest)command, share, state);
                }

                if (command is LockRequest)
                {
                    return LockHelper.GetLockResponse((LockRequest)command, share, state);
                }

                if (command is FlushRequest)
                {
                    return ReadWriteResponseHelper.GetFlushResponse((FlushRequest)command, share, state);
                }

                if (command is CloseRequest)
                {
                    return CloseHelper.GetCloseResponse((CloseRequest)command, share, state);
                }

                if (command is IOCtlRequest)
                {
                    return IOCtlHelper.GetIOCtlResponse((IOCtlRequest)command, share, state);
                }

                if (command is CancelRequest)
                {
                    return CancelHelper.GetCancelResponse((CancelRequest)command, state);
                }

                if (command is ChangeNotifyRequest)
                {
                    return ChangeNotifyHelper.GetChangeNotifyInterimResponse((ChangeNotifyRequest)command, share, state);
                }
            }

            return ObjectsPool<ErrorResponse>.Get().Init(command.CommandName, NTStatus.STATUS_NOT_SUPPORTED);
        }

        internal static void EnqueueResponse(ConnectionState state, SMB2Command response)
        {
            var responseChain = new List<SMB2Command>();
            responseChain.Add(response);
            EnqueueResponseChain(state, responseChain);
        }

        private static void EnqueueResponseChain(ConnectionState state, List<SMB2Command> responseChain)
        {
            byte[] sessionKey = null;
            if (state is SMB2ConnectionState)
            {
                // Note: multiple sessions MAY be multiplexed on the same connection, so theoretically
                // we could have compounding unrelated requests from different sessions.
                // In practice however this is not a real problem.
                var sessionID = responseChain[0].Header.SessionId;
                if (sessionID != 0)
                {
                    var session = ((SMB2ConnectionState)state).GetSession(sessionID);
                    if (session != null)
                    {
                        sessionKey = session.SessionKey;
                    }
                }
            }

            var packet = ObjectsPool<SessionMessagePacket>.Get().Init();
            packet.Trailer = SMB2Command.GetCommandChainBytes(responseChain, sessionKey);
            state.SendQueue.Enqueue(packet);
            state.LogToServer(Severity.Verbose, "SMB2 response chain queued: Response count: {0}, First response: {1}, Packet length: {2}", responseChain.Count, responseChain[0].CommandName.ToString(), packet.Length);
        }

        private static void UpdateSMB2Header(SMB2Command response, SMB2Command request, ConnectionState state)
        {
            response.Header.MessageId = request.Header.MessageId;
            response.Header.CreditCharge = request.Header.CreditCharge;
            response.Header.Credits = Math.Max((ushort)1, request.Header.Credits);
            response.Header.IsRelatedOperations = request.Header.IsRelatedOperations;
            response.Header.Reserved = request.Header.Reserved;
            if (response.Header.SessionId == 0)
            {
                response.Header.SessionId = request.Header.SessionId;
            }
            if (response.Header.TreeId == 0)
            {
                response.Header.TreeId = request.Header.TreeId;
            }
            var signingRequired = false;
            if (state is SMB2ConnectionState)
            {
                var session = ((SMB2ConnectionState)state).GetSession(response.Header.SessionId);
                if (session != null && session.SigningRequired)
                {
                    signingRequired = true;
                }
            }
            // [MS-SMB2] The server SHOULD sign the message [..] if the request was signed by the client,
            // and the response is not an interim response to an asynchronously processed request.
            var isInterimResponse = (response.Header.IsAsync && response.Header.Status == NTStatus.STATUS_PENDING);
            response.Header.IsSigned = (request.Header.IsSigned || signingRequired) && !isInterimResponse;
        }

        private static bool RequestContainsFileID(SMB2Command command)
        {
            return (command is ChangeNotifyRequest ||
                    command is CloseRequest ||
                    command is FlushRequest ||
                    command is IOCtlRequest ||
                    command is LockRequest ||
                    command is QueryDirectoryRequest ||
                    command is QueryInfoRequest ||
                    command is ReadRequest ||
                    command is SetInfoRequest ||
                    command is WriteRequest);
        }

        private static FileID? GetRequestFileID(SMB2Command command)
        {
            if (command is ChangeNotifyRequest)
            {
                return ((ChangeNotifyRequest)command).FileId;
            }

            if (command is CloseRequest)
            {
                return ((CloseRequest)command).FileId;
            }

            if (command is FlushRequest)
            {
                return ((FlushRequest)command).FileId;
            }

            if (command is IOCtlRequest)
            {
                return ((IOCtlRequest)command).FileId;
            }

            if (command is LockRequest)
            {
                return ((LockRequest)command).FileId;
            }

            if (command is QueryDirectoryRequest)
            {
                return ((QueryDirectoryRequest)command).FileId;
            }

            if (command is QueryInfoRequest)
            {
                return ((QueryInfoRequest)command).FileId;
            }

            if (command is ReadRequest)
            {
                return ((ReadRequest)command).FileId;
            }

            if (command is SetInfoRequest)
            {
                return ((SetInfoRequest)command).FileId;
            }

            if (command is WriteRequest)
            {
                return ((WriteRequest)command).FileId;
            }
            return null;
        }

        private static void SetRequestFileID(SMB2Command command, FileID fileID)
        {
            if (command is ChangeNotifyRequest)
            {
                ((ChangeNotifyRequest)command).FileId = fileID;
            }
            else if (command is CloseRequest)
            {
                ((CloseRequest)command).FileId = fileID;
            }
            else if (command is FlushRequest)
            {
                ((FlushRequest)command).FileId = fileID;
            }
            else if (command is IOCtlRequest)
            {
                ((IOCtlRequest)command).FileId = fileID;
            }
            else if (command is LockRequest)
            {
                ((LockRequest)command).FileId = fileID;
            }
            else if (command is QueryDirectoryRequest)
            {
                ((QueryDirectoryRequest)command).FileId = fileID;
            }
            else if (command is QueryInfoRequest)
            {
                ((QueryInfoRequest)command).FileId = fileID;
            }
            else if (command is ReadRequest)
            {
                ((ReadRequest)command).FileId = fileID;
            }
            else if (command is SetInfoRequest)
            {
                ((SetInfoRequest)command).FileId = fileID;
            }
            else if (command is WriteRequest)
            {
                ((WriteRequest)command).FileId = fileID;
            }
        }

        private static bool GeneratesFileID(SMB2Command command)
        {
            return (command.CommandName == SMB2CommandName.Create ||
                    command.CommandName == SMB2CommandName.IOCtl);
        }

        private static FileID? GetResponseFileID(SMB2Command command)
        {
            if (command is CreateResponse)
            {
                return ((CreateResponse)command).FileId;
            }

            if (command is IOCtlResponse)
            {
                return ((IOCtlResponse)command).FileId;
            }
            return null;
        }
    }
}
