/* Copyright (C) 2017-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using MemoryPools.Memory;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Server.SMB2
{
    internal class ChangeNotifyHelper
    {
        /// <remarks>
        /// 'NoRemoteChangeNotify' can be set in the registry to prevent the client from sending ChangeNotify requests altogether.
        /// </remarks>
        internal static SMB2Command GetChangeNotifyInterimResponse(ChangeNotifyRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            var session = state.GetSession(request.Header.SessionId);
            var openFile = session.GetOpenFileObject(request.FileId);
            var watchTree = (request.Flags & ChangeNotifyFlags.WatchTree) > 0;
            var asyncContext = state.CreateAsyncContext(request.FileId, state, request.Header.SessionId, request.Header.TreeId);
            // We have to make sure that we don't send an interim response after the final response.
            lock (asyncContext)
            {
                var status = share.FileStore.NotifyChange(out asyncContext.IORequest, openFile.Handle, request.CompletionFilter, watchTree, (int)request.OutputBufferLength, OnNotifyChangeCompleted, asyncContext);
                if (status == NTStatus.STATUS_PENDING)
                {
                    state.LogToServer(Severity.Verbose, "NotifyChange: Monitoring of '{0}{1}' started. AsyncID: {2}.", share.Name, openFile.Path, asyncContext.AsyncID);
                }
                else if (status == NTStatus.STATUS_NOT_SUPPORTED)
                {
                    // [MS-SMB2] If the underlying object store does not support change notifications, the server MUST fail this request with STATUS_NOT_SUPPORTED.
                    // Unfortunately, Windows 7 / 8 / 10 will immediately retry sending another ChangeNotify request upon getting STATUS_NOT_SUPPORTED,
                    // To prevent flooding, we must return a valid interim response (Status set to STATUS_PENDING and SMB2_FLAGS_ASYNC_COMMAND bit is set in Flags).
                    status = NTStatus.STATUS_PENDING;
                }
                else
                {
                    state.RemoveAsyncContext(asyncContext);
                }

                var response = ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, status);
                if (status == NTStatus.STATUS_PENDING)
                {
                    response.Header.IsAsync = true;
                    response.Header.AsyncId = asyncContext.AsyncID;
                }
                return response;
            }
        }

        private static void OnNotifyChangeCompleted(NTStatus status, IMemoryOwner<byte> buffer, object context)
        {
            var asyncContext = (SMB2AsyncContext)context;
            // Wait until the interim response has been sent
            lock (asyncContext)
            {
                var connection = asyncContext.Connection;
                connection.RemoveAsyncContext(asyncContext);
                var session = connection.GetSession(asyncContext.SessionID);
                if (session != null)
                {
                    var openFile = session.GetOpenFileObject(asyncContext.FileID);
                    if (openFile != null)
                    {
                        connection.LogToServer(Severity.Verbose, "NotifyChange: Monitoring of '{0}{1}' completed. NTStatus: {2}. AsyncID: {3}", openFile.ShareName, openFile.Path, status, asyncContext.AsyncID);
                    }

                    if (status == NTStatus.STATUS_SUCCESS ||
                        status == NTStatus.STATUS_NOTIFY_CLEANUP ||
                        status == NTStatus.STATUS_NOTIFY_ENUM_DIR)
                    {
                        var response = new ChangeNotifyResponse();
                        response.Header.Status = status;
                        response.Header.IsAsync = true;
                        response.Header.IsSigned = session.SigningRequired;
                        response.Header.AsyncId = asyncContext.AsyncID;
                        response.Header.SessionId = asyncContext.SessionID;
                        response.OutputBuffer = buffer;

                        SMBServer.EnqueueResponse(connection, response);
                    }
                    else
                    {
                        // [MS-SMB2] If the object store returns an error, the server MUST fail the request with the error code received.
                        var response = ObjectsPool<ErrorResponse>.Get().Init(SMB2CommandName.ChangeNotify);
                        response.Header.Status = status;
                        response.Header.IsAsync = true;
                        response.Header.IsSigned = session.SigningRequired;
                        response.Header.AsyncId = asyncContext.AsyncID;

                        SMBServer.EnqueueResponse(connection, response);
                    }
                }
            }
        }
    }
}
