/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using MemoryPools.Memory;
using SMBLibrary.SMB1;
using Utilities;

namespace SMBLibrary.Server.SMB1
{
    internal class NotifyChangeHelper
    {
        internal static void ProcessNTTransactNotifyChangeRequest(SMB1Header header, uint maxParameterCount, NTTransactNotifyChangeRequest subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            var session = state.GetSession(header.UID);
            var openFile = session.GetOpenFileObject(subcommand.FID);
            var context = state.CreateAsyncContext(header.UID, header.TID, header.PID, header.MID, subcommand.FID, state);
            // We wish to make sure that the 'Monitoring started' will appear before the 'Monitoring completed' in the log
            lock (context)
            {
                header.Status = share.FileStore.NotifyChange(out context.IORequest, openFile.Handle, subcommand.CompletionFilter, subcommand.WatchTree, (int)maxParameterCount, OnNotifyChangeCompleted, context);
                if (header.Status == NTStatus.STATUS_PENDING)
                {
                    state.LogToServer(Severity.Verbose, "NotifyChange: Monitoring of '{0}{1}' started. PID: {2}. MID: {3}.", share.Name, openFile.Path, context.PID, context.MID);
                }
                else if (header.Status == NTStatus.STATUS_NOT_SUPPORTED)
                {
                    // [MS-CIFS] If the server does not support the NT_TRANSACT_NOTIFY_CHANGE subcommand, it can return an
                    // error response with STATUS_NOT_IMPLEMENTED [..] in response to an NT_TRANSACT_NOTIFY_CHANGE Request.
                    header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
                }
            }
        }

        private static void OnNotifyChangeCompleted(NTStatus status, IMemoryOwner<byte> buffer, object context)
        {
            var asyncContext = (SMB1AsyncContext)context;
            // Wait until the 'Monitoring started' will be written to the log
            lock (asyncContext)
            {
                var connection = asyncContext.Connection;
                connection.RemoveAsyncContext(asyncContext);
                var session = connection.GetSession(asyncContext.UID);
                if (session != null)
                {
                    var openFile = session.GetOpenFileObject(asyncContext.FileID);
                    if (openFile != null)
                    {
                        connection.LogToServer(Severity.Verbose, "NotifyChange: Monitoring of '{0}{1}' completed. NTStatus: {2}. PID: {3}. MID: {4}.", openFile.ShareName, openFile.Path, status, asyncContext.PID, asyncContext.MID);
                    }
                    var header = new SMB1Header();
                    header.Command = CommandName.SMB_COM_NT_TRANSACT;
                    header.Status = status;
                    header.Flags = HeaderFlags.CaseInsensitive | HeaderFlags.CanonicalizedPaths | HeaderFlags.Reply;
                    // [MS-CIFS] SMB_FLAGS2_LONG_NAMES SHOULD be set to 1 when the negotiated dialect is NT LANMAN.
                    // [MS-CIFS] SMB_FLAGS2_UNICODE SHOULD be set to 1 when the negotiated dialect is NT LANMAN.
                    // [MS-CIFS] The Windows NT Server implementation of NT_TRANSACT_NOTIFY_CHANGE always returns the names of changed files in Unicode format.
                    header.Flags2 = HeaderFlags2.LongNamesAllowed | HeaderFlags2.NTStatusCode | HeaderFlags2.Unicode;
                    header.UID = asyncContext.UID;
                    header.TID = asyncContext.TID;
                    header.PID = asyncContext.PID;
                    header.MID = asyncContext.MID;

                    if (status == NTStatus.STATUS_SUCCESS)
                    {
                        var notifyChangeResponse = new NTTransactNotifyChangeResponse();
                        notifyChangeResponse.FileNotifyInformationBytes = buffer;
                        var responseSetup = notifyChangeResponse.GetSetup();
                        var responseParameters = notifyChangeResponse.GetParameters(false);
                        var responseData = notifyChangeResponse.GetData();
                        var responseList = NTTransactHelper.GetNTTransactResponse(responseSetup, responseParameters, responseData, asyncContext.Connection.MaxBufferSize);
                        if (responseList.Count == 1)
                        {
                            var reply = new SMB1Message();
                            reply.Header = header;
                            reply.Commands.Add(responseList[0]);
                            SMBServer.EnqueueMessage(asyncContext.Connection, reply);
                        }
                        else
                        {
                            // [MS-CIFS] In the event that the number of changes exceeds [..] the maximum size of the NT_Trans_Parameter block in
                            // the response [..] the NT Trans subsystem MUST return an error response with a Status value of STATUS_NOTIFY_ENUM_DIR.
                            header.Status = NTStatus.STATUS_NOTIFY_ENUM_DIR;
                            var response = ObjectsPool<ErrorResponse>.Get().Init(CommandName.SMB_COM_NT_TRANSACT);
                            var reply = new SMB1Message();
                            reply.Header = header;
                            reply.Commands.Add(response);
                            SMBServer.EnqueueMessage(asyncContext.Connection, reply);
                        }
                    }
                    else
                    {
                        // Windows Server 2008 SP1 Will use ErrorResponse to return any status other than STATUS_SUCCESS (including STATUS_CANCELLED and STATUS_DELETE_PENDING).
                        //
                        // [MS-CIFS] In the event that the number of changes exceeds the size of the change notify buffer [..] 
                        // the NT Trans subsystem MUST return an error response with a Status value of STATUS_NOTIFY_ENUM_DIR.
                        var response = ObjectsPool<ErrorResponse>.Get().Init(CommandName.SMB_COM_NT_TRANSACT);
                        var reply = new SMB1Message();
                        reply.Header = header;
                        reply.Commands.Add(response);
                        SMBServer.EnqueueMessage(asyncContext.Connection, reply);
                    }
                }
            }
        }
    }
}
