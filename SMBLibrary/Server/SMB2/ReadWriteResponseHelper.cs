/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    internal class ReadWriteResponseHelper
    {
        internal static SMB2Command GetReadResponse(ReadRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            var session = state.GetSession(request.Header.SessionId);
            var openFile = session.GetOpenFileObject(request.FileId);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Read failed. Invalid FileId. (SessionID: {0}, TreeID: {1}, FileId: {2})", request.Header.SessionId, request.Header.TreeId, request.FileId.Volatile);
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_FILE_CLOSED);
            }

            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, openFile.Path))
                {
                    state.LogToServer(Severity.Verbose, "Read from '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                    return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_ACCESS_DENIED);
                }
            }
            IMemoryOwner<byte> data;
            var readStatus = share.FileStore.ReadFile(out data, openFile.Handle, (long)request.Offset, (int)request.ReadLength);
            if (readStatus != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "Read from '{0}{1}' failed. NTStatus: {2}. (FileId: {3})", share.Name, openFile.Path, readStatus, request.FileId.Volatile);
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, readStatus);
            }
            var response = new ReadResponse();
            response.Data = data;
            return response;
        }

        internal static SMB2Command GetWriteResponse(WriteRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            var session = state.GetSession(request.Header.SessionId);
            var openFile = session.GetOpenFileObject(request.FileId);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Write failed. Invalid FileId. (SessionID: {0}, TreeID: {1}, FileId: {2})", request.Header.SessionId, request.Header.TreeId, request.FileId.Volatile);
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_FILE_CLOSED);
            }

            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasWriteAccess(session.SecurityContext, openFile.Path))
                {
                    state.LogToServer(Severity.Verbose, "Write to '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                    return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_ACCESS_DENIED);
                }
            }

            int numberOfBytesWritten;
            var writeStatus = share.FileStore.WriteFile(out numberOfBytesWritten, openFile.Handle, (long)request.Offset, request.Data);
            if (writeStatus != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "Write to '{0}{1}' failed. NTStatus: {2}. (FileId: {3})", share.Name, openFile.Path, writeStatus, request.FileId.Volatile);
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, writeStatus);
            }
            var response = new WriteResponse();
            response.Count = (uint)numberOfBytesWritten;
            return response;
        }

        internal static SMB2Command GetFlushResponse(FlushRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            var session = state.GetSession(request.Header.SessionId);
            var openFile = session.GetOpenFileObject(request.FileId);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Flush failed. Invalid FileId. (SessionID: {0}, TreeID: {1}, FileId: {2})", request.Header.SessionId, request.Header.TreeId, request.FileId.Volatile);
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_FILE_CLOSED);
            }
            var status = share.FileStore.FlushFileBuffers(openFile.Handle);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "Flush '{0}{1}' failed. NTStatus: {2}. (FileId: {3})", share.Name, openFile.Path, status, request.FileId.Volatile);
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, status);
            }
            return new FlushResponse();
        }
    }
}
