/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using MemoryPools.Memory;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Server.SMB2
{
    internal class CreateHelper
    {
        internal static SMB2Command GetCreateResponse(CreateRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            var session = state.GetSession(request.Header.SessionId);
            Span<char> path = stackalloc char[request.Name.Memory.Length + 1];
            if (request.Name.Memory.Span[0] != '\\')
            {
                path[0] = '\\';
                request.Name.Memory.Span.CopyTo(path.Slice(1));
            }
            else
            {
                request.Name.Memory.Span.CopyTo(path);
            }

            var createAccess = NTFileStoreHelper.ToCreateFileAccess(request.DesiredAccess, request.CreateDisposition);
            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasAccess(session.SecurityContext, path, createAccess))
                {
                    state.LogToServer(Severity.Verbose, "Create: Opening '{0}{1}' failed. User '{2}' was denied access.", share.Name, path.ToString(), session.UserName);
                    return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_ACCESS_DENIED);
                }
            }

            object handle;
            FileStatus fileStatus;
            // GetFileInformation/FileNetworkOpenInformation requires FILE_READ_ATTRIBUTES
            var desiredAccess = request.DesiredAccess | (AccessMask)FileAccessMask.FILE_READ_ATTRIBUTES;
            var createStatus = share.FileStore.CreateFile(out handle, out fileStatus, Arrays.RentFrom<char>(path), desiredAccess, request.FileAttributes, request.ShareAccess, request.CreateDisposition, request.CreateOptions, session.SecurityContext);
            if (createStatus != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "Create: Opening '{0}{1}' failed. NTStatus: {2}.", share.Name, path.ToString(), createStatus);
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, createStatus);
            }

            var fileAccess = NTFileStoreHelper.ToFileAccess(desiredAccess);
            var fileID = session.AddOpenFile(request.Header.TreeId, share.Name, path.ToString(), handle, fileAccess);
            if (fileID == null)
            {
                share.FileStore.CloseFile(handle);
                state.LogToServer(Severity.Verbose, "Create: Opening '{0}{1}' failed. Too many open files.", share.Name, path.ToString());
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_TOO_MANY_OPENED_FILES);
            }

            var fileAccessString = fileAccess.ToString().Replace(", ", "|");
            var shareAccessString = request.ShareAccess.ToString().Replace(", ", "|");
            state.LogToServer(Severity.Verbose, "Create: Opened '{0}{1}', FileAccess: {2}, ShareAccess: {3}. (SessionID: {4}, TreeID: {5}, FileId: {6})", share.Name, path.ToString(), fileAccessString, shareAccessString, request.Header.SessionId, request.Header.TreeId, fileID.Volatile);
            if (share is NamedPipeShare)
            {
                return CreateResponseForNamedPipe(fileID, FileStatus.FILE_OPENED);
            }

            var fileInfo = NTFileStoreHelper.GetNetworkOpenInformation(share.FileStore, handle);
            var response = CreateResponseFromFileSystemEntry(fileInfo, fileID, fileStatus);
            return response;
        }

        private static CreateResponse CreateResponseForNamedPipe(FileID fileID, FileStatus fileStatus)
        {
            var response = new CreateResponse();
            response.CreateAction = (CreateAction)fileStatus;
            response.FileAttributes = FileAttributes.Normal;
            response.FileId = fileID;
            return response;
        }

        private static CreateResponse CreateResponseFromFileSystemEntry(FileNetworkOpenInformation fileInfo, FileID fileID, FileStatus fileStatus)
        {
            var response = new CreateResponse();
            response.CreateAction = (CreateAction)fileStatus;
            response.CreationTime = fileInfo.CreationTime;
            response.LastWriteTime = fileInfo.LastWriteTime;
            response.ChangeTime = fileInfo.LastWriteTime;
            response.LastAccessTime = fileInfo.LastAccessTime;
            response.AllocationSize = fileInfo.AllocationSize;
            response.EndofFile = fileInfo.EndOfFile;
            response.FileAttributes = fileInfo.FileAttributes;
            response.FileId = fileID;
            return response;
        }
    }
}
