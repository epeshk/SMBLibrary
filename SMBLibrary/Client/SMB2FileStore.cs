/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MemoryPools.Memory;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Client
{
    public partial class Smb2FileStore : ISMBFileStore
    {
        private const int BytesPerCredit = 65536;

        private Smb2Client m_client;
        private uint m_treeID;

        public Smb2FileStore(Smb2Client client, uint treeId)
        {
            m_client = client;
            m_treeID = treeId;
        }

        public virtual NTStatus CreateFile(out object handle, out FileStatus fileStatus, IMemoryOwner<char> path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
        {
            handle = null;
            fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
            var request = ObjectsPool<CreateRequest>.Get().Init();
            request.Name = path.AddOwner();
            request.DesiredAccess = desiredAccess;
            request.FileAttributes = fileAttributes;
            request.ShareAccess = shareAccess;
            request.CreateDisposition = createDisposition;
            request.CreateOptions = createOptions;
            request.ImpersonationLevel = ImpersonationLevel.Impersonation;
            
            TrySendCommandAndDispose(request);

            var response = WaitForCommand(SMB2CommandName.Create);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is CreateResponse)
                {
                    var createResponse = ((CreateResponse)response);
                    handle = createResponse.FileId;
                    fileStatus = ToFileStatus(createResponse.CreateAction);
                }

                var status = response.Header.Status;
                response.Dispose();
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public virtual NTStatus CloseFile(object handle)
        {
            var request = ObjectsPool<CloseRequest>.Get().Init();
            request.FileId = (FileID)handle;
            TrySendCommandAndDispose(request);
            var response = WaitForCommand(SMB2CommandName.Close);
            if (response != null)
            {
                var status = response.Header.Status;
                response.Dispose();
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus ReadFile(out IMemoryOwner<byte> data, object handle, long offset, int maxCount)
        {
            data = MemoryOwner<byte>.Empty;
            var request = ObjectsPool<ReadRequest>.Get().Init();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxCount / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.ReadLength = (uint)maxCount;
            
            TrySendCommandAndDispose(request);
            var response = WaitForCommand(SMB2CommandName.Read);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is ReadResponse)
                {
                    data = ((ReadResponse)response).Data.AddOwner();
                }
                var status = response.Header.Status;
                response.Dispose();
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, IMemoryOwner<byte> data)
        {
            numberOfBytesWritten = 0;
            var request = ObjectsPool<WriteRequest>.Get().Init();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)data.Length() / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.Data = data;

            TrySendCommandAndDispose(request);
            var response = WaitForCommand(SMB2CommandName.Write);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is WriteResponse)
                {
                    numberOfBytesWritten = (int)((WriteResponse)response).Count;
                }
                var status = response.Header.Status;
                response.Dispose();
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus FlushFileBuffers(object handle)
        {
            throw new NotImplementedException();
        }

        public NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock)
        {
            throw new NotImplementedException();
        }

        public NTStatus UnlockFile(object handle, long byteOffset, long length)
        {
            throw new NotImplementedException();
        }

        public virtual NTStatus QueryDirectory(out List<FindFilesQueryResult> result, object handle, string fileName, FileInformationClass informationClass)
        {
            throw new NotImplementedException();
            // result = QueryDirectoryAsync(handle, fileName, informationClass, CancellationToken.None).ToEnumerable().ToList();
            // return NTStatus.STATUS_SUCCESS;
        }
        
        public virtual IAsyncEnumerable<FindFilesQueryResult> QueryDirectoryAsync(
            object handle, string fileName, FileInformationClass informationClass, bool closeOnFinish,  CancellationToken outerToken)
        {
            return ObjectsPool<QueryDirectoryAsyncEnumerable>.Get().Init(this, m_client, handle, fileName, informationClass, closeOnFinish);
        }
 
        public NTStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass)
        {
            result = null;
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            TrySendCommandAndDispose(request);
            var response = WaitForCommand(SMB2CommandName.QueryInfo);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetFileInformation(informationClass);
                }
                var status = response.Header.Status;
                response.Dispose();
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus SetFileInformation(object handle, FileInformation information)
        {
            var request = ObjectsPool<SetInfoRequest>.Get().Init();
            request.InfoType = InfoType.File;
            request.FileInformationClass = information.FileInformationClass;
            request.FileId = (FileID)handle;
            request.SetFileInformation(information);

            TrySendCommandAndDispose(request);
            var response = WaitForCommand(SMB2CommandName.SetInfo);
            if (response != null)
            {
                var status = response.Header.Status;
                response.Dispose();
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass)
        {
            result = null;
            var status = CreateFile(out var fileHandle, out var _, MemoryOwner<char>.Empty, (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY | (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE, 0, ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FILE_OPEN, CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }

            status = GetFileSystemInformation(out result, fileHandle, informationClass);
            CloseFile(fileHandle);
            return status;
        }

        public NTStatus GetFileSystemInformation(out FileSystemInformation result, object handle, FileSystemInformationClass informationClass)
        {
            result = null;
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.FileSystem;
            request.FileSystemInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            TrySendCommandAndDispose(request);
            var response = WaitForCommand(SMB2CommandName.QueryInfo);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetFileSystemInformation(informationClass);
                }

                var status = response.Header.Status;
                response.Dispose();
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NotImplementedException();
        }

        public NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle, SecurityInformation securityInformation)
        {
            result = null;
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.Security;
            request.SecurityInformation = securityInformation;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            TrySendCommandAndDispose(request);
            var response = WaitForCommand(SMB2CommandName.QueryInfo);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetSecurityInformation();
                }

                var status = response.Header.Status;
                response.Dispose();
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            throw new NotImplementedException();
        }

        public NTStatus Cancel(object ioRequest)
        {
            throw new NotImplementedException();
        }

        public NTStatus DeviceIOControl(object handle, uint ctlCode, IMemoryOwner<byte> input, out IMemoryOwner<byte> output, int maxOutputLength)
        {
            throw new NotImplementedException();
        }

        public NTStatus DeviceIoControl(object handle, uint ctlCode, byte[] input, out IMemoryOwner<byte> output, int maxOutputLength)
        {
            output = null;
            var request = new IOCtlRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxOutputLength / BytesPerCredit);
            request.CtlCode = ctlCode;
            request.IsFSCtl = true;
            request.FileId = (FileID)handle;
            request.Input = new SimpleMemoryOwner(input).AsCountdown();
            request.MaxOutputResponse = (uint)maxOutputLength;
            TrySendCommandAndDispose(request);
            var response = WaitForCommand(SMB2CommandName.IOCtl);
            if (response != null)
            {
                if ((response.Header.Status == NTStatus.STATUS_SUCCESS || response.Header.Status == NTStatus.STATUS_BUFFER_OVERFLOW) && response is IOCtlResponse)
                {
                    output = ((IOCtlResponse)response).Output;
                }

                var status = response.Header.Status;
                response.Dispose();
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus Disconnect()
        {
            var request = new TreeDisconnectRequest();
            TrySendCommandAndDispose(request);
            var response = WaitForCommand(SMB2CommandName.TreeDisconnect);
            if (response != null)
            {
                var status = response.Header.Status;
                response.Dispose();
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        private void TrySendCommandAndDispose(SMB2Command request)
        {
            request.Header.TreeId = m_treeID;
            m_client.TrySendCommand(request);
        }
        
        private ValueTask TrySendCommandAsync(SMB2Command request)
        {
            request.Header.TreeId = m_treeID;
            return m_client.TrySendCommandAsync(request);
        }

        public uint MaxReadSize => m_client.MaxReadSize;

        public uint MaxWriteSize => m_client.MaxWriteSize;

        private static FileStatus ToFileStatus(CreateAction createAction)
        {
            switch (createAction)
            {
                case CreateAction.FILE_SUPERSEDED:
                    return FileStatus.FILE_SUPERSEDED;
                case CreateAction.FILE_OPENED:
                    return FileStatus.FILE_OPENED;
                case CreateAction.FILE_CREATED:
                    return FileStatus.FILE_CREATED;
                case CreateAction.FILE_OVERWRITTEN:
                    return FileStatus.FILE_OVERWRITTEN;
                default:
                    return FileStatus.FILE_OPENED;
            }
        }
        
        private SMB2Command WaitForCommand(SMB2CommandName smb2CommandName)
        {
            SMB2Command response = m_client.WaitForCommand(smb2CommandName);
            while (response != null && response.Header.Status == NTStatus.STATUS_PENDING)
            {
                response = m_client.WaitForCommand(smb2CommandName);
                if (response == null)
                {
                    throw new TimeoutException(
                        "Waiting too long.\n" +
                        $"SMB Server has not responded after sending {nameof(NTStatus.STATUS_PENDING)}.");
                }
            }

            return response;
        }
    }
}
