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

        public async Task<NtResult<(object Handle, FileStatus FileStatus)>> CreateFile(string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
        {
            object handle = null;
            var fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
            var request = ObjectsPool<CreateRequest>.Get().Init();
            
            request.Name = new MemoryOwner<char>(path.ToCharArray().AsMemory());
            request.DesiredAccess = desiredAccess;
            request.FileAttributes = fileAttributes;
            request.ShareAccess = shareAccess;
            request.CreateDisposition = createDisposition;
            request.CreateOptions = createOptions;
            request.ImpersonationLevel = ImpersonationLevel.Impersonation;

            using var response = await TrySendCommandAndDispose(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is CreateResponse)
                {
                    var createResponse = ((CreateResponse)response);
                    handle = createResponse.FileId;
                    fileStatus = ToFileStatus(createResponse.CreateAction);
                    return (handle, fileStatus);
                }

                var status = response.Header.Status;
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTStatus> CloseFile(object handle)
        {
            var request = ObjectsPool<CloseRequest>.Get().Init();
            request.FileId = (FileID)handle;
            
            using var response = await TrySendCommandAndDispose(request);
            if (response != null)
            {
                var status = response.Header.Status;
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NtResult<IMemoryOwner<byte>>> ReadFile(object handle, long offset, int maxCount)
        {
            var request = ObjectsPool<ReadRequest>.Get().Init();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxCount / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.ReadLength = (uint)maxCount;

            using var response = await TrySendCommandAndDispose(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is ReadResponse)
                {
                    return NtResult.Create(((ReadResponse)response).Data.AddOwner());
                }
                var status = response.Header.Status;
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NtResult<int>> WriteFile(object handle, long offset, Memory<byte> data)
        {
            var request = ObjectsPool<WriteRequest>.Get().Init();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)data.Length / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.Data = new MemoryOwner<byte>(data);

            using var response = await TrySendCommandAndDispose(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is WriteResponse)
                {
                    return (int)((WriteResponse)response).Count;
                }
                var status = response.Header.Status;
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public   Task<NTStatus> FlushFileBuffers(object handle)
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
 
        public async Task<NtResult<FileInformation>> GetFileInformation(object handle, FileInformationClass informationClass)
        {
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            using var response = await TrySendCommandAndDispose(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    return ((QueryInfoResponse)response).GetFileInformation(informationClass);
                }
                var status = response.Header.Status;
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTStatus> SetFileInformation(object handle, FileInformation information)
        {
            var request = ObjectsPool<SetInfoRequest>.Get().Init();
            request.InfoType = InfoType.File;
            request.FileInformationClass = information.FileInformationClass;
            request.FileId = (FileID)handle;
            request.SetFileInformation(information);

            using var response = await TrySendCommandAndDispose(request);
            if (response != null)
            {
                var status = response.Header.Status;
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NtResult<FileSystemInformation>> GetFileSystemInformation(FileSystemInformationClass informationClass)
        {
            var result = await CreateFile(String.Empty, (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY | (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE, 0, ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FILE_OPEN, CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE, null);
            if (result.Status != NTStatus.STATUS_SUCCESS)
            {
                return result.Status;
            }

            var fsInfoResponse = await GetFileSystemInformation(result.Content.Handle, informationClass);
            await CloseFile(result.Content.Handle);
            return fsInfoResponse;
        }

        public async Task<NtResult<FileSystemInformation>> GetFileSystemInformation(object handle, FileSystemInformationClass informationClass)
        {
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.FileSystem;
            request.FileSystemInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            
            using var response = await TrySendCommandAndDispose(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    return ((QueryInfoResponse)response).GetFileSystemInformation(informationClass);
                }

                var status = response.Header.Status;
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NotImplementedException();
        }

        public async Task<NtResult<SecurityDescriptor>> GetSecurityInformation(object handle, SecurityInformation securityInformation)
        {
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.Security;
            request.SecurityInformation = securityInformation;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            
            using var response = await TrySendCommandAndDispose(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    return ((QueryInfoResponse)response).GetSecurityInformation();
                }

                var status = response.Header.Status;
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

        public async Task<NtResult<IMemoryOwner<byte>>> DeviceIOControl(object handle, uint ctlCode, byte[] input, int maxOutputLength)
        {
            var request = new IOCtlRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxOutputLength / BytesPerCredit);
            request.CtlCode = ctlCode;
            request.IsFSCtl = true;
            request.FileId = (FileID)handle;
            request.Input = new SimpleMemoryOwner(input).AsCountdown();
            request.MaxOutputResponse = (uint)maxOutputLength;
            
            using var response = await TrySendCommandAndDispose(request);
            if (response != null)
            {
                if ((response.Header.Status == NTStatus.STATUS_SUCCESS || response.Header.Status == NTStatus.STATUS_BUFFER_OVERFLOW) && response is IOCtlResponse)
                {
                    return NtResult.Create(((IOCtlResponse)response).Output);
                }

                var status = response.Header.Status;
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTStatus> Disconnect()
        {
            var request = new TreeDisconnectRequest();
            
            using var response = await TrySendCommandAndDispose(request);
            if (response != null)
            {
                var status = response.Header.Status;
                return status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        private async Task<SMB2Command> TrySendCommandAndDispose(SMB2Command request)
        {
            request.Header.TreeId = m_treeID;
            var response = await m_client.TrySendCommand(request);
            request.Dispose();
            return response;
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
    }
}
