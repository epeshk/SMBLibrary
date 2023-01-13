/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Client
{
    public class SMB2FileStore : ISMBFileStore
    {
        private const int BytesPerCredit = 65536;

        private SMB2Client m_client;
        private uint m_treeID;
        private bool m_encryptShareData;

        public SMB2FileStore(SMB2Client client, uint treeID, bool encryptShareData)
        {
            m_client = client;
            m_treeID = treeID;
            m_encryptShareData = encryptShareData;
        }

        public async Task<NTResult<(object Handle, FileStatus FileStatus)>> CreateFile(string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
        {
            object handle = null;
            var fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
            CreateRequest request = new CreateRequest();
            request.Name = path;
            request.DesiredAccess = desiredAccess;
            request.FileAttributes = fileAttributes;
            request.ShareAccess = shareAccess;
            request.CreateDisposition = createDisposition;
            request.CreateOptions = createOptions;
            request.ImpersonationLevel = ImpersonationLevel.Impersonation;

            SMB2Command response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is CreateResponse)
                {
                    CreateResponse createResponse = (CreateResponse)response;
                    handle = createResponse.FileId;
                    fileStatus = ToFileStatus(createResponse.CreateAction);
                    return (handle, fileStatus);
                }
                return new (response.Header.Status, (handle, fileStatus));
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTStatus> CloseFile(object handle)
        {
            CloseRequest request = new CloseRequest();
            request.FileId = (FileID)handle;
            
            SMB2Command response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTResult<byte[]>> ReadFile(object handle, long offset, int maxCount)
        {
            ReadRequest request = new ReadRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxCount / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.ReadLength = (uint)maxCount;

            SMB2Command response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is ReadResponse)
                {
                    return new (((ReadResponse)response).Data);
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTResult<int>> WriteFile(object handle, long offset, byte[] data)
        {
            WriteRequest request = new WriteRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)data.Length / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.Data = data;

            SMB2Command response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is WriteResponse)
                {
                    return (int)((WriteResponse)response).Count;
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTStatus> FlushFileBuffers(object handle)
        {
            FlushRequest request = new FlushRequest();
            request.FileId = (FileID) handle;

            SMB2Command response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is FlushResponse)
                {
                    return NTStatus.STATUS_SUCCESS;
                }
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTResult<List<QueryDirectoryFileInformation>>> QueryDirectory(object handle, string fileName, FileInformationClass informationClass)
        {
            var result = new List<QueryDirectoryFileInformation>();
            QueryDirectoryRequest request = new QueryDirectoryRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)m_client.MaxTransactSize / BytesPerCredit);
            request.FileInformationClass = informationClass;
            request.Reopen = true;
            request.FileId = (FileID)handle;
            request.OutputBufferLength = m_client.MaxTransactSize;
            request.FileName = fileName;

            SMB2Command response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                while (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryDirectoryResponse)
                {
                    List<QueryDirectoryFileInformation> page = ((QueryDirectoryResponse)response).GetFileInformationList(informationClass);
                    result.AddRange(page);
                    request.Reopen = false;
                    response = await TrySendCommand<SMB2Command>(request);
                }
                return new(response.Header.Status, result);
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTResult<FileInformation>> GetFileInformation(object handle, FileInformationClass informationClass)
        {
            FileInformation result = null;
            QueryInfoRequest request = new QueryInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            SMB2Command response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetFileInformation(informationClass);
                }
                return new (response.Header.Status, result);
            }

            return new (NTStatus.STATUS_INVALID_SMB);
        }

        public async Task<NTStatus> SetFileInformation(object handle, FileInformation information)
        {
            SetInfoRequest request = new SetInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = information.FileInformationClass;
            request.FileId = (FileID)handle;
            request.SetFileInformation(information);

            SMB2Command response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTResult<FileSystemInformation>> GetFileSystemInformation(FileSystemInformationClass informationClass)
        {
            var result = await CreateFile(String.Empty, (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY | (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE, 0, ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FILE_OPEN, CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE, null);
            if (result.Status != NTStatus.STATUS_SUCCESS)
            {
                return new(result.Status);
            }

            var fsInfoResponse = await GetFileSystemInformation(result.Content.Handle, informationClass);
            await CloseFile(result.Content.Handle);
            return fsInfoResponse;
        }

        public async Task<NTResult<FileSystemInformation>> GetFileSystemInformation(object handle, FileSystemInformationClass informationClass)
        {
            QueryInfoRequest request = new QueryInfoRequest();
            request.InfoType = InfoType.FileSystem;
            request.FileSystemInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            SMB2Command response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    var result = ((QueryInfoResponse)response).GetFileSystemInformation(informationClass);
                    return new NTResult<FileSystemInformation>(result);
                }
                return new (response.Header.Status);
            }

            return new(NTStatus.STATUS_INVALID_SMB);
        }

        public async Task<NTResult<SecurityDescriptor>> GetSecurityInformation(object handle, SecurityInformation securityInformation)
        {
            QueryInfoRequest request = new QueryInfoRequest();
            request.InfoType = InfoType.Security;
            request.SecurityInformation = securityInformation;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            SMB2Command response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    return ((QueryInfoResponse)response).GetSecurityInformation();
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public async Task<NTResult<byte[]>> DeviceIOControl(object handle, uint ctlCode, byte[] input, int maxOutputLength)
        {
            IOCtlRequest request = new IOCtlRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxOutputLength / BytesPerCredit);
            request.CtlCode = ctlCode;
            request.IsFSCtl = true;
            request.FileId = (FileID)handle;
            request.Input = input;
            request.MaxOutputResponse = (uint)maxOutputLength;
            SMB2Command response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                if ((response.Header.Status == NTStatus.STATUS_SUCCESS || response.Header.Status == NTStatus.STATUS_BUFFER_OVERFLOW) && response is IOCtlResponse)
                {
                    return ((IOCtlResponse)response).Output;
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTStatus> Disconnect()
        {
            TreeDisconnectRequest request = new TreeDisconnectRequest();
            var response = await TrySendCommand<SMB2Command>(request);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        private Task<TResponse> TrySendCommand<TResponse>(SMB2Command request) where TResponse : SMB2Command
        {
            request.Header.TreeID = m_treeID;
            return m_client.TrySendCommand<TResponse>(request, m_encryptShareData);
        }

        public uint MaxReadSize
        {
            get
            {
                return m_client.MaxReadSize;
            }
        }

        public uint MaxWriteSize
        {
            get
            {
                return m_client.MaxWriteSize;
            }
        }

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
