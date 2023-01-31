/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
using SMBLibrary.Client;

namespace SMBLibrary
{
    public delegate void OnNotifyChangeCompleted(NTStatus status, IMemoryOwner<byte> buffer, object context);

    /// <summary>
    /// A file store (a.k.a. object store) interface to allow access to a file system or a named pipe in an NT-like manner dictated by the SMB protocol.
    /// </summary>
    public interface INTFileStore
    {
        Task<NtResult<(object Handle, FileStatus FileStatus)>> CreateFile(string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext);

        Task<NTStatus> CloseFile(object handle);

        Task<NtResult<IMemoryOwner<byte>>> ReadFile(object handle, long offset, int maxCount);

        Task<NtResult<int>> WriteFile(object handle, long offset, Memory<byte> data);

        Task<NTStatus> FlushFileBuffers(object handle);

        NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock);

        NTStatus UnlockFile(object handle, long byteOffset, long length);

        NTStatus QueryDirectory(out List<FindFilesQueryResult> result, object handle, string fileName, FileInformationClass informationClass);
        IAsyncEnumerable<FindFilesQueryResult> QueryDirectoryAsync(object handle, string fileName, FileInformationClass informationClass, bool closeOnFinish, CancellationToken outerToken = default);
        
        Task<NtResult<FileInformation>> GetFileInformation(object handle, FileInformationClass informationClass);

        Task<NTStatus> SetFileInformation(object handle, FileInformation information);

        Task<NtResult<FileSystemInformation>> GetFileSystemInformation(FileSystemInformationClass informationClass);

        NTStatus SetFileSystemInformation(FileSystemInformation information);

        Task<NtResult<SecurityDescriptor>> GetSecurityInformation(object handle, SecurityInformation securityInformation);

        NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor);

        /// <summary>
        /// Monitor the contents of a directory (and its subdirectories) by using change notifications.
        /// When something changes within the directory being watched this operation is completed.
        /// </summary>
        /// <returns>
        /// STATUS_PENDING - The directory is being watched, change notification will be provided using callback method.
        /// STATUS_NOT_SUPPORTED - The underlying object store does not support change notifications.
        /// STATUS_INVALID_HANDLE - The handle supplied is invalid.
        /// </returns>
        NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context);

        NTStatus Cancel(object ioRequest);

        Task<NtResult<IMemoryOwner<byte>>> DeviceIOControl(object handle, uint ctlCode, byte[] input, int maxOutputLength);
    }
}
