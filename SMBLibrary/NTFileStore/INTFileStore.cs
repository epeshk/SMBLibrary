/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using SMBLibrary.Client;
using Utilities;

namespace SMBLibrary
{
    public delegate void OnNotifyChangeCompleted(NTStatus status, byte[] buffer, object context);

    /// <summary>
    /// A file store (a.k.a. object store) interface to allow access to a file system or a named pipe in an NT-like manner dictated by the SMB protocol.
    /// </summary>
    public interface INTFileStore
    {
        Task<NTResult<(object Handle, FileStatus FileStatus)>> CreateFile(string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext);

        Task<NTStatus> CloseFile(object handle);

        Task<NTResult<byte[]>> ReadFile(object handle, long offset, int maxCount);

        Task<NTResult<int>> WriteFile(object handle, long offset, byte[] data);

        Task<NTStatus> FlushFileBuffers(object handle);

        Task<NTResult<List<QueryDirectoryFileInformation>>> QueryDirectory(object handle, string fileName, FileInformationClass informationClass);

        Task<NTResult<FileInformation>> GetFileInformation(object handle, FileInformationClass informationClass);

        Task<NTStatus> SetFileInformation(object handle, FileInformation information);

        Task<NTResult<FileSystemInformation>> GetFileSystemInformation(FileSystemInformationClass informationClass);

        Task<NTResult<SecurityDescriptor>> GetSecurityInformation(object handle, SecurityInformation securityInformation);

        NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor);

        Task<NTResult<byte[]>> DeviceIOControl(object handle, uint ctlCode, byte[] input, int maxOutputLength);
    }
}
