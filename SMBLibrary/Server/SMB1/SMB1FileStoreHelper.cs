/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using MemoryPools.Memory;
using SMBLibrary.SMB1;

namespace SMBLibrary.Server.SMB1
{
    internal partial class SMB1FileStoreHelper
    {
        public static NTStatus CreateDirectory(INTFileStore fileStore, string path, SecurityContext securityContext)
        {
            object handle;
            FileStatus fileStatus;
            var createStatus = fileStore.CreateFile(out handle, out fileStatus, Arrays.RentFrom<char>(path), (AccessMask)DirectoryAccessMask.FILE_ADD_SUBDIRECTORY, 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_CREATE, CreateOptions.FILE_DIRECTORY_FILE, securityContext);
            if (createStatus != NTStatus.STATUS_SUCCESS)
            {
                return createStatus;
            }
            fileStore.CloseFile(handle);
            return createStatus;
        }

        public static NTStatus DeleteDirectory(INTFileStore fileStore, string path, SecurityContext securityContext)
        {
            return Delete(fileStore, path, CreateOptions.FILE_DIRECTORY_FILE, securityContext);
        }

        public static NTStatus DeleteFile(INTFileStore fileStore, string path, SecurityContext securityContext)
        {
            return Delete(fileStore, path, CreateOptions.FILE_NON_DIRECTORY_FILE, securityContext);
        }

        public static NTStatus Delete(INTFileStore fileStore, string path, CreateOptions createOptions, SecurityContext securityContext)
        {
            object handle;
            FileStatus fileStatus;
            var shareAccess = ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete;
            var status = fileStore.CreateFile(out handle, out fileStatus, Arrays.RentFrom<char>(path), AccessMask.DELETE, 0, shareAccess, CreateDisposition.FILE_OPEN, createOptions, securityContext);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }
            var fileDispositionInfo = new FileDispositionInformation();
            fileDispositionInfo.DeletePending = true;
            status = fileStore.SetFileInformation(handle, fileDispositionInfo);
            fileStore.CloseFile(handle);
            return status;
        }

        public static NTStatus Rename(INTFileStore fileStore, ReadOnlySpan<char> oldName, ReadOnlySpan<char> newName, SMBFileAttributes searchAttributes, SecurityContext securityContext)
        {
            object handle;
            FileStatus fileStatus;
            CreateOptions createOptions = 0;
            // Windows 2000 SP4 clients will use this command to rename directories.
            // Hidden, System and Directory attributes are inclusive.
            if ((searchAttributes & SMBFileAttributes.Directory) == 0)
            {
                createOptions = CreateOptions.FILE_NON_DIRECTORY_FILE;
            }
            var shareAccess = ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete;
            var status = fileStore.CreateFile(out handle, out fileStatus, Arrays.RentFrom(oldName), AccessMask.DELETE, 0, shareAccess, CreateDisposition.FILE_OPEN, createOptions, securityContext);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }
            var renameInfo = new FileRenameInformationType2();
            renameInfo.ReplaceIfExists = false;
            renameInfo.FileName = Arrays.RentFrom(newName);
            status = fileStore.SetFileInformation(handle, renameInfo);
            fileStore.CloseFile(handle);
            return status;
        }

        public static NTStatus CheckDirectory(INTFileStore fileStore, string path, SecurityContext securityContext)
        {
            object handle;
            FileStatus fileStatus;
            var openStatus = fileStore.CreateFile(out handle, out fileStatus, Arrays.RentFrom<char>(path), 0, 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE, securityContext);
            if (openStatus != NTStatus.STATUS_SUCCESS)
            {
                return openStatus;
            }

            fileStore.CloseFile(handle);
            return NTStatus.STATUS_SUCCESS;
        }

        public static NTStatus QueryInformation(out FileNetworkOpenInformation fileInfo, INTFileStore fileStore, string path, SecurityContext securityContext)
        {
            object handle;
            FileStatus fileStatus;
            var openStatus = fileStore.CreateFile(out handle, out fileStatus, Arrays.RentFrom<char>(path), (AccessMask)FileAccessMask.FILE_READ_ATTRIBUTES, 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, 0, securityContext);
            if (openStatus != NTStatus.STATUS_SUCCESS)
            {
                fileInfo = null;
                return openStatus;
            }

            fileInfo = NTFileStoreHelper.GetNetworkOpenInformation(fileStore, handle);
            fileStore.CloseFile(handle);
            return NTStatus.STATUS_SUCCESS;
        }

        public static NTStatus SetInformation(INTFileStore fileStore, string path, SMBFileAttributes fileAttributes, DateTime? lastWriteTime, SecurityContext securityContext)
        {
            object handle;
            FileStatus fileStatus;
            var status = fileStore.CreateFile(out handle, out fileStatus, Arrays.RentFrom<char>(path), (AccessMask)FileAccessMask.FILE_WRITE_ATTRIBUTES, 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, 0, securityContext);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }

            var basicInfo = new FileBasicInformation();
            basicInfo.LastWriteTime = lastWriteTime;

            if ((fileAttributes & SMBFileAttributes.Hidden) > 0)
            {
                basicInfo.FileAttributes.Value |= FileAttributes.Hidden;
            }

            if ((fileAttributes & SMBFileAttributes.ReadOnly) > 0)
            {
                basicInfo.FileAttributes.Value |= FileAttributes.ReadOnly;
            }

            if ((fileAttributes & SMBFileAttributes.Archive) > 0)
            {
                basicInfo.FileAttributes.Value |= FileAttributes.Archive;
            }

            status = fileStore.SetFileInformation(handle, basicInfo);
            fileStore.CloseFile(handle);
            return status;
        }

        public static NTStatus SetInformation2(INTFileStore fileStore, object handle, DateTime? creationTime, DateTime? lastAccessTime, DateTime? lastWriteTime)
        {
            var fileInfo = NTFileStoreHelper.GetNetworkOpenInformation(fileStore, handle);
            var basicInfo = new FileBasicInformation();
            basicInfo.FileAttributes = fileInfo.FileAttributes;
            basicInfo.CreationTime = creationTime;
            basicInfo.LastAccessTime = lastAccessTime;
            basicInfo.LastWriteTime = lastWriteTime;
            return fileStore.SetFileInformation(handle, basicInfo);
        }

        public static SMBFileAttributes GetFileAttributes(FileAttributes attributes)
        {
            var result = SMBFileAttributes.Normal;
            if ((attributes.Value & FileAttributes.Hidden) > 0)
            {
                result |= SMBFileAttributes.Hidden;
            }
            if ((attributes.Value & FileAttributes.ReadOnly) > 0)
            {
                result |= SMBFileAttributes.ReadOnly;
            }
            if ((attributes.Value & FileAttributes.Archive) > 0)
            {
                result |= SMBFileAttributes.Archive;
            }
            if ((attributes.Value & FileAttributes.Directory) > 0)
            {
                result |= SMBFileAttributes.Directory;
            }

            return result;
        }
    }
}
