/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary
{
    public partial class NTFileSystemAdapter
    {
        public NTStatus SetFileInformation(object handle, FileInformation information)
        {
            var fileHandle = (FileHandle)handle;
            if (information is FileBasicInformation)
            {
                var basicInformation = (FileBasicInformation)information;
                var isHidden = ((basicInformation.FileAttributes.Value & FileAttributes.Hidden) > 0);
                var isReadonly = (basicInformation.FileAttributes.Value & FileAttributes.ReadOnly) > 0;
                var isArchived = (basicInformation.FileAttributes.Value & FileAttributes.Archive) > 0;
                try
                {
                    m_fileSystem.SetAttributes(fileHandle.Path.Memory.Span.ToString(), isHidden, isReadonly, isArchived);
                }
                catch (Exception ex)
                {
                    if (ex is IOException || ex is UnauthorizedAccessException)
                    {
                        var status = ToNTStatus(ex);
                        Log(Severity.Verbose, "SetFileInformation: Failed to set file attributes on '{0}'. {1}.", fileHandle.Path, status);
                        return status;
                    }

                    throw;
                }

                try
                {
                    m_fileSystem.SetDates(fileHandle.Path.Memory.Span.ToString(), basicInformation.CreationTime, basicInformation.LastWriteTime, basicInformation.LastAccessTime);
                }
                catch (Exception ex)
                {
                    if (ex is IOException || ex is UnauthorizedAccessException)
                    {
                        var status = ToNTStatus(ex);
                        Log(Severity.Verbose, "SetFileInformation: Failed to set file dates on '{0}'. {1}.", fileHandle.Path, status);
                        return status;
                    }

                    throw;
                }
                return NTStatus.STATUS_SUCCESS;
            }

            if (information is FileRenameInformationType2)
            {
                var renameInformation = (FileRenameInformationType2)information;
                var newFileName = renameInformation.FileName.Memory.Span.ToString();
                if (!newFileName.StartsWith(@"\"))
                {
                    newFileName = @"\" + newFileName;
                }

                if (fileHandle.Stream != null)
                {
                    fileHandle.Stream.Close();
                }

                // Note: it's possible that we just want to upcase / downcase a filename letter.
                try
                {
                    if (renameInformation.ReplaceIfExists && (IsFileExists(newFileName)))
                    {
                        m_fileSystem.Delete(newFileName);
                    }
                    m_fileSystem.Move(fileHandle.Path.Memory.Span.ToString(), newFileName);
                    Log(Severity.Information, "SetFileInformation: Renamed '{0}' to '{1}'", fileHandle.Path, newFileName);
                }
                catch (Exception ex)
                {
                    if (ex is IOException || ex is UnauthorizedAccessException)
                    {
                        var status = ToNTStatus(ex);
                        Log(Severity.Verbose, "SetFileInformation: Cannot rename '{0}' to '{1}'. {2}.", fileHandle.Path, newFileName, status);
                        return status;
                    }

                    throw;
                }
                fileHandle.Path = Arrays.RentFrom<char>(newFileName);
                return NTStatus.STATUS_SUCCESS;
            }

            if (information is FileDispositionInformation)
            {
                if (((FileDispositionInformation)information).DeletePending)
                {
                    // We're supposed to delete the file on close, but it's too late to report errors at this late stage
                    if (fileHandle.Stream != null)
                    {
                        fileHandle.Stream.Close();
                    }

                    try
                    {
                        m_fileSystem.Delete(fileHandle.Path.Memory.Span.ToString());
                        Log(Severity.Information, "SetFileInformation: Deleted '{0}'", fileHandle.Path);
                    }
                    catch (Exception ex)
                    {
                        if (ex is IOException || ex is UnauthorizedAccessException)
                        {
                            var status = ToNTStatus(ex);
                            Log(Severity.Information, "SetFileInformation: Error deleting '{0}'. {1}.", fileHandle.Path, status);
                            return status;
                        }

                        throw;
                    }
                }
                return NTStatus.STATUS_SUCCESS;
            }

            if (information is FileAllocationInformation)
            {
                var allocationSize = ((FileAllocationInformation)information).AllocationSize;
                try
                {
                    fileHandle.Stream.SetLength(allocationSize);
                }
                catch (Exception ex)
                {
                    if (ex is IOException || ex is UnauthorizedAccessException)
                    {
                        var status = ToNTStatus(ex);
                        Log(Severity.Verbose, "SetFileInformation: Cannot set allocation for '{0}'. {1}.", fileHandle.Path, status);
                        return status;
                    }

                    throw;
                }
                return NTStatus.STATUS_SUCCESS;
            }

            if (information is FileEndOfFileInformation)
            {
                var endOfFile = ((FileEndOfFileInformation)information).EndOfFile;
                try
                {
                    fileHandle.Stream.SetLength(endOfFile);
                }
                catch (Exception ex)
                {
                    if (ex is IOException || ex is UnauthorizedAccessException)
                    {
                        var status = ToNTStatus(ex);
                        Log(Severity.Verbose, "SetFileInformation: Cannot set end of file for '{0}'. {1}.", fileHandle.Path, status);
                        return status;
                    }

                    throw;
                }
                return NTStatus.STATUS_SUCCESS;
            }

            return NTStatus.STATUS_NOT_IMPLEMENTED;
        }

        private bool IsFileExists(string path)
        {
            try
            {
                m_fileSystem.GetEntry(path);
            }
            catch (FileNotFoundException)
            {
                return false;
            }
            catch (DirectoryNotFoundException)
            {
                return false;
            }

            return true;
        }
    }
}
