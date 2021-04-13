/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using MemoryPools.Memory;
using SMBLibrary.Client;

namespace SMBLibrary.SMB1
{
    public class FindInformationHelper
    {
        /// <exception cref="SMBLibrary.UnsupportedInformationLevelException"></exception>
        public static FileInformationClass ToFileInformationClass(FindInformationLevel informationLevel)
        {
            switch (informationLevel)
            {
                case FindInformationLevel.SMB_FIND_FILE_DIRECTORY_INFO:
                    return FileInformationClass.FileDirectoryInformation;
                case FindInformationLevel.SMB_FIND_FILE_FULL_DIRECTORY_INFO:
                    return FileInformationClass.FileFullDirectoryInformation;
                case FindInformationLevel.SMB_FIND_FILE_NAMES_INFO:
                    return FileInformationClass.FileNamesInformation;
                case FindInformationLevel.SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
                    return FileInformationClass.FileBothDirectoryInformation;
                case FindInformationLevel.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO:
                    return FileInformationClass.FileIdFullDirectoryInformation;
                case FindInformationLevel.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO:
                    return FileInformationClass.FileIdBothDirectoryInformation;
                default:
                    throw new UnsupportedInformationLevelException();
            }
        }

        /// <exception cref="SMBLibrary.UnsupportedInformationLevelException"></exception>
        public static FindInformationList ToFindInformationList(List<FindFilesQueryResult> entries, bool isUnicode, int maxLength)
        {
            var result = new FindInformationList();
            var pageLength = 0;
            for (var index = 0; index < entries.Count; index++)
            {
                var infoEntry = ToFindInformation(entries[index]);
                var entryLength = infoEntry.GetLength(isUnicode);
                if (pageLength + entryLength <= maxLength)
                {
                    result.Add(infoEntry);
                    pageLength += entryLength;
                }
                else
                {
                    break;
                }
            }
            return result;
        }

        /// <exception cref="SMBLibrary.UnsupportedInformationLevelException"></exception>
        public static FindInformation ToFindInformation(FindFilesQueryResult fileInformation)
        {
            if (fileInformation != null)
            {
                var fileDirectoryInfo = fileInformation;
                var result = new FindFileDirectoryInfo();
                result.FileIndex = fileDirectoryInfo.Index ?? default;
                result.CreationTime = fileDirectoryInfo.CreationTime;
                result.LastAccessTime = fileDirectoryInfo.LastAccessTime;
                result.LastWriteTime = fileDirectoryInfo.LastWriteTime;
                result.LastAttrChangeTime = fileDirectoryInfo.LastWriteTime;
                result.EndOfFile = fileDirectoryInfo.EndOfFile;
                result.AllocationSize = fileDirectoryInfo.AllocationSize;
                result.ExtFileAttributes = fileDirectoryInfo.FileAttributes;
                result.FileName = fileDirectoryInfo.FileName.AddOwner();
                return result;
            }

            throw new NotImplementedException();
        }
    }
}
