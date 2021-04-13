/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using MemoryPools.Memory;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS2_QUERY_FS_INFORMATION Response
    /// </summary>
    public class Transaction2QueryFSInformationResponse : Transaction2Subcommand
    {
        public const int ParametersLength = 0;
        // Data:
        public IMemoryOwner<byte> InformationBytes;

        public Transaction2QueryFSInformationResponse()
        {
        }

        public Transaction2QueryFSInformationResponse(IMemoryOwner<byte> parameters, IMemoryOwner<byte> data, bool isUnicode)
        {
            InformationBytes = data.AddOwner();
        }

        public override IMemoryOwner<byte> GetData(bool isUnicode)
        {
            return InformationBytes;
        }

        public QueryFSInformation GetQueryFSInformation(QueryFSInformationLevel informationLevel, bool isUnicode)
        {
            return QueryFSInformation.GetQueryFSInformation(InformationBytes.Memory.Span, informationLevel, isUnicode);
        }

        public void SetQueryFSInformation(QueryFSInformation queryFSInformation, bool isUnicode)
        {
            InformationBytes = queryFSInformation.GetBytes(isUnicode);
        }

        /// <remarks>
        /// Support for pass-through Information Levels must be enabled.
        /// </remarks>
        public FileSystemInformation GetFileSystemInformation(FileSystemInformationClass informationClass)
        {
            return FileSystemInformation.GetFileSystemInformation(InformationBytes.Memory.Span, 0, informationClass);
        }

        /// <remarks>
        /// Support for pass-through Information Levels must be enabled.
        /// </remarks>
        public void SetFileSystemInformation(FileSystemInformation information)
        {
            InformationBytes = information.GetBytes();
        }

        public override Transaction2SubcommandName SubcommandName => Transaction2SubcommandName.TRANS2_QUERY_FS_INFORMATION;
    }
}
