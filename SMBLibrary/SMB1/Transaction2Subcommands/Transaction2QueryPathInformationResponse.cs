/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS2_QUERY_PATH_INFORMATION Response
    /// </summary>
    public class Transaction2QueryPathInformationResponse : Transaction2Subcommand
    {
        public const int ParametersLength = 2;
        // Parameters:
        public ushort EaErrorOffset; // Meaningful only when request's InformationLevel is SMB_INFO_QUERY_EAS_FROM_LIST
        // Data:
        public IMemoryOwner<byte> InformationBytes;

        public Transaction2QueryPathInformationResponse()
        {
        }

        public Transaction2QueryPathInformationResponse(IMemoryOwner<byte> parameters, IMemoryOwner<byte> data, bool isUnicode)
        {
            EaErrorOffset = LittleEndianConverter.ToUInt16(parameters, 0);
            InformationBytes = data;
        }

        public override IMemoryOwner<byte> GetParameters(bool isUnicode)
        {
            var buf = Arrays.Rent(2);
            LittleEndianConverter.GetBytes(buf.Memory.Span, EaErrorOffset);
            return buf;
        }

        public override IMemoryOwner<byte> GetData(bool isUnicode)
        {
            return InformationBytes;
        }

        public QueryInformation GetQueryInformation(QueryInformationLevel queryInformationLevel)
        {
            return QueryInformation.GetQueryInformation(InformationBytes.Memory.Span, queryInformationLevel);
        }

        public void SetQueryInformation(QueryInformation queryInformation)
        {
            InformationBytes = queryInformation.GetBytes();
        }

        /// <remarks>
        /// Support for pass-through Information Levels must be enabled.
        /// </remarks>
        public FileInformation GetFileInformation(FileInformationClass informationClass)
        {
            return FileInformation.GetFileInformation(InformationBytes.Memory.Span, 0, informationClass);
        }

        /// <remarks>
        /// Support for pass-through Information Levels must be enabled.
        /// </remarks>
        public void SetFileInformation(FileInformation information)
        {
            InformationBytes = information.GetBytes();
        }

        public override Transaction2SubcommandName SubcommandName => Transaction2SubcommandName.TRANS2_QUERY_PATH_INFORMATION;
        
        
    }
}
