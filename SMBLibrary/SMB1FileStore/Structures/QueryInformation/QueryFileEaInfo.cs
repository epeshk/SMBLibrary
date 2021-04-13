/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_QUERY_FILE_EA_INFO
    /// </summary>
    public class QueryFileEaInfo : QueryInformation
    {
        public uint EaSize;

        public QueryFileEaInfo()
        {
        }

        public QueryFileEaInfo(Span<byte> buffer, int offset)
        {
            EaSize = LittleEndianConverter.ToUInt32(buffer, offset);
        }
        
        public override IMemoryOwner<byte> GetBytes()
        {
            var buf = Arrays.Rent(4);
            LittleEndianConverter.GetBytes(buf.Memory.Span, EaSize);
            return buf;
        }

        public override QueryInformationLevel InformationLevel => QueryInformationLevel.SMB_QUERY_FILE_EA_INFO;
    }
}
