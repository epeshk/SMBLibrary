/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// SMB_QUERY_FS_SIZE_INFO
    /// </summary>
    public class QueryFSSizeInfo : QueryFSInformation
    {
        public const int FixedLength = 24;

        public long TotalAllocationUnits;
        public long TotalFreeAllocationUnits;
        public uint SectorsPerAllocationUnit;
        public uint BytesPerSector;

        public QueryFSSizeInfo()
        {
        }

        public QueryFSSizeInfo(Span<byte> buffer, int offset)
        {
            TotalAllocationUnits = LittleEndianConverter.ToInt64(buffer, 0);
            TotalFreeAllocationUnits = LittleEndianConverter.ToInt64(buffer, 8);
            SectorsPerAllocationUnit = LittleEndianConverter.ToUInt32(buffer, 16);
            BytesPerSector = LittleEndianConverter.ToUInt32(buffer, 20);
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            var buffer = Arrays.Rent(Length);
            LittleEndianWriter.WriteInt64(buffer.Memory.Span, 0, TotalAllocationUnits);
            LittleEndianWriter.WriteInt64(buffer.Memory.Span, 8, TotalFreeAllocationUnits);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, 16, SectorsPerAllocationUnit);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, 20, BytesPerSector);
            return buffer;
        }

        public override int Length => FixedLength;

        public override QueryFSInformationLevel InformationLevel => QueryFSInformationLevel.SMB_QUERY_FS_SIZE_INFO;
    }
}
