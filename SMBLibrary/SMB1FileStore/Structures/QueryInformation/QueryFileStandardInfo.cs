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
    /// SMB_QUERY_FILE_STANDARD_INFO
    /// </summary>
    public class QueryFileStandardInfo : QueryInformation
    {
        public const int Length = 22;

        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        public bool DeletePending;
        public bool Directory;

        public QueryFileStandardInfo()
        {
        }

        public QueryFileStandardInfo(Span<byte> buffer, int offset)
        {
            AllocationSize = LittleEndianReader.ReadInt64(buffer, ref offset);
            EndOfFile = LittleEndianReader.ReadInt64(buffer, ref offset);
            NumberOfLinks = LittleEndianReader.ReadUInt32(buffer, ref offset);
            DeletePending = (ByteReader.ReadByte(buffer, ref offset) > 0);
            Directory = (ByteReader.ReadByte(buffer, ref offset) > 0);
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            var buffer = Arrays.Rent(Length);
            var offset = 0;
            LittleEndianWriter.WriteInt64(buffer.Memory.Span, ref offset, AllocationSize);
            LittleEndianWriter.WriteInt64(buffer.Memory.Span, ref offset, EndOfFile);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, NumberOfLinks);
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, Convert.ToByte(DeletePending));
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, Convert.ToByte(Directory));
            return buffer;
        }

        public override QueryInformationLevel InformationLevel => QueryInformationLevel.SMB_QUERY_FILE_STANDARD_INFO;
    }
}
