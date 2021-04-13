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
    /// SMB_QUERY_FILE_COMPRESSION_INFO
    /// </summary>
    public class QueryFileCompressionInfo : QueryInformation
    {
        public const int Length = 16;

        public long CompressedFileSize;
        public CompressionFormat CompressionFormat;
        public byte CompressionUnitShift;
        public byte ChunkShift;
        public byte ClusterShift;
        public byte[] Reserved; // 3 bytes

        public QueryFileCompressionInfo()
        {
            Reserved = new byte[3];
        }

        public QueryFileCompressionInfo(Span<byte> buffer, int offset)
        {
            CompressedFileSize = LittleEndianReader.ReadInt64(buffer, ref offset);
            CompressionFormat = (CompressionFormat)LittleEndianReader.ReadUInt16(buffer, ref offset);
            CompressionUnitShift = ByteReader.ReadByte(buffer, ref offset);
            ChunkShift = ByteReader.ReadByte(buffer, ref offset);
            ClusterShift = ByteReader.ReadByte(buffer, ref offset);
            Reserved = ByteReader.ReadBytes_RentArray(buffer, ref offset, 3);
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            var buffer = Arrays.Rent(Length);
            var offset = 0;
            LittleEndianWriter.WriteInt64(buffer.Memory.Span, ref offset, CompressedFileSize);
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, ref offset, (ushort)CompressionFormat);
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, CompressionUnitShift);
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, ChunkShift);
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, ClusterShift);
            BufferWriter.WriteBytes(buffer.Memory.Span, ref offset, Reserved, 3);
            return buffer;
        }

        public override QueryInformationLevel InformationLevel => QueryInformationLevel.SMB_QUERY_FILE_COMPRESSION_INFO;
    }
}
