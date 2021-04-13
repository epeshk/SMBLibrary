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
    /// SMB_QUERY_FILE_ALL_INFO
    /// </summary>
    public class QueryFileAllInfo : QueryInformation
    {
        public const int FixedLength = 72;

        public DateTime? CreationTime;
        public DateTime? LastAccessTime;
        public DateTime? LastWriteTime;
        public DateTime? LastChangeTime;
        public ExtendedFileAttributes ExtFileAttributes;
        public uint Reserved1;
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        public bool DeletePending;
        public bool Directory;
        public ushort Reserved2;
        public uint EaSize;
        // uint FileNameLength; // In bytes
        public IMemoryOwner<char> FileName; // Unicode

        public QueryFileAllInfo()
        {
        }

        public QueryFileAllInfo(Span<byte> buffer, int offset)
        {
            CreationTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastAccessTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastWriteTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastChangeTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            ExtFileAttributes = LittleEndianReader.ReadUInt32(buffer, ref offset);
            Reserved1 = LittleEndianReader.ReadUInt32(buffer, ref offset);
            AllocationSize = LittleEndianReader.ReadInt64(buffer, ref offset);
            EndOfFile = LittleEndianReader.ReadInt64(buffer, ref offset);
            NumberOfLinks = LittleEndianReader.ReadUInt32(buffer, ref offset);
            DeletePending = (ByteReader.ReadByte(buffer, ref offset) > 0);
            Directory = (ByteReader.ReadByte(buffer, ref offset) > 0);
            Reserved2 = LittleEndianReader.ReadUInt16(buffer, ref offset);
            EaSize = LittleEndianReader.ReadUInt32(buffer, ref offset);
            var fileNameLength = LittleEndianReader.ReadUInt32(buffer, ref offset);
            FileName = Arrays.Rent<char>((int) (fileNameLength / 2));
                
            ByteReader.ReadUTF16String(FileName.Memory.Span, buffer, ref offset, (int)(fileNameLength / 2));
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            var fileNameLength = (uint)(FileName.Memory.Length * 2);
            var buffer = Arrays.Rent((int) (FixedLength + fileNameLength));
            var offset = 0;
            FileTimeHelper.WriteFileTime(buffer.Memory.Span, ref offset, CreationTime);
            FileTimeHelper.WriteFileTime(buffer.Memory.Span, ref offset, LastAccessTime);
            FileTimeHelper.WriteFileTime(buffer.Memory.Span, ref offset, LastWriteTime);
            FileTimeHelper.WriteFileTime(buffer.Memory.Span, ref offset, LastChangeTime);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, (uint)ExtFileAttributes);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, Reserved1); 
            LittleEndianWriter.WriteInt64(buffer.Memory.Span, ref offset, AllocationSize);
            LittleEndianWriter.WriteInt64(buffer.Memory.Span, ref offset, EndOfFile);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, NumberOfLinks);
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, Convert.ToByte(DeletePending));
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, Convert.ToByte(Directory));
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, ref offset, Reserved2);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, EaSize);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, fileNameLength);
            BufferWriter.WriteUTF16String(buffer.Memory.Span, ref offset, FileName.Memory.Span);
            return buffer;
        }

        public override QueryInformationLevel InformationLevel => QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO;
    }
}
