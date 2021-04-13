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
    /// SMB_QUERY_FS_ATTRIBUTE_INFO
    /// </summary>
    public class QueryFSAttibuteInfo : QueryFSInformation
    {
        public const int FixedLength = 12;

        public FileSystemAttributes FileSystemAttributes;
        public uint MaxFileNameLengthInBytes;
        //uint LengthOfFileSystemName; // In bytes
        public IMemoryOwner<char> FileSystemName; // Unicode

        public QueryFSAttibuteInfo()
        {
        }

        public QueryFSAttibuteInfo(Span<byte> buffer, int offset)
        {
            FileSystemAttributes = (FileSystemAttributes)LittleEndianConverter.ToUInt32(buffer, offset + 0);
            MaxFileNameLengthInBytes = LittleEndianConverter.ToUInt32(buffer, offset + 4);
            var lengthOfFileSystemName = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            FileSystemName = Arrays.Rent<char>((int) (lengthOfFileSystemName / 2)); 
            
            ByteReader.ReadUTF16String(FileSystemName.Memory.Span, buffer, offset + 12, (int)(lengthOfFileSystemName / 2));
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            var lengthOfFileSystemName = (uint)(FileSystemName.Memory.Length * 2);
            var buffer = Arrays.Rent(Length);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, 0, (uint)FileSystemAttributes);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, 4, MaxFileNameLengthInBytes);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, 8, lengthOfFileSystemName);
            BufferWriter.WriteUTF16String(buffer.Memory.Span, 12, FileSystemName.Memory.Span);
            return buffer;
        }

        public override int Length => FixedLength + FileSystemName.Memory.Length * 2;

        public override QueryFSInformationLevel InformationLevel => QueryFSInformationLevel.SMB_QUERY_FS_ATTRIBUTE_INFO;
    }
}
