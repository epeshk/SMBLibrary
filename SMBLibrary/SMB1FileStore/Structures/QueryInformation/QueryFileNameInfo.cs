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
    /// SMB_QUERY_FILE_NAME_INFO
    /// </summary>
    public class QueryFileNameInfo : QueryInformation
    {
        //uint FileNameLength; // In bytes
        public IMemoryOwner<char> FileName; // Unicode

        public QueryFileNameInfo()
        {
        }

        public QueryFileNameInfo(Span<byte> buffer, int offset)
        {
            var fileNameLength = LittleEndianConverter.ToUInt32(buffer, 0);
            FileName = Arrays.Rent<char>((int) (fileNameLength / 2)); 
            ByteReader.ReadUTF16String(FileName.Memory.Span, buffer, 4, (int)(fileNameLength / 2));
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            var fileNameLength = (uint)(FileName.Memory.Length * 2);
            var buffer = Arrays.Rent((int) (4 + fileNameLength));
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, 0, fileNameLength);
            BufferWriter.WriteUTF16String(buffer.Memory.Span, 4, FileName.Memory.Span);
            return buffer;
        }

        public override QueryInformationLevel InformationLevel => QueryInformationLevel.SMB_QUERY_FILE_NAME_INFO;
    }
}
