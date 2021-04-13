/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.1.7 - FILE_NAME_INFORMATION
    /// [MS-FSCC] 2.4.25 - FileNameInformation
    /// </summary>
    public class FileNameInformation : FileInformation
    {
        public const int FixedLength = 4;

        private uint FileNameLength;
        public IMemoryOwner<char> FileName = MemoryOwner<char>.Empty;

        public FileNameInformation()
        {
        }

        public FileNameInformation(Span<byte> buffer, int offset)
        {
            FileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 0);
            FileName = Arrays.Rent<char>((int) FileNameLength / 2); 
            
            ByteReader.ReadUTF16String(FileName.Memory.Span, buffer, offset + 4, (int)FileNameLength / 2);
        }

        public override void WriteBytes(Span<byte> buffer, int offset)
        {
            FileNameLength = (uint)(FileName.Memory.Length * 2);
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, FileNameLength);
            BufferWriter.WriteUTF16String(buffer, offset + 4, FileName.Memory.Span);
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileNameInformation;

        public override int Length => FixedLength + FileName.Memory.Length * 2;
    }
}
