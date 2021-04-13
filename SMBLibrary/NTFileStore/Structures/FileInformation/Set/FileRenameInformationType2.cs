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

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.4.34.2 - FileRenameInformation Type 2
    /// </summary>
    /// <remarks>
    /// [MS-FSA] 2.1.5.14.11
    /// FILE_RENAME_INFORMATION_TYPE_1: Used for 32-bit local clients and the SMB1 protocol.
    /// FILE_RENAME_INFORMATION_TYPE_2: Used for 64-bit local clients and the SMB2 protocol.
    /// </remarks>
    public class FileRenameInformationType2 : FileInformation
    {
        public const int FixedLength = 20;

        public bool ReplaceIfExists;
        // 7 reserved bytes
        public ulong RootDirectory;
        private uint FileNameLength;
        public IMemoryOwner<char> FileName = MemoryOwner<char>.Empty;

        public FileRenameInformationType2()
        {
        }

        public FileRenameInformationType2(Span<byte> buffer, int offset)
        {
            ReplaceIfExists = Conversion.ToBoolean(ByteReader.ReadByte(buffer, offset + 0));
            RootDirectory = LittleEndianConverter.ToUInt64(buffer, offset + 8);
            FileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 16);
            FileName = Arrays.Rent<char>((int) FileNameLength / 2);
            ByteReader.ReadUTF16String(FileName.Memory.Span, buffer, offset + 20, (int)FileNameLength / 2);
        }

        public override void WriteBytes(Span<byte> buffer, int offset)
        {
            FileNameLength = (uint)(FileName.Memory.Length * 2);
            BufferWriter.WriteByte(buffer, offset + 0, Convert.ToByte(ReplaceIfExists));
            LittleEndianWriter.WriteUInt64(buffer, offset + 8, RootDirectory);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, FileNameLength);
            BufferWriter.WriteUTF16String(buffer, offset + 20, FileName.Memory.Span);
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileRenameInformation;

        public override int Length => FixedLength + FileName.Memory.Length * 2;
    }
}
