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
    /// [MS-FSCC] 2.4.26 - FileNamesInformation
    /// </summary>
    public class FileNamesInformation : QueryDirectoryFileInformation
    {
        public const int FixedLength = 12;

        private uint FileNameLength;
        public IMemoryOwner<char> FileName = MemoryOwner<char>.Empty;

        public override QueryDirectoryFileInformation Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            FileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            FileName = Arrays.Rent<char>((int)FileNameLength / 2);
            ByteReader.ReadUTF16String(FileName.Memory.Span, buffer, offset + 12, (int)FileNameLength / 2);
            return this;
        }

        public override void WriteBytes(Span<byte> buffer, int offset)
        {
            base.WriteBytes(buffer, offset);
            FileNameLength = (uint)(FileName.Memory.Length * 2);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, FileNameLength);
            BufferWriter.WriteUTF16String(buffer, offset + 12, FileName.Memory.Span);
        }

        public override void Dispose() => ObjectsPool<FileNamesInformation>.Return(this);

        public override FileInformationClass FileInformationClass => FileInformationClass.FileNamesInformation;

        public override int Length => FixedLength + FileName.Memory.Length * 2;
    }
}
