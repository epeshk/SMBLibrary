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
    /// [MS-FSCC] 2.4.18 - FileIdFullDirectoryInformation
    /// </summary>
    public class FileIdFullDirectoryInformation : QueryDirectoryFileInformation
    {
        public const int FixedLength = 80;

        public DateTime CreationTime;
        public DateTime LastAccessTime;
        public DateTime LastWriteTime;
        public DateTime ChangeTime;
        public long EndOfFile;
        public long AllocationSize;
        public FileAttributes FileAttributes;
        private uint FileNameLength;
        public uint EaSize;
        public uint Reserved;
        public ulong FileId;
        public IMemoryOwner<char> FileName = MemoryOwner<char>.Empty;

        public override QueryDirectoryFileInformation Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            CreationTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 8));
            LastAccessTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 16));
            LastWriteTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 24));
            ChangeTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 32));
            EndOfFile = LittleEndianConverter.ToInt64(buffer, offset + 40);
            AllocationSize = LittleEndianConverter.ToInt64(buffer, offset + 48);
            FileAttributes = LittleEndianConverter.ToUInt32(buffer, offset + 56);
            FileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 60);
            EaSize = LittleEndianConverter.ToUInt32(buffer, offset + 64);
            Reserved = LittleEndianConverter.ToUInt32(buffer, offset + 68);
            FileId = LittleEndianConverter.ToUInt64(buffer, offset + 72);
            FileName = Arrays.Rent<char>((int) FileNameLength / 2);
            
            ByteReader.ReadUTF16String(FileName.Memory.Span, buffer, offset + 80, (int) FileNameLength / 2);
            
            return this;
        }

        public override void WriteBytes(Span<byte> buffer, int offset)
        {
            base.WriteBytes(buffer, offset);
            FileNameLength = (uint)(FileName.Memory.Length * 2);
            LittleEndianWriter.WriteInt64(buffer, offset + 8, CreationTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 16, LastAccessTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 24, LastWriteTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 32, ChangeTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 40, EndOfFile);
            LittleEndianWriter.WriteInt64(buffer, offset + 48, AllocationSize);
            LittleEndianWriter.WriteUInt32(buffer, offset + 56, (uint)FileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, offset + 60, FileNameLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 64, EaSize);
            LittleEndianWriter.WriteUInt32(buffer, offset + 68, Reserved);
            LittleEndianWriter.WriteUInt64(buffer, offset + 72, FileId);
            BufferWriter.WriteUTF16String(buffer, offset + 80, FileName.Memory.Span);
        }

        public override void Dispose() => ObjectsPool<FileIdFullDirectoryInformation>.Return(this);

        public override FileInformationClass FileInformationClass => FileInformationClass.FileIdFullDirectoryInformation;

        public override int Length => FixedLength + FileName.Memory.Length * 2;
    }
}
