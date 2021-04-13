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
    /// [MS-FSCC] 2.4.10 - FileDirectoryInformation
    /// </summary>
    public class FileDirectoryInformation : QueryDirectoryFileInformation
    {
        public const int FixedLength = 64;

        public DateTime CreationTime;
        public DateTime LastAccessTime;
        public DateTime LastWriteTime;
        public DateTime ChangeTime;
        public long EndOfFile;
        public long AllocationSize;
        public FileAttributes FileAttributes;
        private uint _fileNameLength;
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
            _fileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 60);
            FileName = Arrays.Rent<char>((int) _fileNameLength / 2); // lnk 1 
            ByteReader.ReadUTF16String(FileName.Memory.Span, buffer, offset + 64, (int)_fileNameLength / 2);
            return this;
        }

        public override void WriteBytes(Span<byte> buffer, int offset)
        {
            base.WriteBytes(buffer, offset);
            _fileNameLength = (uint)(FileName.Memory.Length * 2);
            LittleEndianWriter.WriteInt64(buffer, offset + 8, CreationTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 16, LastAccessTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 24, LastWriteTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 32, ChangeTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 40, EndOfFile);
            LittleEndianWriter.WriteInt64(buffer, offset + 48, AllocationSize);
            LittleEndianWriter.WriteUInt32(buffer, offset + 56, (uint)FileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, offset + 60, _fileNameLength);
            BufferWriter.WriteUTF16String(buffer, offset + 64, FileName.Memory.Span);
        }
        
        public override void Dispose()
        {
            if (FileName != null)
            {
                FileName.Dispose();
                FileName = null;
                
                ObjectsPool<FileDirectoryInformation>.Return(this);
            }
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileDirectoryInformation;

        public override int Length => FixedLength + FileName.Memory.Length * 2;
    }
}
