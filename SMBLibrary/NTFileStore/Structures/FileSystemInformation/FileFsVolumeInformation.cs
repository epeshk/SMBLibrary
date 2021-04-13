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
    /// [MS-FSCC] 2.5.9 - FileFsVolumeInformation
    /// </summary>
    public class FileFsVolumeInformation : FileSystemInformation
    {
        public const int FixedLength = 18;

        public DateTime? VolumeCreationTime;
        public uint VolumeSerialNumber;
        private uint VolumeLabelLength;
        public bool SupportsObjects;
        public byte Reserved;
        public IMemoryOwner<char> VolumeLabel = MemoryOwner<char>.Empty;

        public FileFsVolumeInformation()
        {
        }

        public FileFsVolumeInformation(Span<byte> buffer, int offset)
        {
            VolumeCreationTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + 0);
            VolumeSerialNumber = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            VolumeLabelLength = LittleEndianConverter.ToUInt32(buffer, offset + 12);
            SupportsObjects = Convert.ToBoolean(ByteReader.ReadByte(buffer, offset + 16));
            Reserved = ByteReader.ReadByte(buffer, offset + 17);
            if (VolumeLabelLength > 0)
            {
                VolumeLabel = MemoryOwner<char>.Empty; 
                ByteReader.ReadUTF16String(VolumeLabel.Memory.Span, buffer, offset + 18, (int)VolumeLabelLength / 2);
            }
        }

        public override void WriteBytes(Span<byte> buffer, int offset)
        {
            VolumeLabelLength = (uint)(VolumeLabel.Memory.Length * 2);
            FileTimeHelper.WriteFileTime(buffer, offset + 0, VolumeCreationTime);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, VolumeSerialNumber);
            LittleEndianWriter.WriteUInt32(buffer, offset + 12, VolumeLabelLength);
            BufferWriter.WriteByte(buffer, offset + 16, Convert.ToByte(SupportsObjects));
            BufferWriter.WriteByte(buffer, offset + 17, Reserved);
            BufferWriter.WriteUTF16String(buffer, offset + 18, VolumeLabel.Memory.Span);
        }

        public override FileSystemInformationClass FileSystemInformationClass => FileSystemInformationClass.FileFsVolumeInformation;

        public override int Length => FixedLength + VolumeLabel.Memory.Length * 2;
    }
}
