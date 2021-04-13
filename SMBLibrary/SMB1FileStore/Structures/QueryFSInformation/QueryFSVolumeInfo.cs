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
    /// SMB_QUERY_FS_VOLUME_INFO
    /// </summary>
    public class QueryFSVolumeInfo : QueryFSInformation
    {
        public const int FixedLength = 18;

        public DateTime? VolumeCreationTime;
        public uint SerialNumber;
        private uint VolumeLabelSize;
        public ushort Reserved;
        public IMemoryOwner<char> VolumeLabel; // Unicode

        public QueryFSVolumeInfo()
        {
            VolumeLabel = MemoryOwner<char>.Empty;
        }

        public QueryFSVolumeInfo(Span<byte> buffer, int offset)
        {
            VolumeCreationTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + 0);
            SerialNumber = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            VolumeLabelSize = LittleEndianConverter.ToUInt32(buffer, offset + 12);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + 16);
            VolumeLabel = Arrays.Rent<char>((int) VolumeLabelSize); 
            
            ByteReader.ReadUTF16String(VolumeLabel.Memory.Span, buffer, offset + 18, (int)VolumeLabelSize);
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            VolumeLabelSize = (uint)(VolumeLabel.Memory.Length * 2);

            var buffer = Arrays.Rent(Length);
            FileTimeHelper.WriteFileTime(buffer.Memory.Span, 0, VolumeCreationTime);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, 8, SerialNumber);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, 12, VolumeLabelSize);
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, 16, Reserved);
            BufferWriter.WriteUTF16String(buffer.Memory.Span, 18, VolumeLabel.Memory.Span);
            return buffer;
        }

        public override int Length => FixedLength + VolumeLabel.Memory.Length * 2;

        public override QueryFSInformationLevel InformationLevel => QueryFSInformationLevel.SMB_QUERY_FS_VOLUME_INFO;
    }
}
