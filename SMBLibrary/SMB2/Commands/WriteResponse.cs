/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 WRITE Response
    /// </summary>
    public class WriteResponse : SMB2Command
    {
        public const int FixedSize = 16;
        public const int DeclaredSize = 17;

        private ushort StructureSize;
        public ushort Reserved;
        public uint Count;
        public uint Remaining;
        private ushort WriteChannelInfoOffset;
        private ushort WriteChannelInfoLength;
        public byte[] WriteChannelInfo = Array.Empty<byte>();

        public WriteResponse() 
        {
            Init(SMB2CommandName.Write);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            Count = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            Remaining = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 8);
            WriteChannelInfoOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 12);
            WriteChannelInfoLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 14);
            WriteChannelInfo = ByteReader.ReadBytes_RentArray(buffer, offset + WriteChannelInfoOffset, WriteChannelInfoLength);
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            WriteChannelInfoOffset = 0;
            WriteChannelInfoLength = (ushort)WriteChannelInfo.Length;
            if (WriteChannelInfo.Length > 0)
            {
                WriteChannelInfoOffset = Smb2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, 4, Count);
            LittleEndianWriter.WriteUInt32(buffer, 8, Remaining);
            LittleEndianWriter.WriteUInt16(buffer, 12, WriteChannelInfoOffset);
            LittleEndianWriter.WriteUInt16(buffer, 14, WriteChannelInfoLength);
            if (WriteChannelInfo.Length > 0)
            {
                BufferWriter.WriteBytes(buffer, FixedSize, WriteChannelInfo);
            }
        }

        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<WriteResponse>.Return(this);
        }

        public override int CommandLength => FixedSize + WriteChannelInfo.Length;
    }
}
