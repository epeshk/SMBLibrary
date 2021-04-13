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

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 READ Response
    /// </summary>
    public class ReadResponse : SMB2Command
    {
        public const int FixedSize = 16;
        public const int DeclaredSize = 17;

        private ushort StructureSize;
        private byte DataOffset;
        public byte Reserved;
        private uint DataLength;
        public uint DataRemaining;
        public uint Reserved2;
        public IMemoryOwner<byte> Data = MemoryOwner<byte>.Empty;

        public ReadResponse Init()
        {
            DataOffset = default;
            Reserved = default;
            DataLength = default;
            DataRemaining = default;
            Reserved2 = default;
            
            Init(SMB2CommandName.Read);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
            return this;
        }

        public override void Dispose()
        {
            base.Dispose();
            Data?.Dispose();
            Data = null;
            ObjectsPool<ReadResponse>.Return(this);
        }
        
        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            DataOffset = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            Reserved = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            DataLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            DataRemaining = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 8);
            Reserved2 = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 12);
            if (DataLength > 0)
            {
                Data = Arrays.RentFrom<byte>(buffer.Slice(offset + DataOffset, (int)DataLength));
            }
            return this;
        }
        
        public override void WriteCommandBytes(Span<byte> buffer)
        {
            DataOffset = 0;
            DataLength = (uint)Data.Length();
            if (Data.Length() > 0)
            {
                DataOffset = Smb2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            BufferWriter.WriteByte(buffer, 2, DataOffset);
            BufferWriter.WriteByte(buffer, 3, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, 4, DataLength);
            LittleEndianWriter.WriteUInt32(buffer, 8, DataRemaining);
            LittleEndianWriter.WriteUInt32(buffer, 12, Reserved2);
            if (Data.Length() > 0)
            {
                BufferWriter.WriteBytes(buffer, FixedSize, Data.Memory.Span);
            }
        }

        public override int CommandLength => FixedSize + Data.Length();
    }
}
