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
    /// SMB2 READ Request
    /// </summary>
    public class ReadRequest : SMB2Command
    {
        public const int FixedSize = 48;
        public const int DeclaredSize = 49;

        private ushort StructureSize;
        public byte Padding;
        public ReadFlags Flags;
        public uint ReadLength;
        public ulong Offset;
        public FileID FileId;
        public uint MinimumCount;
        public uint Channel;
        public uint RemainingBytes;
        private ushort ReadChannelInfoOffset;
        private ushort ReadChannelInfoLength;
        public byte[] ReadChannelInfo = Array.Empty<byte>();
        private static byte[] singleByteArray = new byte[1];

        public ReadRequest Init()
        {
            Padding = default;
            Flags = default;
            ReadLength = default;
            Offset = default;
            MinimumCount = default;
            Channel = default;
            RemainingBytes = default;
            ReadChannelInfoOffset = default;
            ReadChannelInfoLength = default;

            Init(SMB2CommandName.Read);
            
            StructureSize = DeclaredSize;
            return this;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Padding = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            Flags = (ReadFlags)ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            ReadLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            Offset = LittleEndianConverter.ToUInt64(buffer, offset + Smb2Header.Length + 8);
            FileId = ObjectsPool<FileID>.Get().Init(buffer, offset + Smb2Header.Length + 16);
            MinimumCount = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 32);
            Channel = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 36);
            RemainingBytes = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 40);
            ReadChannelInfoOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 44);
            ReadChannelInfoLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 46);
            if (ReadChannelInfoLength > 0)
            {
                ReadChannelInfo = ByteReader.ReadBytes_RentArray(buffer, offset + ReadChannelInfoOffset, ReadChannelInfoLength);
            }
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            ReadChannelInfoOffset = 0;
            ReadChannelInfoLength = (ushort)ReadChannelInfo.Length;
            if (ReadChannelInfo.Length > 0)
            {
                ReadChannelInfoOffset = Smb2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            BufferWriter.WriteByte(buffer, 2, Padding);
            BufferWriter.WriteByte(buffer, 3, (byte)Flags);
            LittleEndianWriter.WriteUInt32(buffer, 4, ReadLength);
            LittleEndianWriter.WriteUInt64(buffer, 8, Offset);
            FileId.WriteBytes(buffer, 16);
            LittleEndianWriter.WriteUInt32(buffer, 32, MinimumCount);
            LittleEndianWriter.WriteUInt32(buffer, 36, Channel);
            LittleEndianWriter.WriteUInt32(buffer, 40, RemainingBytes);
            LittleEndianWriter.WriteUInt16(buffer, 44, ReadChannelInfoOffset);
            LittleEndianWriter.WriteUInt16(buffer, 46, ReadChannelInfoLength);
            if (ReadChannelInfo.Length > 0)
            {
                BufferWriter.WriteBytes(buffer, FixedSize, ReadChannelInfo);
            }
            else
            {
                // The client MUST set one byte of [the buffer] field to 0
                BufferWriter.WriteBytes(buffer, FixedSize, singleByteArray);
            }
        }

        public override void Dispose()
        {
            base.Dispose();

            //FileId.Dispose(); - fileId handle is frequently used for multiple requests and can be disposed via ISMBFileStore.CloseFile(...) method.  
            FileId = default;

            ObjectsPool<ReadRequest>.Return(this);
        }

        public override int CommandLength =>
            // The client MUST set one byte of [the buffer] field to 0
            Math.Max(FixedSize + ReadChannelInfo.Length, DeclaredSize);
    }
}
