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
    /// SMB2 WRITE Request
    /// </summary>
    public class WriteRequest : SMB2Command
    {
        public const int FixedSize = 48;
        public const int DeclaredSize = 49;

        private ushort StructureSize;
        private ushort DataOffset;
        private uint DataLength;
        public ulong Offset;
        public FileID FileId;
        public uint Channel;
        public uint RemainingBytes;
        private ushort WriteChannelInfoOffset;
        private ushort WriteChannelInfoLength;
        public WriteFlags Flags;
        
        public IMemoryOwner<byte> Data = MemoryOwner<byte>.Empty;
        public IMemoryOwner<byte> WriteChannelInfo = MemoryOwner<byte>.Empty;

        public WriteRequest Init()
        {
            StructureSize = default;
            DataOffset = default;
            DataLength = default;
            Offset = default;
            FileId = default;
            Channel = default;
            RemainingBytes = default;
            WriteChannelInfoOffset = default;
            WriteChannelInfoLength = default;
            Flags = default;
            
            Init(SMB2CommandName.Write);
            
            StructureSize = DeclaredSize;
            return this;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            DataOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            DataLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            Offset = LittleEndianConverter.ToUInt64(buffer, offset + Smb2Header.Length + 8);
            FileId = ObjectsPool<FileID>.Get().Init(buffer, offset + Smb2Header.Length + 16);
            Channel = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 32);
            RemainingBytes = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 36);
            WriteChannelInfoOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 40);
            WriteChannelInfoLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 42);
            Flags = (WriteFlags)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 44);
            Data = Arrays.RentFrom<byte>(buffer.Slice(offset + DataOffset, (int)DataLength));
            WriteChannelInfo = Arrays.RentFrom<byte>(buffer.Slice(offset + WriteChannelInfoOffset, WriteChannelInfoLength));
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            // Note: DataLength is UInt32 while WriteChannelInfoOffset is UInt16
            // so it is best to put WriteChannelInfo before Data.
            WriteChannelInfoOffset = 0;
            WriteChannelInfoLength = (ushort)WriteChannelInfo.Length();
            if (WriteChannelInfo.Length() > 0)
            {
                WriteChannelInfoOffset = Smb2Header.Length + FixedSize;
            }
            DataOffset = 0;
            DataLength = (uint)Data.Length();
            if (Data.Length() > 0)
            {
                DataOffset = (ushort)(Smb2Header.Length + FixedSize + WriteChannelInfo.Length());
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, DataOffset);
            LittleEndianWriter.WriteUInt32(buffer, 4, DataLength);
            LittleEndianWriter.WriteUInt64(buffer, 8, Offset);
            FileId.WriteBytes(buffer, 16);
            LittleEndianWriter.WriteUInt32(buffer, 32, Channel);
            LittleEndianWriter.WriteUInt32(buffer, 36, RemainingBytes);
            LittleEndianWriter.WriteUInt16(buffer, 40, WriteChannelInfoOffset);
            LittleEndianWriter.WriteUInt16(buffer, 42, WriteChannelInfoLength);
            LittleEndianWriter.WriteUInt32(buffer, 44, (uint)Flags);
            if (WriteChannelInfo.Length() > 0)
            {
                BufferWriter.WriteBytes(buffer, FixedSize, WriteChannelInfo.Memory.Span);
            }
            if (Data.Length() > 0)
            {
                BufferWriter.WriteBytes(buffer, FixedSize + WriteChannelInfo.Length(), Data.Memory.Span);
            }
        }

        public override void Dispose()
        {
            base.Dispose();
            Data.Dispose();

            //FileId.Dispose(); - fileId handle is frequently used for multiple requests and can be disposed via ISMBFileStore.CloseFile(...) method.  
            FileId = default;

            WriteChannelInfo.Dispose();
            WriteChannelInfo = Data = null;
            ObjectsPool<WriteRequest>.Return(this);
        }

        public override int CommandLength => FixedSize + Data.Length() + WriteChannelInfo.Length();
        
    }
}
