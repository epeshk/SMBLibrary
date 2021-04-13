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
    /// SMB2 SESSION_SETUP Request
    /// </summary>
    public class SessionSetupRequest : SMB2Command
    {
        public const int FixedSize = 24;
        public const int DeclaredSize = 25;

        private ushort StructureSize;
        public SessionSetupFlags Flags;
        public SecurityMode SecurityMode;
        public Capabilities Capabilities;   // Values other than SMB2_GLOBAL_CAP_DFS should be treated as reserved.
        public uint Channel;
        private ushort SecurityBufferOffset;
        private ushort SecurityBufferLength;
        public ulong PreviousSessionId;
        public IMemoryOwner<byte> SecurityBuffer = MemoryOwner<byte>.Empty;

        public SessionSetupRequest Init()
        {
            Flags = default;
            SecurityMode = default;
            Capabilities = default;   
            Channel = default;
            SecurityBufferOffset = default;
            SecurityBufferLength = default;
            PreviousSessionId = default;
            
            Init(SMB2CommandName.SessionSetup);
            StructureSize = DeclaredSize;
            return this;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Flags = (SessionSetupFlags)ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            SecurityMode = (SecurityMode)ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            Capabilities = (Capabilities)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            Channel = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 8);
            SecurityBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 12);
            SecurityBufferLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 14);
            PreviousSessionId = LittleEndianConverter.ToUInt64(buffer, offset + Smb2Header.Length + 16);
            if (SecurityBufferLength > 0)
            {
                SecurityBuffer = ByteReader.ReadBytes_Rent(buffer, offset + SecurityBufferOffset, SecurityBufferLength);
            }
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            SecurityBufferOffset = 0;
            SecurityBufferLength = (ushort)SecurityBuffer.Length();
            if (SecurityBuffer.Length() > 0)
            {
                SecurityBufferOffset = Smb2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            BufferWriter.WriteByte(buffer, 2, (byte)Flags);
            BufferWriter.WriteByte(buffer, 3, (byte)SecurityMode);
            LittleEndianWriter.WriteUInt32(buffer, 4, (uint)Capabilities);
            LittleEndianWriter.WriteUInt32(buffer, 8, Channel);
            LittleEndianWriter.WriteUInt16(buffer, 12, SecurityBufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, 14, SecurityBufferLength);
            LittleEndianWriter.WriteUInt64(buffer, 16, PreviousSessionId);
            BufferWriter.WriteBytes(buffer, FixedSize, SecurityBuffer.Memory.Span);
        }

        public override void Dispose()
        {
            base.Dispose();
            SecurityBuffer?.Dispose();
            SecurityBuffer = null;
        }

        public override int CommandLength => FixedSize + SecurityBuffer.Length();
    }
}
