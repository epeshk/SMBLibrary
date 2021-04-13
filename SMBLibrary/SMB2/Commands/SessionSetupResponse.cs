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
    /// SMB2 SESSION_SETUP Response
    /// </summary>
    public class SessionSetupResponse : SMB2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        public SessionFlags SessionFlags;
        private ushort SecurityBufferOffset;
        private ushort SecurityBufferLength;
        public IMemoryOwner<byte> SecurityBuffer = MemoryOwner<byte>.Empty;

        public SessionSetupResponse Init()
        {
            SessionFlags = default;
            SecurityBufferOffset = default;
            SecurityBufferLength = default;
            
            Init(SMB2CommandName.SessionSetup);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
            return this;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            SessionFlags = (SessionFlags)LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            SecurityBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 4);
            SecurityBufferLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 6);
            SecurityBuffer = ByteReader.ReadBytes_Rent(buffer, offset + SecurityBufferOffset, SecurityBufferLength);
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
            LittleEndianWriter.WriteUInt16(buffer, 2, (ushort)SessionFlags);
            LittleEndianWriter.WriteUInt16(buffer, 4, SecurityBufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, 6, SecurityBufferLength);
            BufferWriter.WriteBytes(buffer, 8, SecurityBuffer.Memory.Span);
        }

        public override void Dispose()
        {
            base.Dispose();
            SecurityBuffer?.Dispose();
            SecurityBuffer = null;
            ObjectsPool<SessionSetupResponse>.Return(this);
        }

        public override int CommandLength => FixedSize + SecurityBuffer.Length();
    }
}
