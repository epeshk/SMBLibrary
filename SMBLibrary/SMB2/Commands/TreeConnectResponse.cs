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
    /// SMB2 TREE_CONNECT Response
    /// </summary>
    public class TreeConnectResponse : SMB2Command
    {
        public const int DeclaredSize = 16;

        private ushort StructureSize;
        public ShareType ShareType;
        public byte Reserved;
        public ShareFlags ShareFlags;
        public ShareCapabilities Capabilities;
        public AccessMask MaximalAccess;

        public TreeConnectResponse()
        {
            Init(SMB2CommandName.TreeConnect);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            ShareType = (ShareType)ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            Reserved = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            ShareFlags = (ShareFlags)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            Capabilities = (ShareCapabilities)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 8);
            MaximalAccess = (AccessMask)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 12);
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            BufferWriter.WriteByte(buffer, 2, (byte)ShareType);
            BufferWriter.WriteByte(buffer, 3, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, 4, (uint)ShareFlags);
            LittleEndianWriter.WriteUInt32(buffer, 8, (uint)Capabilities);
            LittleEndianWriter.WriteUInt32(buffer, 12, (uint)MaximalAccess);
        }

        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<TreeConnectResponse>.Return(this);
        }

        public override int CommandLength => DeclaredSize;
    }
}
