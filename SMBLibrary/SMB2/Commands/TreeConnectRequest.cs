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
    /// SMB2 TREE_CONNECT Request
    /// </summary>
    public class TreeConnectRequest : SMB2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        public ushort Reserved;
        private ushort PathOffset;
        private ushort PathLength;
        public string Path = String.Empty;

        public TreeConnectRequest Init()
        {
            base.Init(SMB2CommandName.TreeConnect);
            StructureSize = DeclaredSize;

            return this;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            PathOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 4);
            PathLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 6);
            if (PathLength > 0)
            {
                Path = ByteReader.ReadUTF16String(buffer, offset + PathOffset, PathLength / 2);
            }
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            PathOffset = 0;
            PathLength = (ushort)(Path.Length * 2);
            if (Path.Length > 0)
            {
                PathOffset = Smb2Header.Length + 8;
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, Reserved);
            LittleEndianWriter.WriteUInt16(buffer, 4, PathOffset);
            LittleEndianWriter.WriteUInt16(buffer, 6, PathLength);
            if (Path.Length > 0)
            {
                BufferWriter.WriteUTF16String(buffer, 8, Path);
            }
        }

        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<TreeConnectRequest>.Return(this);
        }

        public override int CommandLength => 8 + Path.Length * 2;
    }
}
