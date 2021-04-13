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
    /// SMB2 CLOSE Request
    /// </summary>
    public class CloseRequest : SMB2Command
    {
        public const int DeclaredSize = 24;

        private ushort StructureSize;
        public CloseFlags Flags;
        public uint Reserved;
        public FileID FileId;

        public CloseRequest Init()
        {
            Init(SMB2CommandName.Close);
            StructureSize = DeclaredSize;
            Reserved = 0;
            return this;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Flags = (CloseFlags)LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            Reserved = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            FileId = ObjectsPool<FileID>.Get().Init(buffer, offset + Smb2Header.Length + 8);
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, (ushort)Flags);
            LittleEndianWriter.WriteUInt32(buffer, 4, Reserved);
            FileId.WriteBytes(buffer, 8);
        }

        public override void Dispose()
        {
            base.Dispose();
            FileId.Dispose();
            ObjectsPool<CloseRequest>.Return(this);
        }

        public bool PostQueryAttributes => ((Flags & CloseFlags.PostQueryAttributes) > 0);

        public override int CommandLength => DeclaredSize;
    }
}
