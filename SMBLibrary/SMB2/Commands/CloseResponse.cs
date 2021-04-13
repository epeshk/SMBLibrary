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
    /// SMB2 CLOSE Response
    /// </summary>
    public class CloseResponse : SMB2Command
    {
        public const int DeclaredSize = 60;

        private ushort StructureSize;
        public CloseFlags Flags;
        public uint Reserved;
        public DateTime? CreationTime;
        public DateTime? LastAccessTime;
        public DateTime? LastWriteTime;
        public DateTime? ChangeTime;
        public long AllocationSize;
        public long EndofFile;
        public FileAttributes FileAttributes;

        public CloseResponse()
        {
            Init(SMB2CommandName.Close);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Flags = (CloseFlags)LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            Reserved = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            CreationTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + Smb2Header.Length + 8);
            LastAccessTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + Smb2Header.Length + 16);
            LastWriteTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + Smb2Header.Length + 24);
            ChangeTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + Smb2Header.Length + 32);
            AllocationSize = LittleEndianConverter.ToInt64(buffer, offset + Smb2Header.Length + 40);
            EndofFile = LittleEndianConverter.ToInt64(buffer, offset + Smb2Header.Length + 48);
            FileAttributes = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 56);
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, (ushort)Flags);
            LittleEndianWriter.WriteUInt32(buffer, 4, Reserved);
            FileTimeHelper.WriteFileTime(buffer, 8, CreationTime);
            FileTimeHelper.WriteFileTime(buffer, 16, LastAccessTime);
            FileTimeHelper.WriteFileTime(buffer, 24, LastWriteTime);
            FileTimeHelper.WriteFileTime(buffer, 32, ChangeTime);
            LittleEndianWriter.WriteInt64(buffer, 40, AllocationSize);
            LittleEndianWriter.WriteInt64(buffer, 48, EndofFile);
            LittleEndianWriter.WriteUInt32(buffer, 56, (uint)FileAttributes);
        }

        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<CloseResponse>.Return(this);
        }

        public override int CommandLength => DeclaredSize;
    }
}
