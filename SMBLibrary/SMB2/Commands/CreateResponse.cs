/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 CREATE Response
    /// </summary>
    public class CreateResponse : SMB2Command
    {
        public const int DeclaredSize = 89;

        private ushort StructureSize;
        public OplockLevel OplockLevel;
        public CreateResponseFlags Flags;
        public CreateAction CreateAction;
        public DateTime? CreationTime;
        public DateTime? LastAccessTime;
        public DateTime? LastWriteTime;
        public DateTime? ChangeTime;
        public long AllocationSize;
        public long EndofFile;
        public FileAttributes FileAttributes;
        public uint Reserved2;
        public FileID FileId;
        private uint CreateContextsOffsets;
        private uint CreateContextsLength;
        public List<CreateContext> CreateContexts = new List<CreateContext>();

        public CreateResponse()
        {
            Init(SMB2CommandName.Create);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            OplockLevel = (OplockLevel)ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            Flags = (CreateResponseFlags)ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            CreateAction = (CreateAction)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            CreationTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + Smb2Header.Length + 8);
            LastAccessTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + Smb2Header.Length + 16);
            LastWriteTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + Smb2Header.Length + 24);
            ChangeTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + Smb2Header.Length + 32);
            AllocationSize = LittleEndianConverter.ToInt64(buffer, offset + Smb2Header.Length + 40);
            EndofFile = LittleEndianConverter.ToInt64(buffer, offset + Smb2Header.Length + 48);
            FileAttributes = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 56);
            Reserved2 = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 60);
            FileId = ObjectsPool<FileID>.Get().Init(buffer, offset + Smb2Header.Length + 64);
            CreateContextsOffsets = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 80);
            CreateContextsLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 84);
            if (CreateContextsLength > 0)
            {
                CreateContexts = CreateContext.ReadCreateContextList(buffer, offset + (int)CreateContextsOffsets);
            }
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            BufferWriter.WriteByte(buffer, 2, (byte)OplockLevel);
            BufferWriter.WriteByte(buffer, 3, (byte)Flags);
            LittleEndianWriter.WriteUInt32(buffer, 4, (uint)CreateAction);
            FileTimeHelper.WriteFileTime(buffer, 8, CreationTime);
            FileTimeHelper.WriteFileTime(buffer, 16, LastAccessTime);
            FileTimeHelper.WriteFileTime(buffer, 24, LastWriteTime);
            FileTimeHelper.WriteFileTime(buffer, 32, ChangeTime);
            LittleEndianWriter.WriteInt64(buffer, 40, AllocationSize);
            LittleEndianWriter.WriteInt64(buffer, 48, EndofFile);
            LittleEndianWriter.WriteUInt32(buffer, 56, (uint)FileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, 60, Reserved2);
            FileId.WriteBytes(buffer, 64);
            CreateContextsOffsets = 0;
            CreateContextsLength = (uint)CreateContext.GetCreateContextListLength(CreateContexts);
            if (CreateContexts.Count > 0)
            {
                CreateContextsOffsets = Smb2Header.Length + 88;
                CreateContext.WriteCreateContextList(buffer, 88, CreateContexts);
            }
        }

        public override void Dispose()
        {
            base.Dispose();
            
            //FileId.Dispose(); - fileId handle is used in outer scope (see SMB2FileStore.CreateFile(out object handler, ...) method)  
            FileId = default;
						
            ObjectsPool<CreateResponse>.Return(this);
        }

        public override int CommandLength => 88 + CreateContext.GetCreateContextListLength(CreateContexts);
    }
}
