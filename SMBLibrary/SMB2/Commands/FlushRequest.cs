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
    /// SMB2 FLUSH Request
    /// </summary>
    public class FlushRequest : SMB2Command
    {
        public const int DeclaredSize = 24;

        private ushort StructureSize;
        public ushort Reserved1;
        public uint Reserved2;
        public FileID FileId;

        public FlushRequest()
        {
            Init(SMB2CommandName.Flush);
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Reserved1 = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            Reserved2 = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            FileId = ObjectsPool<FileID>.Get().Init(buffer, offset + Smb2Header.Length + 8);
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, Reserved1);
            LittleEndianWriter.WriteUInt32(buffer, 4, Reserved2);
            FileId.WriteBytes(buffer, 8);
        }

        public override void Dispose()
        {
            base.Dispose();
            
            //FileId.Dispose(); - fileId handle is frequently used for multiple requests and can be disposed via ISMBFileStore.CloseFile(...) method.  
            FileId = default;

            ObjectsPool<FlushRequest>.Return(this);
        }

        public override int CommandLength => DeclaredSize;
    }
}
