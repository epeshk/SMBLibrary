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
    /// SMB2 LOCK Request
    /// </summary>
    public class LockRequest : SMB2Command
    {
        public const int DeclaredSize = 48;

        private ushort StructureSize;
        // ushort LockCount;
        public byte LSN; // 4 bits
        public uint LockSequenceIndex; // 28 bits
        public FileID FileId;
        public List<LockElement> Locks;

        public LockRequest()
        {
            Init(SMB2CommandName.Lock);
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            var lockCount = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            var temp = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            LSN = (byte)(temp >> 28);
            LockSequenceIndex = (temp & 0x0FFFFFFF);
            FileId = ObjectsPool<FileID>.Get().Init(buffer, offset + Smb2Header.Length + 8);
            Locks = LockElement.ReadLockList(buffer, offset + Smb2Header.Length + 24, lockCount);
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, (ushort)Locks.Count);
            LittleEndianWriter.WriteUInt32(buffer, 4, (uint)(LSN & 0x0F) << 28 | LockSequenceIndex & 0x0FFFFFFF);
            FileId.WriteBytes(buffer, 8);
            LockElement.WriteLockList(buffer, 24, Locks);
        }

        public override void Dispose()
        {
            base.Dispose();
            
            //FileId.Dispose(); - fileId handle is frequently used for multiple requests and can be disposed via ISMBFileStore.CloseFile(...) method.  
            FileId = default;

            ObjectsPool<LockRequest>.Return(this);
        }

        public override int CommandLength => 48 + Locks.Count * LockElement.StructureLength;
    }
}
