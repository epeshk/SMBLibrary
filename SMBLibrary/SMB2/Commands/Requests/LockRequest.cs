/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 LOCK Request
    /// </summary>
    public class LockRequest : SMB2Request
    {
        public const int DeclaredSize = 48;

        private ushort StructureSize;
        // ushort LockCount;
        public byte LSN; // 4 bits
        public uint LockSequenceIndex; // 28 bits
        public FileID FileId;
        public List<LockElement> Locks;

        public LockRequest() : base(SMB2CommandName.Lock)
        {
            StructureSize = DeclaredSize;
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort)Locks.Count);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint)(LSN & 0x0F) << 28 | (uint)(LockSequenceIndex & 0x0FFFFFFF));
            FileId.WriteBytes(buffer, offset + 8);
            LockElement.WriteLockList(buffer, offset + 24, Locks);
        }

        public override int CommandLength
        {
            get
            {
                return 48 + Locks.Count * LockElement.StructureLength;
            }
        }
    }
}
