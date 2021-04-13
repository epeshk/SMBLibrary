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
    /// SMB2 LOGOFF Request
    /// </summary>
    public class LogoffRequest : SMB2Command
    {
        public const int DeclaredSize = 4;

        private ushort StructureSize;
        public ushort Reserved;

        public LogoffRequest Init()
        {
            base.Init(SMB2CommandName.Logoff);
            StructureSize = DeclaredSize;

            return this;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, Reserved);
        }

        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<LogoffRequest>.Return(this);
        }

        public override int CommandLength => DeclaredSize;
    }
}
