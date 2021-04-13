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
    /// SMB2 SET_INFO Response
    /// </summary>
    public class SetInfoResponse : SMB2Command
    {
        public const int DeclaredSize = 2;

        private ushort StructureSize;

        public SetInfoResponse()
        {
            Init(SMB2CommandName.SetInfo);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
        }

        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<SetInfoResponse>.Return(this);
        }

        public override int CommandLength => DeclaredSize;
    }
}
