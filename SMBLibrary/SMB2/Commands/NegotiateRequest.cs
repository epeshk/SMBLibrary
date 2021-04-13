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
    /// SMB2 NEGOTIATE Request
    /// </summary>
    public class NegotiateRequest : SMB2Command
    {
        public const int DeclaredSize = 36;

        private ushort StructureSize;
        // ushort DialectCount;
        public SecurityMode SecurityMode;
        public ushort Reserved;
        public Capabilities Capabilities; // If the client does not implements the SMB 3.x dialect family, this field MUST be set to 0.
        public Guid ClientGuid;
        public DateTime ClientStartTime;
        public List<SMB2Dialect> Dialects = new List<SMB2Dialect>();

        public NegotiateRequest Init()
        {
            SecurityMode = default;
            Reserved = default;
            Capabilities = default;
            ClientGuid = default;
            ClientStartTime = default;
            Dialects.Clear();
                
            Init(SMB2CommandName.Negotiate);
            StructureSize = DeclaredSize;
            return this;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            var dialectCount = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            SecurityMode = (SecurityMode)LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 4);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 6);
            Capabilities = (Capabilities)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 8);
            ClientGuid = LittleEndianConverter.ToGuid(buffer, offset + Smb2Header.Length + 12);
            ClientStartTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + Smb2Header.Length + 28));

            for (var index = 0; index < dialectCount; index++)
            {
                var dialect = (SMB2Dialect)LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 36 + index * 2);
                Dialects.Add(dialect);
            }
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, (ushort)Dialects.Count);
            LittleEndianWriter.WriteUInt16(buffer, 4, (ushort)SecurityMode);
            LittleEndianWriter.WriteUInt16(buffer, 6, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, 8, (uint)Capabilities);
            LittleEndianWriter.WriteGuidBytes(buffer, 12, ClientGuid);
            LittleEndianWriter.WriteInt64(buffer, 28, ClientStartTime.ToFileTimeUtc());
            
            for (var index = 0; index < Dialects.Count; index++)
            {
                var dialect = Dialects[index];
                LittleEndianWriter.WriteUInt16(buffer, 36 + index * 2, (ushort)dialect);
            }
        }

        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<NegotiateRequest>.Return(this);
        }

        public override int CommandLength => 36 + Dialects.Count * 2;
    }
}
