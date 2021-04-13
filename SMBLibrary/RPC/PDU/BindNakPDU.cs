/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.RPC
{
    /// <summary>
    /// rpcconn_bind_nak_hdr_t
    /// </summary>
    public class BindNakPDU : RPCPDU
    {
        public const int BindNakFieldsFixedLength = 2;

        public RejectionReason RejectReason; // provider_reject_reason
        public VersionsSupported Versions; // versions

        public BindNakPDU()
        {
            PacketType = PacketTypeName.BindNak;
        }

        public BindNakPDU(Span<byte> buffer, int offset) : base(buffer, offset)
        {
            var startOffset = offset;
            offset += CommonFieldsLength;
            RejectReason = (RejectionReason)LittleEndianReader.ReadUInt16(buffer, ref offset);
            Versions = new VersionsSupported(buffer, offset);
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            var buffer = Arrays.Rent(Length);
            WriteCommonFieldsBytes(buffer.Memory.Span);
            var offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, ref offset, (ushort)RejectReason);
            Versions.WriteBytes(buffer.Memory.Span, offset);
            
            return buffer;
        }

        public override int Length
        {
            get
            {
                var length = CommonFieldsLength + BindNakFieldsFixedLength;
                if (Versions != null)
                {
                    length += Versions.Length;
                }
                return length;
            }
        }
    }
}
