/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// rpcconn_bind_hdr_t
    /// </summary>
    public class BindPDU : RPCPDU
    {
        public const int BindFieldsFixedLength = 8;

        public ushort MaxTransmitFragmentSize; // max_xmit_frag
        public ushort MaxReceiveFragmentSize; // max_recv_frag
        public uint AssociationGroupID; // assoc_group_id
        public ContextList ContextList;
        public IMemoryOwner<byte> AuthVerifier;

        public BindPDU()
        {
            PacketType = PacketTypeName.Bind;
            ContextList = new ContextList();
            AuthVerifier = MemoryOwner<byte>.Empty;
        }

        public BindPDU(Span<byte> buffer, int offset) : base(buffer, offset)
        {
            offset += CommonFieldsLength;
            MaxTransmitFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            MaxReceiveFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            AssociationGroupID = LittleEndianReader.ReadUInt32(buffer, ref offset);
            ContextList = new ContextList(buffer, offset);
            offset += ContextList.Length;
            AuthVerifier = Arrays.RentFrom<byte>(buffer.Slice(offset, AuthLength));
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            AuthLength = (ushort)AuthVerifier.Length();
            var buffer = Arrays.Rent<byte>(Length);
            WriteCommonFieldsBytes(buffer.Memory.Span);
            var offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, ref offset, MaxTransmitFragmentSize);
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, ref offset, MaxReceiveFragmentSize);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, AssociationGroupID);
            ContextList.WriteBytes(buffer.Memory.Span, ref offset);
            BufferWriter.WriteBytes(buffer.Memory.Span, offset, AuthVerifier.Memory.Span);

            return buffer;
        }

        public override int Length => CommonFieldsLength + BindFieldsFixedLength + ContextList.Length + AuthLength;

        public override void Dispose()
        {
            base.Dispose();
            AuthVerifier.Dispose();
            AuthVerifier = null;
        }
    }
}
