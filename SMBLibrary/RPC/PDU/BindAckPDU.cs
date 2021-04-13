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
    /// rpcconn_bind_ack_hdr_t
    /// </summary>
    public class BindAckPDU : RPCPDU
    {
        public const int BindAckFieldsFixedLength = 8;

        public ushort MaxTransmitFragmentSize; // max_xmit_frag
        public ushort MaxReceiveFragmentSize; // max_recv_frag
        public uint AssociationGroupID; // assoc_group_id
        public string SecondaryAddress; // sec_addr (port_any_t)
        // Padding (alignment to 4 byte boundary)
        public ResultList ResultList; // p_result_list
        public IMemoryOwner<byte> AuthVerifier;

        public BindAckPDU()
        {
            PacketType = PacketTypeName.BindAck;
            SecondaryAddress = String.Empty;
            ResultList = new ResultList();
            AuthVerifier = MemoryOwner<byte>.Empty;
        }

        public BindAckPDU(Span<byte> buffer, int offset) : base(buffer, offset)
        {
            var startOffset = offset;
            offset += CommonFieldsLength;
            MaxTransmitFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            MaxReceiveFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            AssociationGroupID = LittleEndianReader.ReadUInt32(buffer, ref offset);
            SecondaryAddress = RPCHelper.ReadPortAddress(buffer, ref offset);
            var padding = (4 - ((offset - startOffset) % 4)) % 4;
            offset += padding;
            ResultList = new ResultList(buffer, offset);
            offset += ResultList.Length;
            AuthVerifier = Arrays.RentFrom<byte>(buffer.Slice(offset, AuthLength));
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            AuthLength = (ushort)AuthVerifier.Length();
            var padding = (4 - ((SecondaryAddress.Length + 3) % 4)) % 4;
            var buffer = Arrays.Rent<byte>(Length);
            WriteCommonFieldsBytes(buffer.Memory.Span);
            var offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, ref offset, MaxTransmitFragmentSize);
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, ref offset, MaxReceiveFragmentSize);
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, AssociationGroupID);
            RPCHelper.WritePortAddress(buffer.Memory.Span, ref offset, SecondaryAddress);
            offset += padding;
            ResultList.WriteBytes(buffer.Memory.Span, ref offset);
            BufferWriter.WriteBytes(buffer.Memory.Span, offset, AuthVerifier.Memory.Span);
            
            return buffer;
        }

        public override int Length
        {
            get
            {
                var padding = (4 - ((SecondaryAddress.Length + 3) % 4)) % 4;
                return CommonFieldsLength + BindAckFieldsFixedLength + SecondaryAddress.Length + 3 + padding + ResultList.Length + AuthLength;
            }
        }

        public override void Dispose()
        {
            base.Dispose();
            AuthVerifier.Dispose();
            AuthVerifier = null;
        }
    }
}
