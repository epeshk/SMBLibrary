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
    /// rpcconn_request_hdr_t
    /// </summary>
    public class RequestPDU : RPCPDU
    {
        public const int RequestFieldsFixedLength = 8;

        public uint AllocationHint; // alloc_hint
        public ushort ContextID;
        public ushort OpNum;
        public Guid ObjectGuid; // Optional field
        public IMemoryOwner<byte> Data;
        public IMemoryOwner<byte> AuthVerifier;

        public RequestPDU()
        {
            PacketType = PacketTypeName.Request;
            AuthVerifier = MemoryOwner<byte>.Empty;
        }

        public RequestPDU(Span<byte> buffer, int offset) : base(buffer, offset)
        {
            offset += CommonFieldsLength;
            AllocationHint = LittleEndianReader.ReadUInt32(buffer, ref offset);
            ContextID = LittleEndianReader.ReadUInt16(buffer, ref offset);
            OpNum = LittleEndianReader.ReadUInt16(buffer, ref offset);
            if ((Flags & PacketFlags.ObjectUUID) > 0)
            {
                ObjectGuid = LittleEndianReader.ReadGuid(buffer, ref offset);
            }
            var dataLength = FragmentLength - AuthLength - offset;
            Data = Arrays.RentFrom<byte>(buffer.Slice(offset, dataLength)); offset += dataLength;
            AuthVerifier = Arrays.RentFrom<byte>(buffer.Slice(offset, AuthLength));
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            AuthLength = (ushort)AuthVerifier.Length();
            var buffer = Arrays.Rent<byte>(Length);
            WriteCommonFieldsBytes(buffer.Memory.Span);
            var offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, AllocationHint);
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, ref offset, ContextID);
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, ref offset, OpNum);
            if ((Flags & PacketFlags.ObjectUUID) > 0)
            {
                LittleEndianWriter.WriteGuidBytes(buffer.Memory.Span, ref offset, ObjectGuid);
            }
            BufferWriter.WriteBytes(buffer.Memory.Span, ref offset, Data.Memory.Span);
            BufferWriter.WriteBytes(buffer.Memory.Span, ref offset, AuthVerifier.Memory.Span);
            return buffer;
        }

        public override int Length
        {
            get
            {
                var length = CommonFieldsLength + RequestFieldsFixedLength + Data.Length() + AuthVerifier.Length();
                if ((Flags & PacketFlags.ObjectUUID) > 0)
                {
                    length += 16;
                }
                return length;
            }
        }
    }
}
