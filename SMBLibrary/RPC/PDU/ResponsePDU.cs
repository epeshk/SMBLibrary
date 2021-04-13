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
    /// rpcconn_response_hdr_t
    /// </summary>
    public class ResponsePDU : RPCPDU
    {
        public const int ResponseFieldsLength = 8;

        public uint AllocationHint;
        public ushort ContextID;
        public byte CancelCount;
        public byte Reserved;
        public IMemoryOwner<byte> Data;
        public IMemoryOwner<byte> AuthVerifier;

        public ResponsePDU()
        {
            PacketType = PacketTypeName.Response;
            AuthVerifier = MemoryOwner<byte>.Empty;
        }

        public ResponsePDU(Span<byte> buffer, int offset) : base(buffer, offset)
        {
            offset += CommonFieldsLength;
            AllocationHint = LittleEndianReader.ReadUInt32(buffer, ref offset);
            ContextID = LittleEndianReader.ReadUInt16(buffer, ref offset);
            CancelCount = ByteReader.ReadByte(buffer, ref offset);
            Reserved = ByteReader.ReadByte(buffer, ref offset);
            var dataLength = FragmentLength - AuthLength - offset;
            Data = Arrays.RentFrom<byte>(buffer.Slice(offset, dataLength)); offset += dataLength;
            AuthVerifier = Arrays.RentFrom<byte>(buffer.Slice(offset, AuthLength));
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            AuthLength = (ushort)AuthVerifier.Length();
            var buffer = Arrays.Rent(Length);
            WriteCommonFieldsBytes(buffer.Memory.Span);
            var offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt32(buffer.Memory.Span, ref offset, AllocationHint);
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, ref offset, ContextID);
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, CancelCount);
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, Reserved);
            BufferWriter.WriteBytes(buffer.Memory.Span, ref offset, Data.Memory.Span);
            BufferWriter.WriteBytes(buffer.Memory.Span, ref offset, AuthVerifier.Memory.Span);
            return buffer;
        }

        public override int Length => CommonFieldsLength + ResponseFieldsLength + Data.Length() + AuthVerifier.Length();

        public override void Dispose()
        {
            base.Dispose();
            Data.Dispose();
            AuthVerifier.Dispose();
            Data = AuthVerifier = null;
        }
    }
}
