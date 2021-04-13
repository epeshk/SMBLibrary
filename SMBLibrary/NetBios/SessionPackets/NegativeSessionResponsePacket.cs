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

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.4. NEGATIVE SESSION RESPONSE PACKET
    /// </summary>
    public class NegativeSessionResponsePacket : SessionPacket<NegativeSessionResponsePacket>
    {
        public byte ErrorCode;

        public NegativeSessionResponsePacket()
        {
            Type = SessionPacketTypeName.NegativeSessionResponse;
        }

        public override void Init(Span<byte> buffer)
        {
            base.Init(buffer);
            ErrorCode = ByteReader.ReadByte(Trailer.Memory.Span, 0);
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            Trailer = Arrays.Rent(1);
            Trailer.Memory.Span[0] = ErrorCode;

            return base.GetBytes();
        }

        public override int Length => HeaderLength + 1;

        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<NegativeSessionResponsePacket>.Return(this);
        }
    }
}
