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
    /// [RFC 1002] 4.3.5. SESSION RETARGET RESPONSE PACKET
    /// </summary>
    public class SessionRetargetResponsePacket : SessionPacket<SessionRetargetResponsePacket>
    {
        uint IPAddress;
        ushort Port;

        public SessionRetargetResponsePacket()
        {
            Type = SessionPacketTypeName.RetargetSessionResponse;
        }

        public override void Init(Span<byte> buffer)
        {
            base.Init(buffer);
            IPAddress = BigEndianConverter.ToUInt32(Trailer.Memory.Span, 0);
            Port = BigEndianConverter.ToUInt16(Trailer.Memory.Span, 4);
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            Trailer = Arrays.Rent(6);
            BigEndianWriter.WriteUInt32(Trailer.Memory.Span, 0, IPAddress);
            BigEndianWriter.WriteUInt16(Trailer.Memory.Span, 4, Port);
            return base.GetBytes();
        }

        public override int Length => HeaderLength + 6;
        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<SessionRetargetResponsePacket>.Return(this);
        }
    }
}
