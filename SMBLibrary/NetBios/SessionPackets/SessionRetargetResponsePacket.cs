/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Buffers;
using Utilities;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.5. SESSION RETARGET RESPONSE PACKET
    /// </summary>
    public class SessionRetargetResponsePacket : SessionPacket
    {
        uint IPAddress;
        ushort Port;

        public SessionRetargetResponsePacket() : base()
        {
            this.Type = SessionPacketTypeName.RetargetSessionResponse;
        }

        public SessionRetargetResponsePacket(byte[] buffer, int offset, ArrayPool<byte> pool) : base(buffer, offset, pool)
        {
            IPAddress = BigEndianConverter.ToUInt32(this.TrailerBytes, offset + 0);
            Port = BigEndianConverter.ToUInt16(this.TrailerBytes, offset + 4);
        }

        public override ArraySegment<byte>[] GetBytes()
        {
            throw new InvalidOperationException("Shouldn't be called for response packet");
        }

        public override int Length
        {
            get
            {
                return HeaderLength + 6;
            }
        }
    }
}
