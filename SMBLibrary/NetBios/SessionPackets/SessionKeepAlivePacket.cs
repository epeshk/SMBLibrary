/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Buffers;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.7. SESSION KEEP ALIVE PACKET
    /// </summary>
    public class SessionKeepAlivePacket : SessionPacket
    {
        public SessionKeepAlivePacket()
        {
            this.Type = SessionPacketTypeName.SessionKeepAlive;
        }

        public SessionKeepAlivePacket(byte[] buffer, int offset, ArrayPool<byte> pool) : base(buffer, offset, pool)
        {
        }

        public override ArraySegment<byte>[] GetBytes()
        {
            this.TrailerBytes = new byte[0];
            return base.GetBytes();
        }

        public override int Length
        {
            get
            {
                return HeaderLength;
            }
        }
    }
}
