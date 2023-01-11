/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Buffers;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.3. POSITIVE SESSION RESPONSE PACKET
    /// </summary>
    public class PositiveSessionResponsePacket : SessionPacket
    {
        public PositiveSessionResponsePacket() : base()
        {
            this.Type = SessionPacketTypeName.PositiveSessionResponse;
        }

        public PositiveSessionResponsePacket(byte[] buffer, int offset, ArrayPool<byte> pool) : base(buffer, offset, pool)
        {
        }

        public override ArraySegment<byte>[] GetBytes()
        {
            throw new InvalidOperationException("Shouldn't be called for response packet");
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
