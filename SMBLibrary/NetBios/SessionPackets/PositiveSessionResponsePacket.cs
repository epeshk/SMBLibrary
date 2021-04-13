/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using MemoryPools.Memory;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.3. POSITIVE SESSION RESPONSE PACKET
    /// </summary>
    public class PositiveSessionResponsePacket : SessionPacket<PositiveSessionResponsePacket>
    {
        public PositiveSessionResponsePacket()
        {
            Type = SessionPacketTypeName.PositiveSessionResponse;
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            Trailer = MemoryOwner<byte>.Empty;
            return base.GetBytes();
        }

        public override int Length => HeaderLength;

        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<PositiveSessionResponsePacket>.Return(this);
        }
    }
}
