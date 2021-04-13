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
    /// [RFC 1002] 4.3.2. SESSION REQUEST PACKET
    /// </summary>
    public class SessionRequestPacket : SessionPacket<SessionRequestPacket>
    {
        public string CalledName;
        public string CallingName;

        public SessionRequestPacket()
        {
            Type = SessionPacketTypeName.SessionRequest;
        }

        public override void Init(Span<byte> buffer)
        {
            var offset = 0;
            base.Init(buffer);
            CalledName = NetBiosUtils.DecodeName(Trailer.Memory.Span, ref offset);
            CallingName = NetBiosUtils.DecodeName(Trailer.Memory.Span, ref offset);
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            var part1 = NetBiosUtils.EncodeName(CalledName, string.Empty);
            var part2 = NetBiosUtils.EncodeName(CallingName, string.Empty);
            Trailer = Arrays.Rent(part1.Length + part2.Length);
            BufferWriter.WriteBytes(Trailer.Memory.Span, 0, part1);
            BufferWriter.WriteBytes(Trailer.Memory.Span, part1.Length, part2);
            return base.GetBytes();
        }

        public override int Length
        {
            get
            {
                var part1 = NetBiosUtils.EncodeName(CalledName, string.Empty);
                var part2 = NetBiosUtils.EncodeName(CallingName, string.Empty);
                return HeaderLength + part1.Length + part2.Length;
            }
        }
        
        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<SessionRequestPacket>.Return(this);
        }
    }
}
