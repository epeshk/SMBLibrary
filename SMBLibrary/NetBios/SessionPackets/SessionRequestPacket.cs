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
    /// [RFC 1002] 4.3.2. SESSION REQUEST PACKET
    /// </summary>
    public class SessionRequestPacket : SessionPacket
    {
        public string CalledName;
        public string CallingName;

        public SessionRequestPacket()
        {
            this.Type = SessionPacketTypeName.SessionRequest;
        }

        public SessionRequestPacket(byte[] buffer, int offset, ArrayPool<byte> pool) : base(buffer, offset, pool)
        {
            CalledName = NetBiosUtils.DecodeName(this.TrailerBytes, ref offset);
            CallingName = NetBiosUtils.DecodeName(this.TrailerBytes, ref offset);
        }

        public override ArraySegment<byte>[] GetBytes()
        {
            byte[] part1 = NetBiosUtils.EncodeName(CalledName, String.Empty);
            byte[] part2 = NetBiosUtils.EncodeName(CallingName, String.Empty);
            this.TrailerBytes = new byte[part1.Length + part2.Length];
            ByteWriter.WriteBytes(this.TrailerBytes, 0, part1);
            ByteWriter.WriteBytes(this.TrailerBytes, part1.Length, part2);
            return base.GetBytes();
        }

        public override int Length
        {
            get
            {
                byte[] part1 = NetBiosUtils.EncodeName(CalledName, String.Empty);
                byte[] part2 = NetBiosUtils.EncodeName(CallingName, String.Empty);
                return HeaderLength + part1.Length + part2.Length;
            }
        }
    }
}
