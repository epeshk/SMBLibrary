/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using SMBLibrary.SMB2;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.6. SESSION MESSAGE PACKET
    /// </summary>
    public class SessionMessagePacket : SessionPacket
    {
        public SessionMessagePacket() : base()
        {
            this.Type = SessionPacketTypeName.SessionMessage;
        }

        internal SessionMessagePacket(byte[] buffer, int offset, ArrayPool<byte> pool, ITrailerDecryptor decryptor) : base(buffer, offset, pool, decryptor)
        {
        }
    }
}
