/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using MemoryPools.Memory;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.6. SESSION MESSAGE PACKET
    /// </summary>
    public class SessionMessagePacket : SessionPacket<SessionMessagePacket>
    {
        public SessionMessagePacket()
        {
            Type = SessionPacketTypeName.SessionMessage;
        }
        
        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<SessionMessagePacket>.Return(this);
        }
    }
}
