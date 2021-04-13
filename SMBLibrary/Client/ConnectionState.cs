/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using MemoryPools.Memory;
using SMBLibrary.NetBios;

namespace SMBLibrary.Client
{
    public class ConnectionState : IDisposable
    {
        private ConnectionReceiveBuffer m_receiveBuffer;

        public ConnectionState()
        {
            m_receiveBuffer = ObjectsPool<ConnectionReceiveBuffer>.Get().Init();
        }

        public ConnectionReceiveBuffer ReceiveBuffer => m_receiveBuffer;

        public void Dispose()
        {
            if (m_receiveBuffer != null)
            {
                m_receiveBuffer.Dispose();
                ObjectsPool<ConnectionReceiveBuffer>.Return(m_receiveBuffer);
            }
            m_receiveBuffer = null;
        }
    }
}
