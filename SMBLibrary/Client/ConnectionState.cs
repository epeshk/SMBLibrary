/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using System.Net.Sockets;
using SMBLibrary.NetBios;
using SMBLibrary.SMB2;

namespace SMBLibrary.Client
{
    internal class ConnectionState
    {
        private Socket m_clientSocket;
        private NBTConnectionReceiveBuffer m_receiveBuffer;

        public ConnectionState(Socket clientSocket, ArrayPool<byte> pool, ITrailerDecryptor decryptor)
        {
            m_clientSocket = clientSocket;
            m_receiveBuffer = new NBTConnectionReceiveBuffer(pool, decryptor);
        }

        public Socket ClientSocket
        {
            get
            {
                return m_clientSocket;
            }
        }

        public NBTConnectionReceiveBuffer ReceiveBuffer
        {
            get
            {
                return m_receiveBuffer;
            }
        }
    }
}
