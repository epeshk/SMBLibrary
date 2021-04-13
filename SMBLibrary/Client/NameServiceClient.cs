/* Copyright (C) 2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Net;
using System.Net.Sockets;
using MemoryPools.Memory;
using SMBLibrary.NetBios;

namespace SMBLibrary.Client
{
    public class NameServiceClient
    {
        public static readonly int NetBiosNameServicePort = 137;

        private IPAddress m_serverAddress;

        public NameServiceClient(IPAddress serverAddress)
        {
            m_serverAddress = serverAddress;
        }

        public string GetServerName()
        {
            var request = new NodeStatusRequest();
            request.Header.QDCount = 1;
            request.Question.Name = "*".PadRight(16, '\0');
            var response = SendNodeStatusRequest(request);
            for (var index = 0; index < response.Names.Count; index++)
            {
                var entry = response.Names[index];
                var suffix = NetBiosUtils.GetSuffixFromMSNetBiosName(entry.Key);
                if (suffix == NetBiosSuffix.FileServiceService)
                {
                    return entry.Key;
                }
            }

            return null;
        }

        private NodeStatusResponse SendNodeStatusRequest(NodeStatusRequest request)
        {
            var client = new UdpClient();
            var serverEndPoint = new IPEndPoint(m_serverAddress, NetBiosNameServicePort);
            client.Connect(serverEndPoint);

            var requestBytes = request.GetBytes();
            client.Send(requestBytes, requestBytes.Length);
            var responseBytes = client.Receive(ref serverEndPoint);
            return new NodeStatusResponse(responseBytes, 0);
        }
    }
}
