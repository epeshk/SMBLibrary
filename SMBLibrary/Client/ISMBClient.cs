/* Copyright (C) 2017-2022 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace SMBLibrary.Client
{
    public interface ISMBClient
    {
        Task<bool> Connect(string serverName, SMBTransportType transport);

        Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport);

        void Disconnect();

        Task<NTStatus> Login(string domainName, string userName, string password);

        Task<NTStatus> Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod);

        Task<NTStatus> Logoff();

        Task<ISMBFileStore> TreeConnect(string shareName);

        uint MaxReadSize
        {
            get;
        }

        uint MaxWriteSize
        {
            get;
        }

        bool IsConnected
        {
            get;
        }
    }
}
