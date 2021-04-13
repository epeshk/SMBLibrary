/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.IO;
using System.Net;
using MemoryPools.Memory;

namespace SMBLibrary.Server
{
    public class AccessRequestArgs : EventArgs, IDisposable
    {
        public IMemoryOwner<char> UserName;
        public IMemoryOwner<char> Path;
        public FileAccess RequestedAccess;
        public IMemoryOwner<char> MachineName;
        public IPEndPoint ClientEndPoint;
        public bool Allow = true;

        public AccessRequestArgs(ReadOnlySpan<char> userName, ReadOnlySpan<char> path, FileAccess requestedAccess, ReadOnlySpan<char> machineName, IPEndPoint clientEndPoint)
        {
            UserName = Arrays.RentFrom(userName);
            Path = Arrays.RentFrom(path);
            RequestedAccess = requestedAccess;
            MachineName = Arrays.RentFrom(machineName);
            ClientEndPoint = clientEndPoint;
        }

        public void Dispose()
        {
            UserName?.Dispose();
            Path?.Dispose();
            MachineName?.Dispose();
        }
    }
}
