/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-SRVS]
    /// </summary>
    public class ServerService : RemoteService
    {
        public const string ServicePipeName = @"srvsvc";
        public static readonly Guid ServiceInterfaceGuid = new Guid("4B324FC8-1670-01D3-1278-5A47BF6EE188");
        public const int ServiceVersion = 3;

        public const int MaxPreferredLength = -1; // MAX_PREFERRED_LENGTH

        private PlatformName m_platformID;
        private string m_serverName;
        private uint m_verMajor;
        private uint m_verMinor;
        private ServerType m_serverType;

        private List<string> m_shares;

        public ServerService(string serverName, List<string> shares)
        {
            m_platformID = PlatformName.NT;
            m_serverName = serverName;
            m_verMajor = 5;
            m_verMinor = 2;
            m_serverType = ServerType.Workstation | ServerType.Server | ServerType.WindowsNT | ServerType.ServerNT | ServerType.MasterBrowser;

            m_shares = shares;
        }

        public override IMemoryOwner<byte> GetResponseBytes(ushort opNum, IMemoryOwner<byte> requestBytes)
        {
            switch ((ServerServiceOpName)opNum)
            {
                case ServerServiceOpName.NetrShareEnum:
                    {
                        var request = new NetrShareEnumRequest(requestBytes);
                        var response = GetNetrShareEnumResponse(request);
                        return response.GetBytes();
                    }
                case ServerServiceOpName.NetrShareGetInfo:
                    {
                        var request = new NetrShareGetInfoRequest(requestBytes);
                        var response = GetNetrShareGetInfoResponse(request);
                        return response.GetBytes();
                    }
                case ServerServiceOpName.NetrServerGetInfo:
                    {
                        var request = new NetrServerGetInfoRequest(requestBytes);
                        var response = GetNetrWkstaGetInfoResponse(request);
                        return response.GetBytes();
                    }
                default:
                    throw new UnsupportedOpNumException();
            }
        }

        public NetrShareEnumResponse GetNetrShareEnumResponse(NetrShareEnumRequest request)
        {
            var response = new NetrShareEnumResponse();
            switch (request.InfoStruct.Level)
            {
                case 0:
                    {
                        // We ignore request.PreferedMaximumLength
                        var info = new ShareInfo0Container();
                        for (var index = 0; index < m_shares.Count; index++)
                        {
                            var shareName = m_shares[index];
                            info.Add(new ShareInfo0Entry(shareName));
                        }

                        response.InfoStruct = new ShareEnum(info);
                        response.TotalEntries = (uint)m_shares.Count;
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 1:
                    {
                        // We ignore request.PreferedMaximumLength
                        var info = new ShareInfo1Container();
                        for (var index = 0; index < m_shares.Count; index++)
                        {
                            var shareName = m_shares[index];
                            info.Add(new ShareInfo1Entry(shareName, new ShareTypeExtended(ShareType.DiskDrive)));
                        }

                        response.InfoStruct = new ShareEnum(info);
                        response.TotalEntries = (uint)m_shares.Count;
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 2:
                case 501:
                case 502:
                case 503:
                    {
                        response.InfoStruct = new ShareEnum(request.InfoStruct.Level);
                        response.Result = Win32Error.ERROR_NOT_SUPPORTED;
                        return response;
                    }
                default:
                    {
                        response.InfoStruct = new ShareEnum(request.InfoStruct.Level);
                        response.Result = Win32Error.ERROR_INVALID_LEVEL;
                        return response;
                    }
            }
        }

        public NetrShareGetInfoResponse GetNetrShareGetInfoResponse(NetrShareGetInfoRequest request)
        {
            var shareIndex = IndexOfShare(request.NetName);
            
            var response = new NetrShareGetInfoResponse();
            if (shareIndex == -1)
            {
                response.InfoStruct = new ShareInfo(request.Level);
                response.Result = Win32Error.NERR_NetNameNotFound;
                return response;
            }

            switch (request.Level)
            {
                case 0:
                    {
                        var info = new ShareInfo0Entry(m_shares[shareIndex]);
                        response.InfoStruct = new ShareInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 1:
                    {
                        var info = new ShareInfo1Entry(m_shares[shareIndex], new ShareTypeExtended(ShareType.DiskDrive));
                        response.InfoStruct = new ShareInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 2:
                    {
                        var info = new ShareInfo2Entry(m_shares[shareIndex], new ShareTypeExtended(ShareType.DiskDrive));
                        response.InfoStruct = new ShareInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 501:
                case 502:
                case 503:
                case 1005:
                    {
                        response.InfoStruct = new ShareInfo(request.Level);
                        response.Result = Win32Error.ERROR_NOT_SUPPORTED;
                        return response;
                    }
                default:
                    {
                        response.InfoStruct = new ShareInfo(request.Level);
                        response.Result = Win32Error.ERROR_INVALID_LEVEL;
                        return response;
                    }
            }
        }

        public NetrServerGetInfoResponse GetNetrWkstaGetInfoResponse(NetrServerGetInfoRequest request)
        {
            var response = new NetrServerGetInfoResponse();
            switch (request.Level)
            {
                case 100:
                    {
                        var info = new ServerInfo100();
                        info.PlatformID = m_platformID;
                        info.ServerName.Value = m_serverName;
                        response.InfoStruct = new ServerInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 101:
                    {
                        var info = new ServerInfo101();
                        info.PlatformID = m_platformID;
                        info.ServerName.Value = m_serverName;
                        info.VerMajor = m_verMajor;
                        info.VerMinor = m_verMinor;
                        info.Type = m_serverType;
                        info.Comment.Value = String.Empty;
                        response.InfoStruct = new ServerInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 102:
                case 103:
                case 502:
                case 503:
                    {
                        response.InfoStruct = new ServerInfo(request.Level);
                        response.Result = Win32Error.ERROR_NOT_SUPPORTED;
                        return response;
                    }
                default:
                    {
                        response.InfoStruct = new ServerInfo(request.Level);
                        response.Result = Win32Error.ERROR_INVALID_LEVEL;
                        return response;
                    }
            }
        }

        private int IndexOfShare(string shareName)
        {
            for (var index = 0; index < m_shares.Count; index++)
            {
                if (m_shares[index].Equals(shareName, StringComparison.OrdinalIgnoreCase))
                {
                    return index;
                }
            }

            return -1;
        }

        public override Guid InterfaceGuid => ServiceInterfaceGuid;

        public override string PipeName => ServicePipeName;
    }
}
