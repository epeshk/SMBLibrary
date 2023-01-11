/* Copyright (C) 2014-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SMBLibrary.RPC;
using SMBLibrary.Services;
using Utilities;

namespace SMBLibrary.Client
{
    public class ServerServiceHelper
    {
        public static Task<NTResult<List<string>>> ListShares(INTFileStore namedPipeShare, ShareType? shareType)
        {
            return ListShares(namedPipeShare, "*", shareType);
        }

        /// <param name="serverName">
        /// When a Windows Server host is using Failover Cluster and Cluster Shared Volumes, each of those CSV file shares is associated
        /// with a specific host name associated with the cluster and is not accessible using the node IP address or node host name.
        /// </param>
        public static async Task<NTResult<List<string>>> ListShares(INTFileStore namedPipeShare, string serverName, ShareType? shareType)
        {
            object pipeHandle;
            var bindPipeResult = await NamedPipeHelper.BindPipe(namedPipeShare, ServerService.ServicePipeName, ServerService.ServiceInterfaceGuid, ServerService.ServiceVersion);
            if (bindPipeResult.Status != NTStatus.STATUS_SUCCESS)
            {
                return bindPipeResult.Status;
            }

            NetrShareEnumRequest shareEnumRequest = new NetrShareEnumRequest();
            shareEnumRequest.InfoStruct = new ShareEnum();
            shareEnumRequest.InfoStruct.Level = 1;
            shareEnumRequest.InfoStruct.Info = new ShareInfo1Container();
            shareEnumRequest.PreferedMaximumLength = UInt32.MaxValue;
            shareEnumRequest.ServerName = @"\\" + serverName;
            RequestPDU requestPDU = new RequestPDU();
            requestPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            requestPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
            requestPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            requestPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
            requestPDU.OpNum = (ushort)ServerServiceOpName.NetrShareEnum;
            requestPDU.Data = shareEnumRequest.GetBytes();
            requestPDU.AllocationHint = (uint)requestPDU.Data.Length;
            byte[] input = requestPDU.GetBytes();
            int maxOutputLength = bindPipeResult.Content.maxTransmitFragmentSize;
            var ioctlResult = await namedPipeShare.DeviceIOControl(bindPipeResult.Content.pipeHandle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, maxOutputLength);
            if (ioctlResult.Status != NTStatus.STATUS_SUCCESS)
            {
                return ioctlResult.Status;
            }
            ResponsePDU responsePDU = RPCPDU.GetPDU(ioctlResult.Content, 0) as ResponsePDU;
            if (responsePDU == null)
            {
                return NTStatus.STATUS_NOT_SUPPORTED;
            }

            byte[] responseData = responsePDU.Data;
            while ((responsePDU.Flags & PacketFlags.LastFragment) == 0)
            {
                var readResult = await namedPipeShare.ReadFile(bindPipeResult.Content.pipeHandle, 0, maxOutputLength);
                if (readResult.Status != NTStatus.STATUS_SUCCESS)
                {
                    return readResult.Status;
                }
                responsePDU = RPCPDU.GetPDU(readResult.Content.Memory.ToArray(), 0) as ResponsePDU;
                readResult.Content.Dispose();
                if (responsePDU == null)
                {
                    return NTStatus.STATUS_NOT_SUPPORTED;
                }
                responseData = ByteUtils.Concatenate(responseData, responsePDU.Data);
            }
            await namedPipeShare.CloseFile(bindPipeResult.Content.pipeHandle);
            NetrShareEnumResponse shareEnumResponse = new NetrShareEnumResponse(responseData);
            ShareInfo1Container shareInfo1 = shareEnumResponse.InfoStruct.Info as ShareInfo1Container;
            if (shareInfo1 == null || shareInfo1.Entries == null)
            {
                if (shareEnumResponse.Result == Win32Error.ERROR_ACCESS_DENIED)
                {
                    return NTStatus.STATUS_ACCESS_DENIED;
                }
                else
                {
                    return NTStatus.STATUS_NOT_SUPPORTED;
                }
            }

            List<string> result = new List<string>();
            foreach (ShareInfo1Entry entry in shareInfo1.Entries)
            {
                if (!shareType.HasValue || shareType.Value == entry.ShareType.ShareType)
                {
                    result.Add(entry.NetName.Value);
                }
            }
            return result;
        }
    }
}