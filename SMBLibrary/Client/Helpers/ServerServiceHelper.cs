/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;
using MemoryPools.Memory;
using SMBLibrary.RPC;
using SMBLibrary.Services;
using Utilities;

namespace SMBLibrary.Client
{
    public class ServerServiceHelper
    {
        public static List<string> ListShares(INTFileStore namedPipeShare, ShareType? shareType, out NTStatus status)
        {
            object pipeHandle;
            FileStatus fileStatus;
            status = namedPipeShare.CreateFile(out pipeHandle, out fileStatus, Arrays.RentFrom<char>(ServerService.ServicePipeName), (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA), 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, 0, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            var bindPDU = new BindPDU();
            bindPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            bindPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
            bindPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            bindPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
            bindPDU.MaxTransmitFragmentSize = 5680;
            bindPDU.MaxReceiveFragmentSize = 5680;

            var serverServiceContext = new ContextElement();
            serverServiceContext.AbstractSyntax = new SyntaxID(ServerService.ServiceInterfaceGuid, ServerService.ServiceVersion);
            serverServiceContext.TransferSyntaxList.Add(new SyntaxID(RemoteServiceHelper.NDRTransferSyntaxIdentifier, RemoteServiceHelper.NDRTransferSyntaxVersion));
            
            bindPDU.ContextList.Add(serverServiceContext);

            var input = bindPDU.GetBytes();
            IMemoryOwner<byte> output;
            status = namedPipeShare.DeviceIOControl(pipeHandle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, out output, 4096);

            try
            {
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return null;
                }
                var bindAckPDU = RPCPDU.GetPDU(output.Memory.Span, 0) as BindAckPDU;
                if (bindAckPDU == null)
                {
                    status = NTStatus.STATUS_NOT_SUPPORTED;
                    return null;
                }

                var shareEnumRequest = new NetrShareEnumRequest();
                shareEnumRequest.InfoStruct = new ShareEnum();
                shareEnumRequest.InfoStruct.Level = 1;
                shareEnumRequest.InfoStruct.Info = new ShareInfo1Container();
                shareEnumRequest.PreferedMaximumLength = UInt32.MaxValue;
                shareEnumRequest.ServerName = "*";
                var requestPDU = new RequestPDU();
                requestPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
                requestPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
                requestPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
                requestPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
                requestPDU.OpNum = (ushort)ServerServiceOpName.NetrShareEnum;
                requestPDU.Data = shareEnumRequest.GetBytes();
                requestPDU.AllocationHint = (uint)requestPDU.Data.Length();
                input = requestPDU.GetBytes();
                int maxOutputLength = bindAckPDU.MaxTransmitFragmentSize;
                
                bindAckPDU.Dispose();
                
                status = namedPipeShare.DeviceIOControl(pipeHandle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, out output, maxOutputLength);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return null;
                }
                var responsePDU = RPCPDU.GetPDU(output.Memory.Span, 0) as ResponsePDU;
                if (responsePDU == null)
                {
                    status = NTStatus.STATUS_NOT_SUPPORTED;
                    return null;
                }

                var responseData = responsePDU.Data;
                while ((responsePDU.Flags & PacketFlags.LastFragment) == 0)
                {
                    status = namedPipeShare.ReadFile(out output, pipeHandle, 0, maxOutputLength);
                    if (status != NTStatus.STATUS_SUCCESS)
                    {
                        return null;
                    }
                    responsePDU = RPCPDU.GetPDU(output.Memory.Span, 0) as ResponsePDU;
                    if (responsePDU == null)
                    {
                        status = NTStatus.STATUS_NOT_SUPPORTED;
                        return null;
                    }
                    responseData = ByteUtils.Concatenate(responseData.Memory.Span, responsePDU.Data.Memory.Span);
                }
                var shareEnumResponse = new NetrShareEnumResponse(responseData);
                var shareInfo1 = shareEnumResponse.InfoStruct.Info as ShareInfo1Container;
                if (shareInfo1 == null || shareInfo1.Entries == null)
                {
                    if (shareEnumResponse.Result == Win32Error.ERROR_ACCESS_DENIED)
                    {
                        status = NTStatus.STATUS_ACCESS_DENIED;
                    }
                    else
                    {
                        status = NTStatus.STATUS_NOT_SUPPORTED;
                    }
                    return null;
                }

                var result = new List<string>();
                foreach (var entry in shareInfo1.Entries)
                {
                    if (!shareType.HasValue || shareType.Value == entry.ShareType.ShareType)
                    {
                        result.Add(entry.NetName.Value);
                    }
                }
                return result;

            }
            finally
            {
                output.Dispose();
            } 
        }
    }
}
