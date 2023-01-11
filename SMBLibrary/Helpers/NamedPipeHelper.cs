/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Threading.Tasks;
using SMBLibrary.RPC;
using SMBLibrary.Services;

namespace SMBLibrary.Client
{
    public class NamedPipeHelper
    {
        public static async Task<NTResult<(object pipeHandle, int maxTransmitFragmentSize)>> BindPipe(INTFileStore namedPipeShare, string pipeName, Guid interfaceGuid, uint interfaceVersion)
        {
            var result = await namedPipeShare.CreateFile(pipeName, (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA), 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, 0, null);
            if (result.Status != NTStatus.STATUS_SUCCESS)
            {
                return result.Status;
            }
            BindPDU bindPDU = new BindPDU();
            bindPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            bindPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
            bindPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            bindPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
            bindPDU.MaxTransmitFragmentSize = 5680;
            bindPDU.MaxReceiveFragmentSize = 5680;

            ContextElement serviceContext = new ContextElement();
            serviceContext.AbstractSyntax = new SyntaxID(interfaceGuid, interfaceVersion);
            serviceContext.TransferSyntaxList.Add(new SyntaxID(RemoteServiceHelper.NDRTransferSyntaxIdentifier, RemoteServiceHelper.NDRTransferSyntaxVersion));

            bindPDU.ContextList.Add(serviceContext);

            byte[] input = bindPDU.GetBytes();
            var ioControlResult = await namedPipeShare.DeviceIOControl(result.Content.Handle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, 4096);
            if (ioControlResult.Status != NTStatus.STATUS_SUCCESS)
            {
                return ioControlResult.Status;
            }
            BindAckPDU bindAckPDU = RPCPDU.GetPDU(ioControlResult.Content, 0) as BindAckPDU;
            if (bindAckPDU == null)
            {
                return NTStatus.STATUS_NOT_SUPPORTED;
            }

            return (result.Content.Handle, bindAckPDU.MaxTransmitFragmentSize);
        }
    }
}