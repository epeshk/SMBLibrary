/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS_QUERY_NMPIPE_STATE Response
    /// </summary>
    public class TransactionQueryNamedPipeStateResponse : TransactionSubcommand
    {
        public const int ParametersLength = 2;
        // Parameters;
        public NamedPipeStatus NMPipeStatus;

        public TransactionQueryNamedPipeStateResponse()
        {
        }

        public TransactionQueryNamedPipeStateResponse(byte[] parameters)
        {
            NMPipeStatus = new NamedPipeStatus(LittleEndianConverter.ToUInt16(parameters, 0));
        }

        public override IMemoryOwner<byte> GetSetup()
        {
            return MemoryOwner<byte>.Empty;
        }

        public override IMemoryOwner<byte> GetParameters()
        {
            var parameters = Arrays.Rent(2);
            NMPipeStatus.WriteBytes(parameters.Memory.Span, 0);
            return parameters;
        }

        public override TransactionSubcommandName SubcommandName => TransactionSubcommandName.TRANS_QUERY_NMPIPE_STATE;
    }
}
