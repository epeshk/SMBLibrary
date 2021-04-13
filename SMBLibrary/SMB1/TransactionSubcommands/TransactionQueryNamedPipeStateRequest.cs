/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS_QUERY_NMPIPE_STATE Request
    /// </summary>
    public class TransactionQueryNamedPipeStateRequest : TransactionSubcommand
    {
        // Setup:
        public ushort FID;

        public TransactionQueryNamedPipeStateRequest()
        {
        }

        public TransactionQueryNamedPipeStateRequest(Span<byte> setup, Span<byte> parameters)
        {
            FID = LittleEndianConverter.ToUInt16(setup, 2);
        }

        public override IMemoryOwner<byte> GetSetup()
        {
            var buf = Arrays.Rent(2);
            LittleEndianConverter.GetBytes(buf.Memory.Span, (ushort)SubcommandName);
            return buf;
        }

        public override TransactionSubcommandName SubcommandName => TransactionSubcommandName.TRANS_QUERY_NMPIPE_STATE;
    }
}
