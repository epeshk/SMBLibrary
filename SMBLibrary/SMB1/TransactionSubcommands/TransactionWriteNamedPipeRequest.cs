/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// TRANS_WRITE_NMPIPE Request
    /// </summary>
    public class TransactionWriteNamedPipeRequest : TransactionSubcommand
    {
        // Setup:
        public ushort FID;
        // Data:
        public IMemoryOwner<byte> WriteData;

        public TransactionWriteNamedPipeRequest()
        {
        }

        public TransactionWriteNamedPipeRequest(Span<byte> setup, IMemoryOwner<byte> data)
        {
            FID = LittleEndianConverter.ToUInt16(setup, 2);

            WriteData = data.AddOwner();
        }

        public override IMemoryOwner<byte> GetSetup()
        {
            var setup = Arrays.Rent(4);
            LittleEndianWriter.WriteUInt16(setup, 0, (ushort)SubcommandName);
            LittleEndianWriter.WriteUInt16(setup, 2, FID);
            return setup;
        }

        public override IMemoryOwner<byte> GetData(bool isUnicode)
        {
            return WriteData.AddOwner();
        }

        public override TransactionSubcommandName SubcommandName => TransactionSubcommandName.TRANS_WRITE_NMPIPE;

        public override void Dispose()
        {
            base.Dispose();
            WriteData?.Dispose();
            WriteData = null;
        }
    }
}
