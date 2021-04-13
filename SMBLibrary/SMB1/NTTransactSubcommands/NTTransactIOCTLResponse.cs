/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// NT_TRANSACT_IOCTL Response
    /// </summary>
    public class NTTransactIOCTLResponse : NTTransactSubcommand
    {
        public const int ParametersLength = 0;
        public const int SetupLength = 2;
        // Setup:
        public ushort TransactionDataSize; // in bytes
        // Data:
        public IMemoryOwner<byte> Data;

        public NTTransactIOCTLResponse()
        {
        }

        public NTTransactIOCTLResponse(IMemoryOwner<byte> setup, IMemoryOwner<byte> data)
        {
            TransactionDataSize = LittleEndianConverter.ToUInt16(setup, 0);
            Data = data.AddOwner();
        }

        public override IMemoryOwner<byte> GetSetup()
        {
            var setup = Arrays.Rent(SetupLength);
            LittleEndianWriter.WriteUInt16(setup, 0, TransactionDataSize);
            return setup;
        }

        public override IMemoryOwner<byte> GetData()
        {
            return Data;
        }

        public override NTTransactSubcommandName SubcommandName => NTTransactSubcommandName.NT_TRANSACT_IOCTL;

        public override void Dispose()
        {
            base.Dispose();
            Data?.Dispose();
            Data = null;
        }
    }
}
