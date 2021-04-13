/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using MemoryPools.Memory;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS_READ_NMPIPE Request
    /// </summary>
    public class TransactionReadNamedPipeResponse : TransactionSubcommand
    {
        public const int ParametersLength = 0;
        // Data:
        public IMemoryOwner<byte> ReadData;

        public TransactionReadNamedPipeResponse()
        {
        }

        public TransactionReadNamedPipeResponse(IMemoryOwner<byte> data)
        {
            ReadData = data.AddOwner();
        }

        public override IMemoryOwner<byte> GetData(bool isUnicode)
        {
            return ReadData.AddOwner();
        }

        public override TransactionSubcommandName SubcommandName => TransactionSubcommandName.TRANS_READ_NMPIPE;
        
        public override void Dispose()
        {
            base.Dispose();
            ReadData.Dispose();
        }
    }
}
