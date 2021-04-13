/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.IO;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    public abstract class TransactionSubcommand : IDisposable
    {
        public virtual IMemoryOwner<byte> GetSetup()
        {
            return MemoryOwner<byte>.Empty;
        }

        public virtual IMemoryOwner<byte> GetParameters()
        {
            return MemoryOwner<byte>.Empty;
        }

        public virtual IMemoryOwner<byte> GetData(bool isUnicode)
        {
            return MemoryOwner<byte>.Empty;
        }

        public abstract TransactionSubcommandName SubcommandName
        {
            get;
        }

        public static TransactionSubcommand GetSubcommandRequest(IMemoryOwner<byte> setup, IMemoryOwner<byte> parameters, IMemoryOwner<byte> data, bool isUnicode)
        {
            if (setup.Length() == 4)
            {
                var subcommandName = (TransactionSubcommandName)LittleEndianConverter.ToUInt16(setup, 0);
                switch (subcommandName)
                {
                    case TransactionSubcommandName.TRANS_SET_NMPIPE_STATE:
                        return new TransactionSetNamedPipeStateRequest(setup.Memory.Span, parameters.Memory.Span);
                    case TransactionSubcommandName.TRANS_RAW_READ_NMPIPE:
                        return new TransactionRawReadNamedPipeRequest(setup.Memory.Span);
                    case TransactionSubcommandName.TRANS_QUERY_NMPIPE_STATE:
                        return new TransactionQueryNamedPipeStateRequest(setup.Memory.Span, parameters.Memory.Span);
                    case TransactionSubcommandName.TRANS_QUERY_NMPIPE_INFO:
                        return new TransactionQueryNamedPipeInfoRequest(setup.Memory.Span, parameters.Memory.Span);
                    case TransactionSubcommandName.TRANS_PEEK_NMPIPE:
                        return new TransactionPeekNamedPipeRequest(setup.Memory.Span);
                    case TransactionSubcommandName.TRANS_TRANSACT_NMPIPE:
                        return new TransactionTransactNamedPipeRequest(setup.Memory.Span, data);
                    case TransactionSubcommandName.TRANS_RAW_WRITE_NMPIPE:
                        return new TransactionRawWriteNamedPipeRequest(setup.Memory.Span, data);
                    case TransactionSubcommandName.TRANS_READ_NMPIPE:
                        return new TransactionReadNamedPipeRequest(setup.Memory.Span);
                    case TransactionSubcommandName.TRANS_WRITE_NMPIPE:
                        return new TransactionWriteNamedPipeRequest(setup.Memory.Span, data);
                    case TransactionSubcommandName.TRANS_WAIT_NMPIPE:
                        return new TransactionWaitNamedPipeRequest(setup.Memory.Span);
                    case TransactionSubcommandName.TRANS_CALL_NMPIPE:
                        return new TransactionCallNamedPipeRequest(setup.Memory.Span, data);
                }
            }
            throw new InvalidDataException();
        }

        public virtual void Dispose()
        {
        }
    }
}
