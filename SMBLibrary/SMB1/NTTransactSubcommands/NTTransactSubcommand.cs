/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.IO;
using MemoryPools.Memory;

namespace SMBLibrary.SMB1
{
    public abstract class NTTransactSubcommand : IDisposable
    {
        public virtual IMemoryOwner<byte> GetSetup()
        {
            return MemoryOwner<byte>.Empty;
        }

        public virtual IMemoryOwner<byte> GetParameters(bool isUnicode)
        {
            return MemoryOwner<byte>.Empty;
        }

        public virtual IMemoryOwner<byte> GetData()
        {
            return MemoryOwner<byte>.Empty;
        }

        public abstract NTTransactSubcommandName SubcommandName
        {
            get;
        }

        public static NTTransactSubcommand GetSubcommandRequest(NTTransactSubcommandName subcommandName, IMemoryOwner<byte> setup, IMemoryOwner<byte> parameters, IMemoryOwner<byte> data, bool isUnicode)
        {
            switch (subcommandName)
            {
                case NTTransactSubcommandName.NT_TRANSACT_CREATE:
                    return new NTTransactCreateRequest(parameters, data, isUnicode);
                case NTTransactSubcommandName.NT_TRANSACT_IOCTL:
                    return new NTTransactIOCTLRequest(setup, data);
                case NTTransactSubcommandName.NT_TRANSACT_SET_SECURITY_DESC:
                    return new NTTransactSetSecurityDescriptorRequest(parameters.Memory.Span, data.Memory.Span);
                case NTTransactSubcommandName.NT_TRANSACT_NOTIFY_CHANGE:
                    return new NTTransactNotifyChangeRequest(setup.Memory.Span);
                case NTTransactSubcommandName.NT_TRANSACT_QUERY_SECURITY_DESC:
                    return new NTTransactQuerySecurityDescriptorRequest(parameters.Memory.Span);
            }
            throw new InvalidDataException();
        }

        public virtual void Dispose()
        {
            
        }
    }
}
