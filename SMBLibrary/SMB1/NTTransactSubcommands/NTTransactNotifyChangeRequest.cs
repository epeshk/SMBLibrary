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
    /// NT_TRANSACT_NOTIFY_CHANGE Request
    /// </summary>
    public class NTTransactNotifyChangeRequest : NTTransactSubcommand
    {
        public const int SetupLength = 8;
        // Setup:
        public NotifyChangeFilter CompletionFilter;
        public ushort FID;
        public bool WatchTree;
        public byte Reserved;

        public NTTransactNotifyChangeRequest()
        {
        }

        public NTTransactNotifyChangeRequest(Span<byte> setup)
        {
            CompletionFilter = (NotifyChangeFilter)LittleEndianConverter.ToUInt32(setup, 0);
            FID = LittleEndianConverter.ToUInt16(setup, 4);
            WatchTree = (ByteReader.ReadByte(setup, 6) != 0);
            Reserved = ByteReader.ReadByte(setup, 7);
        }

        public override IMemoryOwner<byte> GetSetup()
        {
            var setup = Arrays.Rent(SetupLength);
            LittleEndianWriter.WriteUInt32(setup, 0, (uint)CompletionFilter);
            LittleEndianWriter.WriteUInt32(setup, 4, FID);
            BufferWriter.WriteByte(setup, 6, Convert.ToByte(WatchTree));
            BufferWriter.WriteByte(setup, 7, Reserved);
            return setup;
        }

        public override NTTransactSubcommandName SubcommandName => NTTransactSubcommandName.NT_TRANSACT_NOTIFY_CHANGE;
    }
}
