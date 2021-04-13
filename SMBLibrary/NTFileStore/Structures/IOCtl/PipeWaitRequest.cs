/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.3.31 - FSCTL_PIPE_WAIT Request
    /// </summary>
    public class PipeWaitRequest
    {
        public const int FixedLength = 14;

        public ulong Timeout;
        private uint NameLength;
        public bool TimeSpecified;
        public byte Padding;
        public IMemoryOwner<char> Name = MemoryOwner<char>.Empty;

        public PipeWaitRequest()
        {
        }

        public PipeWaitRequest(Span<byte> buffer, int offset)
        {
            Timeout = LittleEndianConverter.ToUInt64(buffer, offset + 0);
            NameLength = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            TimeSpecified = Convert.ToBoolean(ByteReader.ReadByte(buffer, offset + 12));
            Padding = ByteReader.ReadByte(buffer, offset + 13);
            Name = Arrays.Rent<char>((int) (NameLength / 2)); 
            
            ByteReader.ReadUTF16String(Name.Memory.Span, buffer, offset + 14, (int)(NameLength / 2)); 
        }

        public IMemoryOwner<byte> GetBytes()
        {
            var buffer = Arrays.Rent<byte>(Length);
            LittleEndianWriter.WriteUInt64(buffer, 0, Timeout);
            LittleEndianWriter.WriteUInt32(buffer, 8, (uint)(Name.Memory.Length * 2));
            BufferWriter.WriteByte(buffer, 12, Convert.ToByte(TimeSpecified));
            BufferWriter.WriteByte(buffer, 13, Padding);
            BufferWriter.WriteUTF16String(buffer, 14, Name.Memory.Span);
            return buffer;
        }

        public int Length => FixedLength + Name.Memory.Length * 2;
    }
}
