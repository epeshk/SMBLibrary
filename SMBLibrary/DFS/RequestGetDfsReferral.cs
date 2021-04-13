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

namespace SMBLibrary
{
    /// <summary>
    /// [MS-DFSC] REQ_GET_DFS_REFERRAL
    /// </summary>
    public class RequestGetDfsReferral
    {
        public ushort MaxReferralLevel;
        public string RequestFileName; // Unicode

        public RequestGetDfsReferral()
        {
        }

        public RequestGetDfsReferral(Span<byte> buffer)
        {
            MaxReferralLevel = LittleEndianConverter.ToUInt16(buffer, 0);
            RequestFileName = ByteReader.ReadNullTerminatedUTF16String(buffer, 2);
        }

        public IMemoryOwner<byte> GetBytes()
        {
            var length = 2 + RequestFileName.Length * 2 + 2;
            var buffer = Arrays.Rent(length);
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, 0, MaxReferralLevel);
            BufferWriter.WriteUTF16String(buffer.Memory.Span, 2, RequestFileName);
            return buffer;
        }
    }
}
