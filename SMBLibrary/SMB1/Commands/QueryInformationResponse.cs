/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// SMB_COM_QUERY_INFORMATION Response.
    /// This command is deprecated.
    /// This command is used by Windows NT4 SP6.
    /// </summary>
    public class QueryInformationResponse : SMB1Command
    {
        public const int ParameterLength = 20;
        // Parameters:
        public SMBFileAttributes FileAttributes;
        public DateTime? LastWriteTime;
        public uint FileSize;
        public byte[] Reserved; // 10 bytes

        public override SMB1Command Init()
        {
            FileAttributes = default;
            LastWriteTime = default;
            FileSize = default;
            Reserved = new byte[10];
            return this;
        }

        public QueryInformationResponse Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            FileAttributes = (SMBFileAttributes)LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            LastWriteTime = UTimeHelper.ReadNullableUTime(SmbParameters.Memory.Span, 2);
            FileSize = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 6);
            Reserved = ByteReader.ReadBytes_RentArray(SmbParameters.Memory.Span, 10, 10);
            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParameterLength);;
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, (ushort)FileAttributes);
            UTimeHelper.WriteUTime(SmbParameters.Memory.Span, 2, LastWriteTime);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 6, FileSize);
            BufferWriter.WriteBytes(SmbParameters.Memory.Span, 10, Reserved, 10);
            
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_QUERY_INFORMATION;
    }
}
