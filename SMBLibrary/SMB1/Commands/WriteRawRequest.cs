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
    /// SMB_COM_WRITE_RAW Request
    /// </summary>
    public class WriteRawRequest : SMB1Command
    {
        public const int ParametersFixedLength = 24; // + 4 optional bytes
        // Parameters:
        public ushort FID;
        public ushort CountOfBytes;
        public ushort Reserved1;
        public uint Offset;
        public uint Timeout;
        public WriteMode WriteMode;
        public uint Reserved2;
        //ushort DataLength;
        //ushort DataOffset;
        public uint OffsetHigh; // Optional
        // Data:
        public byte[] Data;

        public override SMB1Command Init()
        {
            base.Init();
            FID = default;
            CountOfBytes = default;
            Reserved1 = default;
            Offset = default;
            Timeout = default;
            WriteMode = default;
            Reserved2 = default;
            OffsetHigh = default; 
            Data = Array.Empty<byte>();

            return this;
        }

        public virtual SMB1Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            FID = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            CountOfBytes = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 2);
            Reserved1 = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);
            Offset = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 6);
            Timeout = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 10);
            WriteMode = (WriteMode)LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 14);
            Reserved2 = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 16);
            var dataLength = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 20);
            var dataOffset = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 22);
            if (SmbParameters.Length() == ParametersFixedLength + 4)
            {
                OffsetHigh = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 24);
            }

            Data = ByteReader.ReadBytes_RentArray(buffer, dataOffset, dataLength);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            throw new NotImplementedException();
        }

        public override CommandName CommandName => CommandName.SMB_COM_WRITE_RAW;
    }
}
