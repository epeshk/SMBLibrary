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
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_READ Response
    /// </summary>
    public class ReadResponse : SMB1Command
    {
        public const int ParametersLength = 10;
        public const int SupportedBufferFormat = 0x01;
        // Parameters:
        public ushort CountOfBytesReturned;
        public IMemoryOwner<byte> Reserved; // 8 reserved bytes
        // Data:
        public byte BufferFormat;
        public IMemoryOwner<byte> Bytes;

        public ReadResponse()
        {
            CountOfBytesReturned = default;
            Reserved = default; 
            BufferFormat = default;
            Reserved = Arrays.Rent(8);
        }

        public ReadResponse Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            
            CountOfBytesReturned = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            Reserved = ByteReader.ReadBytes_Rent(SmbParameters.Memory.Span, 2, 8);

            BufferFormat = ByteReader.ReadByte(SmbData.Memory.Span, 0);
            if (BufferFormat != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }
            var countOfBytesRead = LittleEndianConverter.ToUInt16(SmbData.Memory.Span, 1);
            Bytes = ByteReader.ReadBytes_Rent(SmbData.Memory.Span, 3, countOfBytesRead);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, CountOfBytesReturned);
            BufferWriter.WriteBytes(SmbParameters.Memory.Span, 2, Reserved.Memory.Span, 8);

            SmbData = Arrays.Rent(3 + Bytes.Length());
            BufferWriter.WriteByte(SmbData.Memory.Span, 0, BufferFormat);
            LittleEndianWriter.WriteUInt16(SmbData.Memory.Span, 1, (ushort)Bytes.Length());
            BufferWriter.WriteBytes(SmbData.Memory.Span, 3, Bytes.Memory.Span);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_READ;

        public override void Dispose()
        {
            base.Dispose();
            Bytes?.Dispose(); Bytes = null;
            Reserved?.Dispose(); Reserved = null;
        }
    }
}
