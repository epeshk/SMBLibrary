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
    /// SMB_COM_WRITE Request.
    /// This command is obsolete.
    /// Windows NT4 SP6 will send this command with empty data for some reason.
    /// </summary>
    public class WriteRequest : SMB1Command
    {
        public const int ParametersLength = 8;
        public const int SupportedBufferFormat = 0x01;
        // Parameters:
        public ushort FID;
        public ushort CountOfBytesToWrite;
        public ushort WriteOffsetInBytes;
        public ushort EstimateOfRemainingBytesToBeWritten;
        // Data:
        public byte BufferFormat;
        // ushort DataLength;
        public IMemoryOwner<byte> Data;

        public WriteRequest()
        {
            FID = default;
            CountOfBytesToWrite = default;
            WriteOffsetInBytes = default;
            EstimateOfRemainingBytesToBeWritten = default;
            BufferFormat = SupportedBufferFormat;
            Data = MemoryOwner<byte>.Empty;
        }

        public WriteRequest Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            FID = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            CountOfBytesToWrite = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 2);
            WriteOffsetInBytes = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);
            EstimateOfRemainingBytesToBeWritten = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 6);

            BufferFormat = ByteReader.ReadByte(SmbData.Memory.Span, 0);
            if (BufferFormat != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }
            var dataLength = LittleEndianConverter.ToUInt16(SmbData.Memory.Span, 1);
            Data = Arrays.RentFrom<byte>(SmbData.Memory.Span.Slice(3, dataLength));

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            if (Data.Length() > UInt16.MaxValue)
            {
                throw new ArgumentException("Invalid Data length");
            }
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, FID);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 2, CountOfBytesToWrite);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, WriteOffsetInBytes);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 6, EstimateOfRemainingBytesToBeWritten);

            SmbData = Arrays.Rent(3 + Data.Length());
            BufferWriter.WriteByte(SmbData.Memory.Span, 0, BufferFormat);
            LittleEndianWriter.WriteUInt16(SmbData.Memory.Span, 1, (ushort)Data.Length());
            BufferWriter.WriteBytes(SmbData.Memory.Span, 3, Data.Memory.Span);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_WRITE;

        public override void Dispose()
        {
            base.Dispose();
            Data?.Dispose();
            Data = null;
        }
    }
}
