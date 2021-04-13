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
    /// SMB_COM_READ_ANDX Request
    /// SMB 1.0: The Timeout field becomes Timeout_or_MaxCountHigh (used when the CAP_LARGE_READX capability has been negotiated)
    /// </summary>
    public class ReadAndXRequest : SMBAndXCommand
    {
        public const int ParametersFixedLength = 20;
        // Parameters:
        //CommandName AndXCommand;
        //byte AndXReserved;
        //ushort AndXOffset;
        public ushort FID;
        public ulong Offset; // 4 bytes + 4 optional 'OffsetHigh' bytes
        private ushort MaxCountOfBytesToReturn; // See 'Timeout_or_MaxCountHigh' comment
        public ushort MinCountOfBytesToReturn;
        /// <summary>
        /// SMB 1.0: When reading from a regular file, the field MUST be interpreted as
        /// MaxCountHigh and the two unused bytes MUST be zero.
        /// When reading from a name pipe or I/O device, the field MUST be interpreted as Timeout.
        /// </summary>
        public uint Timeout_or_MaxCountHigh; // CIFS: Timeout only
        public ushort Remaining;

        public override SMB1Command Init()
        {
            base.Init();
            FID = default;
            Offset = default;
            MaxCountOfBytesToReturn = MinCountOfBytesToReturn = default;
            Timeout_or_MaxCountHigh = default;
            Remaining = default;

            return this;
        }

        public ReadAndXRequest Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            FID = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);
            Offset = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 6);
            MaxCountOfBytesToReturn = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 10);
            MinCountOfBytesToReturn = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 12);
            Timeout_or_MaxCountHigh = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 14);
            Remaining = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 18);
            if (SmbParameters.Length() == ParametersFixedLength + 4)
            {
                var offsetHigh = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 20);
                Offset |= ((ulong)offsetHigh << 32);
            }

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            var parametersLength = ParametersFixedLength;
            if (Offset > UInt32.MaxValue)
            {
                parametersLength += 4;
            }

            SmbParameters = Arrays.Rent(parametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, FID);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 6, (uint)(Offset & 0xFFFFFFFF));
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 10, (ushort)(MaxCountOfBytesToReturn & 0xFFFF));
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 12, MinCountOfBytesToReturn);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 14, Timeout_or_MaxCountHigh);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 18, Remaining);
            if (Offset > UInt32.MaxValue)
            {
                var offsetHigh = (uint)(Offset >> 32);
                LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 20, offsetHigh);
            }

            return base.GetBytes(isUnicode);
        }

        /// <summary>
        /// The number of bytes to return when reading from a file and LargeRead is negotiated
        /// </summary>
        public uint MaxCountLarge
        {
            get
            {
                var maxCountHigh = (ushort)(Timeout_or_MaxCountHigh & 0xFFFF);
                return (uint)(maxCountHigh << 16) | MaxCountOfBytesToReturn;
            }
            set
            {
                MaxCountOfBytesToReturn = (ushort)(value & 0xFFFF);
                Timeout_or_MaxCountHigh = (ushort)(value >> 16);
            }
        }

        /// <summary>
        /// The number of bytes to return when reading from a named pipe or LargeRead is not negotiated
        /// </summary>
        public ushort MaxCount
        {
            get => MaxCountOfBytesToReturn;
            set => MaxCountOfBytesToReturn = value;
        }

        public override CommandName CommandName => CommandName.SMB_COM_READ_ANDX;
    }
}
