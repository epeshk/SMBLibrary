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
    /// SMB_COM_WRITE_ANDX Request
    /// SMB 1.0: The 2 reserved bytes at offset 18 become DataLengthHigh (used when the CAP_LARGE_WRITEX capability has been negotiated)
    /// </summary>
    public class WriteAndXRequest : SMBAndXCommand
    {
        public const int ParametersFixedLength = 24;
        // Parameters:
        public ushort FID;
        public ulong Offset; // 4 bytes + 4 optional 'OffsetHigh' bytes
        public uint Timeout;
        public WriteMode WriteMode;
        public ushort Remaining;
        // Data:
        // Optional 1 byte padding
        public IMemoryOwner<byte> Data;

        public override SMB1Command Init()
        {
            base.Init();
            FID = default;
            Offset = default;
            Timeout = default;
            WriteMode = default;
            Remaining = default;
            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            FID = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);
            Offset = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 6);
            Timeout = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 10);
            WriteMode = (WriteMode)LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 14);
            Remaining = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 16);
            var dataLengthHigh = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 18);
            uint DataLength = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 20);
            var DataOffset = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 22);
            if (SmbParameters.Length() == ParametersFixedLength + 4)
            {
                var offsetHigh = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 24);
                Offset |= ((ulong)offsetHigh << 32);
            }

            DataLength |= (uint)(dataLengthHigh << 16);

            Data = Arrays.RentFrom<byte>(buffer.Slice(DataOffset, (int)DataLength));

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            var DataLength = (uint)Data.Length();
            // WordCount + ByteCount are additional 3 bytes
            ushort DataOffset = SMB1Header.Length + 3 + ParametersFixedLength;
            if (isUnicode)
            {
                DataOffset++;
            }
            var dataLengthHigh = (ushort)(DataLength >> 16);
            
            var parametersLength = ParametersFixedLength;
            if (Offset > UInt32.MaxValue)
            {
                parametersLength += 4;
                DataOffset += 4;
            }

            SmbParameters = Arrays.Rent(parametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, FID);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 6, (uint)(Offset & 0xFFFFFFFF));
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 10, Timeout);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 14, (ushort)WriteMode);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 16, Remaining);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 18, dataLengthHigh);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 20, (ushort)(DataLength & 0xFFFF));
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 22, DataOffset);
            if (Offset > UInt32.MaxValue)
            {
                var offsetHigh = (uint)(Offset >> 32);
                LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 24, offsetHigh);
            }

            var smbDataLength = Data.Length();
            if (isUnicode)
            {
                smbDataLength++;
            }
            SmbData = Arrays.Rent(smbDataLength);
            var offset = 0;
            if (isUnicode)
            {
                offset++;
            }
            BufferWriter.WriteBytes(SmbData.Memory.Span, ref offset, Data.Memory.Span);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_WRITE_ANDX;

        public override void Dispose()
        {
            base.Dispose();
            Data.Dispose();
            Data = null;
        }
    }
}
