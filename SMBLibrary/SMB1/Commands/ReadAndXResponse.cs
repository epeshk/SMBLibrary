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
    /// SMB_COM_READ_ANDX Response
    /// SMB 1.0: The 2 reserved bytes at offset 14 become DataLengthHigh (used when the CAP_LARGE_READX capability has been negotiated)
    /// </summary>
    public class ReadAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 24;
        // Parameters:
        public ushort Available;
        public ushort DataCompactionMode; // Not used and MUST be 0x0000
        public ushort Reserved1;
        public static byte[] Reserved2; // 8 bytes
        // Data:
        public IMemoryOwner<byte> Data;

        public override SMB1Command Init()
        {
            Available = default;
            DataCompactionMode = default;
            Reserved1 = default;
            Reserved2 = new byte[8];

            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            
            Available = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);
            DataCompactionMode = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 6);
            Reserved1 = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 8);
            uint dataLength = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 10);
            var dataOffset = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 12);
            var dataLengthHigh = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 14);
            Reserved2 = ByteReader.ReadBytes_RentArray(buffer, 16, 8);

            dataLength |= (uint)(dataLengthHigh << 16);

            Data = Arrays.Rent<byte>((int) dataLength);
            ByteReader.ReadBytes(Data.Memory.Span, buffer, dataOffset, (int)dataLength);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            var DataLength = (uint)Data.Length();
            // WordCount + ByteCount are additional 3 bytes
            ushort DataOffset = SMB1Header.Length + 3 + ParametersLength;
            if (isUnicode)
            {
                DataOffset++;
            }
            var dataLengthHigh = (ushort)(DataLength >> 16);

            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, Available);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 6, DataCompactionMode);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 8, Reserved1);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 10, (ushort)(DataLength & 0xFFFF));
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 12, DataOffset);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 14, dataLengthHigh);
            BufferWriter.WriteBytes(SmbParameters.Memory.Span, 16, Reserved2);

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
            BufferWriter.WriteBytes(SmbData.Memory.Span, offset, Data.Memory.Span);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_READ_ANDX;

        public override void Dispose()
        {
            Data.Dispose();
            ExactArrayPool<byte>.Return(Reserved2);
            base.Dispose();
        }
    }
}
