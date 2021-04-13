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
    /// SMB_COM_NT_TRANSACT_SECONDARY Request
    /// </summary>
    public class NTTransactSecondaryRequest : SMB1Command
    {
        public const int SMBParametersLength = 36;
        // Parameters:
        public byte[] Reserved1; // 3 bytes
        public uint TotalParameterCount;
        public uint TotalDataCount;
        public uint ParameterDisplacement;
        public uint DataDisplacement;
        public byte Reserved2;
        // Data:
        public byte[] TransParameters; // Trans_Parameters
        public byte[] TransData; // Trans_Data

        public override SMB1Command Init()
        {
            base.Init();
            
            TotalParameterCount = default;
            TotalDataCount = default;
            ParameterDisplacement = default;
            DataDisplacement = default;
            Reserved2 = default;
            TransParameters = default; 
            TransData = default;
            Reserved1 = new byte[3];
            
            return this;
        }

        public NTTransactSecondaryRequest Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            
            var readOffset = 0;
            Reserved1 = ByteReader.ReadBytes_RentArray(SmbParameters.Memory.Span, ref readOffset, 3);
            TotalParameterCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            TotalDataCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var parameterCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var parameterOffset = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            ParameterDisplacement = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var dataCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var dataOffset = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            DataDisplacement = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            Reserved2 = ByteReader.ReadByte(SmbParameters.Memory.Span, ref readOffset);

            TransParameters = ByteReader.ReadBytes_RentArray(buffer, (int)parameterOffset, (int)parameterCount);
            TransData = ByteReader.ReadBytes_RentArray(buffer, (int)dataOffset, (int)dataCount);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            uint parameterCount = (ushort)TransParameters.Length;
            uint dataCount = (ushort)TransData.Length;

            // WordCount + ByteCount are additional 3 bytes
            uint parameterOffset = SMB1Header.Length + 3 + (SMBParametersLength);
            var padding1 = (int)(4 - (parameterOffset % 4)) % 4;
            parameterOffset += (ushort)padding1;
            uint dataOffset = (ushort)(parameterOffset + parameterCount);
            var padding2 = (int)(4 - (dataOffset % 4)) % 4;
            dataOffset += (ushort)padding2;

            SmbParameters = Arrays.Rent(SMBParametersLength);
            var writeOffset = 0;
            BufferWriter.WriteBytes(SmbParameters.Memory.Span, ref writeOffset, Reserved1, 3);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, TotalParameterCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, TotalDataCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, parameterCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, parameterOffset);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, ParameterDisplacement);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, dataCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, dataOffset);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, DataDisplacement);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, ref writeOffset, Reserved2);

            SmbData = Arrays.Rent((int) (parameterCount + dataCount + padding1 + padding2));
            BufferWriter.WriteBytes(SmbData.Memory.Span, padding1, TransParameters);
            BufferWriter.WriteBytes(SmbData.Memory.Span, (int)(padding1 + parameterCount + padding2), TransData);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_NT_TRANSACT_SECONDARY;
    }
}
