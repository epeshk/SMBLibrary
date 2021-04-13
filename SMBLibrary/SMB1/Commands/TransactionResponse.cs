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
    /// SMB_COM_TRANSACTION Response
    /// </summary>
    public class TransactionResponse : SMB1Command
    {
        public const int FixedSMBParametersLength = 20;
        
        // Parameters:
        public ushort TotalParameterCount;
        public ushort TotalDataCount;
        public ushort Reserved1;
        public ushort ParameterDisplacement;
        public ushort DataDisplacement;
        public byte Reserved2;
        public IMemoryOwner<byte> Setup;
        
        // Data:
        public IMemoryOwner<byte> TransParameters; // Trans_Parameters
        public IMemoryOwner<byte> TransData; // Trans_Data

        public TransactionResponse()
        {
            Init();
        }
        
        public override SMB1Command Init()
        {
            base.Init();
            TotalParameterCount = default;
            TotalDataCount = default;
            Reserved1 = default;
            ParameterDisplacement = default;
            DataDisplacement = default;
            Reserved2 = default;
            Setup = MemoryOwner<byte>.Empty;
            TransParameters = MemoryOwner<byte>.Empty;
            TransData = MemoryOwner<byte>.Empty;
            return this;
        }

        public virtual SMB1Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            
            TotalParameterCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            TotalDataCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 2);
            Reserved1 = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);
            var parameterCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 6);
            var parameterOffset = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 8);
            ParameterDisplacement = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 10);
            var dataCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 12);
            var dataOffset = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 14);
            DataDisplacement = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 16);
            var setupCount = ByteReader.ReadByte(SmbParameters.Memory.Span, 18);
            Reserved2 = ByteReader.ReadByte(SmbParameters.Memory.Span, 19);
            Setup = Arrays.Rent(setupCount * 2);
            TransParameters = Arrays.Rent(parameterCount);
            TransData = Arrays.Rent(dataCount);

            ByteReader.ReadBytes(Setup.Memory.Span, SmbParameters.Memory.Span, 20, setupCount * 2);
            ByteReader.ReadBytes(TransParameters.Memory.Span, buffer, parameterOffset, parameterCount);
            ByteReader.ReadBytes(TransData.Memory.Span, buffer, dataOffset, dataCount);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            if (TransData.Memory.Length > ushort.MaxValue)
            {
                throw new ArgumentException("Invalid Trans_Data length");
            }
            
            var setupCount = (byte)(Setup.Memory.Length / 2);
            var parameterCount = (ushort)TransParameters.Memory.Length;
            var dataCount = (ushort)TransData.Memory.Length;

            // WordCount + ByteCount are additional 3 bytes
            var parameterOffset = (ushort)(SMB1Header.Length + 3 + (FixedSMBParametersLength + Setup.Memory.Length));
            var padding1 = (4 - (parameterOffset %4)) % 4;
            parameterOffset += (ushort)padding1;
            var dataOffset = (ushort)(parameterOffset + parameterCount);
            var padding2 = (4 - (dataOffset % 4)) % 4;
            dataOffset += (ushort)padding2;

            SmbParameters = Arrays.Rent(FixedSMBParametersLength + Setup.Memory.Length);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, TotalParameterCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 2, TotalDataCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, Reserved1);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 6, parameterCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 8, parameterOffset);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 10, ParameterDisplacement);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 12, dataCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 14, dataOffset);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 16, DataDisplacement);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 18, setupCount);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 19, Reserved2);
            BufferWriter.WriteBytes(SmbParameters.Memory.Span.Slice(20), Setup.Memory.Span);

            SmbData = Arrays.Rent(parameterCount + dataCount + padding1 + padding2);
            BufferWriter.WriteBytes(SmbData.Memory.Span, padding1, TransParameters.Memory.Span);
            BufferWriter.WriteBytes(SmbData.Memory.Span.Slice(padding1 + parameterCount + padding2), TransData.Memory.Span);
            
            var res = base.GetBytes(isUnicode);
            
            Setup.Dispose();
            TransData.Dispose();
            
            return res;
        }

        public override CommandName CommandName => CommandName.SMB_COM_TRANSACTION;

        public static int CalculateMessageSize(int setupLength, int trans2ParametersLength, int trans2DataLength)
        {
            var parameterOffset = SMB1Header.Length + 3 + (FixedSMBParametersLength + setupLength);
            var padding1 = (4 - (parameterOffset %4)) % 4;
            parameterOffset += padding1;
            var dataOffset = (parameterOffset + trans2ParametersLength);
            var padding2 = (4 - (dataOffset % 4)) % 4;

            var messageParametersLength = FixedSMBParametersLength + setupLength;
            var messageDataLength = trans2ParametersLength + trans2DataLength + padding1 + padding2;
            // WordCount + ByteCount are additional 3 bytes
            return SMB1Header.Length + messageParametersLength + messageDataLength + 3;
        }
    }
}
