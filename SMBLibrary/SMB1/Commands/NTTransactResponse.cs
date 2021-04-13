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
    /// SMB_COM_NT_TRANSACT Response
    /// </summary>
    public class NTTransactResponse : SMB1Command
    {
        public const int FixedSMBParametersLength = 36;
        // Parameters:
        public IMemoryOwner<byte> Reserved1; // 3 bytes
        public uint TotalParameterCount;
        public uint TotalDataCount;
        public uint ParameterDisplacement;
        public uint DataDisplacement;
        public IMemoryOwner<byte> Setup;
        // Data:
        public IMemoryOwner<byte> TransParameters; // Trans_Parameters
        public IMemoryOwner<byte> TransData; // Trans_Data

        public override SMB1Command Init()
        {
            base.Init();
            TotalParameterCount = default;
            TotalDataCount = default;
            ParameterDisplacement = default;
            DataDisplacement = default;
            Setup = MemoryOwner<byte>.Empty;
            TransParameters = MemoryOwner<byte>.Empty; // Trans_Parameters
            TransData = MemoryOwner<byte>.Empty; // Trans_Data
            Reserved1 = Arrays.Rent(3);
            return this;
        }

        public NTTransactResponse Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            var readOffset = 0;
            Reserved1 = Arrays.RentFrom<byte>(SmbParameters.Memory.Span.Slice(readOffset, 3)); readOffset += 3;
            TotalParameterCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            TotalDataCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var parameterCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var parameterOffset = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            ParameterDisplacement = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var dataCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var dataOffset = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            DataDisplacement = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var setupCount = ByteReader.ReadByte(SmbParameters.Memory.Span, ref readOffset);
            Setup = Arrays.RentFrom<byte>(SmbParameters.Memory.Span.Slice(offset, setupCount * 2)); offset += setupCount * 2;

            TransParameters = Arrays.RentFrom<byte>(buffer.Slice((int)parameterOffset, (int)parameterCount));
            TransData = Arrays.RentFrom<byte>(buffer.Slice((int)dataOffset, (int)dataCount));

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            var setupCount = (byte)(Setup.Length() / 2);
            uint parameterCount = (ushort)TransParameters.Length();
            uint dataCount = (ushort)TransData.Length();

            // WordCount + ByteCount are additional 3 bytes
            uint parameterOffset = (ushort)(SMB1Header.Length + 3 + (FixedSMBParametersLength + Setup.Length()));
            var padding1 = (int)(4 - (parameterOffset % 4)) % 4;
            parameterOffset += (ushort)padding1;
            uint dataOffset = (ushort)(parameterOffset + parameterCount);
            var padding2 = (int)(4 - (dataOffset % 4)) % 4;
            dataOffset += (ushort)padding2;

            SmbParameters = Arrays.Rent(FixedSMBParametersLength + Setup.Length());
            var writeOffset = 0;
            BufferWriter.WriteBytes(SmbParameters.Memory.Span, ref writeOffset, Reserved1.Memory.Span, 3);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, TotalParameterCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, TotalDataCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, parameterCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, parameterOffset);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, ParameterDisplacement);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, dataCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, dataOffset);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, DataDisplacement);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, ref writeOffset, setupCount);
            BufferWriter.WriteBytes(SmbParameters.Memory.Span, ref writeOffset, Setup.Memory.Span);

            SmbData = Arrays.Rent((int) (parameterCount + dataCount + padding1 + padding2));
            BufferWriter.WriteBytes(SmbData.Memory.Span, padding1, TransParameters.Memory.Span);
            BufferWriter.WriteBytes(SmbData.Memory.Span, (int)(padding1 + parameterCount + padding2), TransData.Memory.Span);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_NT_TRANSACT;

        public static int CalculateMessageSize(int setupLength, int trans2ParametersLength, int trans2DataLength)
        {
            var parameterOffset = SMB1Header.Length + 3 + (FixedSMBParametersLength + setupLength);
            var padding1 = (4 - (parameterOffset % 4)) % 4;
            parameterOffset += padding1;
            var dataOffset = (parameterOffset + trans2ParametersLength);
            var padding2 = (4 - (dataOffset % 4)) % 4;

            var messageParametersLength = FixedSMBParametersLength + setupLength;
            var messageDataLength = trans2ParametersLength + trans2DataLength + padding1 + padding2;
            // WordCount + ByteCount are additional 3 bytes
            return SMB1Header.Length + messageParametersLength + messageDataLength + 3;
        }

        public override void Dispose()
        {
            base.Dispose();
            Reserved1.Dispose();
            TransData.Dispose();
            TransParameters.Dispose();
            Reserved1 = TransData = TransParameters = null;
        }
    }
}
