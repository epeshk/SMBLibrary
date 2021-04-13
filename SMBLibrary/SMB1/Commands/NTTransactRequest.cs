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
    /// SMB_COM_NT_TRANSACT Request
    /// </summary>
    public class NTTransactRequest : SMB1Command
    {
        public const int FixedSMBParametersLength = 38;
        // Parameters:
        public byte MaxSetupCount;
        public ushort Reserved1;
        public uint TotalParameterCount;
        public uint TotalDataCount;
        public uint MaxParameterCount;
        public uint MaxDataCount;
        //uint ParameterCount;
        //uint ParameterOffset;
        //uint DataCount;
        //uint DataOffset;
        //byte SetupCount; // In 2-byte words
        public NTTransactSubcommandName Function;
        public IMemoryOwner<byte> Setup;
        // Data:
        // Padding (alignment to 4 byte boundary)
        public IMemoryOwner<byte> TransParameters; // Trans_Parameters
        // Padding (alignment to 4 byte boundary)
        public IMemoryOwner<byte> TransData; // Trans_Data

        public override SMB1Command Init()
        {
            base.Init();
            return this;
        }

        public NTTransactRequest Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            var readOffset = 0;
            MaxSetupCount = ByteReader.ReadByte(SmbParameters.Memory.Span, ref readOffset);
            Reserved1 = LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref readOffset);
            TotalParameterCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            TotalDataCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            MaxParameterCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            MaxDataCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var parameterCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var parameterOffset = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var dataCount = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var dataOffset = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref readOffset);
            var setupCount = ByteReader.ReadByte(SmbParameters.Memory.Span, ref readOffset);
            Function = (NTTransactSubcommandName)LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref readOffset);
            Setup = Arrays.RentFrom<byte>(SmbParameters.Memory.Span.Slice(readOffset, setupCount * 2)); readOffset += setupCount * 2;

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
            BufferWriter.WriteByte(SmbParameters.Memory.Span, ref writeOffset, MaxSetupCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref writeOffset, Reserved1);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, TotalParameterCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, TotalDataCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, MaxParameterCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, MaxDataCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, parameterCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, parameterOffset);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, dataCount);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref writeOffset, dataOffset);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, ref writeOffset, setupCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref writeOffset, (ushort)Function);
            BufferWriter.WriteBytes(SmbParameters.Memory.Span, ref writeOffset, Setup.Memory.Span);

            SmbData = Arrays.Rent((int)(padding1 + parameterCount + padding2 + dataCount));
            BufferWriter.WriteBytes(SmbData.Memory.Span, padding1, TransParameters.Memory.Span);
            BufferWriter.WriteBytes(SmbData.Memory.Span, (int)(padding1 + parameterCount + padding2), TransData.Memory.Span);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_NT_TRANSACT;
    }
}
