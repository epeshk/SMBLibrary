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
    /// SMB_COM_TRANSACTION Request
    /// </summary>
    public class TransactionRequest : SMB1Command
    {
        public const int FixedSMBParametersLength = 28;
        // Parameters:
        public ushort TotalParameterCount;
        public ushort TotalDataCount;
        public ushort MaxParameterCount;
        public ushort MaxDataCount;
        public byte MaxSetupCount;
        public byte Reserved1;
        public TransactionFlags Flags;
        public uint Timeout;
        public ushort Reserved2;
        public byte Reserved3;
        public IMemoryOwner<byte> Setup;
        // Data:
        public string Name; // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
        public IMemoryOwner<byte> TransParameters; // Trans_Parameters
        public IMemoryOwner<byte> TransData; // Trans_Data

        public override SMB1Command Init()
        {
            TotalParameterCount = default;
            TotalDataCount = default;
            MaxParameterCount = default;
            MaxDataCount = default;
            MaxSetupCount = default;
            Reserved1 = default;
            Flags = default;
            Timeout = default;
            Reserved2 = default;
            Reserved3 = default;
            Setup = default;
            Name = string.Empty;
            
            TransParameters = MemoryOwner<byte>.Empty;
            TransData = MemoryOwner<byte>.Empty;

            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            
            TotalParameterCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            TotalDataCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 2);
            MaxParameterCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);
            MaxDataCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 6);
            MaxSetupCount = ByteReader.ReadByte(SmbParameters.Memory.Span, 8);
            Reserved1 = ByteReader.ReadByte(SmbParameters.Memory.Span, 9);
            Flags = (TransactionFlags)LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 10);
            Timeout = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 12);
            Reserved2 = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 16);
            var transParameterCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 18);
            var transParameterOffset = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 20);
            var transDataCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 22);
            var transDataOffset = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 24);
            var setupCount = ByteReader.ReadByte(SmbParameters.Memory.Span, 26);
            Reserved3 = ByteReader.ReadByte(SmbParameters.Memory.Span, 27);
            Setup = Arrays.RentFrom<byte>(SmbParameters.Memory.Span.Slice(28, setupCount * 2));

            if (SmbData.Length() > 0) // Workaround, Some SAMBA clients will set ByteCount to 0 (Popcorn Hour A-400)
            {
                var dataOffset = 0;
                if (this is Transaction2Request)
                {
                    Name = String.Empty;
                    var nameLength = 1;
                    dataOffset += nameLength;
                }
                else
                {
                    if (isUnicode)
                    {
                        var namePadding = 1;
                        dataOffset += namePadding;
                    }
                    Name = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);
                }
            }
            TransParameters = Arrays.RentFrom<byte>(buffer.Slice(transParameterOffset, transParameterCount));
            TransData = Arrays.RentFrom<byte>(buffer.Slice(transDataOffset, transDataCount));

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            if (Setup.Length() % 2 > 0)
            {
                throw new Exception("Setup length must be a multiple of 2");
            }

            var setupCount = (byte)(Setup.Length() / 2);
            var transParameterCount = (ushort)TransParameters.Length();
            var transDataCount = (ushort)TransData.Length();

            // WordCount + ByteCount are additional 3 bytes
            int nameLength;
            int namePadding;
            if (this is Transaction2Request)
            {
                namePadding = 0;
                nameLength = 1;
            }
            else
            {
                if (isUnicode)
                {
                    namePadding = 1;
                    nameLength = Name.Length * 2 + 2;
                }
                else
                {
                    namePadding = 0;
                    nameLength = Name.Length + 1;
                }
            }
            var transParameterOffset = (ushort)(SMB1Header.Length + 3 + (FixedSMBParametersLength + Setup.Length() + namePadding + nameLength));
            var padding1 = (4 - (transParameterOffset % 4)) % 4;
            transParameterOffset += (ushort)padding1;
            var transDataOffset = (ushort)(transParameterOffset + transParameterCount);
            var padding2 = (4 - (transDataOffset % 4)) % 4;
            transDataOffset += (ushort)padding2;

            SmbParameters = Arrays.Rent(FixedSMBParametersLength + Setup.Length());
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, TotalParameterCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 2, TotalDataCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, MaxParameterCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 6, MaxDataCount);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 8, MaxSetupCount);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 9, Reserved1);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 10, (ushort)Flags);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 12, Timeout);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 16, Reserved2);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 18, transParameterCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 20, transParameterOffset);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 22, transDataCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 24, transDataOffset);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 26, setupCount);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 27, Reserved3);
            BufferWriter.WriteBytes(SmbParameters.Memory.Span, 28, Setup.Memory.Span);

            int offset;
            SmbData = Arrays.Rent(namePadding + nameLength + padding1 + transParameterCount + padding2 + transDataCount);
            offset = namePadding;
            if (this is Transaction2Request)
            {
                 offset += nameLength;
            }
            else
            {
                SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, isUnicode, Name);
            }
            BufferWriter.WriteBytes(SmbData.Memory.Span, offset + padding1, TransParameters.Memory.Span);
            BufferWriter.WriteBytes(SmbData.Memory.Span, offset + padding1 + transParameterCount + padding2, TransData.Memory.Span);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_TRANSACTION;

        public override void Dispose()
        {
            base.Dispose();
            Setup.Dispose();
            TransData.Dispose();
            TransParameters.Dispose();
            Setup = TransData = TransParameters = null;
        }
    }
}
