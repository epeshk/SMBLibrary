/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using Utilities;

namespace SMBLibrary.SMB1
{
    public abstract class SMBAndXCommand : SMB1Command
    {
        public CommandName AndXCommand;
        public byte AndXReserved;
        public ushort AndXOffset;

        public override SMB1Command Init()
        {
            base.Init();
            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            AndXCommand = (CommandName)ByteReader.ReadByte(SmbParameters.Memory.Span, 0);
            AndXReserved = ByteReader.ReadByte(SmbParameters.Memory.Span, 1);
            AndXOffset = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 2);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 0, (byte)AndXCommand);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 1, AndXReserved);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 2, AndXOffset);
            return base.GetBytes(isUnicode);
        }

        public static void WriteAndXOffset(Span<byte> buffer, int commandOffset, ushort andXOffset)
        {
            // 3 preceding bytes: WordCount, AndXCommand and AndXReserved
            LittleEndianWriter.WriteUInt16(buffer, commandOffset + 3, andXOffset);
        }
    }
}
