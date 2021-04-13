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
    /// SMB_COM_RENAME Request
    /// </summary>
    public class RenameRequest : SMB1Command
    {
        public const int SupportedBufferFormat = 0x04;
        public const int ParametersLength = 2;
        // Parameters:
        public SMBFileAttributes SearchAttributes;
        // Data:
        public byte BufferFormat1;
        public string OldFileName; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
        public byte BufferFormat2;
        public string NewFileName; // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)

        public override SMB1Command Init()
        {
            base.Init();
            
            OldFileName = default;
            NewFileName = default;
            BufferFormat1 = SupportedBufferFormat;
            BufferFormat2 = SupportedBufferFormat;

            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            SearchAttributes = (SMBFileAttributes)LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);

            var dataOffset = 0;
            BufferFormat1 = ByteReader.ReadByte(SmbData.Memory.Span, ref dataOffset);
            if (BufferFormat1 != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }
            
            OldFileName = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);
            BufferFormat2 = ByteReader.ReadByte(SmbData.Memory.Span, ref dataOffset);
            if (BufferFormat2 != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }
            if (isUnicode)
            {
                dataOffset++;
            }
            NewFileName = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, (ushort)SearchAttributes);

            if (isUnicode)
            {
                var padding = 1;
                SmbData = Arrays.Rent(2 + OldFileName.Length * 2 + NewFileName.Length * 2 + 4 + padding);
            }
            else
            {
                SmbData = Arrays.Rent(2 + OldFileName.Length + NewFileName.Length + 2);
            }
            var dataOffset = 0;
            BufferWriter.WriteByte(SmbData.Memory.Span, ref dataOffset, BufferFormat1);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode, OldFileName);
            BufferWriter.WriteByte(SmbData.Memory.Span, ref dataOffset, BufferFormat2);
            if (isUnicode)
            {
                dataOffset++; // padding
            }
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode, NewFileName);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_RENAME;
    }
}
