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
    /// SMB_COM_QUERY_INFORMATION Request.
    /// This command is deprecated.
    /// This command is used by Windows NT4 SP6.
    /// </summary>
    public class QueryInformationRequest : SMB1Command
    {
        public const byte SupportedBufferFormat = 0x04;
        // Data:
        public byte BufferFormat;
        public string FileName; // SMB_STRING

        public override SMB1Command Init()
        {
            base.Init();
            
            BufferFormat = SupportedBufferFormat;
            FileName = string.Empty;

            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            
            BufferFormat = ByteReader.ReadByte(SmbData.Memory.Span, 0);
            if (BufferFormat != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }
            FileName = SMB1Helper.ReadSMBString(SmbData.Memory.Span, 1, isUnicode);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            var length = 1;
            if (isUnicode)
            {
                length += FileName.Length * 2 + 2;
            }
            else
            {
                length += FileName.Length + 1;
            }
            SmbData = Arrays.Rent(1 + length);
            BufferWriter.WriteByte(SmbData.Memory.Span, 0, BufferFormat);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, 1, isUnicode, FileName);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_QUERY_INFORMATION;
    }
}
