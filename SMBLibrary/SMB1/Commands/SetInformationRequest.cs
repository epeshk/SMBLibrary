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
    /// SMB_COM_SET_INFORMATION Request
    /// </summary>
    public class SetInformationRequest : SMB1Command
    {
        public const int ParametersLength = 16;
        public const int SupportedBufferFormat = 0x04;
        // Parameters:
        public SMBFileAttributes FileAttributes;
        public DateTime? LastWriteTime;
        public IMemoryOwner<byte> Reserved; // 10 bytes
        // Data:
        public byte BufferFormat;
        public string FileName; // SMB_STRING

        public SetInformationRequest()
        {
            FileAttributes = default;
            LastWriteTime = default;
            Reserved = default; 
            BufferFormat = default;
            FileName = default;
        
            Reserved = Arrays.Rent(10);
            BufferFormat = SupportedBufferFormat;
        }

        public SetInformationRequest Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            FileAttributes = (SMBFileAttributes)LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            LastWriteTime = UTimeHelper.ReadNullableUTime(SmbParameters.Memory.Span, 2);
            Reserved = ByteReader.ReadBytes_Rent(SmbParameters.Memory.Span, 6, 10);

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
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, (ushort)FileAttributes);
            UTimeHelper.WriteUTime(SmbParameters.Memory.Span, 2, LastWriteTime);
            BufferWriter.WriteBytes(SmbParameters.Memory.Span, 6, Reserved.Memory.Span, 10);

            var length = 1;
            if (isUnicode)
            {
                length += FileName.Length * 2 + 2;
            }
            else
            {
                length += FileName.Length + 1;
            }
            SmbData = Arrays.Rent(length);
            BufferWriter.WriteByte(SmbData.Memory.Span, 0, BufferFormat);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, 1, isUnicode, FileName);
            
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_SET_INFORMATION;

        public override void Dispose()
        {
            base.Dispose();
            Reserved?.Dispose();
            Reserved = null;
        }
    }
}
