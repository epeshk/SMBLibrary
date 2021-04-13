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
    /// SMB_COM_OPEN_ANDX Request
    /// </summary>
    public class OpenAndXRequest : SMBAndXCommand
    {
        public const int ParametersLength = 30;
        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
        public OpenFlags Flags;
        public AccessModeOptions AccessMode;
        public SMBFileAttributes SearchAttrs;
        public SMBFileAttributes FileAttrs;
        public DateTime? CreationTime; // UTime
        public OpenMode OpenMode;
        public uint AllocationSize;
        public uint Timeout;
        public uint Reserved;
        // Data:
        public string FileName; // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)

        public override SMB1Command Init()
        {
            base.Init();
            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            var parametersOffset = 4;
            Flags = (OpenFlags)LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            AccessMode = AccessModeOptions.Read(SmbParameters.Memory.Span, ref parametersOffset);
            SearchAttrs = (SMBFileAttributes)LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            FileAttrs = (SMBFileAttributes)LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            CreationTime = UTimeHelper.ReadNullableUTime(SmbParameters.Memory.Span, ref parametersOffset);
            OpenMode = OpenMode.Read(SmbParameters.Memory.Span, ref parametersOffset);
            AllocationSize = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);
            Timeout = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);
            Reserved = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);

            var dataOffset = 0;
            if (isUnicode)
            {
                dataOffset = 1; // 1 byte padding for 2 byte alignment
            }
            FileName = SMB1Helper.ReadSMBString(SmbData.Memory.Span, dataOffset, isUnicode);
            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            var parametersOffset = 4;
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, (ushort)Flags);
            AccessMode.WriteBytes(SmbParameters.Memory.Span, ref parametersOffset);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, (ushort)SearchAttrs);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, (ushort)FileAttrs);
            UTimeHelper.WriteUTime(SmbParameters.Memory.Span, ref parametersOffset, CreationTime);
            OpenMode.WriteBytes(SmbParameters.Memory.Span, ref parametersOffset);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, AllocationSize);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, Timeout);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, Reserved);

            var padding = 0;
            if (isUnicode)
            {
                padding = 1;
                SmbData = Arrays.Rent(padding + FileName.Length * 2 + 2);
            }
            else
            {
                SmbData = Arrays.Rent(FileName.Length + 1);
            }
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, padding, isUnicode, FileName);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_OPEN_ANDX;
    }
}
