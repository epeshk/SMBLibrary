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
    /// SMB_COM_OPEN_ANDX Response
    /// </summary>
    public class OpenAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 30;
        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
        public ushort FID;
        public SMBFileAttributes FileAttrs;
        public DateTime? LastWriteTime; // UTime
        public uint FileDataSize;
        public AccessRights AccessRights;
        public ResourceType ResourceType;
        public NamedPipeStatus NMPipeStatus;
        public OpenResults OpenResults;
        public byte[] Reserved; // 6 bytes

        public override SMB1Command Init()
        {
            FID = default;
            FileAttrs = default;
            LastWriteTime = default; // UTime
            FileDataSize = default;
            AccessRights = default;
            ResourceType = default;
            NMPipeStatus = default;
            OpenResults = default;
            Reserved = new byte[6];

            return this;
        }

        public OpenAndXResponse Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            
            var parametersOffset = 4;
            FID = LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            FileAttrs = (SMBFileAttributes)LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            LastWriteTime = UTimeHelper.ReadNullableUTime(SmbParameters.Memory.Span, ref parametersOffset);
            FileDataSize = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);
            AccessRights = (AccessRights)LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            ResourceType = (ResourceType)LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            NMPipeStatus = NamedPipeStatus.Read(SmbParameters.Memory.Span, ref parametersOffset);
            OpenResults = OpenResults.Read(SmbParameters.Memory.Span, ref parametersOffset);
            Reserved = ByteReader.ReadBytes_RentArray(SmbParameters.Memory.Span, ref parametersOffset, 6);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            var parametersOffset = 4;
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, FID);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, (ushort)FileAttrs);
            UTimeHelper.WriteUTime(SmbParameters.Memory.Span, ref parametersOffset, LastWriteTime);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, FileDataSize);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, (ushort)AccessRights);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, (ushort)ResourceType);
            NMPipeStatus.WriteBytes(SmbParameters.Memory.Span, ref parametersOffset);
            OpenResults.WriteBytes(SmbParameters.Memory.Span, ref parametersOffset);
            BufferWriter.WriteBytes(SmbParameters.Memory.Span, ref parametersOffset, Reserved, 6);
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_OPEN_ANDX;
    }
}
