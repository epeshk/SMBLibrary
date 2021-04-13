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
    /// SMB_COM_OPEN_ANDX Response Extended
    /// </summary>
    public class OpenAndXResponseExtended : SMBAndXCommand
    {
        public const int ParametersLength = 38;
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
        public uint ServerFID;
        public ushort Reserved;
        public AccessMask MaximalAccessRights;
        public AccessMask GuestMaximalAccessRights;

        public override SMB1Command Init()
        {
            base.Init();
            
            FID = default;
            FileAttrs = default;
            LastWriteTime = default; // UTime
            FileDataSize = default;
            AccessRights = default;
            ResourceType = default;
            NMPipeStatus = default;
            OpenResults = default;
            ServerFID = default;
            Reserved = default;
            MaximalAccessRights = default;
            GuestMaximalAccessRights = default;
            
            return this;
        }

        public OpenAndXResponseExtended Init(Span<byte> buffer, int offset)
        {
            throw new NotImplementedException();
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
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, ServerFID);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, Reserved);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, (uint)MaximalAccessRights);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, (uint)GuestMaximalAccessRights);
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_OPEN_ANDX;
    }
}
