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
    /// SMB_COM_TREE_CONNECT_ANDX Extended Response
    /// </summary>
    public class TreeConnectAndXResponseExtended : SMBAndXCommand
    {
        public const int ParametersLength = 14;
        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
        public OptionalSupportFlags OptionalSupport;
        public AccessMask MaximalShareAccessRights;
        public AccessMask GuestMaximalShareAccessRights;
        // Data:
        public ServiceName Service;     // OEM String
        public string NativeFileSystem; // SMB_STRING

        public override SMB1Command Init()
        {
            base.Init();
            OptionalSupport = default;
            MaximalShareAccessRights = default;
            GuestMaximalShareAccessRights = default;
            Service = default;    
            NativeFileSystem = default;
            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            
            var parametersOffset = 4;
            OptionalSupport = (OptionalSupportFlags)LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            MaximalShareAccessRights = (AccessMask)LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);
            GuestMaximalShareAccessRights = (AccessMask)LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);

            var dataOffset = 0;
            var serviceString = ByteReader.ReadNullTerminatedAnsiString(SmbData.Memory.Span, ref dataOffset);
            NativeFileSystem = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);

            Service = ServiceNameHelper.GetServiceName(serviceString);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            var parametersOffset = 4;
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, (ushort)OptionalSupport);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, (uint)MaximalShareAccessRights);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, (uint)GuestMaximalShareAccessRights);

            // Should be written as OEM string but it doesn't really matter
            var serviceString = ServiceNameHelper.GetServiceString(Service);
            if (isUnicode)
            {
                SmbData = Arrays.Rent(serviceString.Length + NativeFileSystem.Length * 2 + 3);
            }
            else
            {
                SmbData = Arrays.Rent(serviceString.Length + NativeFileSystem.Length + 2);
            }

            var offset = 0;
            BufferWriter.WriteNullTerminatedAnsiString(SmbData.Memory.Span, ref offset, serviceString);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, isUnicode, NativeFileSystem);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_TREE_CONNECT_ANDX;
    }
}
