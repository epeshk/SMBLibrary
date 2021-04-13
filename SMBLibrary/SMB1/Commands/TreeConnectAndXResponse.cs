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
    /// SMB_COM_TREE_CONNECT_ANDX Response
    /// </summary>
    public class TreeConnectAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 6;
        // Parameters:
        //CommandName AndXCommand;
        //byte AndXReserved;
        //ushort AndXOffset;
        public OptionalSupportFlags OptionalSupport;
        // Data:
        public ServiceName Service;     // OEM String
        public string NativeFileSystem; // SMB_STRING

        public override SMB1Command Init()
        {
            base.Init();
            Service = default;
            OptionalSupport = default;
            NativeFileSystem = default;
            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            
            OptionalSupport = (OptionalSupportFlags)LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);

            var dataOffset = 0;
            var serviceString = ByteReader.ReadNullTerminatedAnsiString(SmbData.Memory.Span, ref dataOffset);
            NativeFileSystem = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);

            Service = ServiceNameHelper.GetServiceName(serviceString);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, (ushort)OptionalSupport);

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
