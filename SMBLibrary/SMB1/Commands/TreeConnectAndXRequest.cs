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
    /// SMB_COM_TREE_CONNECT_ANDX Request
    /// </summary>
    public class TreeConnectAndXRequest : SMBAndXCommand
    {
        public const int ParametersLength = 8;
        // Parameters:
        public TreeConnectFlags Flags;
        // ushort PasswordLength;
        // Data:
        public byte[] Password;
        // Padding
        public string Path;         // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
        public ServiceName Service; // OEM string

        public override SMB1Command Init()
        {
            base.Init();
            Flags = default;
            Path = default;
            Service = default;
            Password = Array.Empty<byte>();
            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            
            var parametersOffset = 4;
            Flags = (TreeConnectFlags)LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            var passwordLength = LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);

            var dataOffset = 0;
            Password = ByteReader.ReadBytes_RentArray(SmbData.Memory.Span, ref dataOffset, passwordLength);
            if (isUnicode)
            {
                // wordCount is 1 byte
                var padding = (1 + passwordLength) % 2;
                dataOffset += padding;
            }
            Path = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);
            // Should be read as OEM string but it doesn't really matter
            var serviceString = ByteReader.ReadNullTerminatedAnsiString(SmbData.Memory.Span, ref dataOffset);
            Service = ServiceNameHelper.GetServiceName(serviceString);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            var passwordLength = (ushort)Password.Length;

            SmbParameters = Arrays.Rent(ParametersLength);
            var parametersOffset = 4;
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, (ushort)Flags);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, passwordLength);

            var serviceString = ServiceNameHelper.GetServiceString(Service);
            var dataLength = Password.Length + serviceString.Length + 1;
            if (isUnicode)
            {
                var padding = (1 + passwordLength) % 2;
                dataLength += Path.Length * 2 + 2 + padding;
            }
            else
            {
                dataLength += Path.Length + 1;
            }
            SmbData = Arrays.Rent(dataLength);
            var dataOffset = 0;
            BufferWriter.WriteBytes(SmbData.Memory.Span, ref dataOffset, Password);
            if (isUnicode)
            {
                // wordCount is 1 byte
                var padding = (1 + passwordLength) % 2;
                dataOffset += padding;
            }
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode, Path);
            BufferWriter.WriteNullTerminatedAnsiString(SmbData.Memory.Span, ref dataOffset, serviceString);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_TREE_CONNECT_ANDX;
    }
}
