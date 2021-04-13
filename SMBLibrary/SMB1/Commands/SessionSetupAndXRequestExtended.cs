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
    /// SMB_COM_SESSION_SETUP_ANDX Extended Request
    /// </summary>
    public class SessionSetupAndXRequestExtended : SMBAndXCommand
    {
        public const int ParametersLength = 24;
        // Parameters:
        public ushort MaxBufferSize;
        public ushort MaxMpxCount;
        public ushort VcNumber;
        public uint SessionKey;
        private ushort _securityBlobLength;
        public uint Reserved;
        public Capabilities Capabilities;
        // Data:
        public IMemoryOwner<byte> SecurityBlob;
        public string NativeOS;     // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string NativeLanMan; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)

        public override SMB1Command Init()
        {
            base.Init();
            
            MaxBufferSize = default;
            MaxMpxCount = default;
            VcNumber = default;
            SessionKey = default;
            Reserved = default;
            Capabilities = default;
            SecurityBlob = default;
            _securityBlobLength = default;
        
            NativeOS = string.Empty;
            NativeLanMan = string.Empty;

            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            MaxBufferSize = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);
            MaxMpxCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 6);
            VcNumber = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 8);
            SessionKey = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 10);
            _securityBlobLength = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 14);
            Reserved = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 16);
            Capabilities = (Capabilities)LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 20);

            SecurityBlob = ByteReader.ReadBytes_Rent(SmbData.Memory.Span, 0, _securityBlobLength);

            var dataOffset = SecurityBlob.Length();
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                var padding = (1 + _securityBlobLength) % 2;
                dataOffset += padding;
            }
            NativeOS = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);
            NativeLanMan = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            Capabilities |= Capabilities.ExtendedSecurity;
            _securityBlobLength = (ushort)SecurityBlob.Length();

            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, MaxBufferSize);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 6, MaxMpxCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 8, VcNumber);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 10, SessionKey);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 14, _securityBlobLength);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 16, Reserved);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 20, (uint)Capabilities);

            var padding = 0;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                padding = (1 + _securityBlobLength) % 2;
                SmbData = Arrays.Rent(SecurityBlob.Length() + padding + (NativeOS.Length + 1) * 2 + (NativeLanMan.Length  + 1) * 2);
            }
            else
            {
                SmbData = Arrays.Rent(SecurityBlob.Length() + NativeOS.Length + 1 + NativeLanMan.Length  + 1);
            }
            var offset = 0;
            BufferWriter.WriteBytes(SmbData.Memory.Span, ref offset, SecurityBlob.Memory.Span);
            offset += padding;
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, isUnicode, NativeOS);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, isUnicode, NativeLanMan);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_SESSION_SETUP_ANDX;

        public override void Dispose()
        {
            base.Dispose();
            SecurityBlob?.Dispose();
            SecurityBlob = null;
        }
    }
}
