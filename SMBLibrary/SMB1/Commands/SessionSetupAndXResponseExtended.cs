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
    /// SMB_COM_SESSION_SETUP_ANDX Response, NT LAN Manager dialect, Extended Security response
    /// </summary>
    public class SessionSetupAndXResponseExtended : SMBAndXCommand
    {
        public const int ParametersLength = 8;
        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
        public SessionSetupAction Action;
        private ushort SecurityBlobLength;
        // Data:
        public IMemoryOwner<byte> SecurityBlob;
        public string NativeOS;     // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string NativeLanMan; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)

        public override SMB1Command Init()
        {
            base.Init();
            Action = default;
            SecurityBlobLength = default;
            SecurityBlob = MemoryOwner<byte>.Empty;
            NativeOS = string.Empty;
            NativeLanMan = string.Empty;
            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            Action = (SessionSetupAction)LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);
            SecurityBlobLength = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 6);

            SecurityBlob = ByteReader.ReadBytes_Rent(SmbData.Memory.Span, 0, SecurityBlobLength);

            var dataOffset = SecurityBlob.Length();
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                var padding = (1 + SecurityBlobLength) % 2;
                dataOffset += padding;
            }
            NativeOS = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);
            if ((SmbData.Length() - dataOffset) % 2 == 1)
            {
                // Workaround for a single terminating null byte
                SmbData = ByteUtils.Concatenate(SmbData.Memory.Span, new byte[1]);
            }
            NativeLanMan = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            var securityBlobLength = (ushort)SecurityBlob.Length();

            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, (ushort)Action);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 6, securityBlobLength);

            var padding = 0;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                padding = (1 + securityBlobLength) % 2;
                SmbData = Arrays.Rent(SecurityBlob.Length() + padding + NativeOS.Length * 2 + NativeLanMan.Length * 2 + 4);
            }
            else
            {
                SmbData = Arrays.Rent(SecurityBlob.Length() + NativeOS.Length + NativeLanMan.Length + 2);
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
