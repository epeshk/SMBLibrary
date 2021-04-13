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
    /// SMB_COM_SESSION_SETUP_ANDX Response
    /// </summary>
    public class SessionSetupAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 6;
        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
        public SessionSetupAction Action;
        // Data:
        public string NativeOS;      // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string NativeLanMan;  // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string PrimaryDomain; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)

        public SessionSetupAndXResponse Init()
        {
            base.Init();
            Action = default;
            NativeOS = String.Empty;
            NativeLanMan = String.Empty;
            PrimaryDomain = String.Empty;

            return this;
        }

        public SessionSetupAndXResponse Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            
            Action = (SessionSetupAction)LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);

            var dataOffset = 0;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                dataOffset++;
            }
            NativeOS = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);
            NativeLanMan = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);
            if ((SmbData.Length() - dataOffset) % 2 == 1)
            {
                // Workaround for a single terminating null byte
                SmbData = ByteUtils.Concatenate(SmbData.Memory.Span, new byte[1]);
            }
            PrimaryDomain = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, (ushort)Action);

            var offset = 0;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                var padding = 1;
                SmbData = Arrays.Rent(padding + NativeOS.Length * 2 + NativeLanMan.Length * 2 + PrimaryDomain.Length * 2 + 6);
                offset = padding;
            }
            else
            {
                SmbData = Arrays.Rent(NativeOS.Length + NativeLanMan.Length + PrimaryDomain.Length + 3);
            }
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, isUnicode, NativeOS);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, isUnicode, NativeLanMan);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, isUnicode, PrimaryDomain);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_SESSION_SETUP_ANDX;
    }
}
