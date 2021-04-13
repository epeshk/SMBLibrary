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
    /// SMB_COM_SESSION_SETUP_ANDX Request
    /// </summary>
    public class SessionSetupAndXRequest : SMBAndXCommand
    {
        public const int ParametersLength = 26;
        // Parameters:
        public ushort MaxBufferSize;
        public ushort MaxMpxCount;
        public ushort VcNumber;
        public uint SessionKey;
        private ushort OEMPasswordLength;
        private ushort UnicodePasswordLength;
        public uint Reserved;
        public Capabilities Capabilities;
        // Data:
        public byte[] OEMPassword;
        public byte[] UnicodePassword;
        // Padding
        public string AccountName;   // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string PrimaryDomain; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string NativeOS;      // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string NativeLanMan;  // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)

        public override SMB1Command Init()
        {
            base.Init();
            
            MaxBufferSize = default;
            MaxMpxCount = default;
            VcNumber = default;
            SessionKey = default;
            OEMPasswordLength = default;
            UnicodePasswordLength = default;
            Reserved = default;
            Capabilities = default;
            OEMPassword = default;
            UnicodePassword = default;
            AccountName = string.Empty;
            PrimaryDomain = string.Empty;
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
            OEMPasswordLength = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 14);
            UnicodePasswordLength = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 16);
            Reserved = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 18);
            Capabilities = (Capabilities)LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 22);

            OEMPassword = ByteReader.ReadBytes_RentArray(SmbData.Memory.Span, 0, OEMPasswordLength);
            UnicodePassword = ByteReader.ReadBytes_RentArray(SmbData.Memory.Span, OEMPasswordLength, UnicodePasswordLength);

            var dataOffset = OEMPasswordLength + UnicodePasswordLength;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                var padding = (1 + OEMPasswordLength + UnicodePasswordLength) % 2;
                dataOffset += padding;
            }
            AccountName = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);
            PrimaryDomain = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);
            NativeOS = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);
            NativeLanMan = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, isUnicode);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            Capabilities &= ~Capabilities.ExtendedSecurity;

            OEMPasswordLength = (ushort)OEMPassword.Length;
            UnicodePasswordLength = (ushort)UnicodePassword.Length;
            
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, MaxBufferSize);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 6, MaxMpxCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 8, VcNumber);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 10, SessionKey);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 14, OEMPasswordLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 16, UnicodePasswordLength);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 18, Reserved);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 22, (uint)Capabilities);

            var padding = 0;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                padding = (1 + OEMPasswordLength + UnicodePasswordLength) % 2;
                SmbData = Arrays.Rent(OEMPassword.Length + UnicodePassword.Length + padding + (AccountName.Length + 1) * 2 + (PrimaryDomain.Length + 1) * 2 + (NativeOS.Length + 1) * 2 + (NativeLanMan.Length + 1) * 2);
            }
            else
            {
                SmbData = Arrays.Rent(OEMPassword.Length + UnicodePassword.Length + AccountName.Length + 1 + PrimaryDomain.Length + 1 + NativeOS.Length + 1 + NativeLanMan.Length + 1);
            }
            var offset = 0;
            BufferWriter.WriteBytes(SmbData.Memory.Span, ref offset, OEMPassword);
            BufferWriter.WriteBytes(SmbData.Memory.Span, ref offset, UnicodePassword);
            offset += padding;
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, isUnicode, AccountName);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, isUnicode, PrimaryDomain);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, isUnicode, NativeOS);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, isUnicode, NativeLanMan);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_SESSION_SETUP_ANDX;
    }
}
