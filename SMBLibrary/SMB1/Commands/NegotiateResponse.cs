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
    /// SMB_COM_NEGOTIATE Response, NT LAN Manager dialect
    /// </summary>
    public class NegotiateResponse : SMB1Command
    {
        public const int ParametersLength = 34;
        // Parameters:
        public ushort DialectIndex;
        public SecurityMode SecurityMode;
        public ushort MaxMpxCount;
        public ushort MaxNumberVcs;
        public uint MaxBufferSize;
        public uint MaxRawSize;
        public uint SessionKey;
        public Capabilities Capabilities;
        public DateTime SystemTime;
        public short ServerTimeZone;
        private byte ChallengeLength;
        // Data:
        public byte[] Challenge;
        public string DomainName; // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string ServerName; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)

        public override SMB1Command Init()
        {
            base.Init();
            DialectIndex = default;
            SecurityMode = default;
            MaxMpxCount = default;
            MaxNumberVcs = default;
            MaxBufferSize = default;
            MaxRawSize = default;
            SessionKey = default;
            Capabilities = default;
            SystemTime = default;
            ServerTimeZone = default;
            ChallengeLength = default;
            Challenge = Array.Empty<byte>();
            DomainName = String.Empty;
            ServerName = String.Empty;

            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            DialectIndex = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            SecurityMode = (SecurityMode)ByteReader.ReadByte(SmbParameters.Memory.Span, 2);
            MaxMpxCount = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 3);
            MaxNumberVcs = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 5);
            MaxBufferSize = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 7);
            MaxRawSize = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 11);
            SessionKey = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 15);
            Capabilities = (Capabilities)LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 19);
            SystemTime = FileTimeHelper.ReadFileTime(SmbParameters.Memory.Span, 23);
            ServerTimeZone = LittleEndianConverter.ToInt16(SmbParameters.Memory.Span, 31);
            ChallengeLength = ByteReader.ReadByte(SmbParameters.Memory.Span, 33);

            var dataOffset = 0;
            Challenge = ByteReader.ReadBytes_RentArray(SmbData.Memory.Span, ref dataOffset, ChallengeLength);
            // [MS-CIFS] <90> Padding is not added before DomainName
            // DomainName and ServerName are always in Unicode
            DomainName = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, true);
            ServerName = SMB1Helper.ReadSMBString(SmbData.Memory.Span, ref dataOffset, true);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            ChallengeLength = (byte)Challenge.Length;

            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, DialectIndex);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 2, (byte)SecurityMode);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 3, MaxMpxCount);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 5, MaxNumberVcs);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 7, MaxBufferSize);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 11, MaxRawSize);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 15, SessionKey);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 19, (uint)Capabilities);
            FileTimeHelper.WriteFileTime(SmbParameters.Memory.Span, 23, SystemTime);
            LittleEndianWriter.WriteInt16(SmbParameters.Memory.Span, 31, ServerTimeZone);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 33, ChallengeLength);

            // [MS-CIFS] <90> Padding is not added before DomainName
            // DomainName and ServerName are always in Unicode
            SmbData = Arrays.Rent(Challenge.Length + (DomainName.Length + 1) * 2 + (ServerName.Length + 1) * 2);
            var offset = 0;
            BufferWriter.WriteBytes(SmbData.Memory.Span, ref offset, Challenge);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, true, DomainName);
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, ref offset, true, ServerName);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_NEGOTIATE;
    }
}
