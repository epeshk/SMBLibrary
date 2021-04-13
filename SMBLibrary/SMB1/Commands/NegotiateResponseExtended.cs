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
    /// SMB_COM_NEGOTIATE Response, NT LAN Manager dialect, Extended Security response
    /// </summary>
    public class NegotiateResponseExtended : SMB1Command
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
        private byte _challengeLength; // MUST be set to 0
        // Data:
        public Guid ServerGuid;
        public byte[] SecurityBlob;   // [MS-SMB] 3.3.5.2: The server can leave SecurityBlob empty if not configured to send GSS token.

        public override SMB1Command Init()
        {
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
            _challengeLength = default;
            ServerGuid = default;
            SecurityBlob = Array.Empty<byte>();

            return this;
        }

        public NegotiateResponseExtended Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            
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
            _challengeLength = ByteReader.ReadByte(SmbParameters.Memory.Span, 33);

            ServerGuid = LittleEndianConverter.ToGuid(SmbData.Memory.Span, 0);
            SecurityBlob = ByteReader.ReadBytes_RentArray(SmbData.Memory.Span, 16, SmbData.Length() - 16);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            _challengeLength = 0;

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
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 33, _challengeLength);

            SmbData = Arrays.Rent(16 + SecurityBlob.Length);
            LittleEndianWriter.WriteGuidBytes(SmbData.Memory.Span, 0, ServerGuid);
            BufferWriter.WriteBytes(SmbData.Memory.Span, 16, SecurityBlob);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_NEGOTIATE;
    }
}
