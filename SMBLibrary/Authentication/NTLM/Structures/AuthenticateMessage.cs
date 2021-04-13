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

namespace SMBLibrary.Authentication.NTLM
{
    /// <summary>
    /// [MS-NLMP] AUTHENTICATE_MESSAGE (Type 3 Message)
    /// </summary>
    public class AuthenticateMessage : IDisposable
    {
        public const string ValidSignature = "NTLMSSP\0";

        public string Signature; // 8 bytes
        public MessageTypeName MessageType;
        public IMemoryOwner<byte> LmChallengeResponse; // 1 byte for anonymous authentication, 24 bytes for NTLM v1, NTLM v1 Extended Session Security and NTLM v2.
        public IMemoryOwner<byte> NtChallengeResponse; // 0 bytes for anonymous authentication, 24 bytes for NTLM v1 and NTLM v1 Extended Session Security, >= 48 bytes for NTLM v2.
        public string DomainName;
        public string UserName;
        public string WorkStation;
        public IMemoryOwner<byte> EncryptedRandomSessionKey;
        public NegotiateFlags NegotiateFlags;
        public NTLMVersion Version;
        // 16-byte MIC field is omitted for Windows NT / 2000 / XP / Server 2003

        public AuthenticateMessage()
        {
            Signature = ValidSignature;
            MessageType = MessageTypeName.Authenticate;
            DomainName = String.Empty;
            UserName = String.Empty;
            WorkStation = String.Empty;
            EncryptedRandomSessionKey = MemoryOwner<byte>.Empty;
        }

        public void Dispose()
        {
            if(LmChallengeResponse != null) LmChallengeResponse.Dispose();
            if(NtChallengeResponse != null) NtChallengeResponse.Dispose();
            if(EncryptedRandomSessionKey != null) EncryptedRandomSessionKey.Dispose();
            LmChallengeResponse = NtChallengeResponse = EncryptedRandomSessionKey = null;
        }

        public AuthenticateMessage(Span<byte> buffer)
        {
            Signature = ByteReader.ReadAnsiString(buffer, 0, 8);
            MessageType = (MessageTypeName)LittleEndianConverter.ToUInt32(buffer, 8);
            LmChallengeResponse = AuthenticationMessageUtils.ReadBufferPointer(buffer, 12);
            NtChallengeResponse = AuthenticationMessageUtils.ReadBufferPointer(buffer, 20);
            DomainName = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 28);
            UserName = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 36);
            WorkStation = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 44);
            EncryptedRandomSessionKey = AuthenticationMessageUtils.ReadBufferPointer(buffer, 52);
            NegotiateFlags = (NegotiateFlags)LittleEndianConverter.ToUInt32(buffer, 60);
            if ((NegotiateFlags & NegotiateFlags.Version) > 0)
            {
                Version = new NTLMVersion(buffer, 64);
            }
        }

        public IMemoryOwner<byte> GetBytes()
        {
            if ((NegotiateFlags & NegotiateFlags.KeyExchange) == 0)
            {
                EncryptedRandomSessionKey = MemoryOwner<byte>.Empty;
            }

            var fixedLength = 64;
            if ((NegotiateFlags & NegotiateFlags.Version) > 0)
            {
                fixedLength += NTLMVersion.Length;
            }
            var payloadLength = LmChallengeResponse.Length() + NtChallengeResponse.Length() + DomainName.Length * 2 + UserName.Length * 2 + WorkStation.Length * 2 + EncryptedRandomSessionKey.Length();
            var buffer = Arrays.Rent(fixedLength + payloadLength);
            BufferWriter.WriteAnsiString(buffer.Memory.Span, 0, ValidSignature, 8);
            LittleEndianWriter.WriteUInt32(buffer, 8, (uint)MessageType);
            LittleEndianWriter.WriteUInt32(buffer, 60, (uint)NegotiateFlags);
            if ((NegotiateFlags & NegotiateFlags.Version) > 0)
            {
                Version.WriteBytes(buffer.Memory.Span, 64);
            }
            
            var offset = fixedLength;
            AuthenticationMessageUtils.WriteBufferPointer(buffer.Memory.Span, 12, (ushort)LmChallengeResponse.Length(), (uint)offset);
            BufferWriter.WriteBytes(buffer.Memory.Span, ref offset, LmChallengeResponse.Memory.Span);
            AuthenticationMessageUtils.WriteBufferPointer(buffer.Memory.Span, 20, (ushort)NtChallengeResponse.Length(), (uint)offset);
            BufferWriter.WriteBytes(buffer.Memory.Span, ref offset, NtChallengeResponse.Memory.Span);
            AuthenticationMessageUtils.WriteBufferPointer(buffer.Memory.Span, 28, (ushort)(DomainName.Length * 2), (uint)offset);
            BufferWriter.WriteUTF16String(buffer.Memory.Span, ref offset, DomainName);
            AuthenticationMessageUtils.WriteBufferPointer(buffer.Memory.Span, 36, (ushort)(UserName.Length * 2), (uint)offset);
            BufferWriter.WriteUTF16String(buffer.Memory.Span, ref offset, UserName);
            AuthenticationMessageUtils.WriteBufferPointer(buffer.Memory.Span, 44, (ushort)(WorkStation.Length * 2), (uint)offset);
            BufferWriter.WriteUTF16String(buffer.Memory.Span, ref offset, WorkStation);
            AuthenticationMessageUtils.WriteBufferPointer(buffer.Memory.Span, 52, (ushort)EncryptedRandomSessionKey.Length(), (uint)offset);
            BufferWriter.WriteBytes(buffer.Memory.Span, ref offset, EncryptedRandomSessionKey.Memory.Span);

            return buffer;
        }
    }
}
