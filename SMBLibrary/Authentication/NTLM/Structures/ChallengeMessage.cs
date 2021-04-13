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
    /// [MS-NLMP] CHALLENGE_MESSAGE (Type 2 Message)
    /// </summary>
    public class ChallengeMessage
    {
        public string Signature; // 8 bytes
        public MessageTypeName MessageType;
        public string TargetName;
        public NegotiateFlags NegotiateFlags;
        public byte[] ServerChallenge; // 8 bytes
        // Reserved - 8 bytes
        public KeyValuePairList<AVPairKey, byte[]> TargetInfo = new KeyValuePairList<AVPairKey,byte[]>();
        public NTLMVersion Version;

        public ChallengeMessage()
        {
            Signature = AuthenticateMessage.ValidSignature;
            MessageType = MessageTypeName.Challenge;
        }

        public ChallengeMessage(Span<byte> buffer)
        {
            Signature = ByteReader.ReadAnsiString(buffer, 0, 8);
            MessageType = (MessageTypeName)LittleEndianConverter.ToUInt32(buffer, 8);
            TargetName = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 12);
            NegotiateFlags = (NegotiateFlags)LittleEndianConverter.ToUInt32(buffer, 20);
            ServerChallenge = ByteReader.ReadBytes_RentArray(buffer, 24, 8);
            // Reserved
            var targetInfoBytes = AuthenticationMessageUtils.ReadBufferPointer(buffer, 40);
            if (targetInfoBytes.Length() > 0)
            {
                TargetInfo = AVPairUtils.ReadAVPairSequence(targetInfoBytes.Memory.Span, 0);
            }
            if ((NegotiateFlags & NegotiateFlags.Version) > 0)
            {
                Version = new NTLMVersion(buffer, 48);
            }
            targetInfoBytes.Dispose();
        }

        public IMemoryOwner<byte> GetBytes()
        {
            if ((NegotiateFlags & NegotiateFlags.TargetNameSupplied) == 0)
            {
                TargetName = String.Empty;
            }

            var targetInfoBytes = AVPairUtils.GetAVPairSequenceBytes(TargetInfo);
            if ((NegotiateFlags & NegotiateFlags.TargetInfo) == 0)
            {
                targetInfoBytes = Array.Empty<byte>();
            }

            var fixedLength = 48;
            if ((NegotiateFlags & NegotiateFlags.Version) > 0)
            {
                fixedLength += 8;
            }
            var payloadLength = TargetName.Length * 2 + targetInfoBytes.Length;
            var buffer = Arrays.Rent(fixedLength + payloadLength);
            BufferWriter.WriteAnsiString(buffer.Memory.Span, 0, AuthenticateMessage.ValidSignature, 8);
            LittleEndianWriter.WriteUInt32(buffer, 8, (uint)MessageType);
            LittleEndianWriter.WriteUInt32(buffer, 20, (uint)NegotiateFlags);
            BufferWriter.WriteBytes(buffer.Memory.Span, 24, ServerChallenge);
            if ((NegotiateFlags & NegotiateFlags.Version) > 0)
            {
                Version.WriteBytes(buffer.Memory.Span, 48);
            }

            var offset = fixedLength;
            AuthenticationMessageUtils.WriteBufferPointer(buffer.Memory.Span, 12, (ushort)(TargetName.Length * 2), (uint)offset);
            BufferWriter.WriteUTF16String(buffer.Memory.Span, ref offset, TargetName);
            AuthenticationMessageUtils.WriteBufferPointer(buffer.Memory.Span, 40, (ushort)targetInfoBytes.Length, (uint)offset);
            BufferWriter.WriteBytes(buffer.Memory.Span, ref offset, targetInfoBytes);

            return buffer;
        }
    }
}
