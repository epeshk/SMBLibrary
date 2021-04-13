/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Text;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.Authentication.NTLM
{
    public class AuthenticationMessageUtils
    {
        public static string ReadAnsiStringBufferPointer(Span<byte> buffer, int offset)
        {
            using var bytes = ReadBufferPointer(buffer, offset);
            return ASCIIEncoding.Default.GetString(bytes.Memory.Span);
        }

        public static string ReadUnicodeStringBufferPointer(Span<byte> buffer, int offset)
        {
            using var bytes = ReadBufferPointer(buffer, offset);
            return UnicodeEncoding.Unicode.GetString(bytes.Memory.Span);
        }

        public static IMemoryOwner<byte> ReadBufferPointer(Span<byte> buffer, int offset)
        {
            var length = LittleEndianConverter.ToUInt16(buffer, offset);
            var maxLength = LittleEndianConverter.ToUInt16(buffer, offset + 2);
            var bufferOffset = LittleEndianConverter.ToUInt32(buffer, offset + 4);

            if (length == 0)
            {
                return MemoryOwner<byte>.Empty;
            }

            return Arrays.RentFrom<byte>(buffer.Slice((int)bufferOffset, length));
        }

        public static void WriteBufferPointer(Span<byte> buffer, int offset, ushort bufferLength, uint bufferOffset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset, bufferLength);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, bufferLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, bufferOffset);
        }

        public static bool IsSignatureValid(Span<byte> messageBytes)
        {
            if (messageBytes.Length < 8)
            {
                return false;
            }
            var signature = ByteReader.ReadAnsiString(messageBytes, 0, 8);
            return (signature == AuthenticateMessage.ValidSignature);
        }

        /// <summary>
        /// If NTLM v1 Extended Session Security is used, LMResponse starts with 8-byte challenge, followed by 16 bytes of padding (set to zero).
        /// </summary>
        /// <remarks>
        /// LMResponse is 24 bytes for NTLM v1, NTLM v1 Extended Session Security and NTLM v2.
        /// </remarks>
        public static bool IsNTLMv1ExtendedSessionSecurity(Span<byte> lmResponse)
        {
            if (lmResponse.Length == 24)
            {
                if (ByteUtils.AreByteArraysEqual(ByteReader.ReadBytes_RentArray(lmResponse, 0, 8), new byte[8]))
                {
                    // Challenge not present, cannot be NTLM v1 Extended Session Security
                    return false;
                }
                return ByteUtils.AreByteArraysEqual(ByteReader.ReadBytes_RentArray(lmResponse, 8, 16), new byte[16]);
            }
            return false;
        }

        /// <remarks>
        /// NTLM v1 / NTLM v1 Extended Session Security NTResponse is 24 bytes.
        /// </remarks>
        public static bool IsNTLMv2NTResponse(Span<byte> ntResponse)
        {
            return (ntResponse.Length >= 16 + NTLMv2ClientChallenge.MinimumLength &&
                    ntResponse[16] == NTLMv2ClientChallenge.StructureVersion &&
                    ntResponse[17] == NTLMv2ClientChallenge.StructureVersion);
        }

        public static MessageTypeName GetMessageType(Span<byte> messageBytes)
        {
            return (MessageTypeName)LittleEndianConverter.ToUInt32(messageBytes, 8);
        }
    }
}
