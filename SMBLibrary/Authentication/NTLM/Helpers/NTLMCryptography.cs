/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Utilities;

namespace SMBLibrary.Authentication.NTLM
{
    public class NTLMCryptography
    {
        public static byte[] ComputeLMv1Response(Span<byte> challenge, string password)
        {
            var hash = LMOWFv1(password);
            return DesLongEncrypt_Rental(hash, challenge);
        }

        public static byte[] ComputeNTLMv1Response(Span<byte> challenge, string password)
        {
            var hash = NTOWFv1_Rental(password);
            var res = DesLongEncrypt_Rental(hash, challenge);
            ExactArrayPool.Return(hash);
            return res;
        }

        public static byte[] ComputeNTLMv1ExtendedSessionSecurityResponse(byte[] serverChallenge, byte[] clientChallenge, string password)
        {
            var passwordHash = NTOWFv1_Rental(password);
            var challengeHash = MD5.Create().ComputeHash(ByteUtils.Concatenate_Rental(serverChallenge, clientChallenge));
            var challengeHashShort = ExactArrayPool.Rent(8);
            Array.Copy(challengeHash, 0, challengeHashShort, 0, 8);
            var res = DesLongEncrypt_Rental(passwordHash, challengeHashShort);
            ExactArrayPool.Return(passwordHash);
            ExactArrayPool.Return(challengeHashShort);
            return res;
        }

        public static byte[] ComputeLMv2Response(Span<byte> serverChallenge, Span<byte> clientChallenge, string password, string user, string domain)
        {
            var key = LMOWFv2(password, user, domain);
            var bytes = ByteUtils.Concatenate_Rental(serverChallenge, clientChallenge);
            var hmac = new HMACMD5(key);
            var hash = hmac.ComputeHash(bytes, 0, bytes.Length);

            return ByteUtils.Concatenate_Rental(hash, clientChallenge);
        }

        /// <summary>
        /// [MS-NLMP] https://msdn.microsoft.com/en-us/library/cc236700.aspx
        /// </summary>
        /// <param name="clientChallengeStructurePadded">ClientChallengeStructure with 4 zero bytes padding, a.k.a. temp</param>
        public static byte[] ComputeNTLMv2Proof(Span<byte> serverChallenge, byte[] clientChallengeStructurePadded, string password, string user, string domain)
        {
            var key = NTOWFv2(password, user, domain);
            var temp = clientChallengeStructurePadded;

            var hmac = new HMACMD5(key);
            var msg = ByteUtils.Concatenate_Rental(serverChallenge, temp);
            var _NTProof = hmac.ComputeHash(msg, 0, serverChallenge.Length + temp.Length);
            ExactArrayPool.Return(msg);
            return _NTProof;
        }

        public static byte[] DesEncrypt_Rental(byte[] key, byte[] plainText)
        {
            return DesEncrypt_Rental(key, plainText, 0, plainText.Length);
        }

        public static byte[] DesEncrypt_Rental(byte[] key, byte[] plainText, int inputOffset, int inputCount)
        {
            var encryptor = CreateWeakDesEncryptor(CipherMode.ECB, key, new byte[key.Length]);
            var result = ExactArrayPool.Rent(inputCount);
            encryptor.TransformBlock(plainText, inputOffset, inputCount, result, 0);
            return result;
        }

        public static ICryptoTransform CreateWeakDesEncryptor(CipherMode mode, byte[] rgbKey, byte[] rgbIV)
        {
            var des = DES.Create();
            des.Mode = mode;
            var sm = des as DESCryptoServiceProvider;
            var mi = sm.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] Par = { rgbKey, mode, rgbIV, sm.FeedbackSize, 0 };
            var trans = mi.Invoke(sm, Par) as ICryptoTransform;
            return trans;
        }

        /// <summary>
        /// DESL()
        /// </summary>
        public static byte[] DesLongEncrypt_Rental(Span<byte> key, Span<byte> plainText)
        {
            if (key.Length != 16)
            {
                throw new ArgumentException("Invalid key length");
            }

            if (plainText.Length != 8)
            {
                throw new ArgumentException("Invalid plain-text length");
            }
            var padded = ExactArrayPool.Rent(21);
            key.CopyTo(padded);

            var k1 = ExactArrayPool.Rent(7);
            var k2 = ExactArrayPool.Rent(7);
            var k3 = ExactArrayPool.Rent(7);
            
            Array.Copy(padded, 0, k1, 0, 7);
            Array.Copy(padded, 7, k2, 0, 7);
            Array.Copy(padded, 14, k3, 0, 7);
            
            var exdesKey1 = ExtendDESKey_Rental(k1);
            var exdesKey2 = ExtendDESKey_Rental(k2);
            var exdesKey3 = ExtendDESKey_Rental(k3);

            var plain = plainText.ToArray();
            var r1 = DesEncrypt_Rental(exdesKey1, plain);
            var r2 = DesEncrypt_Rental(exdesKey2, plain);
            var r3 = DesEncrypt_Rental(exdesKey3, plain);

            var result = ExactArrayPool.Rent(24);
            
            Array.Copy(r1, 0, result, 0, 8);
            Array.Copy(r2, 0, result, 8, 8);
            Array.Copy(r3, 0, result, 16, 8);

            ExactArrayPool.Return(k1, k2, k3); 
            ExactArrayPool.Return(exdesKey1, exdesKey2, exdesKey3); 
            ExactArrayPool.Return(r1, r2, r3);
            
            return result;
        }

        public static Encoding GetOEMEncoding()
        {
            return Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
        }

        /// <summary>
        /// LM Hash
        /// </summary>
        public static byte[] LMOWFv1(string password)
        {
            var plainText = ASCIIEncoding.ASCII.GetBytes("KGS!@#$%");
            var passwordBytes = GetOEMEncoding().GetBytes(password.ToUpper());
            var key = new byte[14];
            Array.Copy(passwordBytes, key, Math.Min(passwordBytes.Length, 14));

            var k1 = new byte[7];
            var k2 = new byte[7];
            Array.Copy(key, 0, k1, 0, 7);
            Array.Copy(key, 7, k2, 0, 7);

            var part1 = DesEncrypt_Rental(ExtendDESKey_Rental(k1), plainText);
            var part2 = DesEncrypt_Rental(ExtendDESKey_Rental(k2), plainText);

            return ByteUtils.Concatenate_Rental(part1, part2);
        }

        /// <summary>
        /// NTLM hash (NT hash)
        /// </summary>
        public static byte[] NTOWFv1_Rental(string password)
        {
            var passwordBytes = ExactArrayPool.Rent(password.Length << 1);
            UnicodeEncoding.Unicode.GetBytes(password, passwordBytes);
            var buf = Md4.GetByteHashFromBytes_Rental(passwordBytes);
            ExactArrayPool.Return(passwordBytes);
            return buf;
        }

        /// <summary>
        /// LMOWFv2 is identical to NTOWFv2
        /// </summary>
        public static byte[] LMOWFv2(string password, string user, string domain)
        {
            return NTOWFv2(password, user, domain);
        }

        public static byte[] NTOWFv2(string password, string user, string domain)
        {
            
            var r_passwordBytes = ExactArrayPool.Rent(password.Length << 1);
            UnicodeEncoding.Unicode.GetBytes(password, r_passwordBytes);
            
            var r_key = Md4.GetByteHashFromBytes_Rental(r_passwordBytes);
            
            var r_text = ExactArrayPool<char>.Rent(user.Length + domain.Length);
            for (int i = 0; i < user.Length; i++) r_text[i] = char.ToUpper(user[i]);
            for (int i = 0, s = user.Length; i < domain.Length; i++) r_text[s+i] = domain[i];
            
            var r_bytes = ExactArrayPool.Rent(r_text.Length << 1);
            UnicodeEncoding.Unicode.GetBytes(r_text, r_bytes);
            var hmac = new HMACMD5(r_key);
            
            ExactArrayPool<char>.Return(r_text);
            ExactArrayPool.Return(r_passwordBytes);
            ExactArrayPool.Return(r_key);
            
            var res = hmac.ComputeHash(r_bytes, 0, r_bytes.Length);
            
            ExactArrayPool.Return(r_bytes);
            
            return res;
        }

        /// <summary>
        /// Extends a 7-byte key into an 8-byte key.
        /// Note: The DES key ostensibly consists of 64 bits, however, only 56 of these are actually used by the algorithm.
        /// Eight bits are used solely for checking parity, and are thereafter discarded
        /// </summary>
        private static byte[] ExtendDESKey_Rental(byte[] key)
        {
            var result = ExactArrayPool.Rent(8);
            int i;

            result[0] = (byte)((key[0] >> 1) & 0xff);
            result[1] = (byte)((((key[0] & 0x01) << 6) | (((key[1] & 0xff) >> 2) & 0xff)) & 0xff);
            result[2] = (byte)((((key[1] & 0x03) << 5) | (((key[2] & 0xff) >> 3) & 0xff)) & 0xff);
            result[3] = (byte)((((key[2] & 0x07) << 4) | (((key[3] & 0xff) >> 4) & 0xff)) & 0xff);
            result[4] = (byte)((((key[3] & 0x0F) << 3) | (((key[4] & 0xff) >> 5) & 0xff)) & 0xff);
            result[5] = (byte)((((key[4] & 0x1F) << 2) | (((key[5] & 0xff) >> 6) & 0xff)) & 0xff);
            result[6] = (byte)((((key[5] & 0x3F) << 1) | (((key[6] & 0xff) >> 7) & 0xff)) & 0xff);
            result[7] = (byte)(key[6] & 0x7F);
            for (i = 0; i < 8; i++)
            {
                result[i] = (byte)(result[i] << 1);
            }

            return result;
        }

        /// <summary>
        /// [MS-NLMP] 3.4.5.1 - KXKEY - NTLM v1
        /// </summary>
        /// <remarks>
        /// If NTLM v2 is used, KeyExchangeKey MUST be set to the value of SessionBaseKey.
        /// </remarks>
        public static byte[] KXKey_Rental(byte[] sessionBaseKey, NegotiateFlags negotiateFlags, Span<byte> lmChallengeResponse, Span<byte> serverChallenge, Span<byte> lmowf)
        {
            if ((negotiateFlags & NegotiateFlags.ExtendedSessionSecurity) == 0)
            {
                if ((negotiateFlags & NegotiateFlags.LanManagerSessionKey) > 0)
                {
                    var k1 = ByteReader.ReadBytes_RentArray(lmowf, 0, 7);
                    var k2 = ByteUtils.Concatenate_Rental(ByteReader.ReadBytes_RentArray(lmowf, 7, 1), new byte[] { 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD });
                    var buf = ByteReader.ReadBytes_RentArray(lmChallengeResponse, 0, 8);
                    var temp1 = DesEncrypt_Rental(ExtendDESKey_Rental(k1), buf);
                    var temp2 = DesEncrypt_Rental(ExtendDESKey_Rental(k2), buf);
                    var keyExchangeKey = ByteUtils.Concatenate_Rental(temp1, temp2);
                    
                    ExactArrayPool.Return(k1, k2);
                    ExactArrayPool.Return(temp1, temp2);
                    ExactArrayPool.Return(buf);
                    return keyExchangeKey;
                }

                if ((negotiateFlags & NegotiateFlags.RequestLMSessionKey) > 0)
                {
                    var keyExchangeKey = ByteUtils.Concatenate_Rental(ByteReader.ReadBytes_RentArray(lmowf, 0, 8), new byte[8]);
                    return keyExchangeKey;
                }

                return sessionBaseKey;
            }

            {
                var buffer = ByteUtils.Concatenate_Rental(serverChallenge, ByteReader.ReadBytes_RentArray(lmChallengeResponse, 0, 8));
                var keyExchangeKey = new HMACMD5(sessionBaseKey).ComputeHash(buffer);
                return keyExchangeKey;
            }
        }
    }
}
