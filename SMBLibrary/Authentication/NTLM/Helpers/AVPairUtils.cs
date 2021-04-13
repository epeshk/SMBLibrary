/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Text;
using Utilities;

namespace SMBLibrary.Authentication.NTLM
{
    public class AVPairUtils
    {
        public static KeyValuePairList<AVPairKey, byte[]> GetAVPairSequence(string domainName, string computerName)
        {
            var pairs = new KeyValuePairList<AVPairKey, byte[]>();
            pairs.Add(AVPairKey.NbDomainName, UnicodeEncoding.Unicode.GetBytes(domainName));
            pairs.Add(AVPairKey.NbComputerName, UnicodeEncoding.Unicode.GetBytes(computerName));
            return pairs;
        }

        public static byte[] GetAVPairSequenceBytes(KeyValuePairList<AVPairKey, byte[]> pairs)
        {
            var length = GetAVPairSequenceLength(pairs);
            var result = new byte[length];
            var offset = 0;
            WriteAVPairSequence(result, ref offset, pairs);
            return result;
        }

		public static int GetAVPairSequenceLength(KeyValuePairList<AVPairKey, byte[]> pairs)
		{
			var length = 0;
            for (var index = 0; index < pairs.Count; index++)
            {
                var pair = pairs[index];
                length += 4 + pair.Value.Length;
            }

            return length + 4;
		}

		public static void WriteAVPairSequence(Span<byte> buffer, ref int offset, KeyValuePairList<AVPairKey, byte[]> pairs)
		{
            for (var index = 0; index < pairs.Count; index++)
            {
                var pair = pairs[index];
                WriteAVPair(buffer, ref offset, pair.Key, pair.Value);
            }

            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort)AVPairKey.EOL);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, 0);
		}

        private static void WriteAVPair(Span<byte> buffer, ref int offset, AVPairKey key, byte[] value)
        {
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort)key);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort)value.Length);
            BufferWriter.WriteBytes(buffer, ref offset, value);
        }

        public static KeyValuePairList<AVPairKey, byte[]> ReadAVPairSequence(Span<byte> buffer, int offset)
        {
            var result = new KeyValuePairList<AVPairKey,byte[]>();
            var key = (AVPairKey)LittleEndianConverter.ToUInt16(buffer, offset);
            while (key != AVPairKey.EOL)
            {
                var pair = ReadAVPair(buffer, ref offset);
                result.Add(pair);
                key = (AVPairKey)LittleEndianConverter.ToUInt16(buffer, offset);
            }

            return result;
        }

        private static KeyValuePair<AVPairKey, byte[]> ReadAVPair(Span<byte> buffer, ref int offset)
        {
            var key = (AVPairKey)LittleEndianReader.ReadUInt16(buffer, ref offset);
            var length = LittleEndianReader.ReadUInt16(buffer, ref offset);
            var value = ByteReader.ReadBytes_RentArray(buffer, ref offset, length);
            return new KeyValuePair<AVPairKey, byte[]>(key, value);
        }
    }
}
