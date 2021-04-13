/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Text;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.Authentication.GSSAPI
{
    public enum DerEncodingTag : byte
    {
        ByteArray = 0x04,        // Octet String
        ObjectIdentifier = 0x06,
        Enum = 0x0A,
        GeneralString = 0x1B,
        Sequence = 0x30,
    }

    public class DerEncodingHelper
    {
        public static int ReadLength(Span<byte> buffer, ref int offset)
        {
            int length = ByteReader.ReadByte(buffer, ref offset);
            if (length >= 0x80)
            {
                var lengthFieldSize = (length & 0x7F);
                var start = offset;
                offset += lengthFieldSize;
                length = 0;
                for (var i = start; i < offset; i++)
                {
                    length *= 256;
                    length += buffer[i];
                }
            }
            return length;
        }

        public static void WriteLength(Span<byte> buffer, ref int offset, int length)
        {
            var pos = sizeof(int);
            
            if (length >= 0x80)
            {
                using var values = Arrays.Rent(sizeof(int));
                do
                {
                    pos--;
                    var value = (byte)(length % 256);
                    values.Memory.Span[pos] = value;
                    length = length / 256;
                }
                while (length > 0);

                var scoped = values.Memory.Span.Slice(pos);
                BufferWriter.WriteByte(buffer, ref offset, (byte)(0x80 | scoped.Length));
                BufferWriter.WriteBytes(buffer, ref offset, scoped);
            }
            else
            {
                BufferWriter.WriteByte(buffer, ref offset, (byte)length);
            }
        }

        public static int GetLengthFieldSize(int length)
        {
            if (length >= 0x80)
            {
                var result = 1;
                do
                {
                    length = length / 256;
                    result++;
                }
                while(length > 0);
                return result;
            }

            return 1;
        }

        public static byte[] EncodeGeneralString(string value)
        {
            // We do not support character-set designation escape sequences
            return ASCIIEncoding.ASCII.GetBytes(value);
        }

        public static string DecodeGeneralString(byte[] bytes)
        {
            // We do not support character-set designation escape sequences
            return ASCIIEncoding.ASCII.GetString(bytes);
        }
    }
}
