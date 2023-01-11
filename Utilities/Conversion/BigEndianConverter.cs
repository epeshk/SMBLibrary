/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;

namespace Utilities
{
    public class BigEndianConverter
    {
        public static ushort ToUInt16(byte[] buffer, int offset)
        {
            return (ushort)((buffer[offset + 0] << 8) | (buffer[offset + 1] << 0));
        }

        public static uint ToUInt32(byte[] buffer, int offset)
        {
            return (uint)((buffer[offset + 0] << 24) | (buffer[offset + 1] << 16)
                | (buffer[offset + 2] << 8) | (buffer[offset + 3] << 0));
        }

        public static ulong ToUInt64(byte[] buffer, int offset)
        {
            return (((ulong)ToUInt32(buffer, offset + 0)) << 32) | ToUInt32(buffer, offset + 4);
        }

        public static void GetBytes(ushort value, Span<byte> output)
        {
            output[0] = (byte)((value >> 8) & 0xFF);
            output[1] = (byte)((value >> 0) & 0xFF);
        }

        public static void GetBytes(short value, Span<byte> output)
        {
            GetBytes((ushort)value, output);
        }

        public static void GetBytes(uint value, Span<byte> result)
        {
            result[0] = (byte)((value >> 24) & 0xFF);
            result[1] = (byte)((value >> 16) & 0xFF);
            result[2] = (byte)((value >> 8) & 0xFF);
            result[3] = (byte)((value >> 0) & 0xFF);
        }

        public static void GetBytes(ulong value, Span<byte> result)
        {
            GetBytes((uint)(value >> 32), result);
            GetBytes((uint)(value & 0xFFFFFFFF), result.Slice(4));
        }

        public static byte[] GetBytes(Guid value)
        {
            byte[] result = value.ToByteArray();
            if (BitConverter.IsLittleEndian)
            {
                // reverse first 4 bytes
                byte temp = result[0];
                result[0] = result[3];
                result[3] = temp;

                temp = result[1];
                result[1] = result[2];
                result[2] = temp;

                // reverse next 2 bytes
                temp = result[4];
                result[4] = result[5];
                result[5] = temp;

                // reverse next 2 bytes
                temp = result[6];
                result[6] = result[7];
                result[7] = temp;
            }
            return result;
        }
    }
}
