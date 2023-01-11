/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;

namespace Utilities
{
    public class LittleEndianConverter
    {
        public static ushort ToUInt16(Span<byte> buffer, int offset)
        {
            return (ushort)((buffer[offset + 1] << 8) | (buffer[offset + 0] << 0));
        }

        public static short ToInt16(Span<byte> buffer, int offset)
        {
            return (short)ToUInt16(buffer, offset);
        }

        public static uint ToUInt32(Span<byte> buffer, int offset)
        {
            return (uint)((buffer[offset + 3] << 24) | (buffer[offset + 2] << 16)
                | (buffer[offset + 1] << 8) | (buffer[offset + 0] << 0));
        }

        public static int ToInt32(Span<byte> buffer, int offset)
        {
            return (int)ToUInt32(buffer, offset);
        }

        public static ulong ToUInt64(Span<byte> buffer, int offset)
        {
            return (((ulong)ToUInt32(buffer, offset + 4)) << 32) | ToUInt32(buffer, offset + 0);
        }

        public static long ToInt64(Span<byte> buffer, int offset)
        {
            return (long)ToUInt64(buffer, offset);
        }

        public static Guid ToGuid(Span<byte> buffer, int offset)
        {
            return new Guid(
                ToUInt32(buffer, offset + 0),
                ToUInt16(buffer, offset + 4),
                ToUInt16(buffer, offset + 6),
                buffer[offset + 8],
                buffer[offset + 9],
                buffer[offset + 10],
                buffer[offset + 11],
                buffer[offset + 12],
                buffer[offset + 13],
                buffer[offset + 14],
                buffer[offset + 15]);
        }

        public static void GetBytes(ushort value, Span<byte> output)
        {
            output[0] = (byte)((value >> 0) & 0xFF);
            output[1] = (byte)((value >> 8) & 0xFF);
        }

        public static void GetBytes(short value, Span<byte> output)
        {
            GetBytes((ushort)value, output);
        }

        public static void GetBytes(uint value, Span<byte> output)
        {
            output[0] = (byte)((value >> 0) & 0xFF);
            output[1] = (byte)((value >> 8) & 0xFF);
            output[2] = (byte)((value >> 16) & 0xFF);
            output[3] = (byte)((value >> 24) & 0xFF);
        }

        public static void GetBytes(int value, Span<byte> output)
        {
            GetBytes((uint)value, output);
        }

        public static void GetBytes(ulong value, Span<byte> output)
        {
            GetBytes((uint)(value & 0xFFFFFFFF), output.Slice(0, 4));
            GetBytes((uint)(value >> 32), output.Slice(4, 4));
        }

        public static void GetBytes(long value, Span<byte> output)
        {
            GetBytes((ulong)value, output);
        }

        public static byte[] GetBytes(Guid value)
        {
            byte[] result = value.ToByteArray();
            if (!BitConverter.IsLittleEndian)
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
