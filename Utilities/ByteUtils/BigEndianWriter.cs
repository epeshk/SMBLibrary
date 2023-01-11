/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.IO;

namespace Utilities
{
    public class BigEndianWriter
    {
        public static void WriteInt16(byte[] buffer, int offset, short value)
        {
            BigEndianConverter.GetBytes(value, buffer.AsSpan(offset, 2));
        }

        public static void WriteInt16(byte[] buffer, ref int offset, short value)
        {
            WriteInt16(buffer, offset, value);
            offset += 2;
        }

        public static void WriteUInt16(byte[] buffer, int offset, ushort value)
        {
            BigEndianConverter.GetBytes(value, buffer.AsSpan(offset, 2));
        }

        public static void WriteUInt16(byte[] buffer, ref int offset, ushort value)
        {
            WriteUInt16(buffer, offset, value);
            offset += 2;
        }

        public static void WriteUInt32(byte[] buffer, int offset, uint value)
        {
            BigEndianConverter.GetBytes(value, buffer.AsSpan(offset, 4));
        }

        public static void WriteUInt32(byte[] buffer, ref int offset, uint value)
        {
            WriteUInt32(buffer, offset, value);
            offset += 4;
        }

        public static void WriteGuid(byte[] buffer, int offset, Guid value)
        {
            byte[] bytes = BigEndianConverter.GetBytes(value);
            Array.Copy(bytes, 0, buffer, offset, bytes.Length);
        }

        public static void WriteGuid(byte[] buffer, ref int offset, Guid value)
        {
            WriteGuid(buffer, offset, value);
            offset += 16;
        }

        public static void WriteUInt16(Stream stream, ushort value)
        {
            Span<byte> bytes = stackalloc byte[2];
            BigEndianConverter.GetBytes(value, bytes);
            stream.Write(bytes);
        }
    }
}
