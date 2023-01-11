/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.IO;

namespace Utilities
{
    public class LittleEndianWriter
    {
        public static void WriteUInt16(byte[] buffer, int offset, ushort value)
        {
            LittleEndianConverter.GetBytes(value, buffer.AsSpan(offset, 2));
        }

        public static void WriteUInt16(byte[] buffer, ref int offset, ushort value)
        {
            WriteUInt16(buffer, offset, value);
            offset += 2;
        }

        public static void WriteInt16(byte[] buffer, int offset, short value)
        {
            LittleEndianConverter.GetBytes(value, buffer.AsSpan(offset, 2));
        }

        public static void WriteInt16(byte[] buffer, ref int offset, short value)
        {
            WriteInt16(buffer, offset, value);
            offset += 2;
        }

        public static void WriteUInt32(byte[] buffer, int offset, uint value)
        {
            LittleEndianConverter.GetBytes(value, buffer.AsSpan(offset, 4));
        }

        public static void WriteUInt32(byte[] buffer, ref int offset, uint value)
        {
            WriteUInt32(buffer, offset, value);
            offset += 4;
        }

        public static void WriteInt32(byte[] buffer, int offset, int value)
        {
            LittleEndianConverter.GetBytes(value, buffer.AsSpan(offset, 4));
        }

        public static void WriteInt32(byte[] buffer, ref int offset, int value)
        {
            WriteInt32(buffer, offset, value);
            offset += 4;
        }

        public static void WriteUInt64(byte[] buffer, int offset, ulong value)
        {
            LittleEndianConverter.GetBytes(value, buffer.AsSpan(offset, 8));
        }

        public static void WriteUInt64(byte[] buffer, ref int offset, ulong value)
        {
            WriteUInt64(buffer, offset, value);
            offset += 8;
        }

        public static void WriteInt64(byte[] buffer, int offset, long value)
        {
            LittleEndianConverter.GetBytes(value, buffer.AsSpan(offset, 8));
        }

        public static void WriteInt64(byte[] buffer, ref int offset, long value)
        {
            WriteInt64(buffer, offset, value);
            offset += 8;
        }

        public static void WriteGuid(byte[] buffer, int offset, Guid value)
        {
            byte[] bytes = LittleEndianConverter.GetBytes(value);
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
            LittleEndianConverter.GetBytes(value, bytes);
            stream.Write(bytes);
        }

        public static void WriteInt32(Stream stream, int value)
        {
            Span<byte> bytes = stackalloc byte[4];
            LittleEndianConverter.GetBytes(value, bytes);
            stream.Write(bytes);
        }

        public static void WriteUInt32(Stream stream, uint value)
        {
            Span<byte> bytes = stackalloc byte[4];
            LittleEndianConverter.GetBytes(value, bytes);
            stream.Write(bytes);
        }
    }
}
