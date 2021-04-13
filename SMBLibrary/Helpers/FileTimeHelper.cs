/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.IO;
using Utilities;

namespace SMBLibrary
{
    public class FileTimeHelper
    {
        public static readonly DateTime MinFileTimeValue = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static DateTime ReadFileTime(Span<byte> buffer, int offset)
        {
            var span = LittleEndianConverter.ToInt64(buffer, offset);
            if (span >= 0)
            {
                return DateTime.FromFileTimeUtc(span);
            }

            throw new InvalidDataException("FILETIME cannot be negative");
        }

        public static DateTime ReadFileTime(Span<byte> buffer, ref int offset)
        {
            offset += 8;
            return ReadFileTime(buffer, offset - 8);
        }

        public static void WriteFileTime(Span<byte> buffer, int offset, DateTime time)
        {
            var span = time.ToFileTimeUtc();
            LittleEndianWriter.WriteInt64(buffer, offset, span);
        }

        public static void WriteFileTime(Span<byte> buffer, ref int offset, DateTime time)
        {
            WriteFileTime(buffer, offset, time);
            offset += 8;
        }

        public static DateTime? ReadNullableFileTime(Span<byte> buffer, int offset)
        {
            var span = LittleEndianConverter.ToInt64(buffer, offset);
            if (span > 0)
            {
                return DateTime.FromFileTimeUtc(span);
            }

            if (span == 0)
            {
                return null;
            }

            throw new InvalidDataException("FILETIME cannot be negative");
        }

        public static DateTime? ReadNullableFileTime(Span<byte> buffer, ref int offset)
        {
            offset += 8;
            return ReadNullableFileTime(buffer, offset - 8);
        }

        public static void WriteFileTime(Span<byte> buffer, int offset, DateTime? time)
        {
            long span = 0;
            if (time.HasValue)
            {
                span = time.Value.ToFileTimeUtc();
            }
            LittleEndianWriter.WriteInt64(buffer, offset, span);
        }

        public static void WriteFileTime(Span<byte> buffer, ref int offset, DateTime? time)
        {
            WriteFileTime(buffer, offset, time);
            offset += 8;
        }

        /// <summary>
        /// When setting file attributes, a value of -1 indicates to the server that it MUST NOT change this attribute for all subsequent operations on the same file handle.
        /// </summary>
        public static SetFileTime ReadSetFileTime(IMemoryOwner<byte> buffer, int offset) =>
            ReadSetFileTime(buffer.Memory.Span, offset);
        
        public static SetFileTime ReadSetFileTime(Span<byte> buffer, int offset)
        {
            var span = LittleEndianConverter.ToInt64(buffer, offset);
            return SetFileTime.FromFileTimeUtc(span);
        }

        /// <summary>
        /// When setting file attributes, a value of -1 indicates to the server that it MUST NOT change this attribute for all subsequent operations on the same file handle.
        /// </summary>
        public static void WriteSetFileTime(IMemoryOwner<byte> buffer, int offset, SetFileTime time) =>
            WriteSetFileTime(buffer.Memory.Span, offset, time);
        
        public static void WriteSetFileTime(Span<byte> buffer, int offset, SetFileTime time)
        {
            var span = time.ToFileTimeUtc();
            LittleEndianWriter.WriteInt64(buffer, offset, span);
        }
    }
}
