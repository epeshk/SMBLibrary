/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using Utilities;

namespace SMBLibrary.SMB1
{
    public class SMB1Helper
    {
        public static DateTime? ReadNullableFileTime(Span<byte> buffer, int offset)
        {
            var span = LittleEndianConverter.ToInt64(buffer, offset);
            if (span >= 0)
            {
                return DateTime.FromFileTimeUtc(span);
            }

            if (span == 0)
            {
                return null;
            }

            // Tick = 100ns
            return DateTime.UtcNow.Subtract(TimeSpan.FromTicks(span));
        }

        public static DateTime? ReadNullableFileTime(Span<byte> buffer, ref int offset)
        {
            offset += 8;
            return ReadNullableFileTime(buffer, offset - 8);
        }

        /// <summary>
        /// SMB_DATE
        /// </summary>
        public static DateTime ReadSMBDate(Span<byte> buffer, int offset)
        {
            var value = LittleEndianConverter.ToUInt16(buffer, offset);
            var year = ((value & 0xFE00) >> 9) + 1980;
            var month = ((value & 0x01E0) >> 5);
            var day = (value & 0x001F);
            // SMB_DATE & SMB_TIME are represented in the local time zone of the server
            return new DateTime(year, month, day, 0, 0, 0, DateTimeKind.Local);
        }

        public static void WriteSMBDate(Span<byte> buffer, int offset, DateTime date)
        {
            var year = date.Year - 1980;
            var month = date.Month;
            var day = date.Day;
            var value = (ushort)(year << 9 | month << 5 | day);
            LittleEndianWriter.WriteUInt16(buffer, offset, value);
        }

        /// <summary>
        /// SMB_DATE
        /// </summary>
        public static TimeSpan ReadSMBTime(Span<byte> buffer, int offset)
        {
            var value = LittleEndianConverter.ToUInt16(buffer, offset);
            var hours = ((value & 0xF800) >> 11);
            var minutes = ((value & 0x07E0) >> 5);
            var seconds = (value & 0x001F);
            return new TimeSpan(hours, minutes, seconds);
        }

        public static void WriteSMBTime(Span<byte> buffer, int offset, TimeSpan time)
        {
            var value = (ushort)(time.Hours << 11 | time.Minutes << 5 | time.Seconds);
            LittleEndianWriter.WriteUInt16(buffer, offset, value);
        }

        public static DateTime ReadSMBDateTime(Span<byte> buffer, int offset)
        {
            var date = ReadSMBDate(buffer, offset);
            var time = ReadSMBTime(buffer, offset + 2);
            return date.Add(time);
        }

        public static void WriteSMBDateTime(Span<byte> buffer, int offset, DateTime dateTime)
        {
            WriteSMBDate(buffer, offset, dateTime.Date);
            WriteSMBTime(buffer, offset + 2, dateTime.TimeOfDay);
        }

        public static DateTime? ReadNullableSMBDateTime(Span<byte> buffer, int offset)
        {
            var value = LittleEndianConverter.ToUInt32(buffer, offset);
            if (value > 0)
            {
                return ReadSMBDateTime(buffer, offset);
            }
            return null;
        }

        public static void WriteSMBDateTime(Span<byte> buffer, int offset, DateTime? dateTime)
        {
            if (dateTime.HasValue)
            {
                WriteSMBDateTime(buffer, offset, dateTime.Value);
            }
            else
            {
                LittleEndianWriter.WriteUInt32(buffer, offset, 0);
            }
        }

        public static string ReadSMBString(IMemoryOwner<byte> buffer, int offset, bool isUnicode) =>
            ReadSMBString(buffer.Memory.Span, offset, isUnicode);
        
        public static string ReadSMBString(Span<byte> buffer, int offset, bool isUnicode)
        {
            if (isUnicode)
            {
                return ByteReader.ReadNullTerminatedUTF16String(buffer, offset);
            }

            return ByteReader.ReadNullTerminatedAnsiString(buffer, offset);
        }

        public static string ReadSMBString(IMemoryOwner<byte> buffer, ref int offset, bool isUnicode) =>
            ReadSMBString(buffer.Memory.Span, ref offset, isUnicode);
        
        public static string ReadSMBString(Span<byte> buffer, ref int offset, bool isUnicode)
        {
            if (isUnicode)
            {
                return ByteReader.ReadNullTerminatedUTF16String(buffer, ref offset);
            }

            return ByteReader.ReadNullTerminatedAnsiString(buffer, ref offset);
        }

        public static void WriteSMBString(IMemoryOwner<byte> buffer, int offset, bool isUnicode, string value) =>
            WriteSMBString(buffer.Memory.Span, offset, isUnicode, value);
        
        public static void WriteSMBString(Span<byte> buffer, int offset, bool isUnicode, string value)
        {
            if (isUnicode)
            {
                BufferWriter.WriteNullTerminatedUTF16String(buffer, offset, value);
            }
            else
            {
                BufferWriter.WriteNullTerminatedAnsiString(buffer, offset, value);
            }
        }

        public static void WriteSMBString(Span<byte> buffer, ref int offset, bool isUnicode, ReadOnlySpan<char> value)
        {
            if (isUnicode)
            {
                BufferWriter.WriteNullTerminatedUTF16String(buffer, ref offset, value);
            }
            else
            {
                BufferWriter.WriteNullTerminatedAnsiString(buffer, ref offset, value);
            }
        }

        public static void ReadFixedLengthString(Span<char> target, Span<byte> buffer, ref int offset, bool isUnicode, int byteCount)
        {
            if (isUnicode)
            {
                ByteReader.ReadUTF16String(target, buffer, ref offset, byteCount / 2);
            }
            else
            {
                ByteReader.ReadAnsiString(target, buffer, ref offset, byteCount);
            }
        }
        
        [Obsolete]
        public static string ReadFixedLengthString(Span<byte> buffer, ref int offset, bool isUnicode, int byteCount)
        {
            if (isUnicode)
            {
                return ByteReader.ReadUTF16String(buffer, ref offset, byteCount / 2);
            }

            return ByteReader.ReadAnsiString(buffer, ref offset, byteCount);
        }

        public static void WriteFixedLengthString(Span<byte> buffer, ref int offset, bool isUnicode, string value)
        {
            if (isUnicode)
            {
                BufferWriter.WriteUTF16String(buffer, ref offset, value);
            }
            else
            {
                BufferWriter.WriteAnsiString(buffer, ref offset, value);
            }
        }
    }
}
