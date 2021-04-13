using System;
using System.Buffers;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

namespace Utilities
{
    public class BufferWriter
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteByte(IMemoryOwner<byte> buf, int offset, byte value) =>
            WriteByte(buf.Memory.Span, offset, value);
        
        public static void WriteByte(Span<byte> buf, int offset, byte value)
        {
            buf[offset] = value;
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteByte(Span<byte> buf, ref int offset, byte value)
        {
            buf[offset] = value;
            offset++;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteBytes(Span<byte> buffer, int offset, Span<byte> bytes)
        {
            bytes.CopyTo(buffer.Slice(offset));
        }

        public static void WriteBytes(Span<byte> buffer, Span<byte> bytes)
        {
            bytes.CopyTo(buffer);
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteBytes(Span<byte> buffer, ref int offset, Span<byte> bytes)
        {
            bytes.CopyTo(buffer.Slice(offset));
            offset += bytes.Length;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteBytes(Span<byte> buffer, int offset, Span<byte> bytes, int length)
        {
            bytes.Slice(0, length).CopyTo(buffer.Slice(offset));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteBytes(Span<byte> buffer, ref int offset, ReadOnlySpan<byte> bytes, int length)
        {
            bytes.Slice(0, length).CopyTo(buffer.Slice(offset));
            offset += length;
        }

        public static void WriteAnsiString(Span<byte> buffer, int offset, ReadOnlySpan<char> value)
        {
            WriteAnsiString(buffer, offset, value, value.Length);
        }

        public static void WriteAnsiString(Span<byte> buffer, ref int offset, ReadOnlySpan<char> value)
        {
            WriteAnsiString(buffer, ref offset, value, value.Length);
        }

        public static void WriteAnsiString(Span<byte> buffer, int offset, ReadOnlySpan<char> value, int maximumLength)
        {
            Encoding.GetEncoding(28591).GetBytes(value, buffer.Slice(offset));
        }

        public static void WriteAnsiString(Span<byte> buffer, ref int offset, ReadOnlySpan<char> value, int fieldLength)
        {
            WriteAnsiString(buffer, offset, value, fieldLength);
            offset += fieldLength;
        }


        public static void WriteUTF16String(IMemoryOwner<byte> buffer, int offset, ReadOnlySpan<char> value) =>
            WriteUTF16String(buffer.Memory.Span, offset, value);
            
        public static void WriteUTF16String(Span<byte> buffer, int offset, ReadOnlySpan<char> value)
        {
            WriteUTF16String(buffer, offset, value, value.Length);
        }

        public static void WriteUTF16String(Span<byte> buffer, ref int offset, ReadOnlySpan<char> value)
        {
            WriteUTF16String(buffer, ref offset, value, value.Length);
        }

        public static void WriteUTF16String(Span<byte> buffer, int offset, ReadOnlySpan<char> value, int maximumNumberOfCharacters)
        {
            Encoding.Unicode.GetBytes(value.Slice(0, maximumNumberOfCharacters), buffer.Slice(offset));
        }

        public static void WriteUTF16String(Span<byte> buffer, ref int offset, ReadOnlySpan<char> value, int numberOfCharacters)
        {
            WriteUTF16String(buffer, offset, value, numberOfCharacters);
            offset += numberOfCharacters * 2;
        }

        public static void WriteNullTerminatedAnsiString(Span<byte> buffer, int offset, ReadOnlySpan<char> value)
        {
            WriteAnsiString(buffer, offset, value);
            WriteByte(buffer, offset + value.Length, 0x00);
        }

        public static void WriteNullTerminatedAnsiString(Span<byte> buffer, ref int offset, ReadOnlySpan<char> value)
        {
            WriteNullTerminatedAnsiString(buffer, offset, value);
            offset += value.Length + 1;
        }

        public static void WriteNullTerminatedUTF16String(Span<byte> buffer, int offset, ReadOnlySpan<char> value)
        {
            WriteUTF16String(buffer, offset, value);
            WriteBytes(buffer, offset + value.Length * 2, new byte[] { 0x00, 0x00 });
        }

        public static void WriteNullTerminatedUTF16String(Span<byte> buffer, ref int offset, ReadOnlySpan<char> value)
        {
            WriteNullTerminatedUTF16String(buffer, offset, value);
            offset += value.Length * 2 + 2;
        }

        public static void WriteBytes(Stream stream, byte[] bytes)
        {
            stream.Write(bytes, 0, bytes.Length);
        }

        public static void WriteBytes(Stream stream, byte[] bytes, int count)
        {
            stream.Write(bytes, 0, count);
        }

        public static void WriteAnsiString(Stream stream, string value)
        {
            WriteAnsiString(stream, value, value.Length);
        }

        public static void WriteAnsiString(Stream stream, string value, int fieldLength)
        {
            var bytes = Encoding.GetEncoding(28591).GetBytes(value);
            stream.Write(bytes, 0, Math.Min(bytes.Length, fieldLength));
            if (bytes.Length < fieldLength)
            { 
                var zeroFill = new byte[fieldLength - bytes.Length];
                stream.Write(zeroFill, 0, zeroFill.Length);
            }
        }

        public static void WriteUTF8String(Stream stream, string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }

        public static void WriteUTF16String(Stream stream, string value)
        {
            var bytes = Encoding.Unicode.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }

        public static void WriteUTF16BEString(Stream stream, string value)
        {
            var bytes = Encoding.BigEndianUnicode.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }
    }
}
