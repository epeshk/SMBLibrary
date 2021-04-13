using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace Utilities
{
    public class BigEndianWriter
    {
        public static void WriteInt16(Span<byte> buffer, int offset, short value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
        }

        public static void WriteInt16(Span<byte> buffer, ref int offset, short value)
        {
            WriteInt16(buffer, offset, value);
            offset += 2;
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUInt16(Span<byte> buffer, int offset, ushort value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
        }      
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUInt16(Span<byte> buffer, ref int offset, ushort value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
            offset += 2;
        }

        public static void WriteInt32(Span<byte> buffer, int offset, int value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
        }

        public static void WriteInt32(Span<byte> buffer, ref int offset, int value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
            offset += 4;
        }

        public static void WriteUInt32(Span<byte> buffer, int offset, uint value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
        }

        public static void WriteUInt32(Span<byte> buffer, ref int offset, uint value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
            offset += 4;
        }

        public static void WriteInt64(Span<byte> buffer, int offset, long value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
        }

        public static void WriteInt64(Span<byte> buffer, ref int offset, long value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
            offset += 8;
        }

        public static void WriteUInt64(Span<byte> buffer, int offset, ulong value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
        }

        public static void WriteUInt64(Span<byte> buffer, ref int offset, ulong value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
            offset += 8;
        }

        public static void WriteGuidBytes(Span<byte> buffer, int offset, Guid value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
        }

        public static void WriteGuidBytes(Span<byte> buffer, ref int offset, Guid value)
        {
            BigEndianConverter.WriteBytes(buffer.Slice(offset), value);
            offset += 16;
        }

        public static void WriteInt16(Stream stream, short value)
        {
            Span<byte> buf = stackalloc byte[2];
            BigEndianConverter.WriteBytes(buf, value);
            stream.Write(buf);
        }

        public static void WriteUInt16(Stream stream, ushort value)
        {
            Span<byte> buf = stackalloc byte[2];
            BigEndianConverter.WriteBytes(buf, value);
            stream.Write(buf);
        }

        public static void WriteInt32(Stream stream, int value)
        {
            Span<byte> buf = stackalloc byte[4];
            BigEndianConverter.WriteBytes(buf, value);
            stream.Write(buf);
        }

        public static void WriteUInt32(Stream stream, uint value)
        {
            Span<byte> buf = stackalloc byte[4];
            BigEndianConverter.WriteBytes(buf, value);
            stream.Write(buf);
        }

        public static void WriteInt64(Stream stream, long value)
        {
            Span<byte> buf = stackalloc byte[8];
            BigEndianConverter.WriteBytes(buf, value);
            stream.Write(buf);
        }

        public static void WriteUInt64(Stream stream, ulong value)
        {
            Span<byte> buf = stackalloc byte[8];
            BigEndianConverter.WriteBytes(buf, value);
            stream.Write(buf);
        }

        public static void WriteGuidBytes(Stream stream, Guid value)
        {
            Span<byte> buf = stackalloc byte[16];
            BigEndianConverter.WriteBytes(buf, value);
            stream.Write(buf);
        }
    }
}
