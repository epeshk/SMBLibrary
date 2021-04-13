using System;
using System.Buffers;
using System.IO;

namespace Utilities
{
    public class LittleEndianWriter
    {
        public static void WriteUInt16(IMemoryOwner<byte> buffer, int offset, ushort value) => 
            WriteUInt16(buffer.Memory.Span, offset, value);
        
        public static void WriteUInt16(Span<byte> buffer, int offset, ushort value) => 
            LittleEndianConverter.GetBytes(buffer.Slice(offset), value);

        public static void WriteUInt16(Span<byte> buffer, ref int offset, ushort value)
        {
            WriteUInt16(buffer, offset, value);
            offset += 2;
        }

        public static void WriteInt16(Span<byte> buffer, int offset, short value) => 
            LittleEndianConverter.GetBytes(buffer.Slice(offset), value);

        public static void WriteInt16(Span<byte> buffer, ref int offset, short value)
        {
            WriteInt16(buffer, offset, value);
            offset += 2;
        }

        public static void WriteUInt32(IMemoryOwner<byte> buffer, int offset, uint value) => 
            WriteUInt32(buffer.Memory.Span, offset, value);
        
        public static void WriteUInt32(Span<byte> buffer, int offset, uint value) => 
            LittleEndianConverter.GetBytes(buffer.Slice(offset), value);

        public static void WriteUInt32(Span<byte> buffer, ref int offset, uint value)
        {
            WriteUInt32(buffer, offset, value);
            offset += 4;
        }

        public static void WriteInt32(Span<byte> buffer, int offset, int value) => 
            LittleEndianConverter.GetBytes(buffer.Slice(offset), value);

        public static void WriteInt32(Span<byte> buffer, ref int offset, int value)
        {
            WriteInt32(buffer, offset, value);
            offset += 4;
        }

        public static void WriteUInt64(IMemoryOwner<byte> buffer, int offset, ulong value) =>
            WriteUInt64(buffer.Memory.Span, offset, value);
        
        public static void WriteUInt64(Span<byte> buffer, int offset, ulong value)
        {
            LittleEndianConverter.GetBytes(buffer.Slice(offset), value);
        }

        public static void WriteUInt64(Span<byte> buffer, ref int offset, ulong value)
        {
            WriteUInt64(buffer, offset, value);
            offset += 8;
        }

        public static void WriteInt64(Span<byte> buffer, int offset, long value) => 
            LittleEndianConverter.GetBytes(buffer.Slice(offset), value);

        public static void WriteInt64(Span<byte> buffer, ref int offset, long value)
        {
            WriteInt64(buffer, offset, value);
            offset += 8;
        }

        public static void WriteGuidBytes(Span<byte> buffer, int offset, Guid value) => 
            LittleEndianConverter.GetBytes(buffer.Slice(offset), value);

        public static void WriteGuidBytes(Span<byte> buffer, ref int offset, Guid value)
        {
            WriteGuidBytes(buffer, offset, value);
            offset += 16;
        }

        public static void WriteUInt16(Stream stream, ushort value)
        {
            Span<byte> buf = stackalloc byte[2];
            LittleEndianConverter.GetBytes(buf, value);
            stream.Write(buf);
        }

        public static void WriteInt32(Stream stream, int value)
        {
            Span<byte> buf = stackalloc byte[4];
            LittleEndianConverter.GetBytes(buf, value);
            stream.Write(buf);
        }

        public static void WriteUInt32(Stream stream, uint value)
        {
            Span<byte> buf = stackalloc byte[4];
            LittleEndianConverter.GetBytes(buf, value);
            stream.Write(buf);
        }
    }
}
