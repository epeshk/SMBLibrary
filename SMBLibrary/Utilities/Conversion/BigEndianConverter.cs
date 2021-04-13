using System;
using System.Runtime.CompilerServices;

namespace Utilities
{
    public class BigEndianConverter
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ushort ToUInt16(Span<byte> buffer, int offset)
        {
            return (ushort)((buffer[offset + 0] << 8) | (buffer[offset + 1] << 0));
        }

        public static short ToInt16(Span<byte> buffer, int offset)
        {
            return (short)ToUInt16(buffer, offset);
        }

        public static uint ToUInt32(Span<byte> buffer, int offset)
        {
            return (uint)((buffer[offset + 0] << 24) | (buffer[offset + 1] << 16)
                | (buffer[offset + 2] << 8) | (buffer[offset + 3] << 0));
        }

        public static int ToInt32(Span<byte> buffer, int offset)
        {
            return (int)ToUInt32(buffer, offset);
        }

        public static ulong ToUInt64(Span<byte> buffer, int offset)
        {
            return (((ulong)ToUInt32(buffer, offset + 0)) << 32) | ToUInt32(buffer, offset + 4);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteBytes(Span<byte> target, uint value)
        {
            target[0] = (byte)((value >> 24) & 0xFF);
            target[1] = (byte)((value >> 16) & 0xFF);
            target[2] = (byte)((value >> 8) & 0xFF);
            target[3] = (byte)((value >> 0) & 0xFF);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteBytes(Span<byte> target, int value)
        {
            WriteBytes(target, (uint) value);
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteBytes(Span<byte> target, ushort value)
        {
            target[0] = (byte)((value >> 8) & 0xFF);
            target[1] = (byte)((value >> 0) & 0xFF);
        }

        public static void WriteBytes(Span<byte> result, ulong value)
        {
            WriteBytes(result.Slice(0, 4), (uint) (value >> 32));
            WriteBytes(result.Slice(4, 4), (uint) (value  & 0xFFFFFFFF));
        }

        public static void WriteBytes(Span<byte> result, long value)
        {
            WriteBytes(result, (ulong)value);
        }
        
        public static void WriteBytes(Span<byte> t, Guid value)
        {
            value.TryWriteBytes(t);
            if (BitConverter.IsLittleEndian)
            {
                // reverse first 4 bytes
                (t[0], t[1], t[2], t[3]) = (t[3], t[2], t[1], t[0]);

                // reverse next 2 bytes
                (t[4], t[5]) = (t[5], t[4]);

                // reverse next 2 bytes
                (t[6], t[7]) = (t[7], t[6]);
            }
        }
    }
}
