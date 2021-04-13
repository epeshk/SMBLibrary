using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace Utilities
{
    public class LittleEndianConverter
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ushort ToUInt16(IMemoryOwner<byte> buffer, int offset) => ToUInt16(buffer.Memory.Span, offset);
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ushort ToUInt16(Span<byte> buffer, int offset)
        {
            return (ushort)((buffer[offset + 1] << 8) | (buffer[offset + 0] << 0));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static short ToInt16(IMemoryOwner<byte> buffer, int offset) => ToInt16(buffer.Memory.Span, offset);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static short ToInt16(Span<byte> buffer, int offset)
        {
            return (short)ToUInt16(buffer, offset);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ToUInt32(IMemoryOwner<byte> buffer, int offset) => ToUInt32(buffer.Memory.Span, offset);
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ToUInt32(Span<byte> buffer, int offset)
        {
            return (uint)((buffer[offset + 3] << 24) | (buffer[offset + 2] << 16)
                | (buffer[offset + 1] << 8) | (buffer[offset + 0] << 0));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ToInt32(IMemoryOwner<byte> buffer, int offset) => ToInt32(buffer.Memory.Span, offset);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ToInt32(Span<byte> buffer, int offset)
        {
            return (int)ToUInt32(buffer, offset);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToUInt64(Span<byte> buffer, int offset)
        {
            return (((ulong)ToUInt32(buffer, offset + 4)) << 32) | ToUInt32(buffer, offset + 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long ToInt64(Span<byte> buffer, int offset)
        {
            return (long)ToUInt64(buffer, offset);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static float ToFloat32(Span<byte> buffer, int offset)
        {
            var bytes = new byte[4];
            buffer.Slice(offset, 4).CopyTo(bytes);
            
            if (!BitConverter.IsLittleEndian)
            {
                // reverse the order of 'bytes'
                for (var index = 0; index < 2; index++)
                {
                    var temp = bytes[index];
                    bytes[index] = bytes[3 - index];
                    bytes[3 - index] = temp;
                }
            }
            return BitConverter.ToSingle(bytes, 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static double ToFloat64(Span<byte> buffer, int offset)
        {
            var bytes = new byte[8];
            buffer.Slice(offset, 8).CopyTo(bytes);
            
            if (!BitConverter.IsLittleEndian)
            {
                // reverse the order of 'bytes'
                for(var index = 0; index < 4; index++)
                {
                    var temp = bytes[index];
                    bytes[index] = bytes[7 - index];
                    bytes[7 - index] = temp;
                }
            }
            return BitConverter.ToDouble(bytes, 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Guid ToGuid(Span<byte> target, int offset)
        {
            return new Guid(
                ToUInt32(target, offset + 0),
                ToUInt16(target, offset + 4),
                ToUInt16(target, offset + 6),
                target[offset + 8],
                target[offset + 9],
                target[offset + 10],
                target[offset + 11],
                target[offset + 12],
                target[offset + 13],
                target[offset + 14],
                target[offset + 15]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void GetBytes(Span<byte> target, ushort value)
        {
            target[0] = (byte)((value >> 0) & 0xFF);
            target[1] = (byte)((value >> 8) & 0xFF);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void GetBytes(Span<byte> target, short value) => GetBytes(target, (ushort)value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void GetBytes(Span<byte> target, uint value)
        {
            target[0] = (byte)((value >> 0) & 0xFF);
            target[1] = (byte)((value >> 8) & 0xFF);
            target[2] = (byte)((value >> 16) & 0xFF);
            target[3] = (byte)((value >> 24) & 0xFF);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void GetBytes(Span<byte> target, int value)
        {
            target[0] = (byte)((value >> 0) & 0xFF);
            target[1] = (byte)((value >> 8) & 0xFF);
            target[2] = (byte)((value >> 16) & 0xFF);
            target[3] = (byte)((value >> 24) & 0xFF);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void GetBytes(Span<byte> target, ulong value)
        {
            GetBytes(target.Slice(0, 4), (uint)(value & 0xFFFFFFFF));
            GetBytes(target.Slice(4, 4), (uint)(value >> 32));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void GetBytes(Span<byte> target, long value) => GetBytes(target, (ulong)value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void GetBytes(Span<byte> t, Guid value)
        {
            value.TryWriteBytes(t);
            if (!BitConverter.IsLittleEndian)
            {
                (t[0], t[1], t[2], t[3]) = (t[3], t[2], t[1], t[0]);
                (t[4], t[5], t[6], t[7]) = (t[5], t[4], t[7], t[6]);
            }
        }
    }
}
