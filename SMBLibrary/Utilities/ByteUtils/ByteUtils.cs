using System;
using System.Buffers;
using System.IO;
using MemoryPools.Memory;
using SMBLibrary;

namespace Utilities
{
    public class ByteUtils
    {
        public static byte[] Concatenate_Rental(Span<byte> a, Span<byte> b)
        {
            var result = ExactArrayPool.Rent(a.Length + b.Length);
            a.CopyTo(result);
            b.CopyTo(result.AsSpan(a.Length));
            return result;
        }

        public static IMemoryOwner<byte> Concatenate(Span<byte> a, Span<byte> b)
        {
            var result = Arrays.Rent(a.Length + b.Length);
            a.CopyTo(result.Memory.Span);
            b.CopyTo(result.Memory.Span.Slice(a.Length));
            return result;
        }

        public static bool AreByteArraysEqual(Span<byte> array1, Span<byte> array2)
        {
            if (array1.Length != array2.Length)
            {
                return false;
            }

            for (var index = 0; index < array1.Length; index++)
            {
                if (array1[index] != array2[index])
                {
                    return false;
                }
            }

            return true;
        }

        public static byte[] XOR(byte[] array1, byte[] array2)
        {
            if (array1.Length == array2.Length)
            {
                return XOR(array1, 0, array2, 0, array1.Length);
            }

            throw new ArgumentException("Arrays must be of equal length");
        }

        public static byte[] XOR(byte[] array1, int offset1, byte[] array2, int offset2, int length)
        {
            if (offset1 + length <= array1.Length && offset2 + length <= array2.Length)
            {
                var result = new byte[length];
                for (var index = 0; index < length; index++)
                {
                    result[index] = (byte)(array1[offset1 + index] ^ array2[offset2 + index]);
                }
                return result;
            }

            throw new ArgumentOutOfRangeException();
        }

        public static long CopyStream(Stream input, Stream output)
        {
            // input may not support seeking, so don't use input.Position
            return CopyStream(input, output, Int64.MaxValue);
        }

        public static long CopyStream(Stream input, Stream output, long count)
        {
            const int MaxBufferSize = 1048576; // 1 MB
            var bufferSize = (int)Math.Min(MaxBufferSize, count);
            var buffer = new byte[bufferSize];
            long totalBytesRead = 0;
            while (totalBytesRead < count)
            {
                var numberOfBytesToRead = (int)Math.Min(bufferSize, count - totalBytesRead);
                var bytesRead = input.Read(buffer, 0, numberOfBytesToRead);
                totalBytesRead += bytesRead;
                output.Write(buffer, 0, bytesRead);
                if (bytesRead == 0) // no more bytes to read from input stream
                {
                    return totalBytesRead;
                }
            }
            return totalBytesRead;
        }
    }
}
